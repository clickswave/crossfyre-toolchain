//! Node configs (`nodes.d/<node-id>.toml`) as a privileged process reads and writes them.
//!
//! A node config names the API the node authorizes against and the broker it takes
//! commands from, and says whether it runs the commands that broker sends
//! (`remote_exec`). The node service runs as root (LocalSystem on Windows), but nodes.d
//! sits in the operator's config root, which the operator's account can write. So when
//! this process is privileged, a node config is taken only from a file that nobody but
//! root (an administrator, on Windows) can change, and the node writes its configs that
//! way. A file any other account could have written starts nothing.
//!
//! The operator's account still owns nodes.d itself, so it can remove a node's config,
//! which only stops that node. Changing one, `remote_exec` included, takes root.
//!
//! Configs written by 0.1.42 and earlier belong to the operator. The first privileged
//! run of a build with this check takes over those already there, once, and records
//! that it did in a directory only root can write. A file planted after that is never
//! taken over.

use std::io;
use std::path::{Path, PathBuf};

/// The directory in the config root that holds one `<node-id>.toml` per node.
pub const NODES_DIR: &str = "nodes.d";

/// Whether this process runs as root, or elevated on Windows, and so must take a node
/// config only from a file that only root or an administrator can change.
pub fn privileged() -> bool {
    #[cfg(unix)]
    {
        super::sudo_user::root_guards()
    }
    #[cfg(windows)]
    {
        crate::os::is_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Read the node config at `path`. When privileged, a file that another account owns
/// or can write is refused with an error saying how to hand it to root.
pub fn read(path: &Path) -> io::Result<String> {
    if !privileged() {
        return super::sudo_user::read_to_string(path);
    }
    imp::read_trusted(path)
}

/// Write the node config at `path`. When privileged, the file is replaced by a new one
/// that only root (administrators and LocalSystem, on Windows) can read or change, and
/// it is not handed back to the operator.
pub fn write(path: &Path, contents: &str) -> io::Result<()> {
    if !privileged() {
        return crate::write_secret_file(path, contents);
    }
    imp::write_trusted(path, contents.as_bytes())
}

/// Where the record that this host's node configs have been taken over is kept: a
/// directory that only root (administrators, on Windows) can write.
pub fn takeover_record() -> PathBuf {
    const NAME: &str = "node-configs-taken-over";
    #[cfg(windows)]
    {
        let base =
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
        PathBuf::from(base).join("Crossfyre").join(NAME)
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/db/crossfyre").join(NAME)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        PathBuf::from("/var/lib/crossfyre").join(NAME)
    }
}

/// Take over the node configs an earlier release left to the operator, the first time
/// a privileged process of this release runs on the host. Does nothing afterwards, and
/// nothing when not privileged.
pub fn take_over_earlier_configs(base: &Path) {
    if !privileged() {
        return;
    }
    take_over_once(&base.join(NODES_DIR), &takeover_record());
}

fn take_over_once(nodes_dir: &Path, record: &Path) {
    match claim(record) {
        Ok(true) => imp::take_over_all(nodes_dir),
        Ok(false) => {}
        Err(e) => eprintln!(
            "[node] could not write {}: {e}. Node configs that root does not own are not \
             taken over, and the node service will not run them.",
            record.display()
        ),
    }
}

/// Create `record`. True when this call created it, false when it was already there.
fn claim(record: &Path) -> io::Result<bool> {
    use std::io::Write;
    if let Some(dir) = record.parent() {
        #[cfg(unix)]
        super::root_fs::create_dir_all(dir, None)?;
        #[cfg(not(unix))]
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    match opts.open(record) {
        Ok(mut f) => {
            // Only for whoever finds the file: its being there is the record.
            let _ = f.write_all(
                b"The node configs on this host were handed to root once, when a release \
                  that requires it first ran. Delete this file only to do that again.\n",
            );
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// The `.toml` files in `nodes_dir`, skipping what cannot be listed.
fn configs_in(nodes_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(nodes_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect()
}

#[cfg(unix)]
mod imp {
    use super::super::root_fs;
    use std::io::{self, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    #[cfg(test)]
    thread_local! {
        static OWNER: std::cell::Cell<Option<(u32, u32)>> = const { std::cell::Cell::new(None) };
    }

    /// root:root, or in a test the account the test made trusted.
    fn trusted_owner() -> (u32, u32) {
        #[cfg(test)]
        if let Some(o) = OWNER.with(|c| c.get()) {
            return o;
        }
        (0, 0)
    }

    /// Makes `trusted_owner` this test's own account until dropped, so a test can see
    /// a config accepted and taken over without being root.
    #[cfg(test)]
    pub(super) struct TrustSelf;

    #[cfg(test)]
    pub(super) fn trust_self() -> TrustSelf {
        let own = unsafe { (libc::geteuid(), libc::getegid()) };
        OWNER.with(|c| c.set(Some(own)));
        TrustSelf
    }

    #[cfg(test)]
    impl Drop for TrustSelf {
        fn drop(&mut self) {
            OWNER.with(|c| c.set(None));
        }
    }

    /// Whether a file with owner `uid` and `mode` may be run as a node config.
    pub(super) fn judge(path: &Path, uid: u32, mode: u32) -> io::Result<()> {
        let why = if uid != trusted_owner().0 {
            format!("it belongs to uid {uid}")
        } else if mode & 0o022 != 0 {
            format!("its mode {:o} lets other accounts write it", mode & 0o777)
        } else {
            return Ok(());
        };
        let p = path.display();
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{p} is not used as a node config: {why}. A node runs as root and takes \
                 its config only from a file that only root can change. If you wrote this \
                 file, hand it to root: sudo chown root {p} && sudo chmod 600 {p}"
            ),
        ))
    }

    pub(super) fn read_trusted(path: &Path) -> io::Result<String> {
        let mut f = root_fs::open_file(path)?;
        let m = f.metadata()?;
        judge(path, m.uid(), m.mode())?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        Ok(s)
    }

    pub(super) fn write_trusted(path: &Path, contents: &[u8]) -> io::Result<()> {
        root_fs::replace_file(path, contents, 0o600, Some(trusted_owner()))
    }

    pub(super) fn take_over_all(nodes_dir: &Path) {
        let (uid, gid) = trusted_owner();
        for path in super::configs_in(nodes_dir) {
            // Without following a link, and not a file with a second name.
            let f = match root_fs::open_file(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[node] not taking over {}: {e}", path.display());
                    continue;
                }
            };
            let Ok(m) = f.metadata() else { continue };
            if m.uid() == uid && m.mode() & 0o077 == 0 {
                continue;
            }
            let fd = f.as_raw_fd();
            let done = unsafe { libc::fchown(fd, uid, gid) == 0 && libc::fchmod(fd, 0o600) == 0 };
            if done {
                println!(
                    "[node] {} now belongs to root, as every node config does from this \
                     release on. Edit it with sudo.",
                    path.display()
                );
            } else {
                eprintln!(
                    "[node] could not hand {} to root: {}",
                    path.display(),
                    io::Error::last_os_error()
                );
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::super::win;
    use std::io::{self, Read, Write};
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Access rights, from winnt.h.
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_READ: u32 = 0x8000_0000;

    fn refused(path: &Path, why: String) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not used as a node config: {why}. A node runs as LocalSystem and \
                 takes its config only from a file that only administrators can change. \
                 Register the node again from an elevated prompt (crossfyre node init) to \
                 write it that way.",
                path.display()
            ),
        )
    }

    pub(super) fn read_trusted(path: &Path) -> io::Result<String> {
        let mut f = win::open_plain(path, GENERIC_READ)?;
        let secured = win::security_of_file(&f, path).map_err(io::Error::other)?;
        super::super::service::judge_admin_only(&[secured]).map_err(|why| refused(path, why))?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        Ok(s)
    }

    static SEQ: AtomicU32 = AtomicU32::new(0);

    pub(super) fn write_trusted(path: &Path, contents: &[u8]) -> io::Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let name = name.unwrap_or_default();
        let mut attempt = 0;
        let (tmp, f) = loop {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
            match win::create_admin_only(&tmp) {
                Ok(f) => break (tmp, f),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 16 => attempt += 1,
                Err(e) => return Err(e),
            }
        };
        fn finish(
            mut f: std::fs::File,
            contents: &[u8],
            tmp: &Path,
            path: &Path,
        ) -> io::Result<()> {
            f.write_all(contents)?;
            f.sync_all()?;
            // Closed before the rename, which a handle still open would make fail.
            drop(f);
            std::fs::rename(tmp, path)
        }
        let result = finish(f, contents, &tmp, path);
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    pub(super) fn take_over_all(nodes_dir: &Path) {
        for path in super::configs_in(nodes_dir) {
            let f = match win::open_plain(&path, READ_CONTROL | WRITE_DAC | WRITE_OWNER) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[node] not taking over {}: {e}", path.display());
                    continue;
                }
            };
            let admin_only = win::security_of_file(&f, &path)
                .is_ok_and(|s| super::super::service::judge_admin_only(&[s]).is_ok());
            if admin_only {
                continue;
            }
            match win::make_admin_only(&f) {
                Ok(()) => println!(
                    "[node] {} can now be changed by administrators only, as every node \
                     config can from this release on.",
                    path.display()
                ),
                Err(e) => eprintln!(
                    "[node] could not make {} administrators only: {e}",
                    path.display()
                ),
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::io;
    use std::path::Path;

    pub(super) fn read_trusted(path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    pub(super) fn write_trusted(path: &Path, contents: &[u8]) -> io::Result<()> {
        std::fs::write(path, contents)
    }

    pub(super) fn take_over_all(_nodes_dir: &Path) {}
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const A_CONFIG: &str = "api_key = \"k\"\nnode_id = \"n\"\napi_url = \"http://127.0.0.1:9\"\n";

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().mode() & 0o777
    }

    #[test]
    fn a_privileged_read_takes_a_config_only_root_can_change() {
        let t = tempfile::tempdir().expect("tempdir");
        let p = t.path().join("n.toml");
        fs::write(&p, A_CONFIG).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        assert_eq!(read(&p).unwrap(), A_CONFIG);
    }

    #[test]
    fn a_privileged_read_refuses_a_config_others_can_write() {
        let t = tempfile::tempdir().expect("tempdir");
        let p = t.path().join("n.toml");
        fs::write(&p, A_CONFIG).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o620)).unwrap();

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        let err = read(&p).expect_err("took a group-writable config");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_privileged_write_is_owner_only_and_stays_root_s() {
        let t = tempfile::tempdir().expect("tempdir");
        let p = t.path().join("n.toml");
        fs::write(&p, "old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        write(&p, A_CONFIG).unwrap();

        assert_eq!(mode(&p), 0o600);
        assert_eq!(fs::metadata(&p).unwrap().uid(), unsafe { libc::geteuid() });
        assert_eq!(read(&p).unwrap(), A_CONFIG);
    }

    /// Configs from an earlier release are taken over the first time, and only then:
    /// a config that turns up after the record exists stays refused.
    #[test]
    fn earlier_configs_are_taken_over_once() {
        let t = tempfile::tempdir().expect("tempdir");
        let nodes = t.path().join("nodes.d");
        fs::create_dir(&nodes).unwrap();
        let earlier = nodes.join("a.toml");
        fs::write(&earlier, A_CONFIG).unwrap();
        fs::set_permissions(&earlier, fs::Permissions::from_mode(0o644)).unwrap();
        let record = t.path().join("state/taken-over");

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        take_over_once(&nodes, &record);

        assert_eq!(
            mode(&earlier),
            0o600,
            "the earlier config was not taken over"
        );
        assert!(record.exists(), "the take-over was not recorded");

        let later = nodes.join("b.toml");
        fs::write(&later, A_CONFIG).unwrap();
        fs::set_permissions(&later, fs::Permissions::from_mode(0o666)).unwrap();
        take_over_once(&nodes, &record);

        assert_eq!(mode(&later), 0o666, "a later file was taken over");
        assert!(read(&later).is_err(), "a later file was accepted");
    }

    #[test]
    fn taking_over_does_not_chmod_through_a_link() {
        let t = tempfile::tempdir().expect("tempdir");
        let nodes = t.path().join("nodes.d");
        fs::create_dir(&nodes).unwrap();
        let target = t.path().join("shadow");
        fs::write(&target, A_CONFIG).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target, nodes.join("s.toml")).unwrap();

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        take_over_once(&nodes, &t.path().join("taken-over"));

        assert_eq!(mode(&target), 0o644, "chmodded the link's target");
    }
}
