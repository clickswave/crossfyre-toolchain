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
//! Configs written by 0.1.42 and earlier belong to the operator. On a host where an
//! earlier release's node service already ran them as root, the first privileged run of
//! a build with this check takes over those already there, once, and records that it
//! did where only root can write. Anywhere else (a new install, or nodes that so far ran
//! without root) that run only makes the record, so nothing the operator's account
//! wrote is ever taken over there.

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

/// Where the record that this host's node configs have been settled is kept, on Linux
/// and macOS: a directory that only root can write. On Windows it is the registry key
/// `HKLM\SOFTWARE\Crossfyre\NodeConfigsTakenOver`, which an uninstall leaves in place.
#[cfg(unix)]
pub fn takeover_record() -> PathBuf {
    root_state_dir().join("node-configs-taken-over")
}

/// The directory where a privileged node keeps what only root may change, outside the
/// operator's config root: /var/lib/crossfyre on Linux, /var/db/crossfyre on macOS.
#[cfg(unix)]
pub fn root_state_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(d) = imp::STATE_DIR.with(|c| c.borrow().clone()) {
        return d;
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/db/crossfyre")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/var/lib/crossfyre")
    }
}

/// Where node `node_id` keeps its tunnel config and logs. Run as root on Linux or macOS,
/// that is a directory under [`root_state_dir`], since root runs the tunnel config it
/// finds there (wg-quick and OpenVPN run hooks a config names). Otherwise, and on
/// Windows, where no tunnel is started, it is `nodes.d/<node-id>.network`.
pub fn network_dir(nodes_dir: &Path, node_id: &str) -> PathBuf {
    #[cfg(unix)]
    if privileged() {
        return root_state_dir()
            .join(NODES_DIR)
            .join(format!("{node_id}.network"));
    }
    operator_network_dir(nodes_dir, node_id)
}

/// `nodes.d/<node-id>.network`, where every release before this one kept a node's tunnel
/// config, and where an unprivileged node still does.
pub fn operator_network_dir(nodes_dir: &Path, node_id: &str) -> PathBuf {
    nodes_dir.join(format!("{node_id}.network"))
}

/// Make node `node_id`'s root-only network dir (see [`network_dir`]) mode 700, and carry
/// over the tunnel credentials (`auth.txt`) an earlier release kept in the operator's
/// `nodes.d/<node-id>.network`. Nothing else is carried: root runs the tunnel config,
/// and the next answer from the control plane writes it again. Does nothing when not
/// privileged, or on Windows.
pub fn prepare_network_dir(nodes_dir: &Path, node_id: &str) -> io::Result<()> {
    #[cfg(unix)]
    if privileged() {
        let dir = network_dir(nodes_dir, node_id);
        if let Some(parent) = dir.parent() {
            super::root_fs::create_dir_all(parent, None)?;
            super::root_fs::set_dir_mode(parent, 0o700)?;
        }
        super::root_fs::create_dir_all(&dir, None)?;
        super::root_fs::set_dir_mode(&dir, 0o700)?;
        imp::carry_over_auth(&operator_network_dir(nodes_dir, node_id), &dir);
    }
    let _ = (nodes_dir, node_id);
    Ok(())
}

/// Settle the node configs an earlier release left to the operator, the first time a
/// privileged process of this release runs on the host: run by the node supervisor and
/// the daemon. Does nothing afterwards, and nothing when not privileged.
pub fn take_over_earlier_configs(base: &Path) {
    if !privileged() {
        return;
    }
    if let Err(e) = settle(
        &base.join(NODES_DIR),
        claim_record,
        super::service::node_service_exists,
    ) {
        eprintln!(
            "[node] could not record that this host's node configs were settled: {e}. Node \
             configs that root does not own are not taken over, and the node service will \
             not run them."
        );
    }
}

/// Settle node configs before a privileged `node init` writes one. On a host with no
/// node service yet, this only makes the record, so the service that init installs
/// never takes over a file the operator's account put in nodes.d. An error stops init.
pub fn settle_before_init(base: &Path) -> io::Result<()> {
    if !privileged() {
        return Ok(());
    }
    settle(
        &base.join(NODES_DIR),
        claim_record,
        super::service::node_service_exists,
    )
}

/// Make the record. Only when this call made it, and a node service is installed (one
/// that an earlier release set up to run the configs in `nodes_dir` as root), are those
/// configs taken over.
fn settle(
    nodes_dir: &Path,
    claim: impl FnOnce() -> io::Result<bool>,
    service_installed: impl FnOnce() -> bool,
) -> io::Result<()> {
    if claim()? && service_installed() {
        imp::take_over_all(nodes_dir);
    }
    Ok(())
}

#[cfg(unix)]
fn claim_record() -> io::Result<bool> {
    claim(&takeover_record())
}

/// Create `record`. True when this call created it, false when it was already there.
#[cfg(unix)]
fn claim(record: &Path) -> io::Result<bool> {
    use std::io::Write;
    if let Some(dir) = record.parent() {
        super::root_fs::create_dir_all(dir, None)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    use std::os::unix::fs::OpenOptionsExt;
    opts.write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW);
    match opts.open(record) {
        Ok(mut f) => {
            // Only for whoever finds the file: its being there is the record.
            let _ = f.write_all(
                b"The node configs on this host were settled once, when a release that \
                  requires root-owned node configs first ran with root. Delete this file \
                  only to do that again.\n",
            );
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Create the registry key that records it. True when this call created it.
#[cfg(windows)]
fn claim_record() -> io::Result<bool> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_CREATED_NEW_KEY,
        REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW,
    };
    let subkey = crate::os::win::wide(r"SOFTWARE\Crossfyre\NodeConfigsTakenOver");
    let mut key = std::ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: `subkey` is NUL-terminated, the out-pointers are valid, and the key opened
    // is closed before returning.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut key,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    unsafe { RegCloseKey(key) };
    Ok(disposition == REG_CREATED_NEW_KEY)
}

#[cfg(not(any(unix, windows)))]
fn claim_record() -> io::Result<bool> {
    Ok(false)
}

/// The `.toml` files in `nodes_dir`, skipping what cannot be listed.
///
/// Also skipped, with a warning that quotes the path: a name holding a control
/// character. Callers print these paths to the service's log, which is root's, and a
/// line break in a name would write lines of its own there. The node scan never runs
/// such a file either, since no node id holds one.
fn configs_in(nodes_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(nodes_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .filter(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            let plain = !name.chars().any(char::is_control);
            if !plain {
                eprintln!("[node] WARNING: skipping {p:?}: not a node config's name");
            }
            plain
        })
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
        pub(super) static STATE_DIR: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Makes [`super::root_state_dir`] `dir` until dropped.
    #[cfg(test)]
    pub(super) struct StateDir;

    #[cfg(test)]
    pub(super) fn state_dir_at(dir: &Path) -> StateDir {
        STATE_DIR.with(|c| *c.borrow_mut() = Some(dir.to_path_buf()));
        StateDir
    }

    #[cfg(test)]
    impl Drop for StateDir {
        fn drop(&mut self) {
            STATE_DIR.with(|c| *c.borrow_mut() = None);
        }
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
        // On macOS an entry in a file's access list grants access whatever its mode says.
        if root_fs::has_extended_acl(f.as_raw_fd())? {
            let p = path.display();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{p} is not used as a node config: it has an access list, which can \
                     let other accounts change it. Remove the list with: sudo chmod -N {p}"
                ),
            ));
        }
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        Ok(s)
    }

    pub(super) fn write_trusted(path: &Path, contents: &[u8]) -> io::Result<()> {
        root_fs::replace_root_file(path, contents, 0o600, Some(trusted_owner()))
    }

    /// The most a node config or a tunnel's credentials file can hold, read from a file
    /// another account could have written.
    const MAX_READ: u64 = 1 << 20;

    /// Copy `auth.txt` from the operator's `from` into root's `to`, when only the
    /// operator's is there. It holds the tunnel's user name and password, which OpenVPN
    /// only sends; it never runs anything in it.
    pub(super) fn carry_over_auth(from: &Path, to: &Path) {
        let (old, new) = (from.join("auth.txt"), to.join("auth.txt"));
        if !old.exists() || new.exists() {
            return;
        }
        let mut text = Vec::new();
        let copied = root_fs::open_file(&old)
            .and_then(|f| f.take(MAX_READ).read_to_end(&mut text))
            .and_then(|_| root_fs::replace_root_file(&new, &text, 0o600, None));
        match copied {
            Ok(()) => println!(
                "[network] Copied {} to {}, where a node run as root keeps its tunnel \
                 credentials from this release on. Change them there, with sudo.",
                old.display(),
                new.display()
            ),
            Err(e) => eprintln!("[network] could not copy {}: {e}", old.display()),
        }
    }

    /// Replace each config with a new file of the same content that only root can
    /// change. A new file rather than a chown of the old one: whatever had the old one
    /// open for writing, or an access list on it, has no hold on the new one.
    pub(super) fn take_over_all(nodes_dir: &Path) {
        for path in super::configs_in(nodes_dir) {
            // Without following a link, and not a file with a second name.
            let mut text = Vec::new();
            let read =
                root_fs::open_file(&path).and_then(|f| f.take(MAX_READ).read_to_end(&mut text));
            if let Err(e) = read {
                eprintln!("[node] not taking over {}: {e}", path.display());
                continue;
            }
            match write_trusted(&path, &text) {
                Ok(()) => println!(
                    "[node] {} now belongs to root, as every node config does from this \
                     release on. Edit it with sudo.",
                    path.display()
                ),
                Err(e) => eprintln!("[node] could not hand {} to root: {e}", path.display()),
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

    /// An access right, from winnt.h.
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

    /// Replace each config with a new admin-only file of the same content, so a handle
    /// the operator's account already had open reaches only the old one.
    pub(super) fn take_over_all(nodes_dir: &Path) {
        for path in super::configs_in(nodes_dir) {
            let mut text = Vec::new();
            let read = win::open_plain(&path, GENERIC_READ)
                .and_then(|f| f.take(1 << 20).read_to_end(&mut text));
            if let Err(e) = read {
                eprintln!("[node] not taking over {}: {e}", path.display());
                continue;
            }
            match write_trusted(&path, &text) {
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
        settle(&nodes, || claim(&record), || true).unwrap();

        assert_eq!(
            mode(&earlier),
            0o600,
            "the earlier config was not taken over"
        );
        assert_eq!(read(&earlier).unwrap(), A_CONFIG);
        assert!(record.exists(), "the take-over was not recorded");

        let later = nodes.join("b.toml");
        fs::write(&later, A_CONFIG).unwrap();
        fs::set_permissions(&later, fs::Permissions::from_mode(0o666)).unwrap();
        settle(&nodes, || claim(&record), || true).unwrap();

        assert_eq!(mode(&later), 0o666, "a later file was taken over");
        assert!(read(&later).is_err(), "a later file was accepted");
    }

    /// The take-over runs as root and prints each config's path to the service's log.
    /// A file name with a line break in it would write lines of its own there, so such
    /// a file is left alone, as the node scan leaves it.
    #[test]
    fn a_take_over_skips_a_config_whose_name_holds_a_control_character() {
        let t = tempfile::tempdir().expect("tempdir");
        let nodes = t.path().join("nodes.d");
        fs::create_dir(&nodes).unwrap();
        let ok = nodes.join("ok.toml");
        let odd = [
            nodes.join("x\ninjected line\n#.toml"),
            nodes.join("tab\there.toml"),
            nodes.join("esc\u{1b}[2J.toml"),
        ];
        for p in std::iter::once(&ok).chain(&odd) {
            fs::write(p, A_CONFIG).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        settle(&nodes, || claim(&t.path().join("taken-over")), || true).unwrap();

        assert_eq!(mode(&ok), 0o600, "the plain config was not taken over");
        for p in &odd {
            assert_eq!(mode(p), 0o644, "{p:?} was taken over");
        }
    }

    /// On a host where no node service ran configs as root before (a new install, or
    /// nodes run without root so far), the first privileged run only makes the record:
    /// a config the operator's account left in nodes.d is not taken over, then or later.
    #[test]
    fn a_host_without_an_earlier_node_service_takes_nothing_over() {
        let t = tempfile::tempdir().expect("tempdir");
        let nodes = t.path().join("nodes.d");
        fs::create_dir(&nodes).unwrap();
        let planted = nodes.join("evil.toml");
        fs::write(&planted, A_CONFIG).unwrap();
        // Group-writable: this test's own account stands in for root.
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o664)).unwrap();
        let record = t.path().join("state/taken-over");

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        // `node init` with root, before it installs the service.
        settle(&nodes, || claim(&record), || false).unwrap();
        assert!(record.exists(), "init did not make the record");
        // The service it installed, starting.
        settle(&nodes, || claim(&record), || true).unwrap();

        assert_eq!(mode(&planted), 0o664, "a planted config was taken over");
        assert!(read(&planted).is_err(), "a planted config was accepted");
    }

    /// The take-over makes a new file. Whatever had the old one open for writing (or,
    /// on macOS, an access list on it) keeps no hold on the config root runs.
    #[test]
    fn a_take_over_leaves_an_open_writer_holding_the_old_file() {
        use std::io::Write;
        let t = tempfile::tempdir().expect("tempdir");
        let nodes = t.path().join("nodes.d");
        fs::create_dir(&nodes).unwrap();
        let p = nodes.join("a.toml");
        fs::write(&p, A_CONFIG).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let mut writer = fs::OpenOptions::new().write(true).open(&p).unwrap();

        let _root = super::super::sudo_user::act_as_root();
        let _trusted = imp::trust_self();
        // Group-readable, as an earlier release could leave a config.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        settle(&nodes, || claim(&t.path().join("taken-over")), || true).unwrap();
        writer.write_all(b"remote_exec = true\n").unwrap();
        drop(writer);

        assert_eq!(
            read(&p).unwrap(),
            A_CONFIG,
            "an open writer changed the config"
        );
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
        settle(&nodes, || claim(&t.path().join("taken-over")), || true).unwrap();

        assert_eq!(mode(&target), 0o644, "chmodded the link's target");
        assert!(
            fs::symlink_metadata(nodes.join("s.toml"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "replaced the link"
        );
    }

    /// Run as root, a node's tunnel config lives in a directory of root's, mode 700, and
    /// only the credentials file an earlier release kept in nodes.d comes along, never
    /// through a link.
    #[test]
    fn a_root_node_s_network_dir_is_root_s() {
        let t = tempfile::tempdir().expect("tempdir");
        let nodes = t.path().join("home/nodes.d");
        let state = t.path().join("state");
        fs::create_dir_all(nodes.join("n.network")).unwrap();
        fs::write(nodes.join("n.network/auth.txt"), "user\npass\n").unwrap();
        fs::write(nodes.join("n.network/wg0.conf"), "[Interface]\n").unwrap();
        fs::create_dir_all(nodes.join("m.network")).unwrap();
        fs::write(t.path().join("secret"), "s\n").unwrap();
        std::os::unix::fs::symlink(t.path().join("secret"), nodes.join("m.network/auth.txt"))
            .unwrap();

        let _root = super::super::sudo_user::act_as_root();
        let _state = imp::state_dir_at(&state);
        prepare_network_dir(&nodes, "n").unwrap();
        prepare_network_dir(&nodes, "m").unwrap();

        let dir = network_dir(&nodes, "n");
        assert!(dir.starts_with(&state), "{dir:?} is not root's");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(dir.parent().unwrap()), 0o700);
        assert_eq!(
            fs::read_to_string(dir.join("auth.txt")).unwrap(),
            "user\npass\n"
        );
        assert_eq!(mode(&dir.join("auth.txt")), 0o600);
        assert!(!dir.join("wg0.conf").exists(), "carried the tunnel config");
        assert!(
            !network_dir(&nodes, "m").join("auth.txt").exists(),
            "copied through a link"
        );
    }
}
