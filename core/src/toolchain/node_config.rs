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

use std::io;
use std::path::{Path, PathBuf};

/// The directory in the config root that holds one `<node-id>.toml` per node.
pub const NODES_DIR: &str = "nodes.d";

/// Whether `id` can stand for a node in a file name: one plain name, so that
/// `nodes.d/<id>.toml` and the node's network dir stay where they are meant to be. The
/// control plane hands out UUIDs. An id read from a file's contents or taken from the
/// command line is checked with this before any path is made from it. Nor does one
/// start with `-`, since the node is started as `node daemon <id>`, where that would
/// read as an option.
pub fn is_plain_node_id(id: &str) -> bool {
    // `:` too, since on Windows `C:x` joined to a path replaces it.
    !id.is_empty()
        && id != "."
        && id != ".."
        && !id.starts_with('-')
        && !id
            .chars()
            .any(|c| matches!(c, '/' | '\\' | ':') || c.is_control())
}

/// Whether this process runs as root, or elevated on Windows, and so must take a node
/// config only from a file that only root or an administrator can change.
pub fn privileged() -> bool {
    super::sudo_user::root_guards()
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

/// `nodes.d/<node-id>.network`, where a node run without root keeps its tunnel config.
pub fn operator_network_dir(nodes_dir: &Path, node_id: &str) -> PathBuf {
    nodes_dir.join(format!("{node_id}.network"))
}

/// Make node `node_id`'s root-only network dir (see [`network_dir`]) mode 700. Does
/// nothing when not privileged, or on Windows.
pub fn prepare_network_dir(nodes_dir: &Path, node_id: &str) -> io::Result<()> {
    #[cfg(unix)]
    if privileged() {
        secure_state_dir(&root_state_dir())?;
        let dir = network_dir(nodes_dir, node_id);
        if let Some(parent) = dir.parent() {
            super::root_fs::create_dir_all(parent, None)?;
            super::root_fs::set_dir_mode(parent, 0o700)?;
        }
        super::root_fs::create_dir_all(&dir, None)?;
        super::root_fs::set_dir_mode(&dir, 0o700)?;
    }
    let _ = (nodes_dir, node_id);
    Ok(())
}

/// For `crossfyre uninstall --purge`: remove the network dirs of nodes run as root (see
/// [`network_dir`]), which hold the tunnel configs and credentials the control plane
/// sent. Returns the directory removed, or None when there was none. Without root the
/// directory cannot be removed, and that is an error.
#[cfg(unix)]
pub fn purge_root_network_dirs() -> io::Result<Option<PathBuf>> {
    let dir = root_state_dir().join(NODES_DIR);
    if std::fs::symlink_metadata(&dir).is_err() {
        return Ok(None);
    }
    if !privileged() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} belongs to root", dir.display()),
        ));
    }
    super::root_fs::remove_dir_all(&dir)?;
    Ok(Some(dir))
}

/// On Windows the network dirs are in the operator's config root, which a purge removes.
#[cfg(not(unix))]
pub fn purge_root_network_dirs() -> io::Result<Option<PathBuf>> {
    Ok(None)
}

/// Make `dir`, the directory root keeps its nodes' network dirs in, and make it mode
/// 755. One that root does not own is refused: whoever owns it could swap a node's
/// network dir for one of their own, and root runs the tunnel config it finds there.
#[cfg(unix)]
fn secure_state_dir(dir: &Path) -> io::Result<()> {
    super::root_fs::create_dir_all(dir, None)?;
    super::root_fs::set_dir_mode(dir, 0o755).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "{} is where the node service keeps what only root may change, and it \
                 must belong to root: {e}",
                dir.display()
            ),
        )
    })
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
    /// a config accepted without being root.
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
}

#[cfg(windows)]
mod imp {
    use super::super::win::admin_fs;
    use std::io::{self, Read};
    use std::path::Path;

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
        let mut f = admin_fs::open_file(path, GENERIC_READ)?;
        let secured = super::super::win::security_of_file(&f, path).map_err(io::Error::other)?;
        super::super::service::judge_admin_only(&[secured]).map_err(|why| refused(path, why))?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        Ok(s)
    }

    /// A new file that only administrators and LocalSystem can open, from the moment it
    /// exists, renamed over `path` without following a link on the way.
    pub(super) fn write_trusted(path: &Path, contents: &[u8]) -> io::Result<()> {
        admin_fs::replace_file(path, contents, true)
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

    /// The directory root makes its nodes' network dirs in is refused when root does not
    /// own it, and nothing is made in it.
    #[test]
    fn a_state_directory_root_does_not_own_is_refused() {
        let t = tempfile::tempdir().expect("tempdir");
        // Not ours, and writable by us, so only the owner check can refuse it.
        let foreign = if unsafe { libc::geteuid() } == 0 {
            let d = t.path().join("state");
            fs::create_dir(&d).unwrap();
            std::os::unix::fs::chown(&d, Some(65534), Some(65534)).unwrap();
            fs::set_permissions(&d, fs::Permissions::from_mode(0o777)).unwrap();
            d
        } else {
            let tmp = PathBuf::from("/tmp");
            let md = fs::metadata(&tmp).unwrap();
            if md.uid() == unsafe { libc::geteuid() } || md.mode() & 0o002 == 0 {
                eprintln!("skipped: no directory here that another account owns and we can write");
                return;
            }
            tmp
        };

        let _root = super::super::sudo_user::act_as_root();
        let _state = imp::state_dir_at(&foreign);
        let dirs = foreign.join(NODES_DIR);
        let there = dirs.exists();
        let made = prepare_network_dir(&t.path().join("home/nodes.d"), "n");
        let left = dirs.join("n.network").exists();
        if !there {
            let _ = fs::remove_dir_all(&dirs);
        }
        let e = made.expect_err("network dirs were made in a directory root does not own");
        assert!(e.to_string().contains("must belong to root"), "{e}");
        assert!(!left, "a network dir was made");
    }

    /// The directory root's network dirs are made in is made, or left, writable by root
    /// alone.
    #[test]
    fn the_state_directory_is_root_s_alone() {
        let t = tempfile::tempdir().expect("tempdir");
        let state = t.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o777)).unwrap();

        let _root = super::super::sudo_user::act_as_root();
        let _state = imp::state_dir_at(&state);
        prepare_network_dir(&t.path().join("home/nodes.d"), "n").unwrap();
        assert_eq!(mode(&state), 0o755);
    }

    /// A purge takes root's copies of the tunnel configs and credentials with it.
    #[test]
    fn a_purge_removes_root_s_network_dirs() {
        let t = tempfile::tempdir().expect("tempdir");
        let state = t.path().join("state");
        let nodes = t.path().join("home/nodes.d");

        let _root = super::super::sudo_user::act_as_root();
        let _state = imp::state_dir_at(&state);
        prepare_network_dir(&nodes, "n").unwrap();
        fs::write(network_dir(&nodes, "n").join("auth.txt"), "user\npass\n").unwrap();

        let removed = purge_root_network_dirs().unwrap();
        assert_eq!(removed, Some(state.join(NODES_DIR)));
        assert!(!state.join(NODES_DIR).exists(), "left root's network dirs");
        assert_eq!(purge_root_network_dirs().unwrap(), None);
    }

    #[test]
    fn only_one_plain_name_is_a_node_id() {
        assert!(is_plain_node_id("0b7f5d0e-6a7c-4a5e-9f43-1d2b3c4d5e6f"));
        assert!(is_plain_node_id("default-node-1"));
        for bad in [
            "",
            ".",
            "..",
            "/tmp/victim",
            "a/b",
            "../x",
            "a\\b",
            "C:x",
            "a\nb",
            "a\0b",
            "-x",
            "--force",
            "--data-dir=..",
        ] {
            assert!(!is_plain_node_id(bad), "{bad:?} passed");
        }
    }

    /// Run as root, a node's tunnel config lives in a directory of root's, mode 700.
    #[test]
    fn a_root_node_s_network_dir_is_root_s() {
        let t = tempfile::tempdir().expect("tempdir");
        let nodes = t.path().join("home/nodes.d");
        let state = t.path().join("state");

        let _root = super::super::sudo_user::act_as_root();
        let _state = imp::state_dir_at(&state);
        prepare_network_dir(&nodes, "n").unwrap();

        let dir = network_dir(&nodes, "n");
        assert!(dir.starts_with(&state), "{dir:?} is not root's");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(dir.parent().unwrap()), 0o700);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::fs;

    #[test]
    fn an_elevated_config_write_will_not_pass_through_a_junction() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        fs::create_dir(&victim).unwrap();
        let nodes = t.path().join(NODES_DIR);
        super::super::sudo_user::junction(&nodes, &victim);

        let _root = super::super::sudo_user::act_as_root();
        let r = write(&nodes.join("n.toml"), "api_key = \"k\"\n");
        assert!(r.is_err(), "wrote through a junction");
        assert!(!victim.join("n.toml").exists());
        let left: Vec<_> = fs::read_dir(&victim).unwrap().collect();
        assert!(left.is_empty(), "left {left:?} behind");
    }
}
