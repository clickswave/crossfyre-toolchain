// Helpers for running commands and resolving paths as the invoking user
// when crossfyre is run via `sudo`. systemctl --user, ~/.config/systemd/user,
// and DBus session communication all require the invoking user's identity
// and runtime environment - root has none of those.

use std::path::PathBuf;
use std::process::Command;

/// Returns Some((uid, gid, home, name)) if running as root via sudo, else None.
/// Plain root with no SUDO_USER returns None and callers fall back to the
/// root identity, which is what they want for non-user-scoped operations.
#[cfg(unix)]
pub fn sudo_user_info() -> Option<(u32, u32, PathBuf, String)> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return None;
    }
    let sudo_user = std::env::var("SUDO_USER").ok()?;
    if sudo_user.is_empty() || sudo_user == "root" {
        return None;
    }
    use std::ffi::CString;
    let c = CString::new(sudo_user.clone()).ok()?;
    unsafe {
        let pwd = libc::getpwnam(c.as_ptr());
        if pwd.is_null() {
            return None;
        }
        let uid = (*pwd).pw_uid;
        let gid = (*pwd).pw_gid;
        let home_ptr = (*pwd).pw_dir;
        let home = if home_ptr.is_null() {
            PathBuf::from(format!("/home/{sudo_user}"))
        } else {
            PathBuf::from(
                std::ffi::CStr::from_ptr(home_ptr)
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        Some((uid, gid, home, sudo_user))
    }
}

#[cfg(not(unix))]
pub fn sudo_user_info() -> Option<(u32, u32, PathBuf, String)> {
    None
}

/// Home directory of the invoking user. Falls back to dirs::home_dir() (which
/// resolves to /root under sudo) only when SUDO_USER isn't set.
pub fn invoking_user_home() -> PathBuf {
    if let Some((_, _, home, _)) = sudo_user_info() {
        home
    } else {
        dirs::home_dir().expect("Could not find home directory")
    }
}

/// The per-user config root under the home directory `home`, where `dirs::config_dir()`
/// puts it for that user: `~/.config` on Linux (and any other Unix), and
/// `~/Library/Application Support` on macOS. Used where the user is not the one running
/// the process, as under sudo, so the root is the same one that user's own runs find.
pub fn config_root_in(home: &std::path::Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else {
        home.join(".config")
    }
}

/// The variable through which the Windows node service hands its children the account
/// that registered it, which the engines' scheduled tasks run as. The service itself
/// runs as LocalSystem, so its own account is not the operator's.
#[cfg(windows)]
pub const OPERATOR_ENV: &str = "CROSSFYRE_OPERATOR";

/// The Windows account per-user things are done for, as `DOMAIN\user`: the one the
/// node service was registered by when this process runs under it, otherwise the
/// account running this process. An elevated prompt is still its user's own account,
/// which is what sudo is not.
#[cfg(windows)]
pub fn operator_account() -> Result<String, String> {
    if let Some(name) = std::env::var(OPERATOR_ENV).ok().filter(|n| !n.is_empty()) {
        return Ok(name);
    }
    // From the process token, not USERNAME and USERDOMAIN: over SSH USERDOMAIN is the
    // workgroup, and a task registered for `WORKGROUP\user` is refused. LocalSystem
    // has no profile and must not be given the operator's tasks.
    match crate::os::process_account() {
        Some((domain, user)) if !user.is_empty() => Ok(if domain.is_empty() {
            user
        } else {
            format!("{domain}\\{user}")
        }),
        _ => Err(
            "this process does not know which account to act for; run the command from \
             the operator's own elevated prompt"
                .to_string(),
        ),
    }
}

/// Build a Command that, if running under sudo, drops uid/gid back to the
/// invoking user and sets HOME, USER, XDG_RUNTIME_DIR, and
/// DBUS_SESSION_BUS_ADDRESS so `systemctl --user` can reach the user's
/// session bus. Without this it fails with "Failed to connect to user
/// scope bus via local transport".
#[cfg(unix)]
pub fn cmd_as_invoking_user<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(program);
    if let Some((uid, gid, home, name)) = sudo_user_info() {
        cmd.uid(uid).gid(gid);
        cmd.env("HOME", &home);
        cmd.env("USER", &name);
        cmd.env("LOGNAME", &name);
        // systemd --user finds the right bus via these two. Both live under
        // /run/user/<uid> on every modern systemd setup.
        let runtime_dir = format!("/run/user/{uid}");
        cmd.env("XDG_RUNTIME_DIR", &runtime_dir);
        cmd.env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime_dir}/bus"),
        );
    }
    cmd
}

/// Without sudo there is nobody else to act for: the command runs as this process.
#[cfg(not(unix))]
pub fn cmd_as_invoking_user<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    Command::new(program)
}

/// The outermost of `dir` and its ancestors that does not exist yet, which is the first
/// directory `create_dir_all(dir)` creates. None when `dir` is already there.
pub fn first_missing(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut missing = None;
    let mut level = Some(dir);
    while let Some(p) = level {
        if p.exists() {
            break;
        }
        missing = Some(p.to_path_buf());
        level = p.parent();
    }
    missing
}

/// `create_dir_all`, then every directory it created handed back to the invoking user.
/// Under sudo, creating `~/Library/LaunchAgents/` or `~/.config/crossfyre/toolchain/`
/// made each missing level root's, and handing back only the last one left the rest
/// root-owned in the person's home. Directories that were already there keep their owner.
///
/// As root, no link below a directory another account can change is followed: see
/// [`super::root_fs`], and on Windows, when elevated, `win::admin_fs`.
pub fn create_dir_all_for_invoking_user(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if root_guards() {
        let owner = sudo_user_info().map(|(uid, gid, _, _)| (uid, gid));
        return super::root_fs::create_dir_all(dir, owner);
    }
    #[cfg(windows)]
    if root_guards() {
        return super::win::admin_fs::create_dir_all(dir).map(|_| ());
    }
    let top = first_missing(dir);
    std::fs::create_dir_all(dir)?;
    if let Some(top) = top {
        chown_to_invoking_user(&top);
    }
    Ok(())
}

/// Recursively chown a path tree back to the invoking user. Best-effort -
/// any failures are logged to stderr but don't abort the caller. We use
/// this after writing things into the user's home so the user can read /
/// edit them later without sudo.
///
/// Links in the tree are left alone, as are files with a second name elsewhere: see
/// [`super::root_fs::chown_tree`].
#[cfg(unix)]
pub fn chown_to_invoking_user(path: &std::path::Path) {
    let Some((uid, gid, _, _)) = sudo_user_info() else {
        return;
    };
    chown_recursive(path, uid, gid);
}
#[cfg(not(unix))]
pub fn chown_to_invoking_user(_path: &std::path::Path) {}

#[cfg(unix)]
fn chown_recursive(path: &std::path::Path, uid: u32, gid: u32) {
    if let Err(e) = super::root_fs::chown_tree(path, uid, gid)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("[!] chown {} failed: {e}", path.display());
    }
}

#[cfg(test)]
thread_local! {
    static ACT_AS_ROOT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this process runs as root, or elevated on Windows (the node service runs as
/// LocalSystem), and so must not follow links in a tree another account can change.
pub(crate) fn root_guards() -> bool {
    #[cfg(test)]
    if ACT_AS_ROOT.with(|c| c.get()) {
        return true;
    }
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        static ELEVATED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ELEVATED.get_or_init(crate::os::is_elevated)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Makes [`root_guards`] true on this thread until dropped, so a test can take the
/// paths a root process takes without being root.
#[cfg(test)]
pub(crate) struct ActAsRoot;

#[cfg(test)]
pub(crate) fn act_as_root() -> ActAsRoot {
    ACT_AS_ROOT.with(|c| c.set(true));
    ActAsRoot
}

#[cfg(test)]
impl Drop for ActAsRoot {
    fn drop(&mut self) {
        ACT_AS_ROOT.with(|c| c.set(false));
    }
}

/// Write `contents` to `path`, owned by the invoking user.
///
/// As root this replaces whatever is at `path` with a new file of `mode`, and refuses a
/// link anywhere below a directory another account can change; see
/// [`super::root_fs::replace_file`]. Otherwise it is a plain write, and `mode` applies
/// only when the file is new, so a person's own symlinked config keeps working.
pub fn write_for_invoking_user(
    path: &std::path::Path,
    contents: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if root_guards() {
            let owner = sudo_user_info().map(|(uid, gid, _, _)| (uid, gid));
            return super::root_fs::replace_file(path, contents, mode, owner);
        }
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)?;
        f.write_all(contents)
    }
    #[cfg(windows)]
    {
        let _ = mode;
        if root_guards() {
            return super::win::admin_fs::replace_file(path, contents, false);
        }
        std::fs::write(path, contents)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = mode;
        std::fs::write(path, contents)
    }
}

/// Rename `from` to `to`. As root, a link below a directory another account can change
/// is not followed on the way to either.
pub fn rename(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if root_guards() {
        return super::root_fs::rename(from, to);
    }
    #[cfg(windows)]
    if root_guards() {
        return super::win::admin_fs::rename(from, to);
    }
    std::fs::rename(from, to)
}

/// Read `path` as text. As root, a link below a directory another account can change
/// is refused, as is anything but a regular file.
pub fn read_to_string(path: &std::path::Path) -> std::io::Result<String> {
    #[cfg(unix)]
    if root_guards() {
        return super::root_fs::read_to_string(path);
    }
    #[cfg(windows)]
    if root_guards() {
        return super::win::admin_fs::read_to_string(path);
    }
    std::fs::read_to_string(path)
}

/// Remove the file or link at `path`. As root, a link below a directory another account
/// can change is not followed on the way there.
pub fn remove_file(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if root_guards() {
        return super::root_fs::remove_file(path);
    }
    #[cfg(windows)]
    if root_guards() {
        return super::win::admin_fs::remove_file(path);
    }
    std::fs::remove_file(path)
}

/// Remove the directory at `path` and everything in it. As root, a link below a
/// directory another account can change is not followed on the way there.
pub fn remove_dir_all(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if root_guards() {
        return super::root_fs::remove_dir_all(path);
    }
    #[cfg(windows)]
    if root_guards() {
        return super::win::admin_fs::remove_dir_all(path);
    }
    std::fs::remove_dir_all(path)
}

#[cfg(all(test, unix))]
mod root_link_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, symlink};

    /// A group this account belongs to other than its current one, so a test can see
    /// a chown land without being root. None on a host where it has only one.
    fn other_gid() -> Option<u32> {
        let mut groups = vec![0 as libc::gid_t; 256];
        let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
        if n < 0 {
            return None;
        }
        let own = unsafe { libc::getegid() };
        groups[..n as usize].iter().copied().find(|g| *g != own)
    }

    #[test]
    fn a_root_write_replaces_a_planted_link_and_leaves_its_target_alone() {
        let t = tempfile::tempdir().expect("tempdir");
        let victim = t.path().join("victim");
        fs::write(&victim, "root's file\n").expect("victim");
        let tree = t.path().join("nodes.d");
        fs::create_dir(&tree).expect("tree");
        let pid = tree.join("zz.pid");
        symlink(&victim, &pid).expect("link");

        let _root = act_as_root();
        write_for_invoking_user(&pid, b"4242", 0o644).expect("write");

        assert_eq!(fs::read_to_string(&victim).unwrap(), "root's file\n");
        let meta = fs::symlink_metadata(&pid).unwrap();
        assert!(meta.file_type().is_file(), "the link is still there");
        assert_eq!(fs::read_to_string(&pid).unwrap(), "4242");
    }

    #[test]
    fn a_root_write_replaces_a_hard_link_and_leaves_the_other_name_alone() {
        let t = tempfile::tempdir().expect("tempdir");
        let victim = t.path().join("victim");
        fs::write(&victim, "root's file\n").expect("victim");
        let tree = t.path().join("nodes.d");
        fs::create_dir(&tree).expect("tree");
        let cfg = tree.join("zz.toml");
        fs::hard_link(&victim, &cfg).expect("hard link");

        let _root = act_as_root();
        write_for_invoking_user(&cfg, b"api_key = \"k\"\n", 0o600).expect("write");

        assert_eq!(fs::read_to_string(&victim).unwrap(), "root's file\n");
        assert_eq!(fs::read_to_string(&cfg).unwrap(), "api_key = \"k\"\n");
    }

    #[test]
    fn a_root_write_will_not_pass_through_a_linked_directory() {
        let t = tempfile::tempdir().expect("tempdir");
        let etc = t.path().join("etc");
        fs::create_dir(&etc).expect("etc");
        fs::write(etc.join("config.toml"), "root's config\n").expect("config");
        let home = t.path().join("home");
        fs::create_dir(&home).expect("home");
        symlink(&etc, home.join("nodes.d")).expect("link");

        let _root = act_as_root();
        let r = write_for_invoking_user(&home.join("nodes.d/config.toml"), b"x", 0o600);

        assert!(r.is_err(), "wrote through a linked directory");
        assert_eq!(
            fs::read_to_string(etc.join("config.toml")).unwrap(),
            "root's config\n"
        );
    }

    #[test]
    fn creating_directories_as_root_will_not_pass_through_a_link() {
        let t = tempfile::tempdir().expect("tempdir");
        let etc = t.path().join("etc");
        fs::create_dir(&etc).expect("etc");
        let home = t.path().join("home");
        fs::create_dir(&home).expect("home");
        symlink(&etc, home.join("crossfyre")).expect("link");

        let _root = act_as_root();
        let r = create_dir_all_for_invoking_user(&home.join("crossfyre/toolchain/logs"));

        assert!(r.is_err(), "created directories through a link");
        assert!(!etc.join("toolchain").exists());
    }

    #[test]
    fn the_tree_chown_leaves_files_behind_links_alone() {
        let Some(gid) = other_gid() else {
            eprintln!("skipped: this account is in only one group");
            return;
        };
        let uid = unsafe { libc::geteuid() };
        let t = tempfile::tempdir().expect("tempdir");
        let outside_dir = t.path().join("etc");
        fs::create_dir(&outside_dir).expect("etc");
        let outside_file = outside_dir.join("shadow");
        fs::write(&outside_file, "x").expect("file");
        let preload = t.path().join("ld.so.preload");
        fs::write(&preload, "x").expect("file");
        let before_dir = fs::metadata(&outside_dir).unwrap().gid();
        let before_file = fs::metadata(&outside_file).unwrap().gid();
        let before_preload = fs::metadata(&preload).unwrap().gid();

        let tree = t.path().join("crossfyre");
        fs::create_dir_all(tree.join("nodes.d")).expect("tree");
        let own = tree.join("nodes.d/a.pid");
        fs::write(&own, "x").expect("own");
        symlink(&outside_dir, tree.join("nodes.d/e")).expect("dir link");
        symlink(&preload, tree.join("nodes.d/zz.pid")).expect("file link");

        chown_recursive(&tree, uid, gid);

        assert_eq!(
            fs::metadata(&own).unwrap().gid(),
            gid,
            "the tree itself was not chowned"
        );
        assert_eq!(fs::metadata(&outside_dir).unwrap().gid(), before_dir);
        assert_eq!(fs::metadata(&outside_file).unwrap().gid(), before_file);
        assert_eq!(fs::metadata(&preload).unwrap().gid(), before_preload);
    }

    /// Node configs are root's: the root node service runs whatever they say, so
    /// handing the tree back to the operator must leave them out, whether the walk
    /// starts at the data dir (after `node init`) or at nodes.d (after a daemon start).
    #[test]
    fn the_tree_chown_leaves_node_configs_with_root() {
        let Some(gid) = other_gid() else {
            eprintln!("skipped: this account is in only one group");
            return;
        };
        let uid = unsafe { libc::geteuid() };
        for start_at_nodes_dir in [false, true] {
            let t = tempfile::tempdir().expect("tempdir");
            let tree = t.path().join("crossfyre");
            let nodes = tree.join("nodes.d");
            fs::create_dir_all(nodes.join("n.network")).expect("tree");
            let config = nodes.join("n.toml");
            fs::write(&config, "x").expect("config");
            let pid = nodes.join("n.pid");
            fs::write(&pid, "1").expect("pid");
            let tunnel = nodes.join("n.network/wg0.conf");
            fs::write(&tunnel, "x").expect("tunnel");
            let before = fs::metadata(&config).unwrap().gid();

            chown_recursive(if start_at_nodes_dir { &nodes } else { &tree }, uid, gid);

            assert_eq!(
                fs::metadata(&config).unwrap().gid(),
                before,
                "a node config was handed over (walk from nodes.d: {start_at_nodes_dir})"
            );
            assert_eq!(fs::metadata(&pid).unwrap().gid(), gid);
            // Where a node without root keeps its tunnel config. A node run as root keeps
            // it in a directory of root's outside this tree.
            assert_eq!(fs::metadata(&tunnel).unwrap().gid(), gid);
        }
    }

    #[test]
    fn the_tree_chown_leaves_a_hard_linked_file_alone() {
        let Some(gid) = other_gid() else {
            eprintln!("skipped: this account is in only one group");
            return;
        };
        let uid = unsafe { libc::geteuid() };
        let t = tempfile::tempdir().expect("tempdir");
        let victim = t.path().join("sudoers");
        fs::write(&victim, "x").expect("file");
        let before = fs::metadata(&victim).unwrap().gid();
        let tree = t.path().join("crossfyre");
        fs::create_dir(&tree).expect("tree");
        fs::hard_link(&victim, tree.join("s.toml")).expect("hard link");

        chown_recursive(&tree, uid, gid);

        assert_eq!(fs::metadata(&victim).unwrap().gid(), before);
    }

    /// A start point that is itself a link is not followed either: the data dir the
    /// root service is pointed at sits in the operator's home.
    #[test]
    fn the_tree_chown_does_not_follow_a_link_at_its_root() {
        let Some(gid) = other_gid() else {
            eprintln!("skipped: this account is in only one group");
            return;
        };
        let uid = unsafe { libc::geteuid() };
        let t = tempfile::tempdir().expect("tempdir");
        let etc = t.path().join("etc");
        fs::create_dir(&etc).expect("etc");
        fs::write(etc.join("passwd"), "x").expect("file");
        let before = fs::metadata(etc.join("passwd")).unwrap().gid();
        let start = t.path().join("logs");
        symlink(&etc, &start).expect("link");

        chown_recursive(&start, uid, gid);

        assert_eq!(fs::metadata(etc.join("passwd")).unwrap().gid(), before);
    }
}

#[cfg(test)]
mod create_dir_tests {
    use super::first_missing;

    #[test]
    fn the_first_missing_level_is_the_outermost_one_created() {
        let base = tempfile::tempdir().expect("tempdir");
        let deep = base
            .path()
            .join("Library/Application Support/crossfyre/logs");
        assert_eq!(first_missing(&deep), Some(base.path().join("Library")));
        std::fs::create_dir_all(base.path().join("Library/Application Support")).expect("dirs");
        assert_eq!(
            first_missing(&deep),
            Some(base.path().join("Library/Application Support/crossfyre"))
        );
        std::fs::create_dir_all(&deep).expect("dirs");
        assert_eq!(first_missing(&deep), None);
    }
}

/// Makes `link` a junction to the directory `target`, as any account can without
/// elevation. Made here rather than by `mklink /J`, so tests that run beside it see no
/// child process start while their sockets are open.
#[cfg(all(test, windows))]
pub(crate) fn junction(link: &std::path::Path, target: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

    let target = std::path::absolute(target).expect("absolute target");
    let wide = |s: &std::ffi::OsStr| s.encode_wide().collect::<Vec<u16>>();
    let print = wide(target.as_os_str());
    let mut substitute = wide(std::ffi::OsStr::new("\\??\\"));
    substitute.extend_from_slice(&print);
    // The mount point's fields: the two names' offsets and lengths, then both names,
    // each followed by a NUL.
    let sub_bytes = (substitute.len() * 2) as u16;
    let print_bytes = (print.len() * 2) as u16;
    let mut names: Vec<u16> = substitute.clone();
    names.push(0);
    names.extend_from_slice(&print);
    names.push(0);
    let data_len = (8 + names.len() * 2) as u16;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buf.extend_from_slice(&data_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&sub_bytes.to_le_bytes());
    buf.extend_from_slice(&(sub_bytes + 2).to_le_bytes());
    buf.extend_from_slice(&print_bytes.to_le_bytes());
    for c in names {
        buf.extend_from_slice(&c.to_le_bytes());
    }

    std::fs::create_dir(link).expect("junction directory");
    let dir = std::fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(link)
        .expect("open junction directory");
    let mut returned = 0u32;
    // SAFETY: `buf` is a whole mount point reparse buffer of the length given, and the
    // handle is open for writing.
    let ok = unsafe {
        DeviceIoControl(
            dir.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr().cast(),
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    assert!(
        ok != 0,
        "junction {} -> {}: {}",
        link.display(),
        target.display(),
        std::io::Error::last_os_error()
    );
}

#[cfg(all(test, windows))]
mod elevated_link_tests {
    use super::*;
    use std::fs;

    /// A data dir whose `nodes.d` is a junction to `victim`, a directory the operator's
    /// account could not otherwise write.
    fn linked_tree() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let t = tempfile::tempdir().expect("tempdir");
        let victim = t.path().join("victim");
        fs::create_dir(&victim).expect("victim");
        let data = t.path().join("crossfyre");
        fs::create_dir(&data).expect("data");
        junction(&data.join("nodes.d"), &victim);
        (t, data, victim)
    }

    // Every test here is only as good as the junction it makes.
    #[test]
    fn a_junction_made_for_a_test_leads_to_its_target() {
        use std::os::windows::fs::MetadataExt;
        let (_t, data, victim) = linked_tree();
        let link = data.join("nodes.d");
        let attributes = fs::symlink_metadata(&link).expect("link").file_attributes();
        assert_ne!(attributes & 0x400, 0, "not a reparse point");
        fs::write(link.join("through"), "x").expect("write through");
        assert!(victim.join("through").exists());
    }

    #[test]
    fn an_elevated_write_will_not_pass_through_a_junction() {
        let (_t, data, victim) = linked_tree();
        let _root = act_as_root();
        let r = write_for_invoking_user(&data.join("nodes.d").join("n.pid"), b"4242", 0o644);
        assert!(r.is_err(), "wrote through a junction");
        assert!(!victim.join("n.pid").exists());
    }

    #[test]
    fn an_elevated_remove_will_not_pass_through_a_junction() {
        let (_t, data, victim) = linked_tree();
        fs::write(victim.join("n.pid"), "system's file\n").expect("victim file");
        let _root = act_as_root();
        let r = remove_file(&data.join("nodes.d").join("n.pid"));
        assert!(r.is_err(), "removed through a junction");
        assert_eq!(
            fs::read_to_string(victim.join("n.pid")).unwrap(),
            "system's file\n"
        );
    }

    #[test]
    fn an_elevated_read_will_not_pass_through_a_junction() {
        let (_t, data, victim) = linked_tree();
        fs::write(victim.join("n.toml"), "secret\n").expect("victim file");
        let _root = act_as_root();
        assert!(read_to_string(&data.join("nodes.d").join("n.toml")).is_err());
    }

    #[test]
    fn an_elevated_rename_will_not_pass_through_a_junction() {
        let (_t, data, victim) = linked_tree();
        fs::write(victim.join("a"), "system's file\n").expect("victim file");
        let _root = act_as_root();
        let nodes = data.join("nodes.d");
        assert!(rename(&nodes.join("a"), &nodes.join("b")).is_err());
        assert!(victim.join("a").exists());
        assert!(!victim.join("b").exists());
    }

    #[test]
    fn an_elevated_tree_removal_will_not_pass_through_a_junction() {
        let (_t, data, victim) = linked_tree();
        fs::create_dir(victim.join("n.network")).expect("victim dir");
        fs::write(victim.join("n.network").join("keep"), "x").expect("victim file");
        let _root = act_as_root();
        assert!(remove_dir_all(&data.join("nodes.d").join("n.network")).is_err());
        assert!(victim.join("n.network").join("keep").exists());
    }

    #[test]
    fn creating_directories_elevated_will_not_pass_through_a_junction() {
        let (_t, data, victim) = linked_tree();
        let _root = act_as_root();
        let r = create_dir_all_for_invoking_user(&data.join("nodes.d").join("logs"));
        assert!(r.is_err(), "created a directory through a junction");
        assert!(!victim.join("logs").exists());
    }

    #[test]
    fn an_elevated_secret_write_will_not_pass_through_a_junction() {
        let (_t, data, victim) = linked_tree();
        let _root = act_as_root();
        let r = crate::write_secret_file(&data.join("nodes.d").join("config.toml"), "x");
        assert!(r.is_err(), "wrote through a junction");
        assert!(!victim.join("config.toml").exists());
    }
}
