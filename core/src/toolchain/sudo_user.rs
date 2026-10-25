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

/// Config root of the invoking user. Under sudo this is `$SUDO_USER`'s
/// config root (see [`config_root_in`]); otherwise the platform config dir.
pub fn invoking_user_config_dir() -> PathBuf {
    if let Some((_, _, home, _)) = sudo_user_info() {
        config_root_in(&home)
    } else {
        dirs::config_dir().expect("Could not resolve config directory")
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
    let user = std::env::var("USERNAME").unwrap_or_default();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    // LocalSystem's environment names the machine account, which owns no profile and
    // must not be given the operator's tasks.
    if user.is_empty() || user.ends_with('$') {
        return Err(
            "this process does not know which account to act for; run the command from \
             the operator's own elevated prompt"
                .to_string(),
        );
    }
    Ok(if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    })
}

/// Build a Command that, if running under sudo, drops uid/gid back to the
/// invoking user and sets HOME, USER, XDG_RUNTIME_DIR, and
/// DBUS_SESSION_BUS_ADDRESS so `systemctl --user` can reach the user's
/// session bus. Without this it fails with "Failed to connect to user
/// scope bus via local transport".
pub fn cmd_as_invoking_user<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    let mut cmd = Command::new(program);
    if let Some((uid, gid, home, name)) = sudo_user_info() {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.uid(uid).gid(gid);
        }
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

/// Recursively chown a path tree back to the invoking user. Best-effort -
/// any failures are logged to stderr but don't abort the caller. We use
/// this after writing things into the user's home so the user can read /
/// edit them later without sudo.
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
    use std::ffi::CString;
    if let Ok(cpath) = CString::new(path.to_string_lossy().as_bytes()) {
        unsafe {
            // errno symbol differs by libc (__errno_location on Linux,
            // __error on macOS); last_os_error() is portable across both.
            if libc::chown(cpath.as_ptr(), uid, gid) != 0 {
                eprintln!(
                    "[!] chown {} failed: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
    }
    if path.is_dir()
        && let Ok(rd) = std::fs::read_dir(path)
    {
        for entry in rd.flatten() {
            chown_recursive(&entry.path(), uid, gid);
        }
    }
}
