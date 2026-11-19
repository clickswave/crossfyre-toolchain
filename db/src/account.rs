//! Acting on the toolchain directory as the account it belongs to.

use crate::NotReady;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// What making and running the local database does in the toolchain directory, done as
/// the account the directory belongs to. The database is that account's: PostgreSQL's
/// programs will not run as root, and a cluster or a config.toml left to root is one
/// the engines cannot use.
///
/// The engines, and `crossfyre` run by that account, use [`ThisAccount`]. `crossfyre`
/// run as root acts through an account of its own for the user it was run for.
pub trait Account: Sync {
    /// A command that runs `program` as the account.
    fn command(&self, program: &Path) -> Command;
    /// Make `dir` and the parents it lacks, owned by the account.
    fn create_dir_all(&self, dir: &Path) -> io::Result<()>;
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    /// Write `contents` to `path`, readable by the account alone.
    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Take the lock file at `path`, made and owned by the account when missing, without
    /// waiting: Some while this process holds it, None while another one does.
    fn try_lock(&self, path: &Path) -> io::Result<Option<File>>;
    /// The account's runtime directory, where its service manager listens when it runs
    /// one (`XDG_RUNTIME_DIR`).
    fn runtime_dir(&self) -> Option<PathBuf>;
}

/// The account this process runs as, which is never root.
pub struct ThisAccount(());

impl ThisAccount {
    /// This process's account, or why it cannot be the one: root.
    pub fn new() -> Result<Self, NotReady> {
        if is_root() {
            return Err(NotReady::new(
                "the database is not made or started as root. Run this as the user whose \
                 engines use it"
                    .to_string(),
                None,
            ));
        }
        Ok(Self(()))
    }
}

/// Whether this process runs as root. Windows has none: an elevated prompt is its
/// user's own account, and PostgreSQL's programs drop what the elevation adds.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

impl Account for ThisAccount {
    fn command(&self, program: &Path) -> Command {
        Command::new(program)
    }

    fn create_dir_all(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        // Written beside it and renamed over it, so whoever reads it meanwhile, without
        // the lock, finds the whole file or none.
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("no file name"))?
            .to_string_lossy();
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_file_name(format!(".{name}.{}.{n}.tmp", std::process::id()));
        let written = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            io::Write::write_all(&mut file, contents)?;
            std::fs::rename(&tmp, path)
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn try_lock(&self, path: &Path) -> io::Result<Option<File>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            lock_file(file)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Opened unshared, the file cannot be opened again until this handle closes.
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .open(path)
            {
                Ok(file) => Ok(Some(file)),
                // ERROR_SHARING_VIOLATION
                Err(e) if e.raw_os_error() == Some(32) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    fn runtime_dir(&self) -> Option<PathBuf> {
        std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
    }
}

/// Take an exclusive lock on the open `file` without waiting: the file while this
/// process holds it, None while another one does.
#[cfg(unix)]
pub fn lock_file(file: File) -> io::Result<Option<File>> {
    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(e)
    }
}

/// The lock file in the toolchain directory.
pub(crate) const LOCK_FILE: &str = "db.lock";

/// How long to wait for another process to finish making or starting the database.
/// Making one takes a few seconds; starting one, under a second.
const LOCK_WAIT: Duration = Duration::from_secs(120);

/// Held while config.toml or the local database is made or started, so two processes
/// doing it at once make one of each. Released when dropped, or when the process ends.
pub(crate) struct Lock {
    _file: File,
}

impl Lock {
    /// The lock in the toolchain directory `dir`, waiting for another process to let go.
    pub(crate) fn hold(account: &dyn Account, dir: &Path) -> Result<Self, NotReady> {
        let path = dir.join(LOCK_FILE);
        account
            .create_dir_all(dir)
            .map_err(|e| NotReady::new(format!("cannot make {}: {e}", dir.display()), None))?;
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            match account.try_lock(&path) {
                Ok(Some(file)) => return Ok(Self { _file: file }),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Ok(None) => {
                    return Err(NotReady::new(
                        format!(
                            "another process has been making or starting the database for \
                             {} seconds and still holds {}; try again when it is done",
                            LOCK_WAIT.as_secs(),
                            path.display()
                        ),
                        None,
                    ));
                }
                Err(e) => {
                    return Err(NotReady::new(
                        format!("cannot lock {}: {e}", path.display()),
                        None,
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_is_not_taken_twice_and_is_free_once_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let account = ThisAccount(());
        let held = Lock::hold(&account, dir.path()).unwrap();
        assert!(
            account
                .try_lock(&dir.path().join(LOCK_FILE))
                .unwrap()
                .is_none(),
            "taken a second time while held"
        );
        drop(held);
        assert!(
            account
                .try_lock(&dir.path().join(LOCK_FILE))
                .unwrap()
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_private_file_is_the_account_s_alone_even_when_it_was_there() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        ThisAccount(()).write_private(&path, b"new").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }
}
