//! Files the node hands to an engine by path, such as a downloaded wordlist.
//!
//! Each op that hands files over gets a directory of its own, made new under a random
//! name and readable only by the account the engines run as. Files are created in it
//! and never opened by a name that already exists, so nothing another account put in
//! the shared temporary directory beforehand can be written through or read as the
//! op's file. The directory and everything in it are removed when the op ends.
//!
//! On Unix it is made under `/tmp`, which the engines accept wordlists from. On Windows
//! the node runs as LocalSystem, whose temporary directory the operator, whom the
//! engines run as, cannot read, so it is made under the toolchain directory's `tmp`, in
//! the operator's profile, which both can.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(crate) struct Handoff {
    dir: tempfile::TempDir,
    #[cfg(unix)]
    handle: std::fs::File,
    /// The account the engines run as when it is not this process's: the operator a
    /// node running as root acts for.
    #[cfg(unix)]
    owner: Option<(u32, u32)>,
}

impl Handoff {
    /// A new private directory for one op's files.
    pub(crate) fn new() -> io::Result<Handoff> {
        Self::new_in(&base_dir()?)
    }

    fn new_in(base: &Path) -> io::Result<Handoff> {
        let mut builder = tempfile::Builder::new();
        builder.prefix(dguard::HANDOFF_PREFIX);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let dir = builder.tempdir_in(base)?;
        #[cfg(unix)]
        {
            let handle = open_dir(dir.path())?;
            let owner = operator();
            if let Some((uid, gid)) = owner {
                std::os::unix::fs::fchown(&handle, Some(uid), Some(gid))?;
            }
            Ok(Handoff { dir, handle, owner })
        }
        #[cfg(not(unix))]
        {
            Ok(Handoff { dir })
        }
    }

    /// The directory the files are written to.
    pub(crate) fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Write `body` to a new file called `name` in this op's directory and return the
    /// path the engine is given. Characters other than letters, digits, `-`, `_` and `.`
    /// in `name` are replaced, so it cannot reach outside the directory. A name already
    /// written in this directory is refused rather than replaced.
    pub(crate) fn write(&self, name: &str, body: &[u8]) -> io::Result<String> {
        let name = file_name(name);
        let mut file = self.create(&name)?;
        file.write_all(body)?;
        file.flush()?;
        Ok(self.dir.path().join(&name).display().to_string())
    }

    #[cfg(unix)]
    fn create(&self, name: &str) -> io::Result<std::fs::File> {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let c = std::ffi::CString::new(name)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `c` is NUL-terminated and outlives the call, and the mode argument is
        // passed because O_CREAT is set.
        let fd = unsafe {
            libc::openat(
                self.handle.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor that nothing else owns.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        if let Some((uid, gid)) = self.owner {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        }
        Ok(file)
    }

    #[cfg(not(unix))]
    fn create(&self, name: &str) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.path().join(name))
    }
}

/// Write a file called `name` into the op's directory held in `slot`, making the
/// directory on first use, and return the path the engine is given.
pub(crate) fn put(slot: &mut Option<Handoff>, name: &str, body: &[u8]) -> io::Result<String> {
    let handoff = match slot {
        Some(h) => h,
        None => slot.insert(Handoff::new()?),
    };
    handoff.write(name, body)
}

/// `name` with anything but letters, digits, `-`, `_` and `.` replaced by `_`, and a
/// name made only of dots replaced whole.
fn file_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() || clean.chars().all(|c| c == '.') {
        "handoff".to_string()
    } else {
        clean
    }
}

fn base_dir() -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        let dir = crate::toolchain::config::get_toolchain_dir().join("tmp");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from("/tmp"))
    }
}

#[cfg(unix)]
fn open_dir(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

/// The operator a node running as root under sudo, or as a service that names its
/// operator the same way, acts for. The engines run as that account.
#[cfg(unix)]
fn operator() -> Option<(u32, u32)> {
    crate::toolchain::sudo_user::sudo_user_info().map(|(uid, gid, ..)| (uid, gid))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn unique(tag: &str) -> String {
        format!(
            "{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    // A name another account could have planted in /tmp, as a symlink to a file it
    // wants overwritten, is never written through: the file lands in a new directory.
    #[test]
    fn a_link_planted_under_the_old_fixed_name_is_not_written_through() {
        let scratch = tempfile::tempdir().unwrap();
        let victim = scratch.path().join("victim");
        std::fs::write(&victim, "kept\n").unwrap();
        let id = unique("wl");
        let name = format!("cfx-wl-sub-{id}.txt");
        let planted = PathBuf::from("/tmp").join(&name);
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        let handoff = Handoff::new().unwrap();
        let written = handoff.write(&name, b"www\napi\n");
        let _ = std::fs::remove_file(&planted);

        let path = written.unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "kept\n");
        assert_ne!(PathBuf::from(&path), planted);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "www\napi\n");
    }

    // The op's directory is new, private to this account and removed with the op.
    #[test]
    fn each_op_gets_a_private_directory_that_is_removed_after() {
        let a = Handoff::new().unwrap();
        let b = Handoff::new().unwrap();
        assert_ne!(a.dir(), b.dir());
        let path = a.write("cfx-wl-common.txt", b"admin\n").unwrap();
        let dir = std::fs::symlink_metadata(a.dir()).unwrap();
        assert!(dir.is_dir());
        // SAFETY: geteuid has no preconditions and cannot fail.
        assert_eq!(dir.uid(), unsafe { libc::geteuid() });
        assert_eq!(dir.permissions().mode() & 0o777, 0o700);
        let file = std::fs::metadata(&path).unwrap();
        assert_eq!(file.permissions().mode() & 0o077, 0);
        let gone = a.dir().to_path_buf();
        drop(a);
        assert!(!gone.exists());
        assert!(!PathBuf::from(&path).exists());
    }

    // A file that is already there is an error the op sees, not a file it uses.
    #[test]
    fn a_name_that_already_exists_is_refused_rather_than_used() {
        let base = tempfile::tempdir().unwrap();
        let handoff = Handoff::new_in(base.path()).unwrap();
        let first = handoff.write("cfx-wl-x.txt", b"one\n").unwrap();
        let again = handoff.write("cfx-wl-x.txt", b"two\n");
        assert!(again.is_err(), "rewrote {first}");
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "one\n");
    }

    // A wordlist id from the request cannot steer the file out of the directory.
    #[test]
    fn a_name_cannot_leave_the_directory() {
        let base = tempfile::tempdir().unwrap();
        let handoff = Handoff::new_in(base.path()).unwrap();
        for name in ["../../escape.txt", "a/b.txt", "..", "/etc/x"] {
            let path = handoff.write(name, b"x\n").unwrap();
            assert_eq!(PathBuf::from(&path).parent(), Some(handoff.dir()), "{name}");
        }
        assert!(!base.path().join("escape.txt").exists());
    }

    // The engines still accept the file: the path they are given opens under their own
    // wordlist rules, which read only the node's hand-overs from the temp dir.
    #[test]
    fn the_engines_accept_the_handed_off_file() {
        let handoff = Handoff::new().unwrap();
        let path = handoff.write("cfx-wl-sub-default.txt", b"www\n").unwrap();
        let (_, mut f) = dguard::open_wordlist(&path).unwrap();
        let mut s = String::new();
        std::io::Read::read_to_string(&mut f, &mut s).unwrap();
        assert_eq!(s, "www\n");
    }
}
