//! File access for a root process working inside a tree another account owns.
//!
//! The node service runs as root but keeps its state in the operator's config root, and
//! `sudo crossfyre ...` writes into the operator's home as well. Path-based calls follow
//! symlinks at every level, so a link the owner of that tree leaves in it turns a write,
//! chmod or chown meant for one of their own files into one on any file on the host.
//!
//! Everything here walks the path one directory at a time from `/`. A symlink is
//! followed only while the directory holding it is one that nobody but root can change.
//! Below the first directory anyone else can write to, a symlink at any level, the last
//! one included, is refused. Files are replaced by renaming a fresh file over them rather
//! than opened and truncated, so a hard link to another file is never written through.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU32, Ordering};

/// How deep [`chown_tree`] goes. The trees it is pointed at are a few levels deep, and a
/// bound keeps a deliberately deep one from exhausting the stack or the fd table.
const MAX_DEPTH: usize = 32;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

fn cstring(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|_| invalid("path holds a NUL byte"))
}

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn openat(dir: RawFd, name: &CStr, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    let fd = check(unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    Ok(unsafe { st.assume_init() })
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn is_file(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// Whether a symlink in the directory open at `dir` can only have been put there by
/// root, so following it is safe.
fn root_only(dir: RawFd) -> io::Result<bool> {
    let st = fstat(dir)?;
    Ok(st.st_uid == 0 && st.st_mode & 0o022 == 0)
}

/// `path` as the names below `/`, taking a relative path from the current directory.
/// `..` is refused: it would lead back out through a directory already checked.
fn names(path: &Path) -> io::Result<Vec<CString>> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut out = Vec::new();
    for c in abs.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(s) => out.push(cstring(s)?),
            Component::ParentDir => return Err(invalid("path holds `..`")),
            Component::Prefix(_) => return Err(invalid("path has a prefix")),
        }
    }
    Ok(out)
}

fn split(path: &Path) -> io::Result<(Vec<CString>, CString)> {
    let mut parts = names(path)?;
    let last = parts.pop().ok_or_else(|| invalid("path names no file"))?;
    Ok((parts, last))
}

/// Opens the directory named by `dirs` below `/`. With `create`, a missing level is
/// made and handed to `owner`; levels that were already there keep their owner.
fn open_dir(dirs: &[CString], create: bool, owner: Option<(u32, u32)>) -> io::Result<OwnedFd> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let mut cur = openat(libc::AT_FDCWD, c"/", flags, 0)?;
    for name in dirs {
        let nofollow = if root_only(cur.as_raw_fd())? {
            0
        } else {
            libc::O_NOFOLLOW
        };
        let next = match openat(cur.as_raw_fd(), name, flags | nofollow, 0) {
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                let made = unsafe { libc::mkdirat(cur.as_raw_fd(), name.as_ptr(), 0o777) } == 0;
                if !made {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                }
                let fd = openat(cur.as_raw_fd(), name, flags | nofollow, 0)?;
                if made && let Some((uid, gid)) = owner {
                    check(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) })?;
                }
                fd
            }
            other => other?,
        };
        cur = next;
    }
    Ok(cur)
}

/// `mkdir -p path`, with each level it creates handed to `owner`.
pub fn create_dir_all(path: &Path, owner: Option<(u32, u32)>) -> io::Result<()> {
    open_dir(&names(path)?, true, owner).map(|_| ())
}

/// Opens an existing regular file for reading. A link, FIFO or device is refused.
pub fn open_file(path: &Path) -> io::Result<File> {
    let (dirs, name) = split(path)?;
    let dir = open_dir(&dirs, false, None)?;
    let nofollow = if root_only(dir.as_raw_fd())? {
        0
    } else {
        libc::O_NOFOLLOW
    };
    // O_NONBLOCK so a FIFO planted here cannot hang the open; it has no effect on reads
    // from a regular file.
    let fd = openat(
        dir.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | nofollow,
        0,
    )?;
    if !is_file(&fstat(fd.as_raw_fd())?) {
        return Err(invalid("not a regular file"));
    }
    Ok(File::from(fd))
}

pub fn read_to_string(path: &Path) -> io::Result<String> {
    let mut s = String::new();
    io::Read::read_to_string(&mut open_file(path)?, &mut s)?;
    Ok(s)
}

static SEQ: AtomicU32 = AtomicU32::new(0);

/// Replaces `path` with a new file holding `contents`, with `mode`, owned by `owner`.
/// Whatever was at `path` (a file, a symlink, a hard link) is replaced, never written
/// through.
pub fn replace_file(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let (dirs, name) = split(path)?;
    let dir = open_dir(&dirs, false, None)?;
    // O_EXCL: a name someone else made first, link or not, is never opened.
    let mut attempt = 0;
    let (tmp, fd) = loop {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut t = b".".to_vec();
        t.extend_from_slice(name.as_bytes());
        t.extend_from_slice(format!(".{}.{n}.tmp", std::process::id()).as_bytes());
        let tmp = CString::new(t).map_err(|_| invalid("path holds a NUL byte"))?;
        match openat(
            dir.as_raw_fd(),
            &tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            mode & 0o7777,
        ) {
            Ok(fd) => break (tmp, fd),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 16 => attempt += 1,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        let mut f = File::from(fd);
        f.write_all(contents)?;
        if let Some((uid, gid)) = owner {
            check(unsafe { libc::fchown(f.as_raw_fd(), uid, gid) })?;
        }
        // The create mode went through the umask; set the one asked for.
        check(unsafe { libc::fchmod(f.as_raw_fd(), (mode & 0o7777) as libc::mode_t) })?;
        check(unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                tmp.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
    }
    result
}

/// Renames `from` to `to` without following a link on the way to either.
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    let (from_dirs, from_name) = split(from)?;
    let (to_dirs, to_name) = split(to)?;
    let a = open_dir(&from_dirs, false, None)?;
    let b = open_dir(&to_dirs, false, None)?;
    check(unsafe {
        libc::renameat(
            a.as_raw_fd(),
            from_name.as_ptr(),
            b.as_raw_fd(),
            to_name.as_ptr(),
        )
    })
    .map(|_| ())
}

/// Sets the mode of the regular file at `path`, through its fd.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    let f = open_file(path)?;
    check(unsafe { libc::fchmod(f.as_raw_fd(), (mode & 0o7777) as libc::mode_t) }).map(|_| ())
}

/// Hands `path` and, if it is a directory, everything under it to `uid:gid`.
///
/// Links are neither followed nor changed. A file with more than one name is skipped,
/// since the other name can be anywhere on the same filesystem, as is anything owned
/// by an account other than root and `uid`. Each entry is opened without following
/// links and changed through its fd, so swapping an entry between the check and the
/// change reaches nothing else. Returns the first error; the rest of the tree is still
/// walked.
pub fn chown_tree(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let (dirs, name) = split(path)?;
    let dir = open_dir(&dirs, false, None)?;
    // The start point is opened like any entry below it: in the operator's home, it
    // can be a link as easily as anything inside it.
    chown_entry(dir.as_raw_fd(), &name, uid, gid, 0)
}

fn chown_entry(dir: RawFd, name: &CStr, uid: u32, gid: u32, depth: usize) -> io::Result<()> {
    let fd = match openat(
        dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
        0,
    ) {
        Ok(fd) => fd,
        // A link (ELOOP), a socket (ENXIO) or an entry that went away: nothing to do.
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENXIO) | Some(libc::ENOENT)
            ) =>
        {
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let st = fstat(fd.as_raw_fd())?;
    if st.st_uid != 0 && st.st_uid != uid {
        return Ok(());
    }
    let dir_entry = is_dir(&st);
    if !dir_entry && st.st_nlink > 1 {
        return Ok(());
    }
    let mut first_err = None;
    if unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) } != 0 {
        first_err = Some(io::Error::last_os_error());
    }
    if dir_entry && depth < MAX_DEPTH {
        for child in list(fd.as_raw_fd())? {
            if let Err(e) = chown_entry(fd.as_raw_fd(), &child, uid, gid, depth + 1) {
                first_err.get_or_insert(e);
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The names in the directory open at `dir`, without `.` and `..`.
fn list(dir: RawFd) -> io::Result<Vec<CString>> {
    let dup = check(unsafe { libc::dup(dir) })?;
    let d = unsafe { libc::fdopendir(dup) };
    if d.is_null() {
        let e = io::Error::last_os_error();
        unsafe { libc::close(dup) };
        return Err(e);
    }
    // The dup shares its offset with `dir`; start from the top whatever it was.
    unsafe { libc::rewinddir(d) };
    let mut out = Vec::new();
    loop {
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            break;
        }
        let n = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        if n.to_bytes() != b"." && n.to_bytes() != b".." {
            out.push(n.to_owned());
        }
    }
    unsafe { libc::closedir(d) };
    Ok(out)
}
