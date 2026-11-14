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

/// Whether `name` in the directory open at `dir` is a symlink.
fn is_link_at(dir: RawFd, name: &CStr) -> bool {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let r = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    r == 0 && unsafe { st.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// `e`, from opening `name` in `dir` without following a link, said in words when the
/// cause was a link: the bare "Too many levels of symbolic links" names neither the
/// path nor what to do about it. `shown` is the path up to and including `name`.
fn refused_link(e: io::Error, dir: RawFd, name: &CStr, shown: &Path) -> io::Error {
    // ELOOP is what a link gives under O_NOFOLLOW; Linux says ENOTDIR instead when
    // O_DIRECTORY is set too.
    let link_errno = matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR));
    if !link_errno || !is_link_at(dir, name) {
        return e;
    }
    io::Error::new(
        e.kind(),
        format!(
            "{} is a symbolic link in a directory another account can change, and a \
             process running as root does not follow it there (the node service, or a \
             command run with sudo); make it a real directory or file instead",
            shown.display()
        ),
    )
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
    let mut shown = std::path::PathBuf::from("/");
    for name in dirs {
        shown.push(OsStr::from_bytes(name.as_bytes()));
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
            other => other.map_err(|e| refused_link(e, cur.as_raw_fd(), name, &shown))?,
        };
        cur = next;
    }
    Ok(cur)
}

/// `mkdir -p path`, with each level it creates handed to `owner`.
pub fn create_dir_all(path: &Path, owner: Option<(u32, u32)>) -> io::Result<()> {
    open_dir(&names(path)?, true, owner).map(|_| ())
}

/// Opens an existing regular file for reading. A link, FIFO or device is refused, and
/// so, in a directory another account can change, is a file with a second name: that
/// name can be a root file anywhere on the same filesystem.
pub fn open_file(path: &Path) -> io::Result<File> {
    let (dirs, name) = split(path)?;
    let dir = open_dir(&dirs, false, None)?;
    let guarded = !root_only(dir.as_raw_fd())?;
    let nofollow = if guarded { libc::O_NOFOLLOW } else { 0 };
    // O_NONBLOCK so a FIFO planted here cannot hang the open; it has no effect on reads
    // from a regular file.
    let fd = openat(
        dir.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | nofollow,
        0,
    )
    .map_err(|e| refused_link(e, dir.as_raw_fd(), &name, path))?;
    let st = fstat(fd.as_raw_fd())?;
    if !is_file(&st) {
        return Err(invalid("not a regular file"));
    }
    if guarded && st.st_nlink > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} has another name (a hard link), and a process running as root does \
                 not read or change such a file in a directory another account can change",
                path.display()
            ),
        ));
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
        // A link (ELOOP), a socket (ENXIO on Linux, EOPNOTSUPP on macOS) or an entry
        // that went away: nothing to do.
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENXIO) | Some(libc::EOPNOTSUPP) | Some(libc::ENOENT)
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

/// Removes the file or link at `path`. A link at `path` is removed, not followed, and
/// no link is followed on the way there.
pub fn remove_file(path: &Path) -> io::Result<()> {
    let (dirs, name) = split(path)?;
    let dir = open_dir(&dirs, false, None)?;
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) }).map(|_| ())
}

/// Removes the directory at `path` and everything in it. No link is followed, on the
/// way there or inside: a link in the tree is removed itself. A link at `path` is
/// refused rather than removed, as `path` names a directory.
pub fn remove_dir_all(path: &Path) -> io::Result<()> {
    let (dirs, name) = split(path)?;
    let dir = open_dir(&dirs, false, None)?;
    remove_tree_at(dir.as_raw_fd(), &name, 0)
        .map_err(|e| refused_link(e, dir.as_raw_fd(), &name, path))
}

fn remove_tree_at(parent: RawFd, name: &CStr, depth: usize) -> io::Result<()> {
    let fd = openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )?;
    if depth >= MAX_DEPTH {
        return Err(invalid("directory tree too deep to remove"));
    }
    for child in list(fd.as_raw_fd())? {
        // Anything but a directory, links included, goes with a plain unlink, which
        // removes the name and never what a link names.
        if unsafe { libc::unlinkat(fd.as_raw_fd(), child.as_ptr(), 0) } == 0 {
            continue;
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            // A directory: Linux says EISDIR, macOS EPERM.
            Some(libc::EISDIR) | Some(libc::EPERM) => {
                remove_tree_at(fd.as_raw_fd(), &child, depth + 1)?
            }
            Some(libc::ENOENT) => {}
            _ => return Err(e),
        }
    }
    check(unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) }).map(|_| ())
}

/// Opens `path` for reading and writing, creating it with `mode` if it is missing,
/// without following a link on the way there or at `path` itself. Whether what it
/// opened may be used (a regular file, with one name) is for the caller to check.
pub fn open_lock(path: &Path, mode: u32) -> io::Result<File> {
    let (dirs, name) = split(path)?;
    let dir = open_dir(&dirs, false, None)?;
    // O_NONBLOCK so a FIFO at that name cannot hang the open.
    let fd = openat(
        dir.as_raw_fd(),
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
        mode & 0o7777,
    )
    .map_err(|e| refused_link(e, dir.as_raw_fd(), &name, path))?;
    Ok(File::from(fd))
}

/// Opens the log a root service writes, appending, for a directory of its own that
/// only this account may change: the directory is made if missing and then set to
/// 0755 and this account's, and the file to 0640 and `group` (when given) so that
/// group can read it. A link at the file's name is refused, as is a file with a
/// second name.
///
/// The directory holding the log's directory must be one only this account can
/// change; the walk to it refuses a link anywhere another account can.
pub fn open_log(path: &Path, group: Option<u32>) -> io::Result<File> {
    let (mut dirs, name) = split(path)?;
    let leaf = dirs
        .pop()
        .ok_or_else(|| invalid("log path names no directory"))?;
    let parent = open_dir(&dirs, false, None)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o755) } != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let dir = openat(parent.as_raw_fd(), &leaf, flags, 0)?;
    let me = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    check(unsafe { libc::fchown(dir.as_raw_fd(), me, gid) })?;
    check(unsafe { libc::fchmod(dir.as_raw_fd(), 0o755) })?;
    let fd = openat(
        dir.as_raw_fd(),
        &name,
        libc::O_WRONLY
            | libc::O_APPEND
            | libc::O_CREAT
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_NOCTTY,
        0o640,
    )?;
    let st = fstat(fd.as_raw_fd())?;
    if !is_file(&st) || st.st_nlink > 1 {
        return Err(invalid("the log is not a file of its own"));
    }
    if let Some(g) = group {
        check(unsafe { libc::fchown(fd.as_raw_fd(), me, g) })?;
    } else {
        check(unsafe { libc::fchown(fd.as_raw_fd(), me, gid) })?;
    }
    check(unsafe { libc::fchmod(fd.as_raw_fd(), 0o640) })?;
    // Writes go through a blocking descriptor.
    let fl = check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK) })?;
    Ok(File::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[test]
    fn a_hard_linked_file_is_not_read_in_a_tree_others_can_change() {
        let t = tempfile::tempdir().expect("tempdir");
        let victim = t.path().join("shadow");
        fs::write(&victim, "root:$6$hash:::\n").unwrap();
        let tree = t.path().join("nodes.d");
        fs::create_dir(&tree).unwrap();
        fs::hard_link(&victim, tree.join("s.toml")).unwrap();

        assert!(read_to_string(&tree.join("s.toml")).is_err());
        assert!(set_mode(&tree.join("s.toml"), 0o600).is_err());
        assert_eq!(fs::metadata(&victim).unwrap().nlink(), 2);
    }

    #[test]
    fn a_linked_directory_is_named_in_the_error() {
        let t = tempfile::tempdir().expect("tempdir");
        let real = t.path().join("dotfiles");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("a.toml"), "x").unwrap();
        let home = t.path().join("home");
        fs::create_dir(&home).unwrap();
        symlink(&real, home.join("nodes.d")).unwrap();

        let e = read_to_string(&home.join("nodes.d/a.toml")).unwrap_err();
        let said = e.to_string();
        assert!(
            said.contains(&home.join("nodes.d").display().to_string()),
            "{said}"
        );
        assert!(said.contains("real directory"), "{said}");
    }

    #[test]
    fn removing_a_file_does_not_pass_through_a_linked_directory() {
        let t = tempfile::tempdir().expect("tempdir");
        let etc = t.path().join("etc");
        fs::create_dir(&etc).unwrap();
        fs::write(etc.join("zz.pid"), "x").unwrap();
        let home = t.path().join("home");
        fs::create_dir(&home).unwrap();
        symlink(&etc, home.join("nodes.d")).unwrap();

        assert!(remove_file(&home.join("nodes.d/zz.pid")).is_err());
        assert!(etc.join("zz.pid").exists());
    }

    #[test]
    fn removing_a_tree_does_not_pass_through_a_link() {
        let t = tempfile::tempdir().expect("tempdir");
        let etc = t.path().join("etc");
        fs::create_dir_all(etc.join("zz.network")).unwrap();
        fs::write(etc.join("zz.network/wg0.conf"), "x").unwrap();
        let home = t.path().join("home");
        fs::create_dir(&home).unwrap();
        symlink(&etc, home.join("nodes.d")).unwrap();

        assert!(remove_dir_all(&home.join("nodes.d/zz.network")).is_err());
        assert!(etc.join("zz.network/wg0.conf").exists());

        // A link inside the tree is removed, and what it names is left alone.
        let own = home.join("own");
        fs::create_dir_all(own.join("x.network/sub")).unwrap();
        fs::write(own.join("x.network/sub/f"), "x").unwrap();
        symlink(&etc, own.join("x.network/e")).unwrap();
        remove_dir_all(&own.join("x.network")).unwrap();
        assert!(!own.join("x.network").exists());
        assert!(etc.join("zz.network/wg0.conf").exists());
    }

    #[test]
    fn a_lock_file_is_not_created_through_a_linked_directory() {
        let t = tempfile::tempdir().expect("tempdir");
        let elsewhere = t.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let home = t.path().join("home");
        fs::create_dir(&home).unwrap();
        symlink(&elsewhere, home.join("toolchain")).unwrap();

        assert!(open_lock(&home.join("toolchain/db.lock"), 0o600).is_err());
        assert!(!elsewhere.join("db.lock").exists());
    }

    #[test]
    fn the_root_log_is_not_opened_through_a_link() {
        let t = tempfile::tempdir().expect("tempdir");
        let script = t.path().join("110.clean-tmps");
        fs::write(&script, "#!/bin/sh\n").unwrap();
        let logs = t.path().join("crossfyre");
        fs::create_dir(&logs).unwrap();
        symlink(&script, logs.join("node.log")).unwrap();

        assert!(open_log(&logs.join("node.log"), None).is_err());
        assert_eq!(fs::read_to_string(&script).unwrap(), "#!/bin/sh\n");
    }

    #[test]
    fn the_root_log_dir_is_made_private_to_its_owner() {
        let t = tempfile::tempdir().expect("tempdir");
        let logs = t.path().join("crossfyre");
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o777)).unwrap();

        let mut f = open_log(&logs.join("node.log"), None).expect("open");
        io::Write::write_all(&mut f, b"x\n").unwrap();

        let dir_mode = fs::metadata(&logs).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o755, "left the log dir {dir_mode:o}");
        let mode = fs::metadata(logs.join("node.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "log is {mode:o}");
    }
}
