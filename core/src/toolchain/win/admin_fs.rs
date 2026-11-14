//! File access for an elevated process working inside a tree another account owns: the
//! Windows counterpart of `root_fs`.
//!
//! The node service runs as LocalSystem but keeps its state in the operator's
//! %APPDATA%\crossfyre, and a command run from an elevated prompt writes there too. A
//! call by path follows a junction or a symbolic link at every level, and the operator's
//! account can put one anywhere in that tree without elevation, including one into the
//! object manager's namespace, which leads to any path on the machine. A write, rename
//! or delete meant for one of the node's own files then lands on a file of the system's.
//!
//! Everything here opens a path one directory at a time from the drive's root, each
//! level relative to the handle of the one above it. A junction or symbolic link is
//! followed only where nobody but an administrator could have put it there. Below the
//! first directory another account can change, a link at any level, the last one
//! included, is refused. Files are renamed and deleted through their own handles, and
//! replaced by renaming a new file over them, so nothing is done to a name after it
//! could have been changed to lead somewhere else.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
    FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation,
    FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FULL_DIR_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FileDispositionInfo, FileFullDirectoryInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, READ_CONTROL, SYNCHRONIZE, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// How deep [`remove_dir_all`] goes, as in `root_fs`.
const MAX_DEPTH: usize = 32;

/// What a directory on the way is opened with: enough to open what is in it, list it
/// and read its access list.
const DIR_ACCESS: u32 =
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

/// Every file here is opened sharing all access, as std opens files, so the operator's
/// own tools keep working on them.
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn refused_link(shown: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} is a junction or symbolic link in a directory another account can change, \
             and an elevated process (the node service, or a command run as administrator) \
             does not follow it there; make it a real directory or file instead",
            shown.display()
        ),
    )
}

fn second_name(shown: &Path) -> io::Error {
    invalid(format!(
        "{} has another name (a hard link), and an elevated process does not read or \
         change such a file in a directory another account can change",
        shown.display()
    ))
}

/// A directory opened by [`open_dir`], held open.
pub struct Dir {
    handle: OwnedHandle,
    /// Nobody but an administrator can add, remove or rename what is in it, or the
    /// directory itself, here or on the way to it. Only then is a link in it followed.
    fixed: bool,
    path: PathBuf,
}

impl Dir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates the file `name` in this directory, which must not exist yet, for writing.
    /// Nothing that was at that name before is ever opened.
    pub fn create_new(&self, name: &OsStr) -> io::Result<File> {
        let h = nt_open(
            self.raw(),
            name,
            FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            None,
        )?;
        Ok(File::from(h))
    }

    /// Makes the directory `name` in this one, which must not exist yet, and opens it.
    pub fn create_dir(&self, name: &OsStr) -> io::Result<Dir> {
        let h = nt_open(
            self.raw(),
            name,
            DIR_ACCESS | DELETE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            None,
        )?;
        Ok(Dir {
            handle: h,
            fixed: false,
            path: self.path.join(name),
        })
    }

    /// Deletes this directory, through its handle, once it is empty.
    pub fn remove(self) -> io::Result<()> {
        delete_handle(self.raw())
    }

    /// Deletes everything in this directory and then the directory, through handles. A
    /// link inside is removed itself, never followed.
    pub fn remove_all(self) -> io::Result<()> {
        empty_and_remove(self, 0)
    }

    /// Deletes the file or link `name` in this directory; a link is removed, not
    /// followed.
    pub fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        let h = nt_open(
            self.raw(),
            name,
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT,
            None,
        )?;
        let i = info(&h)?;
        if is_dir(&i) && !is_link(&i) {
            return Err(invalid(format!(
                "{} is a directory",
                self.path.join(name).display()
            )));
        }
        delete_handle(h.as_raw_handle())
    }

    fn raw(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }
}

/// Opens `name` in the directory `dir`, a single name, never a path.
fn nt_open(
    dir: RawHandle,
    name: &OsStr,
    access: u32,
    disposition: u32,
    options: u32,
    security: Option<&super::AdminOnly>,
) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = name.encode_wide().collect();
    let separator = |c: &u16| *c == b'\\' as u16 || *c == b'/' as u16 || *c == 0;
    let dots = name == OsStr::new(".") || name == OsStr::new("..");
    if wide.is_empty() || wide.len() > 32_000 || wide.iter().any(separator) || dots {
        return Err(invalid(format!("{name:?} is not a file name")));
    }
    let bytes = (wide.len() * 2) as u16;
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: wide.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir as HANDLE,
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.map_or(std::ptr::null(), |s| s.0.cast_const().cast()),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: an all-zero IO_STATUS_BLOCK is valid.
    let mut io_status: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer is valid for the call: `wide` backs `object_name`, which
    // `attributes` points to, and the security descriptor outlives the call. The handle
    // returned is owned by the OwnedHandle made from it.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut io_status,
            std::ptr::null(),
            0,
            SHARE_ALL,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: a plain conversion with no preconditions.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: NtCreateFile succeeded, so `handle` is a new handle nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

fn info(h: &impl AsRawHandle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is valid, and the call writes no
    // more than its size.
    unsafe {
        let mut i: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(h.as_raw_handle(), &mut i) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(i)
    }
}

/// A junction, a symbolic link or any other reparse point.
fn is_link(i: &BY_HANDLE_FILE_INFORMATION) -> bool {
    i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn is_dir(i: &BY_HANDLE_FILE_INFORMATION) -> bool {
    i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

fn delete_handle(h: RawHandle) -> io::Result<()> {
    let d = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `d` is a valid FILE_DISPOSITION_INFO of the size given.
    let ok = unsafe {
        SetFileInformationByHandle(
            h,
            FileDispositionInfo,
            (&d as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Gives the file open at `file` the name `name` in the directory `dir`, replacing
/// what is there: a link at that name is replaced, not followed.
///
/// As `std::fs::rename` does, it asks for POSIX semantics first, under which a file
/// another process has open can still be replaced, and falls back to a plain rename
/// where the system or the file system does not offer them.
fn rename_handle(file: RawHandle, dir: &Dir, name: &OsStr) -> io::Result<()> {
    let posix = rename_with(
        file,
        dir,
        name,
        FileRenameInformationEx,
        FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
    );
    // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED and ERROR_INVALID_PARAMETER: no
    // FileRenameInformationEx here, or no POSIX semantics on this file system.
    match posix {
        Err(e) if matches!(e.raw_os_error(), Some(1 | 50 | 87)) => {
            // ReplaceIfExists, a BOOLEAN, is the low byte of the flags.
            rename_with(file, dir, name, FileRenameInformation, 1)
        }
        other => other,
    }
}

fn rename_with(file: RawHandle, dir: &Dir, name: &OsStr, class: i32, flags: u32) -> io::Result<()> {
    let wide: Vec<u16> = name.encode_wide().collect();
    let head = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = head + wide.len() * 2;
    // u64s, so the buffer is aligned for the structure's handle.
    let mut buf = vec![0u64; size.div_ceil(8)];
    // SAFETY: the buffer is zeroed, aligned and at least `size` bytes long, which holds
    // the structure and the name written after its head.
    let status = unsafe {
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        (*info).Anonymous.Flags = flags;
        (*info).RootDirectory = dir.raw() as HANDLE;
        (*info).FileNameLength = (wide.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            buf.as_mut_ptr().cast::<u8>().add(head).cast::<u16>(),
            wide.len(),
        );
        let mut io_status: IO_STATUS_BLOCK = std::mem::zeroed();
        NtSetInformationFile(
            file as HANDLE,
            &mut io_status,
            buf.as_ptr().cast(),
            size as u32,
            class,
        )
    };
    if status < 0 {
        // SAFETY: a plain conversion with no preconditions.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

/// Whether nobody but an administrator can change `entry`, or what is in `parent`.
fn admin_only(entry: &impl AsHandle, parent: &impl AsHandle, shown: &Path) -> bool {
    let (Ok(e), Ok(p)) = (
        super::security_of_handle(entry.as_handle(), shown),
        super::security_of_handle(parent.as_handle(), shown),
    ) else {
        return false;
    };
    super::super::service::judge_admin_only(&[e, p]).is_ok()
}

/// `path` as the root of its drive or share and the names below it, taking a relative
/// path from the current directory. `..` is refused, as in `root_fs`.
fn names(path: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
    let abs = std::path::absolute(path)?;
    let mut root = OsString::new();
    let mut names = Vec::new();
    for c in abs.components() {
        match c {
            Component::Prefix(p) => root.push(p.as_os_str()),
            Component::RootDir => root.push("\\"),
            Component::CurDir => {}
            Component::Normal(s) => names.push(s.to_os_string()),
            Component::ParentDir => {
                return Err(invalid(format!("{} holds `..`", path.display())));
            }
        }
    }
    if root.is_empty() {
        return Err(invalid(format!(
            "{} names no drive or share",
            path.display()
        )));
    }
    Ok((PathBuf::from(root), names))
}

fn split(path: &Path) -> io::Result<(PathBuf, Vec<OsString>, OsString)> {
    let (root, mut parts) = names(path)?;
    let last = parts
        .pop()
        .ok_or_else(|| invalid(format!("{} names no file", path.display())))?;
    Ok((root, parts, last))
}

/// Opens the directory `dirs` below `root`, one level at a time. With `create`, a
/// missing level is made. A link is followed only in a directory nobody but an
/// administrator can change; anywhere else it is refused.
fn walk(root: &Path, dirs: &[OsString], create: bool) -> io::Result<Dir> {
    use std::os::windows::fs::OpenOptionsExt;
    // The root of a drive or a share is the machine's, as `/` is on Unix.
    let top = std::fs::OpenOptions::new()
        .access_mode(DIR_ACCESS)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)?;
    let mut cur = Dir {
        handle: OwnedHandle::from(top),
        fixed: true,
        path: root.to_path_buf(),
    };
    for name in dirs {
        let shown = cur.path.join(name);
        let opened = nt_open(
            cur.raw(),
            name,
            DIR_ACCESS,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            None,
        );
        let entry = match opened {
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => nt_open(
                cur.raw(),
                name,
                DIR_ACCESS,
                FILE_OPEN_IF,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
                None,
            )?,
            other => other?,
        };
        let i = info(&entry)?;
        let fixed = cur.fixed && admin_only(&entry, &cur.handle, &shown);
        let handle = if is_link(&i) {
            if !fixed {
                return Err(refused_link(&shown));
            }
            let target = nt_open(
                cur.raw(),
                name,
                DIR_ACCESS,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                None,
            )?;
            // Where it leads must be the administrators' too.
            let leads = super::security_of_handle(target.as_handle(), &shown)
                .is_ok_and(|s| super::super::service::judge_admin_only(&[s]).is_ok());
            if !leads {
                return Err(refused_link(&shown));
            }
            target
        } else {
            entry
        };
        cur = Dir {
            handle,
            fixed,
            path: shown,
        };
    }
    Ok(cur)
}

/// Opens the directory at `path`.
pub fn open_dir(path: &Path) -> io::Result<Dir> {
    let (root, dirs) = names(path)?;
    walk(&root, &dirs, false)
}

/// `mkdir -p path`, without following a link another account could have made on the
/// way. Directories it makes take their access list from the one they are in.
pub fn create_dir_all(path: &Path) -> io::Result<Dir> {
    let (root, dirs) = names(path)?;
    walk(&root, &dirs, true)
}

/// Opens the existing file `name` in `dir` with `access`. A link is refused, and so, in
/// a directory another account can change, is a file with a second name, which can be
/// any file on the volume.
fn open_in(dir: &Dir, name: &OsStr, access: u32) -> io::Result<File> {
    let shown = dir.path.join(name);
    let h = nt_open(
        dir.raw(),
        name,
        access | FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        None,
    )?;
    let i = info(&h)?;
    if is_link(&i) {
        return Err(refused_link(&shown));
    }
    if !dir.fixed && i.nNumberOfLinks > 1 {
        return Err(second_name(&shown));
    }
    Ok(File::from(h))
}

/// Opens an existing regular file at `path` with `access`.
pub fn open_file(path: &Path, access: u32) -> io::Result<File> {
    let (root, dirs, name) = split(path)?;
    open_in(&walk(&root, &dirs, false)?, &name, access)
}

pub fn read_to_string(path: &Path) -> io::Result<String> {
    let mut s = String::new();
    io::Read::read_to_string(&mut open_file(path, FILE_GENERIC_READ)?, &mut s)?;
    Ok(s)
}

static SEQ: AtomicU32 = AtomicU32::new(0);

/// Replaces `path` with a new file holding `contents`. Whatever was at `path` (a file,
/// a link, a hard link) is replaced, never written through. With `admin_only`, the new
/// file can be opened by administrators and LocalSystem only from the moment it exists;
/// otherwise it takes its access list from the directory, as a new file would.
pub fn replace_file(path: &Path, contents: &[u8], admin_only: bool) -> io::Result<()> {
    let (root, dirs, name) = split(path)?;
    let dir = walk(&root, &dirs, false)?;
    let security = if admin_only {
        Some(super::AdminOnly::new()?)
    } else {
        None
    };
    let mut attempt = 0;
    let file = loop {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut tmp = OsString::from(".");
        tmp.push(&name);
        tmp.push(format!(".{}.{n}.tmp", std::process::id()));
        match nt_open(
            dir.raw(),
            &tmp,
            FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            security.as_ref(),
        ) {
            Ok(h) => break File::from(h),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 16 => attempt += 1,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        let mut f = &file;
        f.write_all(contents)?;
        if admin_only {
            file.sync_all()?;
        }
        rename_handle(file.as_raw_handle(), &dir, &name)
    })();
    if result.is_err() {
        let _ = delete_handle(file.as_raw_handle());
    }
    result
}

/// Renames `from` to `to`, replacing what is at `to`, without following a link on the
/// way to either. A link at `from` is renamed itself.
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    let (from_root, from_dirs, from_name) = split(from)?;
    let (to_root, to_dirs, to_name) = split(to)?;
    let a = walk(&from_root, &from_dirs, false)?;
    let b = walk(&to_root, &to_dirs, false)?;
    let h = nt_open(
        a.raw(),
        &from_name,
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT,
        None,
    )?;
    rename_handle(h.as_raw_handle(), &b, &to_name)
}

/// Removes the file or link at `path`. A link at `path` is removed, not followed, and
/// no link is followed on the way there.
pub fn remove_file(path: &Path) -> io::Result<()> {
    let (root, dirs, name) = split(path)?;
    walk(&root, &dirs, false)?.remove_file(&name)
}

/// Removes the directory at `path` and everything in it. No link is followed, on the
/// way there or inside: a link in the tree is removed itself. A link at `path` is
/// refused rather than removed, as `path` names a directory.
pub fn remove_dir_all(path: &Path) -> io::Result<()> {
    let (root, dirs, name) = split(path)?;
    let parent = walk(&root, &dirs, false)?;
    remove_tree_at(&parent, &name, 0)
}

fn remove_tree_at(parent: &Dir, name: &OsStr, depth: usize) -> io::Result<()> {
    let shown = parent.path.join(name);
    let h = nt_open(
        parent.raw(),
        name,
        DIR_ACCESS | DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        None,
    )?;
    if is_link(&info(&h)?) {
        return Err(refused_link(&shown));
    }
    if depth >= MAX_DEPTH {
        return Err(invalid(format!(
            "{} is too deep to remove",
            shown.display()
        )));
    }
    empty_and_remove(
        Dir {
            handle: h,
            fixed: false,
            path: shown,
        },
        depth,
    )
}

fn empty_and_remove(dir: Dir, depth: usize) -> io::Result<()> {
    for (child, attributes) in list(&dir)? {
        if attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        {
            remove_tree_at(&dir, &child, depth + 1)?;
        } else {
            match dir.remove_file(&child) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                other => other?,
            }
        }
    }
    dir.remove()
}

/// The names in `dir`, with their attributes, `.` and `..` left out.
fn list(dir: &Dir) -> io::Result<Vec<(OsString, u32)>> {
    use std::os::windows::ffi::OsStringExt;
    let mut out = Vec::new();
    // u64s, so the buffer is aligned for the entries' 8-byte fields.
    let mut buf = vec![0u64; 8 * 1024];
    loop {
        // SAFETY: the buffer is writable for the size given.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.raw(),
                FileFullDirectoryInfo,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
            )
        };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                return Ok(out);
            }
            return Err(e);
        }
        let base = buf.as_ptr().cast::<u8>();
        let head = std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName);
        let mut offset = 0usize;
        loop {
            // SAFETY: the system wrote whole entries into the buffer, each at the offset
            // the one before it gives, with its name right after its head.
            let (next, attributes, name) = unsafe {
                let entry = base.add(offset).cast::<FILE_FULL_DIR_INFO>();
                let len = (*entry).FileNameLength as usize / 2;
                let name = std::slice::from_raw_parts(base.add(offset + head).cast::<u16>(), len);
                (
                    (*entry).NextEntryOffset as usize,
                    (*entry).FileAttributes,
                    OsString::from_wide(name),
                )
            };
            if name != "." && name != ".." {
                out.push((name, attributes));
            }
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
}

/// Opens the log at `path` for appending, making its directory if it is missing, after
/// keeping the log as `<name>.1` and starting a new one once it is over `limit` bytes.
/// A link at the log's name is refused, as is a log with a second name.
pub fn open_log(path: &Path, limit: u64) -> io::Result<File> {
    let (root, dirs, name) = split(path)?;
    let dir = walk(&root, &dirs, true)?;
    let shown = dir.path.join(&name);
    // Best-effort, as before: a log another process holds open is not started afresh this
    // time. Whatever is at the name is renamed itself, within this directory, and the
    // open below checks what it then finds there.
    let current = nt_open(
        dir.raw(),
        &name,
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        None,
    );
    if let Ok(h) = current
        && info(&h).is_ok_and(|i| {
            !is_link(&i) && (u64::from(i.nFileSizeHigh) << 32 | u64::from(i.nFileSizeLow)) > limit
        })
    {
        let mut old = name.clone();
        old.push(".1");
        let _ = rename_handle(h.as_raw_handle(), &dir, &old);
    }
    let h = nt_open(
        dir.raw(),
        &name,
        FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        None,
    )?;
    let i = info(&h)?;
    if is_link(&i) {
        return Err(refused_link(&shown));
    }
    if i.nNumberOfLinks > 1 {
        return Err(second_name(&shown));
    }
    Ok(File::from(h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn a_replace_puts_a_new_file_over_a_link_and_leaves_its_target_alone() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("x"), "system's\n").unwrap();
        let tree = t.path().join("tree");
        fs::create_dir(&tree).unwrap();
        if std::os::windows::fs::symlink_file(victim.join("x"), tree.join("n.pid")).is_err() {
            eprintln!("skipped: this account may not make symbolic links");
            return;
        }

        replace_file(&tree.join("n.pid"), b"4242", false).unwrap();

        // The name now holds the new file. Read through its metadata: Wine, which these
        // tests also run under, cannot open a file renamed over one of its links.
        let meta = fs::symlink_metadata(tree.join("n.pid")).unwrap();
        assert!(!meta.is_symlink() && meta.is_file() && meta.len() == 4);
        assert_eq!(fs::read_to_string(victim.join("x")).unwrap(), "system's\n");
        let left: Vec<_> = fs::read_dir(&tree).unwrap().collect();
        assert_eq!(left.len(), 1, "left {left:?}");
    }

    #[test]
    fn a_replace_overwrites_a_file_and_leaves_no_temporary_file() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("config.toml");
        fs::write(&p, "old, and longer than the new\n").unwrap();
        replace_file(&p, b"new\n", false).unwrap();
        replace_file(&p, b"newer\n", true).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "newer\n");
        assert_eq!(read_to_string(&p).unwrap(), "newer\n");
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
    }

    // The supervisor, `node status` and the engines read these files while the node
    // may be replacing them.
    #[test]
    fn a_file_another_process_has_open_is_still_replaced() {
        let t = tempfile::tempdir().unwrap();
        // Where std cannot do this either (Wine, or a file system with no POSIX
        // semantics), neither can this.
        fs::write(t.path().join("a"), "1").unwrap();
        fs::write(t.path().join("b"), "2").unwrap();
        let held = fs::File::open(t.path().join("a")).unwrap();
        if fs::rename(t.path().join("b"), t.path().join("a")).is_err() {
            eprintln!("skipped: this system cannot replace a file that is open");
            return;
        }
        drop(held);

        let p = t.path().join("n.pid");
        fs::write(&p, "1").unwrap();
        let reader = fs::File::open(&p).unwrap();
        replace_file(&p, b"2", false).unwrap();
        drop(reader);
        assert_eq!(fs::read_to_string(&p).unwrap(), "2");
    }

    #[test]
    fn a_hard_link_is_neither_read_nor_written_through() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        fs::write(&victim, "system's\n").unwrap();
        let tree = t.path().join("tree");
        fs::create_dir(&tree).unwrap();
        let p = tree.join("n.toml");
        if fs::hard_link(&victim, &p).is_err() {
            eprintln!("skipped: no hard links here");
            return;
        }
        assert!(read_to_string(&p).is_err());
        replace_file(&p, b"x", false).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "system's\n");
        assert_eq!(fs::read_to_string(&p).unwrap(), "x");
    }

    #[test]
    fn removing_a_link_removes_the_link_only() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("x"), "system's\n").unwrap();
        let link = t.path().join("n.pid");
        crate::toolchain::sudo_user::junction(&link, &victim);

        remove_file(&link).unwrap();

        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(fs::read_to_string(victim.join("x")).unwrap(), "system's\n");
    }

    #[test]
    fn a_tree_is_removed_without_following_a_link_inside_it() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("x"), "system's\n").unwrap();
        let tree = t.path().join("n.network");
        fs::create_dir_all(tree.join("a").join("b")).unwrap();
        fs::write(tree.join("a").join("b").join("f"), "1").unwrap();
        fs::write(tree.join("g"), "2").unwrap();
        crate::toolchain::sudo_user::junction(&tree.join("a").join("j"), &victim);

        remove_dir_all(&tree).unwrap();

        assert!(!tree.exists());
        assert_eq!(fs::read_to_string(victim.join("x")).unwrap(), "system's\n");
    }

    #[test]
    fn directories_are_made_level_by_level_and_a_name_cannot_be_a_path() {
        let t = tempfile::tempdir().unwrap();
        let deep = t.path().join("a").join("b").join("c");
        let dir = create_dir_all(&deep).unwrap();
        assert!(deep.is_dir());
        assert_eq!(dir.path(), std::path::absolute(&deep).unwrap());
        create_dir_all(&deep).unwrap();
        for bad in ["..", "x\\y", "x/y", ""] {
            assert!(dir.create_new(OsStr::new(bad)).is_err(), "{bad:?}");
        }
    }
}
