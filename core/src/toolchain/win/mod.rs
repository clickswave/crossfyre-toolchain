// Windows: the service manager, the Task Scheduler, and what a process running under
// either needs that a terminal would otherwise have given it.

pub mod admin_fs;
pub mod scm;
pub mod tasks;

use std::path::Path;

/// A log is started afresh, the old one kept as `<name>.1`, once it reaches this size.
const LOG_LIMIT: u64 = 10 * 1024 * 1024;

/// Send this process's stdout and stderr, and those of every process it starts, to the
/// file at `path`, appended to. For a process the service manager or the Task Scheduler
/// started, which has no console to write to. Best-effort: when the file cannot be
/// opened, output goes where it went before.
pub fn log_to(path: &Path) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle};
    let Some(file) = open_log(path) else {
        return;
    };
    // The handle has to outlive every write, so it is never closed.
    let handle = file.into_raw_handle();
    // SAFETY: the handle is a valid, open file handle that is never closed.
    unsafe {
        SetStdHandle(STD_OUTPUT_HANDLE, handle);
        SetStdHandle(STD_ERROR_HANDLE, handle);
    }
}

/// The log at `path`, opened for appending, after starting it afresh when it has
/// reached [`LOG_LIMIT`].
///
/// The node service runs as LocalSystem and logs into the operator's data dir, so when
/// elevated no link on the way is followed: see [`admin_fs`].
fn open_log(path: &Path) -> Option<std::fs::File> {
    if super::sudo_user::root_guards() {
        return admin_fs::open_log(path, LOG_LIMIT)
            .inspect_err(|e| eprintln!("[service] could not open {}: {e}", path.display()))
            .ok();
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::metadata(path).is_ok_and(|m| m.len() > LOG_LIMIT) {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        let _ = std::fs::rename(path, old);
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Put this process in a job that ends every process in it when the job's last handle
/// closes, which is when this process ends, however it ends. Children join the job as
/// they start. A task that is stopped, or a host that is killed, then never leaves an
/// engine behind holding its port.
fn end_children_with_this_process() {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: the job handle is checked, and kept open for the life of the process on
    // purpose; the limit structure is zeroed and then given its one flag.
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            eprintln!(
                "[host] could not create a job object: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let set = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if set == 0 || AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
            eprintln!(
                "[host] could not tie the engine's life to this process: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(job);
        }
    }
}

/// Run the engine `cmd` starts until it exits cleanly, starting it again 5 seconds after
/// each failure, as `Restart=on-failure` and `RestartSec=5` do. Its output, and this
/// host's, go to `log`.
pub fn host(
    name: &str,
    mut cmd: std::process::Command,
    log: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::process::CommandExt;
    // CREATE_NO_WINDOW: a console program started from a task would otherwise be given a
    // console of its own.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    log_to(log);
    end_children_with_this_process();
    cmd.creation_flags(CREATE_NO_WINDOW);
    loop {
        let status = cmd
            .spawn()
            .map_err(|e| format!("could not start {name}: {e}"))?
            .wait()?;
        if status.success() {
            return Ok(());
        }
        eprintln!("[host] {name} exited with {status}; starting it again in 5 seconds");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

/// The owner and the access list of the file or directory at `path`, as SID strings and
/// masks, for `service::judge_admin_only`.
pub fn security_of(path: &Path) -> Result<super::service::Secured, String> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide_with_nul();
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: every out-pointer is valid, and the descriptor is freed below once the
    // owner and access list that point into it have been read.
    unsafe {
        let status = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if status != ERROR_SUCCESS {
            return Err(format!(
                "{}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        let out = secured(path, owner, dacl);
        LocalFree(sd.cast());
        Ok(out)
    }
}

/// [`security_of`] for a file already open, so what is judged is what is then read,
/// whatever its name has been changed to meanwhile. `path` is only shown.
pub fn security_of_file(
    file: &std::fs::File,
    path: &Path,
) -> Result<super::service::Secured, String> {
    use std::os::windows::io::AsHandle;
    security_of_handle(file.as_handle(), path)
}

/// [`security_of_file`] for any open handle, a directory's included.
pub fn security_of_handle(
    handle: std::os::windows::io::BorrowedHandle<'_>,
    path: &Path,
) -> Result<super::service::Secured, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: as in `security_of`; the handle stays open for the length of the call.
    unsafe {
        let status = GetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if status != ERROR_SUCCESS {
            return Err(format!(
                "{}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        let out = secured(path, owner, dacl);
        LocalFree(sd.cast());
        Ok(out)
    }
}

/// The owner and the allow entries of a security descriptor, as `security_of` returns
/// them.
///
/// # Safety
/// `owner` and `dacl` must point into a security descriptor that is still alive.
unsafe fn secured(
    path: &Path,
    owner: windows_sys::Win32::Security::PSID,
    dacl: *mut windows_sys::Win32::Security::ACL,
) -> super::service::Secured {
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, GetAce, INHERIT_ONLY_ACE, PSID,
    };
    // Only allow entries are read. A deny entry can only narrow what they grant, so
    // leaving it out errs towards refusing a path, never towards trusting one.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    fn sid_string(sid: PSID) -> String {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        let mut out: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` points into a security descriptor that is still alive, and the
        // string ConvertSidToStringSidW allocates is freed here.
        unsafe {
            if ConvertSidToStringSidW(sid, &mut out) == 0 || out.is_null() {
                return "an unreadable account".to_string();
            }
            let len = (0..).take_while(|&i| *out.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
            LocalFree(out.cast());
            s
        }
    }

    let mut out = super::service::Secured {
        path: path.to_path_buf(),
        owner: sid_string(owner),
        allows: None,
    };
    if !dacl.is_null() {
        let mut allows = Vec::new();
        // SAFETY: the ACEs are read within the bounds the ACL's own count gives.
        unsafe {
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    continue;
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || header.AceFlags as u32 & INHERIT_ONLY_ACE != 0
                {
                    continue;
                }
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
                allows.push((sid_string(sid), allowed.Mask));
            }
        }
        out.allows = Some(allows);
    }
    out
}

/// Owned by the Administrators group, with an access list that lets LocalSystem and
/// administrators do anything and nobody else anything, and inherits nothing from the
/// directory it is in. What a file the node service takes orders from has to be.
const ADMIN_ONLY_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// [`ADMIN_ONLY_SDDL`] as a security descriptor, freed on drop.
struct AdminOnly(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

impl AdminOnly {
    fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let sddl = std::ffi::OsStr::new(ADMIN_ONLY_SDDL).encode_wide_with_nul();
        let mut sd = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and `sd` is a valid out-pointer; the
        // descriptor it receives is freed by Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(sd))
    }
}

impl Drop for AdminOnly {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
    }
}

/// `OsStr` to a NUL-terminated wide string.
trait WideNul {
    fn encode_wide_with_nul(&self) -> Vec<u16>;
}

impl WideNul for std::ffi::OsStr {
    fn encode_wide_with_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A file of `len` bytes at `path`, without writing them.
    fn sized(path: &Path, len: u64) {
        fs::File::create(path).unwrap().set_len(len).unwrap();
    }

    #[test]
    fn a_log_past_its_limit_is_kept_as_the_old_one_and_started_afresh() {
        for elevated in [false, true] {
            let t = tempfile::tempdir().unwrap();
            let log = t.path().join("logs").join("node.log");
            fs::create_dir(t.path().join("logs")).unwrap();
            sized(&log, LOG_LIMIT + 1);

            let _root = elevated.then(super::super::sudo_user::act_as_root);
            let mut f = open_log(&log).expect("log");
            std::io::Write::write_all(&mut f, b"started\n").unwrap();
            drop(f);

            let old = t.path().join("logs").join("node.log.1");
            assert_eq!(fs::metadata(&old).unwrap().len(), LOG_LIMIT + 1);
            assert_eq!(fs::read_to_string(&log).unwrap(), "started\n");

            // Below the limit, it is appended to.
            let mut f = open_log(&log).expect("log");
            std::io::Write::write_all(&mut f, b"again\n").unwrap();
            drop(f);
            assert_eq!(fs::read_to_string(&log).unwrap(), "started\nagain\n");
        }
    }

    #[test]
    fn an_elevated_log_is_not_moved_or_opened_through_a_junction() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        fs::create_dir(&victim).unwrap();
        sized(&victim.join("node.log"), LOG_LIMIT + 1);
        let logs = t.path().join("logs");
        super::super::sudo_user::junction(&logs, &victim);

        let _root = super::super::sudo_user::act_as_root();
        let opened = open_log(&logs.join("node.log"));

        assert!(opened.is_none(), "opened a log through a junction");
        assert_eq!(
            fs::metadata(victim.join("node.log")).unwrap().len(),
            LOG_LIMIT + 1
        );
        assert!(
            !victim.join("node.log.1").exists(),
            "moved through a junction"
        );
    }
}
