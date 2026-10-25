//! What this crate needs from the operating system where Linux, macOS and Windows differ:
//! privilege, other processes, stop requests and the machine's identity. Each need has
//! one function here, so the code that uses it reads the same on every platform.
//!
//! On Linux every function does exactly what the code that called libc or /proc directly
//! used to do.

/// Does this process have full administrative rights: root on Unix, an elevated token on
/// Windows?
#[cfg(unix)]
pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the token handle is closed below, and GetTokenInformation writes at most
    // the size it is given into `elevation`.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// The account this process runs as, from its token: `(domain, name)` as Windows
/// resolves them, so a local account's domain is its machine name and a domain
/// account's is its domain. Not the USERDOMAIN variable, which a Windows OpenSSH
/// session sets to the workgroup, and `WORKGROUP\user` names no account. None for
/// LocalSystem, which owns no profile and must not be anyone's operator.
#[cfg(windows)]
pub fn process_account() -> Option<(String, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the token handle is closed before returning, GetTokenInformation writes
    // at most `buf.len()` bytes into `buf`, which is u64-aligned for TOKEN_USER, and
    // LookupAccountSidW writes at most the lengths it is given.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut buf = vec![0u64; 64];
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut len,
        );
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
            return None;
        }
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind: SID_NAME_USE = 0;
        if LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        ) == 0
        {
            return None;
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        Some((domain, name))
    }
}

/// `command` as a person runs it with administrative rights: under sudo on Unix, from an
/// elevated prompt on Windows.
pub fn elevated(command: &str) -> String {
    if cfg!(windows) {
        format!("{command} (from an elevated prompt)")
    } else {
        format!("sudo {command}")
    }
}

/// Is there a process with this id?
#[cfg(target_os = "linux")]
pub fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Is there a process with this id? Signal 0 checks without sending anything, and EPERM
/// means the process is there and belongs to someone else.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    let sent = unsafe { libc::kill(pid, 0) } == 0;
    sent || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Is there a process with this id? A process that cannot be opened for lack of rights is
/// there all the same.
#[cfg(windows)]
pub fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // What GetExitCodeProcess reports for a process that has not exited.
    const STILL_ACTIVE: u32 = 259;
    if pid == 0 {
        return false;
    }
    // SAFETY: the handle is checked before use and closed after it.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(handle, &mut code);
        CloseHandle(handle);
        ok != 0 && code == STILL_ACTIVE
    }
}

/// Ask the process `pid` to stop. On Unix that is SIGTERM, which it may catch to tidy up.
/// Windows has no signal one process can send another's handler, so there it is ended.
#[cfg(unix)]
pub fn terminate(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

#[cfg(windows)]
pub fn terminate(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    // SAFETY: the handle is checked before use and closed after it.
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !handle.is_null() {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}

/// The variable that tells a child on Windows that the end of its stdin is a request to
/// stop. A supervisor there cannot signal a child, so it closes the child's stdin instead.
#[cfg(windows)]
const STOP_ON_EOF_ENV: &str = "CFX_STOP_ON_STDIN_EOF";

/// Set up `cmd` so that [`ask_to_stop`] can stop the child it starts, and the child can
/// tidy up first. Nothing to do on Unix, where that is SIGTERM.
pub fn make_stoppable(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        cmd.env(STOP_ON_EOF_ENV, "1");
        cmd.stdin(std::process::Stdio::piped());
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// Ask a child started with [`make_stoppable`] to stop: SIGTERM on Unix, and on Windows
/// the end of its stdin, which its [`StopSignal`] reads as the same request.
pub fn ask_to_stop(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    #[cfg(windows)]
    drop(child.stdin.take());
}

/// How a stop request is named in the log: the signal on Unix.
pub const STOP_SIGNAL_NAME: &str = if cfg!(unix) {
    "SIGTERM"
} else {
    "Stop request"
};

/// A request for this process to stop, other than Ctrl+C, which callers wait for on its
/// own.
///
/// On Unix it is SIGTERM, which is what `kill` and the service manager send. On Windows it
/// is any of: the console being closed, the machine shutting down, Ctrl+Break, the service
/// manager's stop (see [`request_stop`]), or, for a child started with
/// [`make_stoppable`], the end of its stdin.
pub struct StopSignal {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(windows)]
    win: WindowsStop,
}

#[cfg(windows)]
struct WindowsStop {
    brk: tokio::signal::windows::CtrlBreak,
    close: tokio::signal::windows::CtrlClose,
    shutdown: tokio::signal::windows::CtrlShutdown,
}

impl StopSignal {
    pub fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                term: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            watch_stdin_for_stop();
            Ok(Self {
                win: WindowsStop {
                    brk: tokio::signal::windows::ctrl_break()?,
                    close: tokio::signal::windows::ctrl_close()?,
                    shutdown: tokio::signal::windows::ctrl_shutdown()?,
                },
            })
        }
    }

    /// Wait for the request.
    pub async fn recv(&mut self) {
        #[cfg(unix)]
        {
            self.term.recv().await;
        }
        #[cfg(windows)]
        {
            let w = &mut self.win;
            tokio::select! {
                _ = w.brk.recv() => {}
                _ = w.close.recv() => {}
                _ = w.shutdown.recv() => {}
                _ = stop_requested() => {}
            }
        }
    }
}

#[cfg(windows)]
static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(windows)]
static STOP: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Ask this process to stop, as the Windows service manager does through the node
/// service's control handler. Every [`StopSignal`] sees it, including one made later.
#[cfg(windows)]
pub fn request_stop() {
    STOP_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
    STOP.notify_waiters();
}

#[cfg(windows)]
async fn stop_requested() {
    loop {
        // Made before the flag is read, so a request between the two still wakes it.
        let woken = STOP.notified();
        if STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        woken.await;
    }
}

/// For a child started with [`make_stoppable`]: read stdin to its end on a thread of its
/// own, and take the end as a request to stop. Started once, whatever the number of
/// [`StopSignal`]s.
#[cfg(windows)]
fn watch_stdin_for_stop() {
    static WATCHING: std::sync::Once = std::sync::Once::new();
    if std::env::var_os(STOP_ON_EOF_ENV).is_none_or(|v| v != "1") {
        return;
    }
    WATCHING.call_once(|| {
        std::thread::spawn(|| {
            let mut sink = [0u8; 256];
            let mut stdin = std::io::stdin();
            while let Ok(n) = std::io::Read::read(&mut stdin, &mut sink) {
                if n == 0 {
                    break;
                }
            }
            request_stop();
        });
    });
}

/// What identifies this machine: an install id and a hardware id, either of which may be
/// missing. Linux has /etc/machine-id and the SMBIOS product_uuid. macOS has only the
/// hardware UUID, which is stable across reinstalls. Windows has the MachineGuid the
/// installer writes.
pub fn host_ids() -> (Option<String>, Option<String>) {
    let clean = |s: String| Some(s.trim().to_string()).filter(|s| !s.is_empty());
    #[cfg(target_os = "linux")]
    {
        let machine_id = std::fs::read_to_string("/etc/machine-id")
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
            .ok()
            .and_then(clean);
        let product_uuid = std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
            .ok()
            .and_then(clean);
        (machine_id, product_uuid)
    }
    #[cfg(target_os = "macos")]
    {
        // `"IOPlatformUUID" = "564D....-...."` in the platform expert device's properties.
        let out = std::process::Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let uuid = out
            .lines()
            .find(|l| l.contains("\"IOPlatformUUID\""))
            .and_then(|l| l.rsplit('"').nth(1))
            .map(str::to_string)
            .and_then(clean);
        (None, uuid)
    }
    #[cfg(windows)]
    {
        let guid = win::reg_string(
            win::Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Cryptography",
            "MachineGuid",
        )
        .and_then(clean);
        (guid, None)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = clean;
        (None, None)
    }
}

/// The small amount of the Win32 registry this crate reads.
#[cfg(windows)]
pub mod win {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RRF_RT_REG_SZ,
        RRF_SUBKEY_WOW6464KEY, RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
    };

    #[derive(Clone, Copy)]
    pub enum Hive {
        LocalMachine,
        CurrentUser,
    }

    impl Hive {
        fn key(self) -> HKEY {
            match self {
                Hive::LocalMachine => HKEY_LOCAL_MACHINE,
                Hive::CurrentUser => HKEY_CURRENT_USER,
            }
        }
    }

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    /// The string value `value` of `subkey`, read from the 64-bit view. An empty `value`
    /// is the key's default value.
    pub fn reg_string(hive: Hive, subkey: &str, value: &str) -> Option<String> {
        let subkey = wide(subkey);
        let value = wide(value);
        let mut size = 0u32;
        // SAFETY: the first call only reports the size; the second writes at most `size`
        // bytes into a buffer of that many.
        unsafe {
            let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY;
            if RegGetValueW(
                hive.key(),
                subkey.as_ptr(),
                value.as_ptr(),
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            ) != 0
            {
                return None;
            }
            let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
            let mut size = (buf.len() * 2) as u32;
            if RegGetValueW(
                hive.key(),
                subkey.as_ptr(),
                value.as_ptr(),
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            ) != 0
            {
                return None;
            }
            Some(from_wide(&buf))
        }
    }

    /// The names of the keys directly under `subkey`, from the 64-bit view.
    pub fn reg_subkeys(hive: Hive, subkey: &str) -> Vec<String> {
        let subkey = wide(subkey);
        let mut key: HKEY = std::ptr::null_mut();
        let mut out = Vec::new();
        // SAFETY: the key is opened, read and closed here, and each name is read into a
        // buffer whose length is passed with it.
        unsafe {
            if RegOpenKeyExW(
                hive.key(),
                subkey.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut key,
            ) != 0
            {
                return out;
            }
            for index in 0.. {
                let mut name = [0u16; 256];
                let mut len = name.len() as u32;
                let status = RegEnumKeyExW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if status != 0 {
                    break;
                }
                out.push(String::from_utf16_lossy(&name[..len as usize]));
            }
            RegCloseKey(key);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_alive_and_an_unused_id_is_not() {
        assert!(process_alive(std::process::id()));
        assert!(!process_alive(0));
    }

    #[test]
    fn an_elevated_command_says_how_to_get_the_rights() {
        let cmd = elevated("crossfyre node up");
        if cfg!(windows) {
            assert_eq!(cmd, "crossfyre node up (from an elevated prompt)");
        } else {
            assert_eq!(cmd, "sudo crossfyre node up");
        }
    }
}
