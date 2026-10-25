// The engine daemons as scheduled tasks.
//
// On Linux each engine is a systemd user unit: it runs as the operator, not as root,
// starts when the operator's session does, and restarts when it fails. That decides the
// shape here. A Windows service would run as LocalSystem or a service account, and an
// engine that reads wordlists by path for anyone who reaches its port must not read
// them with more rights than the operator has. A service cannot run as the operator
// without the operator's password, and a scheduled task can: with the S4U logon type
// it runs as them, with no password stored, at boot and at their logon, whether or not
// they are logged on, and in no visible window. Registering one needs an elevated
// prompt. Where S4U is refused (an account without the batch logon right, or one the
// machine cannot vouch for itself), the task runs with the operator's interactive
// token instead, which starts it at their logon only.
//
// Tasks are registered from task XML through the Task Scheduler's COM interface rather
// than with schtasks.exe, whose output is translated into the system's language and
// therefore cannot be parsed for a task's state.
//
// The task does not run the engine directly. It runs `crossfyre extension host
// <engine>` (see `win::host`), which restarts the engine when it fails, as
// `Restart=on-failure` does, and which a task's own restart setting cannot do: that
// covers a task that fails to start, not a program that exits with an error.

use std::path::Path;
use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskFolder, ITaskService, TASK_CREATE_OR_UPDATE,
    TASK_LOGON_INTERACTIVE_TOKEN, TASK_LOGON_S4U, TASK_LOGON_TYPE, TASK_STATE_DISABLED,
    TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING, TaskScheduler,
};
use windows::core::{BSTR, VARIANT};

/// The task's name, in the root folder of the Task Scheduler library.
pub fn task_name(key: &str) -> String {
    format!("Crossfyre-{key}")
}

/// COM for the length of one call into the Task Scheduler.
struct Com {
    owned: bool,
}

impl Com {
    fn init() -> Self {
        // S_FALSE (already initialised on this thread) still has to be balanced. A thread
        // that was initialised in the other apartment model keeps it, and this leaves it
        // alone.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        Com { owned: hr.is_ok() }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.owned {
            unsafe { CoUninitialize() };
        }
    }
}

/// The root task folder. The fields drop in order, so the folder is released before COM.
struct Session {
    folder: ITaskFolder,
    _com: Com,
}

fn session() -> Result<Session, String> {
    let com = Com::init();
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("cannot reach the Task Scheduler: {e}"))?;
    let none = VARIANT::default();
    unsafe { service.Connect(&none, &none, &none, &none) }
        .map_err(|e| format!("cannot connect to the Task Scheduler: {e}"))?;
    let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|e| format!("cannot open the Task Scheduler library: {e}"))?;
    Ok(Session { folder, _com: com })
}

fn task(s: &Session, key: &str) -> Option<IRegisteredTask> {
    unsafe { s.folder.GetTask(&BSTR::from(task_name(key))) }.ok()
}

/// `s` with the five characters XML reserves replaced, for text and attribute values.
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The task definition: `command` with `arguments`, run as `user` with `logon`, created
/// disabled, as a new unit is left disabled until `enable`.
pub fn task_xml(
    description: &str,
    user: &str,
    logon: TASK_LOGON_TYPE,
    command: &Path,
    arguments: &str,
) -> String {
    let user = xml(user);
    let s4u = logon == TASK_LOGON_S4U;
    // Without a stored password or S4U nothing can run before the operator logs on.
    let boot = if s4u {
        "    <BootTrigger><Enabled>true</Enabled></BootTrigger>\n"
    } else {
        ""
    };
    let logon_type = if s4u { "S4U" } else { "InteractiveToken" };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
         <Task version=\"1.3\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
         \x20 <RegistrationInfo><Description>{description}</Description></RegistrationInfo>\n\
         \x20 <Triggers>\n\
         {boot}\
         \x20   <LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger>\n\
         \x20 </Triggers>\n\
         \x20 <Principals>\n\
         \x20   <Principal id=\"Operator\"><UserId>{user}</UserId><LogonType>{logon_type}</LogonType>\
         <RunLevel>LeastPrivilege</RunLevel></Principal>\n\
         \x20 </Principals>\n\
         \x20 <Settings>\n\
         \x20   <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n\
         \x20   <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n\
         \x20   <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n\
         \x20   <AllowHardTerminate>true</AllowHardTerminate>\n\
         \x20   <StartWhenAvailable>true</StartWhenAvailable>\n\
         \x20   <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n\
         \x20   <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\n\
         \x20   <AllowStartOnDemand>true</AllowStartOnDemand>\n\
         \x20   <Enabled>false</Enabled>\n\
         \x20   <Hidden>false</Hidden>\n\
         \x20   <RunOnlyIfIdle>false</RunOnlyIfIdle>\n\
         \x20   <WakeToRun>false</WakeToRun>\n\
         \x20   <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n\
         \x20   <Priority>5</Priority>\n\
         \x20 </Settings>\n\
         \x20 <Actions Context=\"Operator\">\n\
         \x20   <Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec>\n\
         \x20 </Actions>\n\
         </Task>\n",
        description = xml(description),
        command = xml(&command.display().to_string()),
        arguments = xml(arguments),
    )
}

/// Register (or replace) the task for `key`, run as the operator. The ExecutionTimeLimit
/// of PT0S matters: the default is 72 hours, after which a daemon would be killed.
pub fn create(key: &str, description: &str, command: &Path, arguments: &str) -> Result<(), String> {
    let user = super::super::sudo_user::operator_account()?;
    let s = session()?;
    let name = BSTR::from(task_name(key));
    let mut refused = String::new();
    for logon in [TASK_LOGON_S4U, TASK_LOGON_INTERACTIVE_TOKEN] {
        let definition = BSTR::from(task_xml(description, &user, logon, command, arguments));
        let registered = unsafe {
            s.folder.RegisterTask(
                &name,
                &definition,
                TASK_CREATE_OR_UPDATE.0,
                &VARIANT::from(user.as_str()),
                &VARIANT::default(),
                logon,
                &VARIANT::default(),
            )
        };
        match registered {
            Ok(_) if logon == TASK_LOGON_S4U => return Ok(()),
            Ok(_) => {
                eprintln!(
                    "[!] {} runs only while {user} is logged on: running it at boot as well \
                     was refused ({refused}). Registering it from an elevated prompt, or \
                     granting {user} the \"Log on as a batch job\" right, lifts that.",
                    task_name(key)
                );
                return Ok(());
            }
            Err(e) if logon == TASK_LOGON_S4U => refused = e.message().to_string(),
            Err(e) => {
                return Err(format!(
                    "cannot register the task {}: {} (and running it at boot: {refused})",
                    task_name(key),
                    e.message()
                ));
            }
        }
    }
    unreachable!("the last logon type returns")
}

pub fn exists(key: &str) -> bool {
    session().ok().is_some_and(|s| task(&s, key).is_some())
}

pub fn delete(key: &str) -> Result<(), String> {
    let s = session()?;
    if let Some(t) = task(&s, key) {
        let _ = unsafe { t.Stop(0) };
    }
    unsafe { s.folder.DeleteTask(&BSTR::from(task_name(key)), 0) }
        .map_err(|e| format!("cannot remove the task {}: {}", task_name(key), e.message()))
}

/// start | stop | restart | enable | disable, as `systemctl` takes them.
pub fn action(action: &str, key: &str) -> Result<(), String> {
    let s = session()?;
    let t = task(&s, key).ok_or_else(|| format!("no task {} is registered", task_name(key)))?;
    let name = task_name(key);
    let fail =
        |what: &str, e: windows::core::Error| format!("cannot {what} {name}: {}", e.message());
    unsafe {
        match action {
            "start" => {
                if t.State().ok() != Some(TASK_STATE_RUNNING) {
                    t.Run(&VARIANT::default()).map_err(|e| fail("start", e))?;
                }
            }
            // Stopping ends the host, and the job it put itself in ends the engine with it.
            "stop" => t.Stop(0).map_err(|e| fail("stop", e))?,
            "restart" => {
                let _ = t.Stop(0);
                // A stop is not finished when Stop returns, and a Run before it is would be
                // ignored as a second instance.
                for _ in 0..40 {
                    if t.State().ok() != Some(TASK_STATE_RUNNING) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                t.Run(&VARIANT::default()).map_err(|e| fail("start", e))?;
            }
            "enable" => t.SetEnabled(VARIANT_TRUE).map_err(|e| fail("enable", e))?,
            "disable" => t
                .SetEnabled(VARIANT_FALSE)
                .map_err(|e| fail("disable", e))?,
            other => return Err(format!("Unsupported action: {other}")),
        }
    }
    Ok(())
}

/// The codes a task's last result carries for something other than a failure: it has
/// not run yet, it is running, it was stopped, and the like (SCHED_S_*).
fn informational(result: i32) -> bool {
    result == 0 || (0x0004_1300..=0x0004_13FF).contains(&result)
}

/// running | stopped | failed | disabled | unknown.
pub fn status(key: &str) -> String {
    let Ok(s) = session() else {
        return "unknown".to_string();
    };
    let Some(t) = task(&s, key) else {
        return "unknown".to_string();
    };
    let state = unsafe { t.State() };
    match state {
        Ok(TASK_STATE_RUNNING) => "running",
        Ok(TASK_STATE_DISABLED) => "disabled",
        Ok(TASK_STATE_READY | TASK_STATE_QUEUED) => match unsafe { t.LastTaskResult() } {
            Ok(r) if !informational(r) => "failed",
            _ => "stopped",
        },
        _ => "unknown",
    }
    .to_string()
}

pub fn is_enabled(key: &str) -> bool {
    session()
        .ok()
        .and_then(|s| task(&s, key))
        .and_then(|t| unsafe { t.Enabled() }.ok())
        .is_some_and(|e| e == VARIANT_TRUE)
}
