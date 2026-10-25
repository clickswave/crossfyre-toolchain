// The node supervisor as a Windows service.
//
// Linux runs it from /etc/systemd/system/crossfyre-node.service as root. Here it is the
// `crossfyre-node` service, run by the service control manager as LocalSystem, started
// at boot and restarted 5 seconds after it fails, as `Restart=on-failure` and
// `RestartSec=5` do. A console program registered with sc.exe would not do: the service
// manager kills a process that does not answer it within 30 seconds, so the node binary
// speaks the service protocol itself (`node service`, which runs `run_node_service`).
//
// The unit bakes in SUDO_USER so the root daemon keeps finding the operator's files.
// Windows has no sudo, so the command line carries the same facts: the data directory,
// the CLI that registered the service, and the operator's account, which the engines'
// scheduled tasks run as.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// The service's name, which `sc.exe` and services.msc show.
pub const NODE_SERVICE: &str = "crossfyre-node";

type BoxErr = Box<dyn std::error::Error>;

/// The arguments `node.exe` is started with by the service manager, after its path.
pub fn node_arguments(data_dir: &Path, cli: &Path, operator: &str) -> Vec<OsString> {
    vec![
        "service".into(),
        "--data-dir".into(),
        data_dir.as_os_str().to_owned(),
        "--cli".into(),
        cli.as_os_str().to_owned(),
        "--operator".into(),
        operator.into(),
    ]
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, BoxErr> {
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|e| format!("cannot reach the service manager: {e}").into())
}

fn open(access: ServiceAccess) -> Result<windows_service::service::Service, BoxErr> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(NODE_SERVICE, access)
        .map_err(|e| format!("cannot open the {NODE_SERVICE} service: {e}").into())
}

/// Register the service, or bring an existing registration up to date, for the node
/// worker at `node_exe`. It is left stopped and set to start on demand only, as a new
/// unit is left disabled until `enable`.
pub fn create_node(node_exe: &Path, cli: &Path, data_dir: &Path) -> Result<(), BoxErr> {
    let operator = super::super::sudo_user::operator_account()?;
    let info = ServiceInfo {
        name: NODE_SERVICE.into(),
        display_name: "Crossfyre node supervisor".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: node_exe.to_path_buf(),
        launch_arguments: node_arguments(data_dir, cli, &operator),
        dependencies: vec![],
        // LocalSystem, as root runs it on Linux.
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP;
    let service =
        match manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?
            .open_service(NODE_SERVICE, access)
        {
            Ok(service) => {
                service.change_config(&info)?;
                service
            }
            Err(_) => {
                manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?
                    .create_service(&info, access)
                    .map_err(|e| format!("cannot register the {NODE_SERVICE} service: {e}"))?
            }
        };
    let _ = service.set_description("Keeps the Crossfyre nodes registered on this machine online.");
    // Restart 5 seconds after any failure, a non-zero exit included, and forget past
    // failures after a day, so a service that once crashed is not given up on.
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

pub fn node_exists() -> bool {
    open(ServiceAccess::QUERY_STATUS).is_ok()
}

/// Stop the service and remove its registration.
pub fn delete_node() -> Result<(), BoxErr> {
    let service = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    let _ = stop_and_wait(&service);
    service.delete()?;
    Ok(())
}

/// Ask the service to stop and wait up to 30 seconds for it to.
fn stop_and_wait(service: &windows_service::service::Service) -> Result<(), BoxErr> {
    match service.stop() {
        Ok(_) => {}
        // ERROR_SERVICE_NOT_ACTIVE: there is nothing to stop.
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1062) => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    for _ in 0..120 {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("{NODE_SERVICE} did not stop within 30 seconds").into())
}

fn start(service: &windows_service::service::Service) -> Result<(), BoxErr> {
    match service.start::<&str>(&[]) {
        Ok(()) => Ok(()),
        // ERROR_SERVICE_ALREADY_RUNNING
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1056) => Ok(()),
        Err(e) => Err(format!("cannot start {NODE_SERVICE}: {e}").into()),
    }
}

/// Change only the start type: automatic at boot when enabled, on demand when not, as
/// `systemctl disable` leaves a unit that can still be started by hand.
fn set_start_type(
    service: &windows_service::service::Service,
    automatic: bool,
) -> Result<(), BoxErr> {
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfigW, SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
    };
    let start = if automatic {
        SERVICE_AUTO_START
    } else {
        SERVICE_DEMAND_START
    };
    // SAFETY: the handle is the open service's, and every other setting is passed as
    // SERVICE_NO_CHANGE or NULL, which ChangeServiceConfigW reads as "leave it".
    let ok = unsafe {
        ChangeServiceConfigW(
            service.raw_handle() as _,
            SERVICE_NO_CHANGE,
            start,
            SERVICE_NO_CHANGE,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "cannot change how {NODE_SERVICE} starts: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}

/// start | stop | restart | enable | disable, as `systemctl` takes them.
pub fn node_action(action: &str) -> Result<(), BoxErr> {
    let service = open(
        ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG,
    )?;
    match action {
        "start" => start(&service),
        "stop" => stop_and_wait(&service),
        "restart" => {
            stop_and_wait(&service)?;
            start(&service)
        }
        "enable" => set_start_type(&service, true),
        "disable" => set_start_type(&service, false),
        other => Err(format!("Unsupported action: {other}").into()),
    }
}

/// running | stopped | failed | starting | stopping | unknown.
pub fn node_status() -> String {
    let Ok(service) = open(ServiceAccess::QUERY_STATUS) else {
        return "unknown".to_string();
    };
    match service.query_status() {
        Ok(s) => match s.current_state {
            ServiceState::Running => "running",
            ServiceState::Stopped => match s.exit_code {
                ServiceExitCode::Win32(0) | ServiceExitCode::ServiceSpecific(0) => "stopped",
                _ => "failed",
            },
            ServiceState::StartPending | ServiceState::ContinuePending => "starting",
            ServiceState::StopPending | ServiceState::PausePending => "stopping",
            ServiceState::Paused => "paused",
        }
        .to_string(),
        Err(_) => "unknown".to_string(),
    }
}

pub fn node_enabled() -> bool {
    open(ServiceAccess::QUERY_CONFIG)
        .ok()
        .and_then(|s| s.query_config().ok())
        .is_some_and(|c| c.start_type == ServiceStartType::AutoStart)
}

// ── Running as the service ────────────────────────────────────────────

/// What `node service` was started with, for `service_main`, which the service manager
/// calls on a thread of its own with arguments of its own.
static ARGS: std::sync::OnceLock<(PathBuf, PathBuf, String)> = std::sync::OnceLock::new();

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Hand this process to the service manager as the node service. Returns once the
/// service has stopped. `data_dir`, `cli` and `operator` are what `create_node` put on
/// the command line.
pub fn run_node_service(data_dir: PathBuf, cli: PathBuf, operator: String) -> Result<(), BoxErr> {
    let _ = ARGS.set((data_dir, cli, operator));
    windows_service::service_dispatcher::start(NODE_SERVICE, ffi_service_main).map_err(|e| {
        format!(
            "{e}. `node service` is started by the service manager; to run the supervisor \
             in a console, use `node supervise`"
        )
    })?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = serve() {
        eprintln!("[service] {e}");
    }
}

fn serve() -> Result<(), BoxErr> {
    let (data_dir, cli, operator) = ARGS.get().cloned().ok_or("started without its arguments")?;
    // A service has no console. Without this, everything the supervisor and its node
    // daemons print would be lost, where systemd would have kept it in the journal.
    super::log_to(&data_dir.join("logs").join("node.log"));

    let handle = service_control_handler::register(NODE_SERVICE, |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            crate::os::request_stop();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let report = |state: ServiceState, exit: ServiceExitCode| {
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: exit,
            checkpoint: 0,
            wait_hint: Duration::from_secs(if state == ServiceState::StopPending {
                10
            } else {
                0
            }),
            process_id: None,
        });
    };
    report(ServiceState::Running, ServiceExitCode::NO_ERROR);

    // SAFETY: nothing else in this process reads the environment yet. The service
    // manager's own threads do not, and the runtime below, which runs everything that
    // might, is made after this.
    unsafe {
        std::env::set_var(super::super::sudo_user::OPERATOR_ENV, &operator);
        std::env::set_var(super::super::packaging::CLI_ENV, &cli);
    }
    super::super::config::set_toolchain_dir(data_dir.clone());
    super::super::packaging::set_cli(cli);

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| -> BoxErr { e.into() })
        .and_then(|rt| rt.block_on(crate::run_boot(false, &data_dir)));
    report(ServiceState::StopPending, ServiceExitCode::NO_ERROR);
    match result {
        Ok(()) => {
            report(ServiceState::Stopped, ServiceExitCode::NO_ERROR);
            Ok(())
        }
        Err(e) => {
            // A non-zero exit, which the failure actions set in `create_node` restart.
            report(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(1));
            Err(e)
        }
    }
}
