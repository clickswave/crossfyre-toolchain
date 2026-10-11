// Cross-platform daemon service management for the Crossfyre toolchain.
//
// Two kinds of services:
//
// 1. Extension daemons (mach, voyage, pulse) - long-lived *per-user* daemons:
//      Linux   -> systemd user units      (~/.config/systemd/user, systemctl --user)
//      macOS   -> launchd user agents     (~/Library/LaunchAgents, launchctl)
//      Windows -> Task Scheduler tasks    (schtasks, ONLOGON trigger)
//
// 2. The node supervisor itself (`crossfyre node up`) - a *system* service, because
//    tunnel bring-up (network namespaces, openvpn) needs root. Linux only for
//    now: /etc/systemd/system/crossfyre-node.service with SUDO_USER baked in
//    so user-scoped state keeps resolving to the operator's home.
//
// Each `imp` exposes the same set of primitives; only the one matching the
// build target compiles.

use super::ENGINES;
use super::config::is_extension_installed;

pub const NODE_TARGET: &str = "node";

// When true, the per-op status lines ("[+] start ...", "[+] Created ...") are
// suppressed. Bulk flows like `crossfyre update` enable this and render their
// own summary; standalone commands (`crossfyre extension start`) leave it off.
static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_quiet(q: bool) {
    QUIET.store(q, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn quiet() -> bool {
    QUIET.load(std::sync::atomic::Ordering::Relaxed)
}

// ── Shared styled output ──────────────────────────────────────────────
// These service ops are the low-level plumbing behind several commands
// (`node up/down`, `extension start/stop`, `update`), so every op reports
// through one styled success line for a consistent look. Callers keep their
// own `quiet()` guard where they had one.

/// A ✓ success line for a service op (e.g. "crossfyre-node.service started").
fn svc_ok(msg: &str) {
    super::ui::ok(msg);
}

/// Past-tense form of an action verb, for the status line.
fn action_past(action: &str) -> &str {
    match action {
        "start" => "started",
        "stop" => "stopped",
        "restart" => "restarted",
        "enable" => "enabled",
        "disable" => "disabled",
        other => other,
    }
}

fn resolve_targets(target: &str) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    if target == NODE_TARGET {
        Ok(vec![NODE_TARGET])
    } else {
        super::resolve_extensions(target)
    }
}

/// The name an engine's service is registered under on this machine: its public name,
/// unless only a unit under its legacy name exists, which is a machine the rename has
/// not been carried to yet. Anything that is not an engine is its own key.
fn unit_key(ext: &str) -> String {
    match super::engine(ext) {
        Some(e) => match e.legacy {
            Some(old) if !imp::exists(e.name) && imp::exists(old) => old.to_string(),
            _ => e.name.to_string(),
        },
        None => ext.to_string(),
    }
}

/// Every name a unit for `ext` may be registered under, public name first.
fn unit_keys(ext: &str) -> Vec<&str> {
    match super::engine(ext) {
        Some(e) => std::iter::once(e.name).chain(e.legacy).collect(),
        None => vec![ext],
    }
}

// ── Public API ────────────────────────────────────────────────────────

/// Register the service for an extension (write unit/plist/task) under its public
/// name. Called after install. The service exists but is left disabled until `enable`.
pub fn create_service_file(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    imp::create(ext)
}

/// Remove the service registration for an extension, under every name it may have.
/// Called during `remove`.
pub fn remove_service_file(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    for key in unit_keys(ext) {
        imp::delete(key)?;
    }
    Ok(())
}

/// Human-readable run state of an extension's daemon: running | stopped |
/// failed | disabled | unknown.
pub fn daemon_status(ext: &str) -> String {
    imp::status(&unit_key(ext))
}

/// Best-effort stop used before replacing a binary on reinstall. Never errors.
pub fn try_stop(ext: &str) {
    let _ = imp::action("stop", &unit_key(ext));
}

/// Stop and disable `ext`'s service under every name it may have. Never errors.
pub fn try_stop_and_disable_all(ext: &str) {
    for key in unit_keys(ext) {
        if imp::exists(key) {
            let _ = imp::action("stop", key);
            let _ = imp::action("disable", key);
        }
    }
}

/// The systemd user unit directory, where the drop-in directories that
/// configure an extension's unit live. `None` off Linux.
pub fn user_unit_dir() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(super::sudo_user::invoking_user_home().join(".config/systemd/user"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// This machine's service manager, as the engine migration drives it.
pub struct HostUnits;

impl super::migrate::Units for HostUnits {
    fn exists(&self, key: &str) -> bool {
        imp::exists(key)
    }
    fn stop(&self, key: &str) {
        let _ = imp::action("stop", key);
    }
    fn disable(&self, key: &str) {
        let _ = imp::action("disable", key);
    }
    fn enable(&self, key: &str) {
        let _ = imp::action("enable", key);
    }
    fn start(&self, key: &str) {
        let _ = imp::action("start", key);
    }
    fn remove(&self, key: &str) {
        let _ = imp::delete(key);
    }
    fn create(&self, id: &str) {
        let _ = imp::create(id);
    }
}

pub fn start(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("start")?;
        } else {
            imp::action("start", &unit_key(t))?;
        }
    }
    Ok(())
}

pub fn stop(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("stop")?;
        } else {
            imp::action("stop", &unit_key(t))?;
        }
    }
    Ok(())
}

pub fn restart(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("restart")?;
        } else {
            imp::action("restart", &unit_key(t))?;
        }
    }
    Ok(())
}

pub fn enable(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("enable")?;
        } else {
            imp::action("enable", &unit_key(t))?;
        }
    }
    Ok(())
}

pub fn disable(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("disable")?;
        } else {
            imp::action("disable", &unit_key(t))?;
        }
    }
    Ok(())
}

pub fn list() -> Result<(), Box<dyn std::error::Error>> {
    println!("Crossfyre Services");
    println!("==================");
    println!();
    println!(
        "  {:<12} {:<12} {:<10} {:<10}",
        "SERVICE", "INSTALLED", "STATUS", "ENABLED"
    );
    println!(
        "  {:<12} {:<12} {:<10} {:<10}",
        "-------", "---------", "------", "-------"
    );

    // The node supervisor service (system scope).
    {
        let has_service = node::exists();
        let status_str = if has_service {
            node::status()
        } else {
            "no service".to_string()
        };
        let enabled_str = if !has_service {
            "-".to_string()
        } else if node::is_enabled() {
            "yes".to_string()
        } else {
            "no".to_string()
        };
        println!(
            "  {:<12} {:<12} {:<10} {:<10}",
            NODE_TARGET, "yes", status_str, enabled_str
        );
    }

    for e in ENGINES {
        let installed = is_extension_installed(e.id);
        let key = unit_key(e.id);
        let has_service = imp::exists(&key);

        let status_str = if !installed {
            "-".to_string()
        } else if !has_service {
            "no service".to_string()
        } else {
            imp::status(&key)
        };

        let enabled_str = if !installed || !has_service {
            "-".to_string()
        } else if imp::is_enabled(&key) {
            "yes".to_string()
        } else {
            "no".to_string()
        };

        println!(
            "  {:<12} {:<12} {:<10} {:<10}",
            e.name,
            if installed { "yes" } else { "no" },
            status_str,
            enabled_str,
        );
    }
    println!();
    Ok(())
}

// ── Node supervisor service (system scope) ───────────────────────────

/// Install + enable + start the node supervisor as an OS service so registered
/// nodes survive reboots and closed terminals. `exe` is the stable binary path
/// the unit should exec (normally `/opt/crossfyre/bin/crossfyre`).
pub fn install_node_service(
    exe: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    node::create(exe, data_dir)?;
    node::action("enable")?;
    node::action("start")?;
    Ok(())
}

pub fn remove_node_service() -> Result<(), Box<dyn std::error::Error>> {
    node::delete()
}

pub fn node_service_exists() -> bool {
    node::exists()
}

#[cfg(target_os = "linux")]
mod node {
    use std::fs;

    const UNIT: &str = "crossfyre-node.service";
    const UNIT_PATH: &str = "/etc/systemd/system/crossfyre-node.service";

    fn require_root() -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("managing the node service needs root - re-run with sudo".into());
        }
        Ok(())
    }

    pub fn create(
        exe: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        require_root()?;
        // Bake SUDO_USER into the unit so the daemon's user-scoped state
        // (config root, systemctl --user for extensions) keeps resolving to
        // the operator's home instead of /root.
        let sudo_env = match super::super::sudo_user::sudo_user_info() {
            Some((_, _, _, name)) => format!("Environment=SUDO_USER={name}\n"),
            None => String::new(),
        };
        // The supervisor is the separate `node` worker binary, installed
        // alongside `crossfyre` (e.g. /opt/crossfyre/bin/node). Derive its path
        // from the crossfyre binary path we were given.
        let node_exe = exe.with_file_name("node");
        let body = format!(
            "[Unit]\n\
             Description=Crossfyre node supervisor\n\
             After=network-online.target docker.service\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={node_exe} supervise --data-dir {data_dir}\n\
             {sudo_env}\
             Restart=on-failure\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            node_exe = node_exe.display(),
            data_dir = data_dir.display(),
            sudo_env = sudo_env,
        );
        fs::write(UNIT_PATH, body)?;
        let _ = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .status();
        if !super::quiet() {
            super::svc_ok(&format!("{UNIT} created"));
        }
        Ok(())
    }

    pub fn delete() -> Result<(), Box<dyn std::error::Error>> {
        if std::path::Path::new(UNIT_PATH).exists() {
            require_root()?;
            let _ = std::process::Command::new("systemctl")
                .args(["stop", UNIT])
                .status();
            let _ = std::process::Command::new("systemctl")
                .args(["disable", UNIT])
                .status();
            fs::remove_file(UNIT_PATH)?;
            let _ = std::process::Command::new("systemctl")
                .arg("daemon-reload")
                .status();
            super::svc_ok(&format!("{UNIT} removed"));
        }
        Ok(())
    }

    pub fn action(action: &str) -> Result<(), Box<dyn std::error::Error>> {
        require_root()?;
        let status = std::process::Command::new("systemctl")
            .args([action, UNIT])
            .status()
            .map_err(|e| format!("systemctl failed: {e}"))?;
        if !status.success() {
            return Err(format!("Failed to {action} {UNIT}").into());
        }
        if !super::quiet() {
            super::svc_ok(&format!("{} {}", UNIT, super::action_past(action)));
        }
        Ok(())
    }

    pub fn status() -> String {
        match std::process::Command::new("systemctl")
            .args(["is-active", UNIT])
            .output()
        {
            Ok(o) => match String::from_utf8_lossy(&o.stdout).trim() {
                "active" => "running".to_string(),
                "inactive" => "stopped".to_string(),
                "failed" => "failed".to_string(),
                other => other.to_string(),
            },
            Err(_) => "unknown".to_string(),
        }
    }

    pub fn is_enabled() -> bool {
        std::process::Command::new("systemctl")
            .args(["is-enabled", UNIT])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
            .unwrap_or(false)
    }

    pub fn exists() -> bool {
        std::path::Path::new(UNIT_PATH).exists()
    }
}

#[cfg(not(target_os = "linux"))]
mod node {
    // Auto-start of the node supervisor is Linux-only for now. On macOS and
    // Windows the operator runs `crossfyre node up` in a terminal (or wires up
    // their own LaunchDaemon / scheduled task).
    pub fn create(
        _exe: &std::path::Path,
        _data_dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err("the node service is only supported on Linux for now - run `crossfyre node up` directly".into())
    }
    pub fn delete() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    pub fn action(_action: &str) -> Result<(), Box<dyn std::error::Error>> {
        Err("the node service is only supported on Linux for now - run `crossfyre node up` directly".into())
    }
    pub fn status() -> String {
        "unsupported".to_string()
    }
    pub fn is_enabled() -> bool {
        false
    }
    pub fn exists() -> bool {
        false
    }
}

// ── Linux: systemd user units (extensions) ────────────────────────────
#[cfg(target_os = "linux")]
mod imp {
    use super::super::config::ext_bin_path;
    use super::super::sudo_user::{
        chown_to_invoking_user, cmd_as_invoking_user, invoking_user_home,
    };
    use std::fs;

    /// `key` is the name inside the unit name: an engine's public name, or its
    /// legacy name for a unit registered before the engine took its current one.
    fn service_name(key: &str) -> String {
        format!("crossfyre-{key}.service")
    }

    fn unit_dir() -> std::path::PathBuf {
        // Honor SUDO_USER so units land in the real user's
        // ~/.config/systemd/user, not /root's where they'd be invisible.
        invoking_user_home().join(".config/systemd/user")
    }

    fn unit_body(ext: &str) -> String {
        let bin = ext_bin_path(ext);
        let name = super::super::public_name(ext);
        // Daemon port from the host config.toml (defaults to the protocol
        // constant). Baked into ExecStart so a reinstall picks up a changed
        // port; the op-clients and heartbeat read the same source.
        let port = super::super::config::engine_port(ext);
        // Optional egress-proxy env (BYO residential/mobile egress). The `-`
        // prefix makes it non-fatal when absent, so direct-egress nodes are
        // unaffected; the node writes this file when a proxy egress is configured.
        let egress_env = invoking_user_home().join(".config/crossfyre/egress.env");
        format!(
            "[Unit]\n\
             Description=Crossfyre {name} extension daemon\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             EnvironmentFile=-{egress_env}\n\
             ExecStart={bin} --daemon --port {port}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            name = name,
            bin = bin.display(),
            egress_env = egress_env.display(),
            port = port,
        )
    }

    pub fn create(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let dir = unit_dir();
        let svc = service_name(super::super::public_name(ext));
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(&svc), unit_body(ext))?;
        // Written into the user's home as root - chown it back.
        chown_to_invoking_user(&dir);
        let _ = cmd_as_invoking_user("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        if !super::quiet() {
            super::svc_ok(&format!("{svc} created"));
        }
        Ok(())
    }

    pub fn delete(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = unit_dir().join(service_name(ext));
        if path.exists() {
            fs::remove_file(&path)?;
            let _ = cmd_as_invoking_user("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
            super::svc_ok(&format!("{} removed", service_name(ext)));
        }
        Ok(())
    }

    pub fn action(action: &str, ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let svc = service_name(ext);
        let status = cmd_as_invoking_user("systemctl")
            .args(["--user", action, &svc])
            .status()
            .map_err(|e| format!("systemctl failed: {e}"))?;
        if !status.success() {
            return Err(format!("Failed to {action} {svc}").into());
        }
        if !super::quiet() {
            super::svc_ok(&format!("{} {}", svc, super::action_past(action)));
        }
        Ok(())
    }

    pub fn status(ext: &str) -> String {
        let svc = service_name(ext);
        match cmd_as_invoking_user("systemctl")
            .args(["--user", "is-active", &svc])
            .output()
        {
            Ok(o) => match String::from_utf8_lossy(&o.stdout).trim() {
                "active" => "running".to_string(),
                "inactive" => "stopped".to_string(),
                "failed" => "failed".to_string(),
                other => other.to_string(),
            },
            Err(_) => "unknown".to_string(),
        }
    }

    pub fn is_enabled(ext: &str) -> bool {
        let svc = service_name(ext);
        cmd_as_invoking_user("systemctl")
            .args(["--user", "is-enabled", &svc])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
            .unwrap_or(false)
    }

    pub fn exists(ext: &str) -> bool {
        unit_dir().join(service_name(ext)).exists()
    }
}

// ── macOS: launchd user agents (extensions) ───────────────────────────
#[cfg(target_os = "macos")]
mod imp {
    use super::super::config::ext_bin_path;
    use super::super::sudo_user::{
        chown_to_invoking_user, cmd_as_invoking_user, invoking_user_home,
    };
    use std::fs;
    use std::path::PathBuf;

    fn label(ext: &str) -> String {
        format!("io.crossfyre.{}", ext)
    }

    fn agents_dir() -> PathBuf {
        // Honor SUDO_USER so the agent lands in the real user's LaunchAgents.
        invoking_user_home().join("Library").join("LaunchAgents")
    }

    fn plist_path(ext: &str) -> PathBuf {
        agents_dir().join(format!("{}.plist", label(ext)))
    }

    fn plist_body(ext: &str) -> String {
        let bin = ext_bin_path(ext);
        let port = super::super::config::engine_port(ext);
        let key = super::super::public_name(ext);
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \x20 <key>Label</key>\n\
             \x20 <string>{label}</string>\n\
             \x20 <key>ProgramArguments</key>\n\
             \x20 <array>\n\
             \x20   <string>{bin}</string>\n\
             \x20   <string>--daemon</string>\n\
             \x20   <string>--port</string>\n\
             \x20   <string>{port}</string>\n\
             \x20 </array>\n\
             \x20 <key>RunAtLoad</key>\n\
             \x20 <true/>\n\
             \x20 <key>KeepAlive</key>\n\
             \x20 <true/>\n\
             </dict>\n\
             </plist>\n",
            label = label(key),
            bin = bin.display(),
            port = port,
        )
    }

    pub fn create(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let dir = agents_dir();
        let key = super::super::public_name(ext);
        fs::create_dir_all(&dir)?;
        fs::write(plist_path(key), plist_body(ext))?;
        chown_to_invoking_user(&dir);
        super::svc_ok(&format!("{} created", label(key)));
        Ok(())
    }

    pub fn delete(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = plist_path(ext);
        if path.exists() {
            // Unload (best-effort) before deleting the plist.
            let _ = cmd_as_invoking_user("launchctl")
                .args(["unload", "-w", &path.to_string_lossy()])
                .status();
            fs::remove_file(&path)?;
            super::svc_ok(&format!("{} removed", label(ext)));
        }
        Ok(())
    }

    pub fn action(action: &str, ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let lbl = label(ext);
        let plist = plist_path(ext).to_string_lossy().into_owned();
        let result = match action {
            "start" => cmd_as_invoking_user("launchctl")
                .args(["start", &lbl])
                .status(),
            "stop" => cmd_as_invoking_user("launchctl")
                .args(["stop", &lbl])
                .status(),
            // load -w / unload -w toggle the Disabled key, i.e. start-on-login.
            "enable" => cmd_as_invoking_user("launchctl")
                .args(["load", "-w", &plist])
                .status(),
            "disable" => cmd_as_invoking_user("launchctl")
                .args(["unload", "-w", &plist])
                .status(),
            "restart" => {
                let _ = cmd_as_invoking_user("launchctl")
                    .args(["stop", &lbl])
                    .status();
                cmd_as_invoking_user("launchctl")
                    .args(["start", &lbl])
                    .status()
            }
            other => return Err(format!("Unsupported action: {}", other).into()),
        }
        .map_err(|e| format!("launchctl failed: {}", e))?;

        if !result.success() {
            return Err(format!("Failed to {} {}", action, lbl).into());
        }
        super::svc_ok(&format!("{} {}", lbl, super::action_past(action)));
        Ok(())
    }

    pub fn status(ext: &str) -> String {
        // `launchctl list <label>` exits 0 and prints a dict (with "PID" when
        // the job is actually running) only if the agent is loaded.
        match cmd_as_invoking_user("launchctl")
            .args(["list", &label(ext)])
            .output()
        {
            Ok(o) if o.status.success() => {
                if String::from_utf8_lossy(&o.stdout).contains("\"PID\"") {
                    "running".to_string()
                } else {
                    "stopped".to_string()
                }
            }
            _ => "stopped".to_string(),
        }
    }

    pub fn is_enabled(ext: &str) -> bool {
        // Loaded == enabled (will RunAtLoad on next login).
        cmd_as_invoking_user("launchctl")
            .args(["list", &label(ext)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn exists(ext: &str) -> bool {
        plist_path(ext).exists()
    }
}

// ── Windows: Task Scheduler (extensions) ──────────────────────────────
#[cfg(target_os = "windows")]
mod imp {
    use super::super::config::ext_bin_path;
    use std::process::Command;

    fn task_name(ext: &str) -> String {
        format!("Crossfyre-{}", ext)
    }

    pub fn create(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let bin = ext_bin_path(ext);
        let port = super::super::config::engine_port(ext);
        let key = super::super::public_name(ext);
        // Quote the path; ONLOGON mirrors systemd --user (starts at user login).
        let tr = format!("\"{}\" --daemon --port {}", bin.display(), port);
        let status = Command::new("schtasks")
            .args([
                "/Create",
                "/TN",
                &task_name(key),
                "/TR",
                &tr,
                "/SC",
                "ONLOGON",
                "/RL",
                "LIMITED",
                "/F",
            ])
            .status()
            .map_err(|e| format!("schtasks failed: {}", e))?;
        if !status.success() {
            return Err(format!("Failed to create task {}", task_name(key)).into());
        }
        // Created enabled by default; disable to mirror "installed, not enabled".
        let _ = Command::new("schtasks")
            .args(["/Change", "/TN", &task_name(key), "/DISABLE"])
            .status();
        super::svc_ok(&format!("{} created", task_name(key)));
        Ok(())
    }

    pub fn delete(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        if exists(ext) {
            let status = Command::new("schtasks")
                .args(["/Delete", "/TN", &task_name(ext), "/F"])
                .status()
                .map_err(|e| format!("schtasks failed: {}", e))?;
            if !status.success() {
                return Err(format!("Failed to delete task {}", task_name(ext)).into());
            }
            super::svc_ok(&format!("{} removed", task_name(ext)));
        }
        Ok(())
    }

    pub fn action(action: &str, ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tn = task_name(ext);
        let result = match action {
            "start" => Command::new("schtasks").args(["/Run", "/TN", &tn]).status(),
            "stop" => Command::new("schtasks").args(["/End", "/TN", &tn]).status(),
            "enable" => Command::new("schtasks")
                .args(["/Change", "/TN", &tn, "/ENABLE"])
                .status(),
            "disable" => Command::new("schtasks")
                .args(["/Change", "/TN", &tn, "/DISABLE"])
                .status(),
            "restart" => {
                let _ = Command::new("schtasks").args(["/End", "/TN", &tn]).status();
                Command::new("schtasks").args(["/Run", "/TN", &tn]).status()
            }
            other => return Err(format!("Unsupported action: {}", other).into()),
        }
        .map_err(|e| format!("schtasks failed: {}", e))?;

        if !result.success() {
            return Err(format!("Failed to {} {}", action, tn).into());
        }
        super::svc_ok(&format!("{} {}", tn, super::action_past(action)));
        Ok(())
    }

    fn query(ext: &str) -> Option<String> {
        match Command::new("schtasks")
            .args(["/Query", "/TN", &task_name(ext), "/FO", "LIST"])
            .output()
        {
            Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
            _ => None,
        }
    }

    pub fn status(ext: &str) -> String {
        match query(ext) {
            Some(out) => {
                let line = out
                    .lines()
                    .find(|l| l.trim_start().to_lowercase().starts_with("status:"));
                match line
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_lowercase())
                {
                    Some(s) if s == "running" => "running".to_string(),
                    Some(s) if s == "ready" => "stopped".to_string(),
                    Some(s) if s == "disabled" => "disabled".to_string(),
                    Some(s) if !s.is_empty() => s,
                    _ => "unknown".to_string(),
                }
            }
            None => "unknown".to_string(),
        }
    }

    pub fn is_enabled(ext: &str) -> bool {
        match query(ext) {
            Some(out) => !out.to_lowercase().contains("disabled"),
            None => false,
        }
    }

    pub fn exists(ext: &str) -> bool {
        Command::new("schtasks")
            .args(["/Query", "/TN", &task_name(ext)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
