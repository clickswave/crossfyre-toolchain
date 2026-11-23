// Cross-platform daemon service management for the Crossfyre toolchain.
//
// Two kinds of services:
//
// 1. Extension daemons (ambulo, voyage, doorward) - long-lived *per-user* daemons:
//      Linux   -> systemd user units      (~/.config/systemd/user, systemctl --user),
//                 with lingering on for the user so they run outside a login (see `linger`)
//      macOS   -> launchd user agents     (~/Library/LaunchAgents, launchctl)
//      Windows -> scheduled tasks run as the operator (see `win::tasks`)
//
// 2. The node supervisor itself (`crossfyre node up`) - a *system* service, because
//    tunnel bring-up (network namespaces, openvpn) needs root:
//      Linux   -> /etc/systemd/system/crossfyre-node.service with SUDO_USER baked in
//                 so user-scoped state keeps resolving to the operator's home
//      macOS   -> /Library/LaunchDaemons/io.crossfyre.node.plist, the same way
//      Windows -> the crossfyre-node service, as LocalSystem (see `win::scm`)
//
// On macOS and Windows an engine's job runs the CLI's hidden `extension host <engine>`
// rather than the engine itself, to give the engine what a systemd unit would: its
// toolchain directory and the egress-proxy environment file (see `host`).
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

// ── Public API ────────────────────────────────────────────────────────

/// Register the service for an extension (write unit/plist/task) under its name.
/// Called after install. The service exists but is left disabled until `enable`.
pub fn create_service_file(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    imp::create(ext)
}

/// Is a service registered for an extension?
pub fn has_service_file(ext: &str) -> bool {
    imp::exists(ext)
}

/// What [`refresh_service_file`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refreshed {
    /// It was what this build writes already.
    Current,
    /// It was missing, or another release wrote it, and it is this build's now.
    Written,
    /// As `Written`, and the engine, which was running, was restarted from it.
    Restarted,
}

/// Make engine `ext`'s service what this build writes. A unit is a file crossfyre
/// generates, so one that is missing or that another release wrote, such as one naming
/// a command line that release had, is written again, and an engine that was running
/// is restarted to run from it. `node init` and `extension install` do this for an
/// engine that is installed already, and the node service for every engine when it
/// starts, which is what carries an upgrade by a package manager or by the dashboard.
pub fn refresh_service_file(ext: &str) -> Result<Refreshed, Box<dyn std::error::Error>> {
    imp::refresh(ext)
}

/// Remove the service registration for an extension. Called during `remove`.
pub fn remove_service_file(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    imp::delete(ext)
}

/// Human-readable run state of an extension's daemon: running | stopped |
/// failed | disabled | unknown.
pub fn daemon_status(ext: &str) -> String {
    imp::status(ext)
}

/// Best-effort stop used before replacing a binary on reinstall. Never errors.
pub fn try_stop(ext: &str) {
    let _ = imp::action("stop", ext);
}

/// Stop and disable `ext`'s service, when it has one. Never errors.
pub fn try_stop_and_disable(ext: &str) {
    if imp::exists(ext) {
        let _ = imp::action("stop", ext);
        let _ = imp::action("disable", ext);
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

pub fn start(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("start")?;
        } else {
            imp::action("start", t)?;
        }
    }
    Ok(())
}

pub fn stop(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("stop")?;
        } else {
            imp::action("stop", t)?;
        }
    }
    Ok(())
}

pub fn restart(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("restart")?;
        } else {
            imp::action("restart", t)?;
        }
    }
    Ok(())
}

pub fn enable(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("enable")?;
        } else {
            imp::action("enable", t)?;
        }
    }
    Ok(())
}

pub fn disable(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    for t in resolve_targets(target)? {
        if t == NODE_TARGET {
            node::action("disable")?;
        } else {
            imp::action("disable", t)?;
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
        let installed = is_extension_installed(e.name);
        let has_service = imp::exists(e.name);

        let status_str = if !installed {
            "-".to_string()
        } else if !has_service {
            "no service".to_string()
        } else {
            imp::status(e.name)
        };

        let enabled_str = if !installed || !has_service {
            "-".to_string()
        } else if imp::is_enabled(e.name) {
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
/// nodes survive reboots and closed terminals. The unit runs the node worker in
/// the bin directory, and names `cli` (normally `/opt/crossfyre/bin/crossfyre`,
/// or wherever a package put it) to the node in `CROSSFYRE_CLI`.
pub fn install_node_service(
    cli: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    node::create(cli, data_dir)?;
    node::action("enable")?;
    // One that runs already may run an older node, as after the installer put a new one
    // in its place, and would run that one until it started again: it is restarted.
    let how = if node::status() == "running" {
        "restart"
    } else {
        "start"
    };
    node::action(how)?;
    Ok(())
}

/// The node worker the node unit runs: the one in the bin directory.
pub fn node_binary() -> std::path::PathBuf {
    super::config::get_bin_dir().join(super::config::file_name("node"))
}

/// The node unit for a CLI at `cli` whose node worker lives in `bin_dir`.
///
/// The worker is taken from `bin_dir` and never from beside the CLI. The installer puts
/// the two side by side, but a package puts the CLI in /usr/bin, and /usr/bin/node is
/// Node.js where it is installed and nothing at all where it is not, while the worker is
/// fetched into the bin directory.
pub fn node_unit(
    cli: &std::path::Path,
    bin_dir: &std::path::Path,
    data_dir: &std::path::Path,
    sudo_user: Option<&str>,
) -> Result<String, String> {
    let node_exe = bin_dir.join(super::config::file_name("node"));
    let node_exe = unit_line_value(&node_exe.display().to_string())?.to_string();
    let data_dir = unit_line_value(&data_dir.display().to_string())?.to_string();
    let cli_env = quoted_assignment(super::packaging::CLI_ENV, &cli.display().to_string())?;
    // Bake SUDO_USER into the unit so the daemon's user-scoped state (config root,
    // systemctl --user for extensions) keeps resolving to the operator's home
    // instead of /root.
    let sudo_env = match sudo_user {
        Some(name) => format!("Environment=SUDO_USER={}\n", unit_line_value(name)?),
        None => String::new(),
    };
    Ok(format!(
        "[Unit]\n\
         Description=Crossfyre node supervisor\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={node_exe} supervise --data-dir {data_dir}\n\
         Environment={cli_env}\n\
         {sudo_env}\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    ))
}

/// `value` as it may appear on one line of a unit file. A line break would end the
/// directive and start another one, so it is refused rather than written.
fn unit_line_value(value: &str) -> Result<&str, String> {
    if value.contains(['\n', '\r']) {
        return Err(format!("{value:?} cannot go in a unit file"));
    }
    Ok(value)
}

/// `name=value` in double quotes, as `Environment=` reads it: one assignment even when
/// the value has a space in it, with no `%` specifier expanded.
fn quoted_assignment(name: &str, value: &str) -> Result<String, String> {
    let value = unit_line_value(value)?
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    Ok(format!("\"{name}={value}\""))
}

/// One path on the way to a file a root service runs: its owner, group and mode.
#[cfg(any(unix, test))]
pub(crate) struct PathOwner {
    pub path: std::path::PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// Could anyone other than root replace the file whose path is described by `chain`, the
/// file first and then each directory above it? The file must belong to root and be
/// writable by nobody else, and so must every directory, except that a directory with its
/// sticky bit set (the Nix store) does not let anyone replace an entry they do not own.
/// Write access for the root group counts as root's.
#[cfg(any(unix, test))]
pub(crate) fn judge_root_run(chain: &[PathOwner]) -> Result<(), String> {
    for (i, p) in chain.iter().enumerate() {
        let others_write = p.mode & 0o002 != 0 || (p.mode & 0o020 != 0 && p.gid != 0);
        let sticky_dir = i > 0 && p.mode & 0o1000 != 0;
        let why = if p.uid != 0 {
            format!("{} belongs to uid {}", p.path.display(), p.uid)
        } else if others_write && !sticky_dir {
            format!("{} may be written by others", p.path.display())
        } else {
            continue;
        };
        return Err(format!(
            "{} could be replaced by a user other than root ({why}), and a service running \
             as root would run it",
            chain[0].path.display()
        ));
    }
    Ok(())
}

/// Refuse to point a root service at `path` when anyone but root could replace it. The
/// path is checked as given and where its symlinks lead, since either could be swapped.
#[cfg(unix)]
pub fn root_may_run(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    for start in [real.as_path(), path] {
        let mut chain = Vec::new();
        for p in start.ancestors() {
            if p.as_os_str().is_empty() {
                continue;
            }
            let m = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
            chain.push(PathOwner {
                path: p.to_path_buf(),
                uid: m.uid(),
                gid: m.gid(),
                mode: m.mode(),
            });
        }
        judge_root_run(&chain)?;
    }
    Ok(())
}

/// The owner of a file or directory on Windows and who its access list lets do what, as
/// SID strings and access masks. `allows` is `None` for an object with no access list
/// at all, which lets everyone do everything.
pub struct Secured {
    pub path: std::path::PathBuf,
    pub owner: String,
    pub allows: Option<Vec<(String, u32)>>,
}

/// The accounts that own and may write what a LocalSystem service runs: LocalSystem,
/// the Administrators group and TrustedInstaller, which owns what Windows installs.
const ADMIN_SIDS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Could anyone but an administrator replace the file whose path `chain` describes, the
/// file first and then each directory above it? The Windows counterpart of
/// [`judge_root_run`]. Everything on the way must be owned by an administrator. Nobody
/// else may write or replace the file. Nobody else may add a file to the directory it is
/// in, since a DLL dropped beside a program is loaded before the system's own, nor
/// remove or rename one. Higher up, adding is harmless and removing or renaming is not.
pub fn judge_admin_only(chain: &[Secured]) -> Result<(), String> {
    // Access mask bits, from winnt.h.
    const WRITE_DATA_OR_ADD_FILE: u32 = 0x0002;
    const APPEND_DATA_OR_ADD_SUBDIR: u32 = 0x0004;
    const DELETE_CHILD: u32 = 0x0040;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    let take_over = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    for (i, p) in chain.iter().enumerate() {
        let dangerous = match i {
            0 => take_over | GENERIC_WRITE | WRITE_DATA_OR_ADD_FILE | APPEND_DATA_OR_ADD_SUBDIR,
            1 => take_over | GENERIC_WRITE | WRITE_DATA_OR_ADD_FILE | DELETE_CHILD,
            _ => take_over | DELETE_CHILD,
        };
        let why = if !ADMIN_SIDS.contains(&p.owner.as_str()) {
            Some(format!("{} belongs to {}", p.path.display(), p.owner))
        } else {
            match &p.allows {
                None => Some(format!(
                    "{} has no access list, so anyone may write it",
                    p.path.display()
                )),
                Some(allows) => allows
                    .iter()
                    .find(|(sid, mask)| {
                        !ADMIN_SIDS.contains(&sid.as_str()) && mask & dangerous != 0
                    })
                    .map(|(sid, _)| format!("{} may be changed by {sid}", p.path.display())),
            }
        };
        if let Some(why) = why {
            return Err(format!(
                "{} could be replaced by an account other than an administrator ({why}), and \
                 a service running as LocalSystem would run it",
                chain[0].path.display()
            ));
        }
    }
    Ok(())
}

/// Refuse to point a LocalSystem service at `path` when anyone but an administrator could
/// replace it, or plant a DLL beside it.
#[cfg(windows)]
pub fn root_may_run(path: &std::path::Path) -> Result<(), String> {
    let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut chain = Vec::new();
    for p in real.ancestors() {
        if p.as_os_str().is_empty() {
            continue;
        }
        let mut s = super::win::security_of(p)?;
        // Shown as given rather than with the \\?\ prefix canonicalize adds.
        if p == real {
            s.path = path.to_path_buf();
        }
        chain.push(s);
    }
    judge_admin_only(&chain)
}

#[cfg(not(any(unix, windows)))]
pub fn root_may_run(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

/// `s` as plist text: the three characters XML reserves in text, replaced.
fn plist_string(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A launchd property list from its top-level entries, each a key and the XML of its
/// value.
fn plist(entries: &[(&str, String)]) -> String {
    let mut body = String::new();
    for (key, value) in entries {
        body.push_str(&format!("  <key>{key}</key>\n  {value}\n"));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n{body}</dict>\n</plist>\n"
    )
}

fn plist_array(items: &[String]) -> String {
    let inner: String = items
        .iter()
        .map(|i| format!("    <string>{}</string>\n", plist_string(i)))
        .collect();
    format!("<array>\n{inner}  </array>")
}

/// The entries every Crossfyre job shares: started when loaded, started again when it
/// exits with a failure and not when it exits cleanly (`Restart=on-failure`), 5 seconds
/// apart (`RestartSec=5`), and logging to `log`.
fn job_entries(label: &str, args: &[String], log: &std::path::Path) -> Vec<(&'static str, String)> {
    let log = format!(
        "<string>{}</string>",
        plist_string(&log.display().to_string())
    );
    vec![
        ("Label", format!("<string>{}</string>", plist_string(label))),
        ("ProgramArguments", plist_array(args)),
        ("RunAtLoad", "<true/>".to_string()),
        (
            "KeepAlive",
            "<dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>".to_string(),
        ),
        ("ThrottleInterval", "<integer>5</integer>".to_string()),
        ("StandardOutPath", log.clone()),
        ("StandardErrorPath", log),
    ]
}

/// The launchd daemon for the node supervisor on macOS, the counterpart of
/// [`node_unit`]: the node worker in the bin directory supervising the nodes under
/// `data_dir`, told which CLI set it up, and, under sudo, which user it acts for. It
/// logs to [`NODE_LOG`].
pub fn node_plist(
    node_exe: &std::path::Path,
    cli: &std::path::Path,
    data_dir: &std::path::Path,
    sudo_user: Option<&str>,
) -> String {
    let log = std::path::Path::new(NODE_LOG);
    let args = [
        node_exe.display().to_string(),
        "supervise".to_string(),
        "--data-dir".to_string(),
        data_dir.display().to_string(),
    ];
    let mut env = format!(
        "<dict>\n    <key>{}</key>\n    <string>{}</string>\n",
        super::packaging::CLI_ENV,
        plist_string(&cli.display().to_string())
    );
    if let Some(name) = sudo_user {
        env.push_str(&format!(
            "    <key>SUDO_USER</key>\n    <string>{}</string>\n",
            plist_string(name)
        ));
    }
    env.push_str("  </dict>");
    let mut entries = job_entries(NODE_LABEL, &args, log);
    entries.push(("EnvironmentVariables", env));
    plist(&entries)
}

/// The launchd label of the node supervisor on macOS.
pub const NODE_LABEL: &str = "io.crossfyre.node";

/// Where the root node service on macOS logs: a directory only root can change.
/// launchd opens this path itself, as root, following any link in it, so it cannot be
/// in the operator's data dir.
pub const NODE_LOG: &str = "/var/log/crossfyre/node.log";

/// The launchd agent for an engine on macOS: the CLI's `extension host <engine>`, which
/// starts the engine's daemon (see [`host`]).
pub fn agent_plist(
    label: &str,
    cli: &std::path::Path,
    engine: &str,
    log: &std::path::Path,
) -> String {
    let args = [
        cli.display().to_string(),
        "extension".to_string(),
        "host".to_string(),
        engine.to_string(),
    ];
    let mut entries = job_entries(label, &args, log);
    // An agent loads into the gui/<uid> domain when someone is logged in at the screen
    // and into user/<uid> otherwise, and launchd refuses it there (bootstrap fails with
    // "Input/output error") unless it may run in a background session too.
    entries.push((
        "LimitLoadToSessionType",
        plist_array(&["Aqua".to_string(), "Background".to_string()]),
    ));
    plist(&entries)
}

/// The `KEY=VALUE` assignments in an environment file as systemd's `EnvironmentFile=`
/// reads them, for the engine host where systemd does not read it: one per line, blank
/// lines and `#` or `;` comments skipped, and a value in matching double or single
/// quotes taken without them.
pub fn env_assignments(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let valid = key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            continue;
        }
        let value = value.trim();
        let value = ['"', '\'']
            .iter()
            .find_map(|q| value.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
            .unwrap_or(value);
        out.push((key.to_string(), value.to_string()));
    }
    out
}

/// The CLI an engine's service names on macOS and Windows to host the engine: the one in
/// the bin directory, else the path a package names its CLI by, else this CLI, else the
/// one that set up the node this process is.
#[cfg(not(target_os = "linux"))]
fn host_cli() -> std::path::PathBuf {
    let cli = super::config::file_name("crossfyre");
    let stable = super::config::get_bin_dir().join(&cli);
    if stable.is_file() {
        return stable;
    }
    let exe = std::env::current_exe().ok();
    if let Some(exe) = exe.as_deref()
        && exe.file_name().is_some_and(|n| n == cli.as_str())
    {
        return super::packaging::cli_path_for(exe);
    }
    super::packaging::named_cli()
        .map(std::path::Path::to_path_buf)
        .unwrap_or(stable)
}

/// Engine `ext`'s daemon as its service runs it: on its configured port, told where the
/// toolchain directory is, and with the egress-proxy variables of the file a systemd unit
/// reads. The engine host on macOS and Windows runs it, and so does the node supervisor
/// where no service manager runs the engines (see `node_engines`).
pub fn engine_command(ext: &str) -> Result<std::process::Command, String> {
    let e = super::engine(ext).ok_or_else(|| format!("{ext} is not an engine"))?;
    let mut cmd = std::process::Command::new(super::config::ext_bin_path(e.name));
    cmd.args(dguard::daemon_args(super::config::engine_port(e.name)));
    cmd.env(
        dguard::TOOLCHAIN_DIR_ENV,
        super::config::get_toolchain_dir(),
    );
    if let Ok(text) = super::sudo_user::read_to_string(&super::config::egress_env_path()) {
        for (key, value) in env_assignments(&text) {
            cmd.env(key, value);
        }
    }
    Ok(cmd)
}

/// Start engine `ext`'s daemon the way its service on macOS or Windows wants it (see
/// [`engine_command`]). Run by the CLI's hidden `extension host <engine>`, which the
/// launchd agent and the scheduled task name.
///
/// On macOS this becomes the engine (exec), so launchd supervises the daemon itself. On
/// Windows it stays to restart the engine when it fails (see `win::host`).
#[cfg(not(target_os = "linux"))]
pub fn host(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cmd = engine_command(ext)?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = cmd;
        let err = cmd.exec();
        Err(format!(
            "could not start {}: {err}",
            std::path::Path::new(cmd.get_program()).display()
        )
        .into())
    }
    #[cfg(windows)]
    {
        let name = super::engine(ext).map_or(ext, |e| e.name);
        let log = super::config::logs_dir().join(format!("{name}.log"));
        super::win::host(name, cmd, &log)
    }
}

pub fn remove_node_service() -> Result<(), Box<dyn std::error::Error>> {
    node::delete()
}

pub fn node_service_exists() -> bool {
    node::exists()
}

/// Is systemd the service manager here? The test systemd itself documents: it makes
/// /run/systemd/system as it starts. WSL without systemd and most containers have none.
#[cfg(target_os = "linux")]
pub fn systemd_runs() -> bool {
    std::path::Path::new("/run/systemd/system").is_dir()
}

/// What an action on an engine's service says where no service manager runs one.
pub const NODE_UP_RUNS_ENGINES: &str =
    "no service manager runs here, so `crossfyre node up` runs the engines";

/// Whether the user's service manager runs, to run the engines' units: it answers on a
/// bus in their runtime directory, which is what an engine's client looks for before it
/// starts a unit too. WSL without systemd and most containers run none, systemctl binary
/// or not, and there `crossfyre node up` runs the engines (see `node_engines`). macOS and
/// Windows always run theirs.
pub fn user_manager_runs() -> bool {
    #[cfg(target_os = "linux")]
    {
        super::linger::user_bus().is_some_and(|bus| bus.exists())
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// [`user_manager_runs`], once what starts the user's service manager has had its chance,
/// for a command about to give the installed engines their units. Where systemd is the
/// service manager and no engine has a unit yet, lingering is turned on for the user, so
/// theirs runs whether or not they are logged in and the engines do not stop at their
/// logout; and where theirs does not answer, it is waited for for a few seconds, as it
/// may still be starting, as at boot. Asked once in a process.
pub fn user_manager_started() -> bool {
    static STARTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *STARTED.get_or_init(|| {
        #[cfg(target_os = "linux")]
        if systemd_runs() && ENGINES.iter().any(|e| is_extension_installed(e.name)) {
            if !ENGINES.iter().any(|e| imp::exists(e.name)) {
                super::linger::keep_engines_running();
            } else if !user_manager_runs() {
                super::linger::wait_for_manager();
            }
        }
        user_manager_runs()
    })
}

/// Say, once in a process, that no service manager runs here, so `crossfyre node up` runs
/// the engines: what an engine's install says where it makes no unit. Not in a command
/// that renders its own summary (see [`set_quiet`]).
pub fn say_node_up_runs_engines() {
    static SAID: std::sync::Once = std::sync::Once::new();
    if !quiet() {
        SAID.call_once(|| {
            super::ui::step(
                "No service manager runs here, so `crossfyre node up` runs the engines",
            );
        });
    }
}

/// Is the node service running, once its service manager is done starting it? A
/// service can show as starting for a moment after it was told to start, and longer
/// while it fails and is restarted, so that is waited out for up to ten seconds.
pub fn node_service_running() -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = node::status();
        let starting = matches!(status.as_str(), "starting" | "activating");
        if !starting || std::time::Instant::now() >= deadline {
            return status == "running";
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[cfg(target_os = "linux")]
mod node {
    use std::fs;

    const UNIT: &str = "crossfyre-node.service";
    const UNIT_PATH: &str = "/etc/systemd/system/crossfyre-node.service";

    fn require_root() -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("managing the node service needs root".into());
        }
        Ok(())
    }

    pub fn create(
        cli: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        require_root()?;
        // A unit left where nothing runs it would stand in for a service: `node up` would
        // ask systemctl to start it rather than run the node itself.
        if !super::systemd_runs() {
            return Err("systemd is not running here, so the node cannot run as a service".into());
        }
        let sudo_user = super::super::sudo_user::sudo_user_info().map(|(_, _, _, name)| name);
        // The supervisor is the separate `node` worker binary in the bin directory,
        // and it runs as root, so it has to be a file only root can replace.
        super::root_may_run(&super::node_binary())?;
        let bin_dir = super::super::config::get_bin_dir();
        let body = super::node_unit(cli, &bin_dir, data_dir, sudo_user.as_deref())?;
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

// ── launchd (macOS) ───────────────────────────────────────────────────
//
// Jobs are addressed by domain and label, through the subcommands launchd has had
// since macOS 10.10: `bootstrap` loads a job from its plist, `bootout` unloads it (which
// stops it, and KeepAlive does not bring it back), `kickstart` starts a loaded one, and
// `enable` / `disable` keep a persistent setting that decides whether it may be loaded,
// which is what `systemctl enable` decides. The node daemon is in the `system` domain.
// An engine agent is in its user's `gui/<uid>` domain, or `user/<uid>` when that user
// has no graphical session, as on a Mac used over ssh.
#[cfg(target_os = "macos")]
mod launchd {
    use std::process::Command;

    fn launchctl(args: &[&str]) -> std::io::Result<std::process::Output> {
        Command::new("/bin/launchctl").args(args).output()
    }

    fn run(args: &[&str]) -> Result<(), String> {
        let out = launchctl(args).map_err(|e| format!("launchctl failed: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(format!("launchctl {} failed: {said}", args.join(" ")))
    }

    fn target(domain: &str, label: &str) -> String {
        format!("{domain}/{label}")
    }

    /// Is the job loaded in `domain`?
    pub fn loaded(domain: &str, label: &str) -> bool {
        launchctl(&["print", &target(domain, label)]).is_ok_and(|o| o.status.success())
    }

    /// The domain a user's agents belong in.
    pub fn user_domain(uid: u32) -> String {
        let gui = format!("gui/{uid}");
        if launchctl(&["print", &gui]).is_ok_and(|o| o.status.success()) {
            gui
        } else {
            format!("user/{uid}")
        }
    }

    /// start | stop | restart | enable | disable, as `systemctl` takes them.
    pub fn act(domain: &str, label: &str, plist: &str, action: &str) -> Result<(), String> {
        let t = target(domain, label);
        match action {
            "start" if loaded(domain, label) => run(&["kickstart", &t]),
            "start" => run(&["bootstrap", domain, plist]),
            "stop" => bootout(domain, label),
            // Booted out and in again, so a plist rewritten since it was loaded (a new
            // port, say) is the one that runs, as a restart after daemon-reload does.
            "restart" => {
                bootout(domain, label)?;
                run(&["bootstrap", domain, plist])
            }
            "enable" => run(&["enable", &t]),
            "disable" => run(&["disable", &t]),
            other => Err(format!("Unsupported action: {other}")),
        }
    }

    /// running | starting | stopped | failed (see [`super::launchd_state`]).
    pub fn status(domain: &str, label: &str) -> String {
        let Ok(out) = launchctl(&["print", &target(domain, label)]) else {
            return "unknown".to_string();
        };
        if !out.status.success() {
            return "stopped".to_string();
        }
        super::launchd_state(&String::from_utf8_lossy(&out.stdout)).to_string()
    }

    /// Has `disable` been set for the job? `print-disabled` lists a job switched off as
    /// `"label" => disabled`, or `=> true` on releases before macOS 13.
    pub fn disabled(domain: &str, label: &str) -> bool {
        let quoted = format!("\"{label}\"");
        launchctl(&["print-disabled", domain]).is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout).lines().any(|l| {
                l.contains(&quoted) && (l.contains("=> disabled") || l.contains("=> true"))
            })
        })
    }

    /// Unload the job if it is loaded, and wait until it is gone. `bootout` returns once
    /// launchd has sent the job SIGTERM, and the job stays loaded, as `SIGTERMed`, until
    /// its process exits: about two seconds for the node. Until then launchd refuses to
    /// load it again, and `kickstart` starts nothing. launchd kills the process
    /// ExitTimeOut seconds after the SIGTERM, 20 unless the plist sets it, so that is
    /// waited out with a few seconds to spare.
    pub fn bootout(domain: &str, label: &str) -> Result<(), String> {
        if !loaded(domain, label) {
            return Ok(());
        }
        run(&["bootout", &target(domain, label)])?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
        while loaded(domain, label) {
            if std::time::Instant::now() >= deadline {
                return Err(format!("{label} was stopped and has not exited"));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(())
    }

    pub fn disable(domain: &str, label: &str) {
        let _ = launchctl(&["disable", &target(domain, label)]);
    }
}

/// A launchd job's state from what `launchctl print` says of it: running; starting while
/// launchd is still bringing its process up (`xpcproxy`, `spawn scheduled`), as just after
/// it is loaded; failed when its last exit was a failure; and otherwise stopped.
#[cfg(any(target_os = "macos", test))]
fn launchd_state(print: &str) -> &'static str {
    let state = print
        .lines()
        .find_map(|l| l.trim().strip_prefix("state = "))
        .unwrap_or("");
    match state {
        "running" => return "running",
        "xpcproxy" | "spawn scheduled" => return "starting",
        _ => {}
    }
    // `last exit code = 1: Operation not permitted`, or `(never exited)`.
    let failed = print
        .lines()
        .filter_map(|l| l.trim().strip_prefix("last exit code = "))
        .any(|code| {
            code.chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit() && c != '0')
        });
    if failed { "failed" } else { "stopped" }
}

// ── macOS: the node supervisor as a launchd daemon ───────────────────
#[cfg(target_os = "macos")]
mod node {
    use super::launchd;
    use std::fs;

    const PLIST: &str = "/Library/LaunchDaemons/io.crossfyre.node.plist";
    const DOMAIN: &str = "system";

    fn require_root() -> Result<(), Box<dyn std::error::Error>> {
        if !crate::os::is_elevated() {
            return Err("managing the node service needs root".into());
        }
        Ok(())
    }

    pub fn create(
        cli: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        require_root()?;
        let sudo_user = super::super::sudo_user::sudo_user_info().map(|(_, _, _, name)| name);
        // The daemon runs the node worker as root, so it has to be a file only root can
        // replace.
        super::root_may_run(&super::node_binary())?;
        // Made here, root's, before launchd opens it.
        drop(open_root_log()?);
        let body = super::node_plist(&super::node_binary(), cli, data_dir, sudo_user.as_deref());
        let fresh = !exists();
        fs::write(PLIST, body)?;
        // launchd refuses a daemon whose plist anyone but root could write.
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(PLIST, fs::Permissions::from_mode(0o644))?;
        }
        // Off until `enable`, as a new unit is. A plist in LaunchDaemons is otherwise
        // loaded at the next boot.
        if fresh {
            launchd::disable(DOMAIN, super::NODE_LABEL);
        }
        if !super::quiet() {
            super::svc_ok(&format!("{} created", super::NODE_LABEL));
        }
        Ok(())
    }

    pub fn delete() -> Result<(), Box<dyn std::error::Error>> {
        if exists() {
            require_root()?;
            launchd::bootout(DOMAIN, super::NODE_LABEL)?;
            fs::remove_file(PLIST)?;
            super::svc_ok(&format!("{} removed", super::NODE_LABEL));
        }
        Ok(())
    }

    pub fn action(action: &str) -> Result<(), Box<dyn std::error::Error>> {
        require_root()?;
        launchd::act(DOMAIN, super::NODE_LABEL, PLIST, action)?;
        if !super::quiet() {
            super::svc_ok(&format!(
                "{} {}",
                super::NODE_LABEL,
                super::action_past(action)
            ));
        }
        Ok(())
    }

    pub fn status() -> String {
        launchd::status(DOMAIN, super::NODE_LABEL)
    }

    pub fn is_enabled() -> bool {
        exists() && !launchd::disabled(DOMAIN, super::NODE_LABEL)
    }

    pub fn exists() -> bool {
        std::path::Path::new(PLIST).exists()
    }

    /// [`super::NODE_LOG`], open for appending: root's, readable by the admin group,
    /// which is who may run `sudo` on a Mac.
    fn open_root_log() -> std::io::Result<fs::File> {
        let admin = unsafe { libc::getgrnam(c"admin".as_ptr()) };
        let group = (!admin.is_null()).then(|| unsafe { (*admin).gr_gid });
        super::super::root_fs::open_log(std::path::Path::new(super::NODE_LOG), group)
    }
}

// ── Windows: the node supervisor as a service ─────────────────────────
#[cfg(windows)]
mod node {
    use super::super::win::scm;

    fn require_elevated() -> Result<(), Box<dyn std::error::Error>> {
        if !crate::os::is_elevated() {
            return Err(
                "managing the node service needs an elevated prompt. Re-run it as administrator."
                    .into(),
            );
        }
        Ok(())
    }

    pub fn create(
        cli: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        require_elevated()?;
        // The service runs the node worker as LocalSystem, so it has to be a file only
        // an administrator can replace.
        super::root_may_run(&super::node_binary())?;
        scm::create_node(&super::node_binary(), cli, data_dir)?;
        if !super::quiet() {
            super::svc_ok(&format!("{} created", scm::NODE_SERVICE));
        }
        Ok(())
    }

    pub fn delete() -> Result<(), Box<dyn std::error::Error>> {
        if exists() {
            require_elevated()?;
            scm::delete_node()?;
            super::svc_ok(&format!("{} removed", scm::NODE_SERVICE));
        }
        Ok(())
    }

    pub fn action(action: &str) -> Result<(), Box<dyn std::error::Error>> {
        require_elevated()?;
        scm::node_action(action)?;
        if !super::quiet() {
            super::svc_ok(&format!(
                "{} {}",
                scm::NODE_SERVICE,
                super::action_past(action)
            ));
        }
        Ok(())
    }

    pub fn status() -> String {
        scm::node_status()
    }

    pub fn is_enabled() -> bool {
        scm::node_enabled()
    }

    pub fn exists() -> bool {
        scm::node_exists()
    }
}

// ── Linux: systemd user units (extensions) ────────────────────────────
#[cfg(target_os = "linux")]
mod imp {
    use super::super::config::ext_bin_path;
    use super::super::sudo_user::{
        cmd_as_invoking_user, create_dir_all_for_invoking_user, invoking_user_home,
        write_for_invoking_user,
    };

    fn unit_dir() -> std::path::PathBuf {
        // Honor SUDO_USER so units land in the real user's
        // ~/.config/systemd/user, not /root's where they'd be invisible.
        invoking_user_home().join(".config/systemd/user")
    }

    fn unit_body(ext: &str) -> String {
        let bin = ext_bin_path(ext);
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
             Description=Crossfyre {ext} extension daemon\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             EnvironmentFile=-{egress_env}\n\
             ExecStart={bin} {daemon}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            ext = ext,
            bin = bin.display(),
            egress_env = egress_env.display(),
            daemon = dguard::daemon_args(port).join(" "),
        )
    }

    /// Write engine `ext`'s unit. The user's service manager that runs it was started first
    /// where it has to be (see `user_manager_started`), lingering included, so the engines
    /// run whether or not the user is logged in.
    pub fn create(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let dir = unit_dir();
        let svc = dguard::unit_name(ext);
        create_dir_all_for_invoking_user(&dir)?;
        // Written into the user's home as root, and handed back to them. Only this one
        // file: the rest of this directory holds the person's own units, and the ones
        // they enabled are links to files their packages own.
        write_for_invoking_user(&dir.join(&svc), unit_body(ext).as_bytes(), 0o644)?;
        let _ = cmd_as_invoking_user("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        if !super::quiet() {
            super::svc_ok(&format!("{svc} created"));
        }
        Ok(())
    }

    pub fn delete(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        if remove_unit(&unit_dir(), ext)? {
            if super::user_manager_runs() {
                let _ = cmd_as_invoking_user("systemctl")
                    .args(["--user", "daemon-reload"])
                    .status();
            }
            super::svc_ok(&format!("{} removed", dguard::unit_name(ext)));
        }
        Ok(())
    }

    /// Removes `ext`'s unit from `dir` when it is there, and says whether it was. `dir` is
    /// in the operator's home, so as root no link on the way there is followed.
    fn remove_unit(dir: &std::path::Path, ext: &str) -> std::io::Result<bool> {
        let path = dir.join(dguard::unit_name(ext));
        if !path.exists() {
            return Ok(false);
        }
        super::super::sudo_user::remove_file(&path)?;
        Ok(true)
    }

    pub fn action(action: &str, ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !super::user_manager_runs() {
            return Err(super::NODE_UP_RUNS_ENGINES.into());
        }
        let svc = dguard::unit_name(ext);
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

    /// Where no service manager runs, `crossfyre node up` runs the engine, and it is running
    /// when it answers on its port.
    pub fn status(ext: &str) -> String {
        if !super::user_manager_runs() {
            let port = super::super::config::engine_port(ext);
            let answers = super::super::status::port_open(port);
            return if answers { "running" } else { "stopped" }.to_string();
        }
        let svc = dguard::unit_name(ext);
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
        let svc = dguard::unit_name(ext);
        cmd_as_invoking_user("systemctl")
            .args(["--user", "is-enabled", &svc])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
            .unwrap_or(false)
    }

    pub fn exists(ext: &str) -> bool {
        unit_dir().join(dguard::unit_name(ext)).exists()
    }

    pub fn refresh(ext: &str) -> Result<super::Refreshed, Box<dyn std::error::Error>> {
        use super::Refreshed;
        let path = unit_dir().join(dguard::unit_name(ext));
        if !path.exists() {
            create(ext)?;
            return Ok(Refreshed::Written);
        }
        // Asked before the unit changes: a unit another release wrote may be failing over
        // and over, which systemd shows as activating.
        let was = status(ext);
        if !write_if_differs(&path, &unit_body(ext))? {
            return Ok(Refreshed::Current);
        }
        let _ = cmd_as_invoking_user("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        if !super::quiet() {
            super::svc_ok(&format!("{} rewritten", dguard::unit_name(ext)));
        }
        if matches!(was.as_str(), "running" | "activating") {
            action("restart", ext)?;
            return Ok(Refreshed::Restarted);
        }
        Ok(Refreshed::Written)
    }

    /// Write `body` to the unit file at `path` unless it holds `body` already, and say
    /// whether it was written.
    fn write_if_differs(path: &std::path::Path, body: &str) -> std::io::Result<bool> {
        if super::super::sudo_user::read_to_string(path).is_ok_and(|now| now == body) {
            return Ok(false);
        }
        write_for_invoking_user(path, body.as_bytes(), 0o644)?;
        Ok(true)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::toolchain::sudo_user::act_as_root;
        use std::fs;

        #[test]
        fn a_unit_another_release_wrote_is_written_again_and_one_this_build_wrote_is_not() {
            let _dir = super::super::super::config::TestToolchainDir::new();
            let t = tempfile::tempdir().expect("tempdir");
            let path = t.path().join(dguard::unit_name("voyage"));
            let body = unit_body("voyage");
            fs::write(
                &path,
                "[Service]\nExecStart=/opt/crossfyre/bin/voyage --daemon --port 4442\n",
            )
            .expect("an older unit");
            assert!(write_if_differs(&path, &body).expect("written"));
            assert_eq!(fs::read_to_string(&path).expect("read"), body);
            assert!(
                !write_if_differs(&path, &body).expect("left"),
                "written again"
            );
        }

        /// `sudo crossfyre uninstall` removes the units it made in the operator's
        /// ~/.config/systemd/user, a directory the operator can swap for a link.
        #[test]
        fn removing_a_unit_as_root_will_not_pass_through_a_linked_directory() {
            let t = tempfile::tempdir().expect("tempdir");
            let victim = t.path().join("victim");
            fs::create_dir(&victim).expect("victim");
            let unit = dguard::unit_name("x");
            fs::write(victim.join(&unit), "root's file\n").expect("victim file");
            let systemd = t.path().join("home/.config/systemd");
            fs::create_dir_all(&systemd).expect("systemd");
            std::os::unix::fs::symlink(&victim, systemd.join("user")).expect("link");

            let _root = act_as_root();
            let r = remove_unit(&systemd.join("user"), "x");

            assert!(r.is_err(), "removed through a link");
            assert!(victim.join(&unit).exists());
        }

        #[test]
        fn an_engine_s_unit_runs_it_as_its_daemon_on_its_port() {
            let _dir = super::super::super::config::TestToolchainDir::new();
            let port = super::super::super::config::engine_port("voyage");
            assert_eq!(port, 24442, "the test's own config gives it");
            let exec = format!(
                "ExecStart={} {}",
                ext_bin_path("voyage").display(),
                dguard::daemon_args(port).join(" ")
            );
            let unit = unit_body("voyage");
            assert!(unit.lines().any(|l| l == exec), "{unit}");
        }

        #[test]
        fn removing_a_unit_as_root_removes_it() {
            let t = tempfile::tempdir().expect("tempdir");
            fs::write(t.path().join(dguard::unit_name("x")), "x").expect("unit");
            let _root = act_as_root();
            assert!(remove_unit(t.path(), "x").expect("remove"));
            assert!(!remove_unit(t.path(), "x").expect("again"));
        }
    }
}

// ── macOS: launchd user agents (extensions) ───────────────────────────
#[cfg(target_os = "macos")]
mod imp {
    use super::super::sudo_user::{
        create_dir_all_for_invoking_user, invoking_user_home, sudo_user_info,
        write_for_invoking_user,
    };
    use super::launchd;
    use std::path::PathBuf;

    fn label(key: &str) -> String {
        format!("io.crossfyre.{key}")
    }

    fn agents_dir() -> PathBuf {
        // Honor SUDO_USER so the agent lands in the real user's LaunchAgents.
        invoking_user_home().join("Library").join("LaunchAgents")
    }

    fn plist_path(key: &str) -> PathBuf {
        agents_dir().join(format!("{}.plist", label(key)))
    }

    /// The user whose agents these are: the invoking one under sudo.
    fn domain() -> String {
        let uid = sudo_user_info()
            .map(|(uid, _, _, _)| uid)
            .unwrap_or_else(|| unsafe { libc::getuid() });
        launchd::user_domain(uid)
    }

    pub fn create(key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let dir = agents_dir();
        create_dir_all_for_invoking_user(&dir)?;
        let logs = super::super::config::logs_dir();
        create_dir_all_for_invoking_user(&logs)?;
        let fresh = !exists(key);
        let body = super::agent_plist(
            &label(key),
            &super::host_cli(),
            key,
            &logs.join(format!("{key}.log")),
        );
        // Written into the user's home as root, and handed back to them.
        write_for_invoking_user(&plist_path(key), body.as_bytes(), 0o644)?;
        // Off until `enable`, as a new unit is. A plist in LaunchAgents is otherwise
        // loaded at the user's next login.
        if fresh {
            launchd::disable(&domain(), &label(key));
        }
        if !super::quiet() {
            super::svc_ok(&format!("{} created", label(key)));
        }
        Ok(())
    }

    pub fn delete(key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = plist_path(key);
        if path.exists() {
            launchd::bootout(&domain(), &label(key))?;
            // In the operator's home: as root, no link on the way there is followed.
            super::super::sudo_user::remove_file(&path)?;
            super::svc_ok(&format!("{} removed", label(key)));
        }
        Ok(())
    }

    pub fn action(action: &str, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let plist = plist_path(key).to_string_lossy().into_owned();
        launchd::act(&domain(), &label(key), &plist, action)?;
        if !super::quiet() {
            super::svc_ok(&format!("{} {}", label(key), super::action_past(action)));
        }
        Ok(())
    }

    pub fn status(key: &str) -> String {
        launchd::status(&domain(), &label(key))
    }

    pub fn is_enabled(key: &str) -> bool {
        exists(key) && !launchd::disabled(&domain(), &label(key))
    }

    pub fn exists(key: &str) -> bool {
        plist_path(key).exists()
    }

    /// The agent names `crossfyre extension host <engine>`, which builds the engine's
    /// command line each time it starts it, so no release's command line is kept in it.
    pub fn refresh(key: &str) -> Result<super::Refreshed, Box<dyn std::error::Error>> {
        if !exists(key) {
            create(key)?;
            return Ok(super::Refreshed::Written);
        }
        Ok(super::Refreshed::Current)
    }
}

// ── Windows: scheduled tasks (extensions) ─────────────────────────────
#[cfg(windows)]
mod imp {
    use super::super::win::tasks;

    /// Registered from an elevated prompt (or by the node service) the task runs at boot;
    /// from an ordinary one it runs at the operator's logon, and `tasks::create` says so.
    pub fn create(key: &str) -> Result<(), Box<dyn std::error::Error>> {
        tasks::create(
            key,
            &format!("Crossfyre {key} extension daemon"),
            &super::host_cli(),
            &format!("extension host {key}"),
        )?;
        if !super::quiet() {
            super::svc_ok(&format!("{} created", tasks::task_name(key)));
        }
        Ok(())
    }

    pub fn delete(key: &str) -> Result<(), Box<dyn std::error::Error>> {
        if exists(key) {
            tasks::delete(key)?;
            super::svc_ok(&format!("{} removed", tasks::task_name(key)));
        }
        Ok(())
    }

    pub fn action(action: &str, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        tasks::action(action, key)?;
        if !super::quiet() {
            super::svc_ok(&format!(
                "{} {}",
                tasks::task_name(key),
                super::action_past(action)
            ));
        }
        Ok(())
    }

    pub fn status(key: &str) -> String {
        tasks::status(key)
    }

    pub fn is_enabled(key: &str) -> bool {
        tasks::is_enabled(key)
    }

    pub fn exists(key: &str) -> bool {
        tasks::exists(key)
    }

    /// The task names `crossfyre extension host <engine>`, which builds the engine's
    /// command line each time it starts it, so no release's command line is kept in it.
    pub fn refresh(key: &str) -> Result<super::Refreshed, Box<dyn std::error::Error>> {
        if !exists(key) {
            create(key)?;
            return Ok(super::Refreshed::Written);
        }
        Ok(super::Refreshed::Current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    fn exec_start(unit: &str) -> &str {
        unit.lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("an ExecStart line")
    }

    // Unix only: packaged installs and their systemd units are a Linux and macOS layout.
    #[cfg(unix)]
    #[test]
    fn a_packaged_cli_in_usr_bin_has_the_unit_run_the_node_in_the_bin_dir() {
        // apt and pacman put the CLI in /usr/bin and leave the CLI to fetch the node
        // worker into /opt/crossfyre/bin. Taking the worker from beside the CLI made the
        // unit run /usr/bin/node, which is Node.js.
        let unit = node_unit(
            Path::new("/usr/bin/crossfyre"),
            Path::new("/opt/crossfyre/bin"),
            Path::new("/home/op/.config/crossfyre"),
            Some("op"),
        )
        .expect("unit");
        assert_eq!(
            exec_start(&unit),
            "ExecStart=/opt/crossfyre/bin/node supervise --data-dir /home/op/.config/crossfyre"
        );
        assert!(
            unit.contains("\nEnvironment=\"CROSSFYRE_CLI=/usr/bin/crossfyre\"\n"),
            "the node is told which CLI set it up: {unit}"
        );
        assert!(unit.contains("\nEnvironment=SUDO_USER=op\n"), "{unit}");
    }

    // Unix only: packaged installs and their systemd units are a Linux and macOS layout.
    #[cfg(unix)]
    #[test]
    fn the_installer_layout_runs_the_node_beside_the_cli() {
        let unit = node_unit(
            Path::new("/opt/crossfyre/bin/crossfyre"),
            Path::new("/opt/crossfyre/bin"),
            Path::new("/root/.config/crossfyre"),
            None,
        )
        .expect("unit");
        assert_eq!(
            exec_start(&unit),
            "ExecStart=/opt/crossfyre/bin/node supervise --data-dir /root/.config/crossfyre"
        );
        assert!(!unit.contains("SUDO_USER"), "{unit}");
    }

    #[test]
    fn a_line_break_in_a_path_is_refused_rather_than_written() {
        // It would end the directive and start one of the caller's choosing in a unit
        // that runs as root.
        for (cli, data) in [
            ("/usr/bin/crossfyre", "/home/op\nExecStartPre=/bin/sh -c id"),
            ("/usr/bin/crossfyre\nUser=nobody", "/home/op"),
        ] {
            assert!(
                node_unit(
                    Path::new(cli),
                    Path::new("/opt/crossfyre/bin"),
                    Path::new(data),
                    None
                )
                .is_err(),
                "{cli:?} {data:?}"
            );
        }
    }

    #[test]
    fn the_cli_stays_one_assignment_whatever_its_path_holds() {
        let unit = node_unit(
            Path::new("/opt/my tools/cross%fyre\"x"),
            Path::new("/opt/crossfyre/bin"),
            Path::new("/d"),
            None,
        )
        .expect("unit");
        assert!(
            unit.contains("\nEnvironment=\"CROSSFYRE_CLI=/opt/my tools/cross%%fyre\\\"x\"\n"),
            "{unit}"
        );
    }

    #[test]
    fn the_macos_node_daemon_runs_the_worker_and_restarts_only_on_failure() {
        let plist = node_plist(
            Path::new("/opt/crossfyre/bin/node"),
            Path::new("/opt/crossfyre/bin/crossfyre"),
            Path::new("/Users/op/Library/Application Support/crossfyre"),
            Some("op"),
        );
        assert!(
            plist.contains("<string>io.crossfyre.node</string>"),
            "{plist}"
        );
        assert!(
            plist.contains(
                "    <string>/opt/crossfyre/bin/node</string>\n    <string>supervise</string>\n    \
                 <string>--data-dir</string>\n    \
                 <string>/Users/op/Library/Application Support/crossfyre</string>\n"
            ),
            "one argument per string, the space kept: {plist}"
        );
        assert!(
            plist.contains("<key>SuccessfulExit</key>\n    <false/>"),
            "Restart=on-failure, not always: {plist}"
        );
        assert!(plist.contains("<key>ThrottleInterval</key>\n  <integer>5</integer>"));
        assert!(plist.contains(
            "<key>CROSSFYRE_CLI</key>\n    <string>/opt/crossfyre/bin/crossfyre</string>"
        ));
        assert!(plist.contains("<key>SUDO_USER</key>\n    <string>op</string>"));
        let without = node_plist(Path::new("/n"), Path::new("/c"), Path::new("/d"), None);
        assert!(!without.contains("SUDO_USER"), "{without}");
    }

    /// launchd opens the log itself, as root, and follows a link it finds there. In the
    /// operator's data dir, a link left at that name sends root's output into any file.
    #[test]
    fn the_macos_node_daemon_logs_where_only_root_can_write() {
        let data = "/Users/op/Library/Application Support/crossfyre";
        let plist = node_plist(
            Path::new("/n"),
            Path::new("/c"),
            Path::new(data),
            Some("op"),
        );
        let log = format!("<string>{NODE_LOG}</string>");
        assert!(
            plist.contains(&format!("<key>StandardOutPath</key>\n  {log}")),
            "{plist}"
        );
        assert!(
            plist.contains(&format!("<key>StandardErrorPath</key>\n  {log}")),
            "{plist}"
        );
        assert!(!plist.contains(&format!("{data}/logs")), "{plist}");
    }

    #[test]
    fn a_plist_value_cannot_open_an_element_of_its_own() {
        let plist = agent_plist(
            "io.crossfyre.ambulo",
            Path::new("/opt/a&b/<crossfyre>"),
            "ambulo",
            Path::new("/l"),
        );
        assert!(
            plist.contains("<string>/opt/a&amp;b/&lt;crossfyre&gt;</string>"),
            "{plist}"
        );
        assert!(plist.contains(
            "<string>extension</string>\n    <string>host</string>\n    <string>ambulo</string>"
        ));
    }

    #[test]
    fn an_engine_agent_loads_without_a_desktop_login() {
        // With nobody logged in at the screen (a Mac reached over SSH, or one that
        // has just booted), only the user's background domain exists, and launchd
        // loads an agent there only if the agent says it may run in that session.
        let plist = agent_plist(
            "io.crossfyre.voyage",
            Path::new("/c"),
            "voyage",
            Path::new("/l"),
        );
        assert!(
            plist.contains(
                "<key>LimitLoadToSessionType</key>\n  <array>\n    <string>Aqua</string>\n    \
                 <string>Background</string>\n  </array>"
            ),
            "{plist}"
        );
    }

    /// What `launchctl print` says of a job, as the node's status. Just loaded, a job is
    /// in launchd's hands until its process runs, and node init, which asks at once, read
    /// that as stopped and said the node it had just started was not running.
    #[test]
    fn a_job_launchd_is_still_starting_is_starting() {
        let print = |state: &str, exit: &str| {
            format!(
                "system/io.crossfyre.node = {{\n\tactive count = 1\n\tstate = {state}\n\t\
                 program = /opt/crossfyre/bin/node\n\tlast exit code = {exit}\n}}\n"
            )
        };
        assert_eq!(
            launchd_state(&print("running", "(never exited)")),
            "running"
        );
        assert_eq!(
            launchd_state(&print("xpcproxy", "(never exited)")),
            "starting"
        );
        assert_eq!(
            launchd_state(&print("spawn scheduled", "(never exited)")),
            "starting"
        );
        assert_eq!(
            launchd_state(&print("not running", "(never exited)")),
            "stopped"
        );
        assert_eq!(
            launchd_state(&print("not running", "1: Operation not permitted")),
            "failed"
        );
        assert_eq!(launchd_state(&print("not running", "0")), "stopped");
    }

    #[test]
    fn the_environment_file_is_read_as_systemd_reads_it() {
        let text = "# written by the node\n\nCROSSFYRE_EGRESS_PROXY=socks5://u:p@h:1080/?a=1&b=2\n\
                    ; a comment\nQUOTED=\"x y\"\nSINGLE='z'\n not a line\n1BAD=x\nBAD KEY=x\n";
        assert_eq!(
            env_assignments(text),
            vec![
                (
                    "CROSSFYRE_EGRESS_PROXY".to_string(),
                    "socks5://u:p@h:1080/?a=1&b=2".to_string()
                ),
                ("QUOTED".to_string(), "x y".to_string()),
                ("SINGLE".to_string(), "z".to_string()),
            ]
        );
    }

    fn secured(path: &str, owner: &str, allows: &[(&str, u32)]) -> Secured {
        Secured {
            path: PathBuf::from(path),
            owner: owner.to_string(),
            allows: Some(allows.iter().map(|(s, m)| (s.to_string(), *m)).collect()),
        }
    }

    #[test]
    fn a_localsystem_service_runs_only_what_administrators_alone_can_replace() {
        const SYSTEM: &str = "S-1-5-18";
        const ADMINS: &str = "S-1-5-32-544";
        const TRUSTED_INSTALLER: &str =
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        const USERS: &str = "S-1-5-32-545";
        const AUTHENTICATED: &str = "S-1-5-11";
        const READ_EXECUTE: u32 = 0x0012_00A9;
        const FULL: u32 = 0x001F_01FF;
        const ADD_SUBDIR: u32 = 0x0004;
        const ADD_FILE: u32 = 0x0002;
        // What a default install of Windows gives Program Files and C:\.
        let chain = |file: Secured, bin: Secured| {
            vec![
                file,
                bin,
                secured(
                    r"C:\Program Files\Crossfyre",
                    ADMINS,
                    &[(SYSTEM, FULL), (ADMINS, FULL), (USERS, READ_EXECUTE)],
                ),
                secured(
                    r"C:\Program Files",
                    TRUSTED_INSTALLER,
                    &[
                        (TRUSTED_INSTALLER, FULL),
                        (SYSTEM, FULL),
                        (USERS, READ_EXECUTE),
                    ],
                ),
                secured(
                    r"C:\",
                    TRUSTED_INSTALLER,
                    &[
                        (ADMINS, FULL),
                        (AUTHENTICATED, ADD_SUBDIR),
                        (USERS, READ_EXECUTE),
                    ],
                ),
            ]
        };
        let file = |allows: &[(&str, u32)]| {
            secured(r"C:\Program Files\Crossfyre\bin\node.exe", ADMINS, allows)
        };
        let bin =
            |allows: &[(&str, u32)]| secured(r"C:\Program Files\Crossfyre\bin", ADMINS, allows);
        let safe = &[(SYSTEM, FULL), (ADMINS, FULL), (USERS, READ_EXECUTE)];
        assert!(judge_admin_only(&chain(file(safe), bin(safe))).is_ok());

        // A worker a user may write could be swapped for anything.
        let err = judge_admin_only(&chain(file(&[(USERS, FULL)]), bin(safe)))
            .expect_err("a file users may write");
        assert!(err.contains("node.exe") && err.contains(USERS), "{err}");
        // A bin directory a user may add to takes a DLL the worker loads first.
        assert!(judge_admin_only(&chain(file(safe), bin(&[(USERS, ADD_FILE)]))).is_err());
        // A file another account owns, or one with no access list at all.
        let mut theirs = file(safe);
        theirs.owner = "S-1-5-21-1-2-3-1001".to_string();
        assert!(judge_admin_only(&chain(theirs, bin(safe))).is_err());
        let mut open = file(safe);
        open.allows = None;
        assert!(judge_admin_only(&chain(open, bin(safe))).is_err());
        // Higher up, creating a folder is harmless, and renaming one is not.
        let mut renamable = chain(file(safe), bin(safe));
        renamable[3] = secured(r"C:\Program Files", TRUSTED_INSTALLER, &[(USERS, 0x0040)]);
        assert!(judge_admin_only(&renamable).is_err());
    }

    fn owned(path: &str, uid: u32, gid: u32, mode: u32) -> PathOwner {
        PathOwner {
            path: PathBuf::from(path),
            uid,
            gid,
            mode,
        }
    }

    #[test]
    fn root_runs_only_what_root_alone_can_replace() {
        let root_dirs = || {
            vec![
                owned("/opt/crossfyre/bin", 0, 0, 0o40755),
                owned("/opt/crossfyre", 0, 0, 0o40755),
                owned("/opt", 0, 0, 0o40755),
                owned("/", 0, 0, 0o40755),
            ]
        };
        let with_file = |file: PathOwner, dirs: Vec<PathOwner>| {
            let mut chain = vec![file];
            chain.extend(dirs);
            judge_root_run(&chain)
        };
        assert!(
            with_file(
                owned("/opt/crossfyre/bin/node", 0, 0, 0o100755),
                root_dirs()
            )
            .is_ok()
        );

        // A worker a user owns, or one anyone may write, could be swapped for anything.
        for file in [
            owned("/opt/crossfyre/bin/node", 1000, 1000, 0o100755),
            owned("/opt/crossfyre/bin/node", 0, 0, 0o100777),
            owned("/opt/crossfyre/bin/node", 0, 1000, 0o100775),
        ] {
            assert!(with_file(file, root_dirs()).is_err());
        }

        // So could one in a directory a user owns or may write.
        let mut user_dir = root_dirs();
        user_dir[0] = owned("/opt/crossfyre/bin", 1000, 1000, 0o40755);
        assert!(with_file(owned("/opt/crossfyre/bin/node", 0, 0, 0o100755), user_dir).is_err());
        let mut open_dir = root_dirs();
        open_dir[1] = owned("/opt/crossfyre", 0, 0, 0o40777);
        let err = with_file(owned("/opt/crossfyre/bin/node", 0, 0, 0o100755), open_dir)
            .expect_err("a directory others may write");
        assert!(err.contains("/opt/crossfyre/bin/node"), "{err}");

        // Write access for the root group is root's, and a sticky directory such as the
        // Nix store does not let others replace what they do not own.
        assert!(
            with_file(
                owned("/opt/crossfyre/bin/node", 0, 0, 0o100775),
                root_dirs()
            )
            .is_ok()
        );
        let store = vec![
            owned("/nix/store/x-crossfyre/bin", 0, 0, 0o40555),
            owned("/nix/store/x-crossfyre", 0, 0, 0o40555),
            owned("/nix/store", 0, 30000, 0o41775),
            owned("/nix", 0, 0, 0o40755),
            owned("/", 0, 0, 0o40755),
        ];
        assert!(
            with_file(
                owned("/nix/store/x-crossfyre/bin/node", 0, 0, 0o100555),
                store
            )
            .is_ok()
        );
    }
}
