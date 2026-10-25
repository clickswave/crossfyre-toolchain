// Cross-platform daemon service management for the Crossfyre toolchain.
//
// Two kinds of services:
//
// 1. Extension daemons (ambulo, voyage, doorward) - long-lived *per-user* daemons:
//      Linux   -> systemd user units      (~/.config/systemd/user, systemctl --user)
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

/// Is a service registered for an extension, under any name it may have?
pub fn has_service_file(ext: &str) -> bool {
    unit_keys(ext).into_iter().any(imp::exists)
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
/// nodes survive reboots and closed terminals. The unit runs the node worker in
/// the bin directory, and names `cli` (normally `/opt/crossfyre/bin/crossfyre`,
/// or wherever a package put it) to the node in `CROSSFYRE_CLI`.
pub fn install_node_service(
    cli: &std::path::Path,
    data_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    node::create(cli, data_dir)?;
    node::action("enable")?;
    node::action("start")?;
    Ok(())
}

/// The node worker the node unit runs: the one in the bin directory.
pub fn node_binary() -> std::path::PathBuf {
    super::config::get_bin_dir().join(super::config::ext_file_name("node"))
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
    let node_exe = bin_dir.join(super::config::ext_file_name("node"));
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
         After=network-online.target docker.service\n\
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
/// `data_dir`, told which CLI set it up, and, under sudo, which user it acts for.
pub fn node_plist(
    node_exe: &std::path::Path,
    cli: &std::path::Path,
    data_dir: &std::path::Path,
    sudo_user: Option<&str>,
    log: &std::path::Path,
) -> String {
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

/// Start engine `ext`'s daemon the way its service on macOS or Windows wants it: on its
/// configured port, told where the toolchain directory is, and with the egress-proxy
/// variables of the file a systemd unit would have read. Run by the CLI's hidden
/// `extension host <engine>`, which the launchd agent and the scheduled task name.
///
/// On macOS this becomes the engine (exec), so launchd supervises the daemon itself. On
/// Windows it stays to restart the engine when it fails (see `win::host`).
#[cfg(not(target_os = "linux"))]
pub fn host(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    let e = super::engine(ext).ok_or_else(|| format!("{ext} is not an engine"))?;
    let bin = super::config::ext_bin_path(e.id);
    let port = super::config::engine_port(e.id);
    let mut cmd = std::process::Command::new(&bin);
    cmd.args(["--daemon", "--port", &port.to_string()]);
    cmd.env(
        super::config::TOOLCHAIN_DIR_ENV,
        super::config::get_toolchain_dir(),
    );
    if let Ok(text) = std::fs::read_to_string(super::config::egress_env_path()) {
        for (key, value) in env_assignments(&text) {
            cmd.env(key, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(format!("could not start {}: {err}", bin.display()).into())
    }
    #[cfg(windows)]
    {
        let log = super::config::logs_dir().join(format!("{}.log", e.name));
        super::win::host(e.name, cmd, &log)
    }
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
        cli: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        require_root()?;
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

    /// Load the job from `plist`. A job that was booted out a moment ago may still be
    /// on its way out, and launchd refuses to load it again until it is gone, so a
    /// refusal is tried again for a few seconds.
    fn bootstrap(domain: &str, label: &str, plist: &str) -> Result<(), String> {
        let mut last = String::new();
        for _ in 0..20 {
            match run(&["bootstrap", domain, plist]) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
            if loaded(domain, label) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err(last)
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
            "start" => bootstrap(domain, label, plist),
            "stop" if loaded(domain, label) => run(&["bootout", &t]),
            "stop" => Ok(()),
            // Booted out and in again, so a plist rewritten since it was loaded (a new
            // port, say) is the one that runs, as a restart after daemon-reload does.
            "restart" => {
                if loaded(domain, label) {
                    run(&["bootout", &t])?;
                }
                bootstrap(domain, label, plist)
            }
            "enable" => run(&["enable", &t]),
            "disable" => run(&["disable", &t]),
            other => Err(format!("Unsupported action: {other}")),
        }
    }

    /// running | stopped | failed.
    pub fn status(domain: &str, label: &str) -> String {
        let Ok(out) = launchctl(&["print", &target(domain, label)]) else {
            return "unknown".to_string();
        };
        if !out.status.success() {
            return "stopped".to_string();
        }
        let text = String::from_utf8_lossy(&out.stdout);
        if text.lines().any(|l| l.trim() == "state = running") {
            return "running".to_string();
        }
        // `last exit code = 1: Operation not permitted`, or `(never exited)`.
        let failed = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("last exit code = "))
            .any(|code| {
                code.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit() && c != '0')
            });
        if failed { "failed" } else { "stopped" }.to_string()
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

    pub fn bootout(domain: &str, label: &str) {
        let _ = launchctl(&["bootout", &target(domain, label)]);
    }

    pub fn disable(domain: &str, label: &str) {
        let _ = launchctl(&["disable", &target(domain, label)]);
    }
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
            return Err("managing the node service needs root - re-run with sudo".into());
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
        let logs = data_dir.join("logs");
        fs::create_dir_all(&logs)?;
        super::super::sudo_user::chown_to_invoking_user(&logs);
        let body = super::node_plist(
            &super::node_binary(),
            cli,
            data_dir,
            sudo_user.as_deref(),
            &logs.join("node.log"),
        );
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
            launchd::bootout(DOMAIN, super::NODE_LABEL);
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
}

// ── Windows: the node supervisor as a service ─────────────────────────
#[cfg(windows)]
mod node {
    use super::super::win::scm;

    fn require_elevated() -> Result<(), Box<dyn std::error::Error>> {
        if !crate::os::is_elevated() {
            return Err(
                "managing the node service needs an elevated prompt - re-run it as administrator"
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
        chown_to_invoking_user, cmd_as_invoking_user, create_dir_all_for_invoking_user,
        invoking_user_home,
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
        create_dir_all_for_invoking_user(&dir)?;
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
    use super::super::sudo_user::{
        chown_to_invoking_user, create_dir_all_for_invoking_user, invoking_user_home,
        sudo_user_info,
    };
    use super::launchd;
    use std::fs;
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

    pub fn create(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key = super::super::public_name(ext);
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
        fs::write(plist_path(key), body)?;
        // Written into the user's home as root - chown it back.
        chown_to_invoking_user(&dir);
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
            launchd::bootout(&domain(), &label(key));
            fs::remove_file(&path)?;
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
}

// ── Windows: scheduled tasks (extensions) ─────────────────────────────
#[cfg(windows)]
mod imp {
    use super::super::win::tasks;

    /// Registered from an elevated prompt (or by the node service) the task runs at boot;
    /// from an ordinary one it runs at the operator's logon, and `tasks::create` says so.
    pub fn create(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key = super::super::public_name(ext);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

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
            Path::new("/Users/op/Library/Application Support/crossfyre/logs/node.log"),
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
        let without = node_plist(
            Path::new("/n"),
            Path::new("/c"),
            Path::new("/d"),
            None,
            Path::new("/l"),
        );
        assert!(!without.contains("SUDO_USER"), "{without}");
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
