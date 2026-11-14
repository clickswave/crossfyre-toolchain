// Toolchain Postgres container management. The extension daemons persist
// scan state to a shared Postgres instance; by default that's a local Docker
// container named `crossfyre-postgres`, published on loopback port 4440 and
// protected by the password in config.toml.

use super::config::{PostgresSection, ToolchainConfig};
use super::config::{
    ensure_postgres_password_at, get_config_path, load_config, load_config_at,
    load_or_create_config, new_postgres_password, save_config, save_config_at,
};
use super::sudo_user;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CONTAINER_NAME: &str = "crossfyre-postgres";
const IMAGE: &str = "postgres";

/// The environment entry the official image reads at first start. Its value is
/// handed to the docker CLI through its own environment, never its arguments, so it
/// does not show up in a process listing.
const PASSWORD_ENV: &str = "POSTGRES_PASSWORD";

/// What a container made by 0.1.42 and earlier carried in place of a password.
const TRUST_ENV: &str = "POSTGRES_HOST_AUTH_METHOD=trust";

pub fn run(command: &crate::DbCommands) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_or_create_config()?;

    match command {
        crate::DbCommands::Up => up(),
        crate::DbCommands::Down => down(&config),
        crate::DbCommands::Start => {
            secure_existing()?;
            start(&load_config()?).map(|_| ())
        }
        crate::DbCommands::Stop => stop(&config),
        crate::DbCommands::Restart => {
            stop(&config)?;
            secure_existing()?;
            start(&load_config()?).map(|_| ())
        }
    }
}

/// Bring the database up for init / the dashboard's start-postgres action:
/// `start` an existing container, or `up` a fresh one when none exists. A container
/// left by an earlier release is secured first, so it is never started as it was.
pub fn ensure_up() -> Result<(), Box<dyn std::error::Error>> {
    load_or_create_config()?;
    secure_existing()?;
    let config = load_config()?;
    let target = resolve_container(&config);
    let recorded = config.container.id.is_some();
    let container = match inspect(&target) {
        Ok(found) => found,
        Err(e) if recorded => return Err(e.into()),
        // No Docker here, and no container ever recorded.
        Err(_) => None,
    };
    match plan(container.as_ref(), recorded, running(&config)) {
        Plan::Up => {
            println!("Postgres is already running.");
            return Ok(());
        }
        Plan::Make => return up(),
        Plan::Start => {}
    }
    // A container that is there is never recreated here, which would leave its data
    // behind: a server recovering after an unclean stop can take a while to answer, and
    // one that cannot start may only have found its port taken.
    if !start(&config)? {
        return Err(format!(
            "the database container did not start. If something else listens on \
             127.0.0.1:{}, stop it and run `crossfyre db start`; see `docker logs {target}`",
            config.postgres.port
        )
        .into());
    }
    let deadline = Instant::now() + START_WAIT;
    while Instant::now() < deadline {
        if is_up(&target) && running(&config) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "the database container started but does not answer on 127.0.0.1:{}; see \
         `docker logs {target}`, or make a new, empty one with `crossfyre db up`",
        config.postgres.port
    )
    .into())
}

/// What [`ensure_up`] does about the database.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// It is up: nothing to do.
    Up,
    /// Start the container that is there.
    Start,
    /// Make a new container.
    Make,
}

/// What to do given the `docker inspect` record of the container config.toml names (or
/// of the default one), whether config.toml records one, and whether something answers
/// on the database port. While the container is stopped anyone can listen on its port,
/// so a container of ours is up only when Docker says it is running.
fn plan(container: Option<&serde_json::Value>, recorded: bool, port_answers: bool) -> Plan {
    match container {
        Some(info) if info["State"]["Running"].as_bool() == Some(true) => Plan::Up,
        Some(_) => Plan::Start,
        // No container of ours, ever: a database the operator runs on this host.
        None if !recorded && port_answers => Plan::Up,
        None => Plan::Make,
    }
}

/// The restart policy the database container is made with, so it is back on its port
/// when Docker starts after a reboot rather than whenever someone next starts it.
const RESTART_POLICY: &str = "unless-stopped";

/// Whether a container was made without a restart policy, as earlier releases made it.
fn lacks_restart_policy(info: &serde_json::Value) -> bool {
    matches!(
        info["HostConfig"]["RestartPolicy"]["Name"].as_str(),
        None | Some("" | "no")
    )
}

/// How long a started container has to answer on its port.
const START_WAIT: Duration = Duration::from_secs(120);

/// True if the configured Postgres port accepts TCP connections.
pub fn running(config: &ToolchainConfig) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], config.postgres.port)),
        std::time::Duration::from_millis(300),
    )
    .is_ok()
}

/// (Re)create the container from config.toml, generating the password first if the
/// file has none.
pub fn up() -> Result<(), Box<dyn std::error::Error>> {
    if up_at(CONTAINER_NAME, &get_config_path())? {
        restart_engines();
    }
    Ok(())
}

/// Make a container from an earlier release safe, if there is one: it was published
/// on every interface and let anyone in without a password. The engines' rows are kept
/// (see [`rebuild`]). Returns whether anything changed. Runs at every node start, which
/// is how an upgraded host is repaired, and before the database is started. An error means a container may
/// still be open, including when Docker could not be asked about one config.toml names.
pub fn secure_existing() -> Result<bool, Box<dyn std::error::Error>> {
    let path = get_config_path();
    let changed = secure_at(CONTAINER_NAME, &path)?;
    // The engines only use this container, and so its password, when config.toml
    // points them at this host.
    if changed && load_config_at(&path).is_ok_and(|c| is_local_host(&c.postgres.host)) {
        restart_engines();
    }
    Ok(changed)
}

/// Whether config.toml's database host is this machine, which is where the container
/// is. Any other host is a database the operator runs themselves. The container used to
/// be published on every interface, so a config may reach it through the machine's own
/// name or one of its addresses: the host is resolved, and an address this machine can
/// bind is one of its own.
fn is_local_host(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let Ok(addrs) = (host, 0u16).to_socket_addrs() else {
        return false;
    };
    addrs.into_iter().any(|a| {
        let ip = a.ip();
        ip.is_loopback() || ip.is_unspecified() || std::net::UdpSocket::bind((ip, 0)).is_ok()
    })
}

/// The `-p` value: loopback only. The engines are on this host, and Docker's own
/// forwarding rules put a port published without an address beyond host firewalls.
fn publish_arg(port: u16) -> String {
    format!("127.0.0.1:{port}:5432")
}

/// `docker run` arguments for the database container. The password is named but not
/// given here; see [`PASSWORD_ENV`].
fn run_args(
    name: &str,
    pg: &PostgresSection,
    image: &str,
    volumes_from: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--restart".to_string(),
        RESTART_POLICY.to_string(),
        "-p".to_string(),
        publish_arg(pg.port),
        "-e".to_string(),
        format!("POSTGRES_USER={}", pg.user),
        "-e".to_string(),
        format!("POSTGRES_DB={}", pg.db_name),
        "-e".to_string(),
        PASSWORD_ENV.to_string(),
    ];
    if let Some(from) = volumes_from {
        args.push("--volumes-from".to_string());
        args.push(from.to_string());
    }
    args.push(image.to_string());
    args
}

/// What needs fixing in a container, from its `docker inspect` record.
#[derive(Debug, PartialEq, Eq)]
struct Exposure {
    /// Published on an address other than loopback, or on all of them.
    on_network: bool,
    /// Made to accept connections without a password.
    trust: bool,
}

impl Exposure {
    fn safe(&self) -> bool {
        !self.on_network && !self.trust
    }
}

fn assess(info: &serde_json::Value) -> Exposure {
    let on_network = info["HostConfig"]["PortBindings"]
        .as_object()
        .into_iter()
        .flat_map(|ports| ports.values())
        .filter_map(|bindings| bindings.as_array())
        .flatten()
        .any(|b| !matches!(b["HostIp"].as_str(), Some("127.0.0.1" | "::1")));
    let trust = info["Config"]["Env"]
        .as_array()
        .is_some_and(|env| env.iter().any(|e| e.as_str() == Some(TRUST_ENV)));
    Exposure { on_network, trust }
}

/// One way of running the docker CLI: which binary, and whether as the operator who
/// registered the node rather than as this process.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DockerCli {
    program: PathBuf,
    /// Run as the operator, so the CLI talks to the daemon and context their own
    /// shell uses: Docker Desktop, colima or rootless Docker are per-user, and the
    /// node supervisor runs as root.
    as_operator: bool,
    /// A daemon address to use instead of the one the CLI would pick.
    host: Option<String>,
}

impl DockerCli {
    fn command(&self) -> Command {
        let mut cmd = if self.as_operator {
            let mut cmd = sudo_user::cmd_as_invoking_user(&self.program);
            cmd.current_dir(sudo_user::invoking_user_home());
            cmd
        } else {
            Command::new(&self.program)
        };
        if let Some(host) = &self.host {
            cmd.env("DOCKER_HOST", host);
        }
        cmd
    }

    /// Whether this CLI reaches a daemon. The error says why not.
    fn reach(&self) -> Result<(), String> {
        let mut cmd = self.command();
        cmd.args(["version", "--format", "{{.Server.Version}}"]);
        let out = output_within(cmd, REACH_WAIT)
            .map_err(|e| format!("{}: {e}", self.program.display()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{}{}: {}",
                self.program.display(),
                if self.as_operator {
                    " (as the operator)"
                } else {
                    ""
                },
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

/// Where Docker's CLI is installed besides PATH. A service has a short PATH: launchd
/// gives a daemon /usr/bin:/bin:/usr/sbin:/sbin, and Docker Desktop, Homebrew and
/// the Windows installer all put the CLI elsewhere.
fn system_docker_dirs() -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/Applications/Docker.app/Contents/Resources/bin"),
        ]
    } else if cfg!(windows) {
        let program_files =
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        vec![PathBuf::from(program_files).join(r"Docker\Docker\resources\bin")]
    } else {
        vec![
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/snap/bin"),
        ]
    }
}

/// Per-user CLI locations (Docker Desktop's user install, OrbStack, Rancher Desktop).
/// A binary there is only ever run as that user.
fn home_docker_dirs(home: &Path) -> Vec<PathBuf> {
    [".docker/bin", ".orbstack/bin", ".rd/bin"]
        .iter()
        .map(|d| home.join(d))
        .collect()
}

/// The first docker binary on `path_var`, then in `dirs`. Relative PATH entries are
/// skipped, since this may run as root.
fn find_docker(path_var: Option<&OsStr>, dirs: &[PathBuf]) -> Option<PathBuf> {
    docker_paths(path_var, dirs).next()
}

/// Every docker binary on `path_var`, then in `dirs`, in that order.
fn docker_paths<'a>(
    path_var: Option<&OsStr>,
    dirs: &'a [PathBuf],
) -> impl Iterator<Item = PathBuf> + 'a {
    let name = if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    };
    path_var
        .into_iter()
        .flat_map(std::env::split_paths)
        .collect::<Vec<_>>()
        .into_iter()
        .filter(|d| d.is_absolute())
        .chain(dirs.iter().cloned())
        .map(move |d| d.join(name))
        .filter(|p| p.is_file())
}

/// Says once per process which docker binaries were not run with full rights.
fn note_refused(reasons: &[String]) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for r in reasons {
            eprintln!("[db] not using it with full rights: {r}");
        }
    });
}

/// The ways this process can run docker, in the order they are tried.
fn candidates() -> Vec<DockerCli> {
    let operator_home = sudo_user::sudo_user_info().map(|(_, _, home, _)| home);
    candidates_in(
        std::env::var_os("PATH").as_deref(),
        system_docker_dirs(),
        crate::os::is_elevated(),
        operator_home.as_deref(),
    )
}

/// With full rights (`elevated`), a binary is run as this process only when no other
/// user could have replaced it: Homebrew's directories and a drag-installed Docker.app
/// belong to the operator, and a binary there would otherwise run as root at every
/// boot. Such a binary is still used, as the operator.
fn candidates_in(
    path: Option<&OsStr>,
    system: Vec<PathBuf>,
    elevated: bool,
    operator_home: Option<&Path>,
) -> Vec<DockerCli> {
    let mut out = Vec::new();
    let mut refused = Vec::new();
    let own = docker_paths(path, &system).find(|program| {
        if !elevated {
            return true;
        }
        match super::service::root_may_run(program) {
            Ok(()) => true,
            Err(e) => {
                refused.push(e);
                false
            }
        }
    });
    if let Some(program) = own {
        out.push(DockerCli {
            program,
            as_operator: false,
            host: None,
        });
    }
    if !refused.is_empty() {
        note_refused(&refused);
    }
    if let Some(home) = operator_home {
        let mut dirs = system;
        dirs.extend(home_docker_dirs(home));
        if let Some(program) = find_docker(path, &dirs) {
            out.push(DockerCli {
                program,
                as_operator: true,
                host: None,
            });
        }
    }
    out
}

/// How long a daemon has to answer `docker version`. Docker Desktop that is still
/// starting, or a daemon that has hung, would otherwise hold up whoever asked.
const REACH_WAIT: Duration = Duration::from_secs(20);
const INSPECT_WAIT: Duration = Duration::from_secs(60);

/// `cmd`'s output, or an error once `limit` has passed, when it is killed.
fn output_within(mut cmd: Command, limit: Duration) -> std::io::Result<std::process::Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no answer within {} seconds", limit.as_secs()),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok(std::process::Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// Everything `pipe` says, read on a thread of its own so the child never blocks on it.
fn drain(pipe: Option<impl std::io::Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    })
}

/// The first `cap` bytes of what `pipe` says, which is still read to its end on a thread
/// of its own so the child never blocks on it.
fn drain_capped(
    pipe: Option<impl std::io::Read + Send + 'static>,
    cap: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    use std::io::Read;
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.by_ref().take(cap as u64).read_to_end(&mut buf);
            let _ = std::io::copy(&mut p, &mut std::io::sink());
        }
        buf
    })
}

/// The CLI picked for this process, once one has reached a daemon.
static SELECTED: Mutex<Option<DockerCli>> = Mutex::new(None);

fn remember(cli: &DockerCli) {
    if let Ok(mut chosen) = SELECTED.lock() {
        *chosen = Some(cli.clone());
    }
}

fn docker() -> Command {
    let chosen = SELECTED.lock().ok().and_then(|c| c.clone());
    if let Some(cli) = chosen {
        return cli.command();
    }
    let cands = candidates();
    if let Some(cli) = cands.iter().find(|c| c.reach().is_ok()) {
        remember(cli);
        return cli.command();
    }
    match cands.into_iter().next() {
        Some(cli) => cli.command(),
        // A bare name is looked up on PATH, which may name a binary another user can
        // replace, so with full rights there is nothing safe to run.
        None if crate::os::is_elevated() => Command::new(NO_DOCKER),
        None => Command::new("docker"),
    }
}

/// A program that does not exist, so the command fails as a missing docker would.
const NO_DOCKER: &str = if cfg!(windows) {
    r"C:\nonexistent\crossfyre\docker.exe"
} else {
    "/nonexistent/crossfyre/docker"
};

/// Pick the CLI that sees one of `targets`, or else the first that reaches a daemon.
/// An error means no candidate reached one.
fn select(cands: &[DockerCli], targets: &[&str]) -> Result<DockerCli, String> {
    let mut first = None;
    let mut errors = Vec::new();
    for cli in cands {
        if let Err(e) = cli.reach() {
            errors.push(e);
            continue;
        }
        if targets
            .iter()
            .any(|t| matches!(inspect_cmd(cli.command(), t), Ok(Some(_))))
        {
            return Ok(cli.clone());
        }
        first.get_or_insert_with(|| cli.clone());
    }
    first.ok_or_else(|| {
        if errors.is_empty() {
            "the docker command was not found".to_string()
        } else {
            format!("Docker did not answer ({})", errors.join("; "))
        }
    })
}

/// The container's `docker inspect` record, None when there is no such container,
/// and an error when Docker could not be asked.
fn inspect(target: &str) -> Result<Option<serde_json::Value>, String> {
    inspect_cmd(docker(), target)
}

fn inspect_cmd(mut cmd: Command, target: &str) -> Result<Option<serde_json::Value>, String> {
    cmd.args(["inspect", "--type", "container", target]);
    let out = output_within(cmd, INSPECT_WAIT).map_err(|e| format!("could not run docker: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let lower = err.to_ascii_lowercase();
        // Only these mean the container is absent. An unreachable daemon also says
        // "no such file or directory", about its socket.
        if lower.contains("no such container") || lower.contains("no such object") {
            return Ok(None);
        }
        return Err(format!("docker inspect failed: {}", err.trim()));
    }
    let list: Vec<serde_json::Value> =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("docker inspect: {e}"))?;
    Ok(list.into_iter().next())
}

fn docker_ok(args: &[&str]) -> Result<(), String> {
    let out = docker()
        .args(args)
        .output()
        .map_err(|e| format!("docker {}: {e}", args[0]))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "docker {} failed: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Held while the container is made, moved or replaced, so two runs (the node
/// supervisor at boot and an operator's `crossfyre db start`, say) never work on it
/// at once. Released when dropped, or when the process ends.
struct DbLock {
    _file: std::fs::File,
}

fn lock_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("db.lock")
}

fn lock_db(config_path: &Path, wait: Duration) -> Result<DbLock, String> {
    let path = lock_path(config_path);
    let deadline = Instant::now() + wait;
    loop {
        match try_lock(&path) {
            Ok(Some(file)) => return Ok(DbLock { _file: file }),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Ok(None) => {
                return Err(
                    "another crossfyre process is still changing the database container; \
                     try again when it has finished"
                        .to_string(),
                );
            }
            Err(e) => return Err(format!("could not lock {}: {e}", path.display())),
        }
    }
}

#[cfg(unix)]
fn try_lock(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    // No following a link: this may run as root in the operator's directory.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    // Nor a hard link to someone else's file, which the chown below would hand over.
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        let me = unsafe { libc::geteuid() };
        let operator = sudo_user::sudo_user_info().map(|(uid, _, _, _)| uid);
        if !lock_file_usable(
            meta.file_type().is_file(),
            meta.nlink(),
            meta.uid(),
            me,
            operator,
        ) {
            return Err(std::io::Error::other(
                "it is not a file of its own that belongs to this account; remove it",
            ));
        }
    }
    if let Some((uid, gid, _, _)) = sudo_user::sudo_user_info() {
        unsafe {
            libc::fchown(file.as_raw_fd(), uid, gid);
        }
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(err)
    }
}

/// Whether a lock file may be used: a file of its own. When it is handed to the
/// operator, it must also belong to this account or the operator already. When it is
/// only locked, whoever owns it does not matter.
#[cfg(unix)]
fn lock_file_usable(is_file: bool, links: u64, owner: u32, me: u32, operator: Option<u32>) -> bool {
    is_file && links == 1 && operator.is_none_or(|op| owner == me || owner == op)
}

#[cfg(windows)]
fn try_lock(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::os::windows::fs::OpenOptionsExt;
    // Opened unshared, the file cannot be opened again until this handle closes.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        // ERROR_SHARING_VIOLATION
        Err(e) if e.raw_os_error() == Some(32) => Ok(None),
        Err(e) => Err(e),
    }
}

/// How long a run waits for another to finish with the container.
const LOCK_WAIT: Duration = Duration::from_secs(600);

/// The config, the password the new container gets, and whether that password is new
/// to the engines.
fn up_password(
    config_path: &Path,
) -> Result<(ToolchainConfig, String, bool), Box<dyn std::error::Error>> {
    let config = load_config_at(config_path)?;
    if !is_local_host(&config.postgres.host) {
        // The engines use another database, whose config this password must not reach.
        let password = match config.postgres.password.clone() {
            Some(p) if !p.is_empty() => p,
            _ => new_postgres_password()?,
        };
        return Ok((config, password, false));
    }
    let (config, generated) = ensure_postgres_password_at(config_path)?;
    let password = config.postgres.password.clone().unwrap_or_default();
    Ok((config, password, generated))
}

fn up_at(name: &str, config_path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let (config, password, generated) = up_password(config_path)?;
    let _lock = lock_db(config_path, LOCK_WAIT)?;

    // Stop and remove any existing container by saved ID first, and by name in case
    // of a leftover the ID no longer names.
    if let Some(ref id) = config.container.id {
        println!(
            "Removing existing container ({})...",
            &id[..id.len().min(12)]
        );
        let _ = docker().args(["rm", "-f", id]).output();
    }
    let _ = docker().args(["rm", "-f", name]).output();

    let output = docker()
        .args(run_args(name, &config.postgres, IMAGE, None))
        .env(PASSWORD_ENV, &password)
        .output()?;

    if output.status.success() {
        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!(
            "Postgres container is up. ID: {}",
            &container_id[..container_id.len().min(12)]
        );

        let mut updated = load_config_at(config_path)?;
        updated.container.id = Some(container_id);
        save_config_at(config_path, &updated)?;
    } else {
        eprintln!("Failed to bring up Postgres container.");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(generated)
}

fn secure_at(name: &str, config_path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    secure_using(&candidates(), name, config_path)
}

fn secure_using(
    cands: &[DockerCli],
    name: &str,
    config_path: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    // No config.toml means no container of ours.
    let Ok(config) = load_config_at(config_path) else {
        return Ok(false);
    };
    let _lock = lock_db(config_path, LOCK_WAIT)?;
    let staged = format!("{name}-new");
    let scratch = format!("{name}-fix");
    let user = config.postgres.user.clone();

    let mut targets = vec![name, staged.as_str()];
    if let Some(id) = config.container.id.as_deref() {
        targets.insert(0, id);
    }
    match select(cands, &targets) {
        Ok(cli) => remember(&cli),
        // Nothing recorded, so nothing was ever made here: a node without Docker.
        Err(_) if config.container.id.is_none() => return Ok(false),
        Err(e) => {
            return Err(format!(
                "Docker could not be asked about the database container config.toml names: {e}"
            )
            .into());
        }
    }

    // A server left from an interrupted run below, on the old data volume. It has to
    // be gone before anything else starts on that volume.
    if inspect(&scratch)?.is_some() {
        docker_ok(&["rm", "-f", &scratch])?;
    }

    let mut current = match config.container.id.as_deref() {
        Some(id) => inspect(id)?,
        None => None,
    };
    if current.is_none() {
        current = inspect(name)?;
    }
    let mut assume_open = false;
    // Whether an interrupted run found the old container running before it stopped it.
    let mut resumed_running = false;
    match (current.is_some(), inspect(&staged)?) {
        (_, None) => {}
        // A move or rebuild that stopped after the old container was removed. Both
        // remove it only once the copy is complete and has its password, so all that
        // is left is to give the copy its name, and to stop it if the old one was.
        (false, Some(info)) if made_as(&info).is_some() => {
            docker_ok(&["rename", &staged, name])?;
            let mut updated = load_config_at(config_path)?;
            updated.container.id = info["Id"].as_str().map(str::to_string);
            save_config_at(config_path, &updated)?;
            if !was_running_label(&info) {
                let _ = docker().args(["stop", name]).output();
            }
            if made_as(&info) == Some(REBUILT) {
                tell_rebuilt(None, &kept_for(name));
            }
            println!("Finished moving the toolchain database to 127.0.0.1 with a password.");
            // The interrupted run may have made the password the engines now need.
            return Ok(true);
        }
        // One that stopped before the old container was removed: start again from the
        // old one. A rebuilt copy has a data volume of its own, which goes with it; any
        // other copy shares the old container's.
        (true, Some(info)) => {
            resumed_running = was_running_label(&info);
            let mut rm = vec!["rm", "-f"];
            if made_as(&info) == Some(REBUILT) {
                rm.push("-v");
            }
            rm.push(&staged);
            docker_ok(&rm)?;
        }
        // A copy on the old data volume that this release did not make, with no other
        // container left: its data is treated as having been open to anyone.
        (false, Some(_)) => {
            docker_ok(&["rename", &staged, name])?;
            current = inspect(name)?;
            assume_open = true;
        }
    }
    let Some(info) = current else {
        return Ok(false);
    };
    let mut exposure = assess(&info);
    exposure.trust |= assume_open;
    if exposure.safe() {
        // A run that stopped between giving the new container its name and recording
        // its id leaves config.toml naming a container that is gone, which would have
        // the next `db up` make an empty one in place of this. This one was found by
        // its name only when the recorded one is gone.
        if let Some(found) = info["Id"].as_str()
            && config
                .container
                .id
                .as_deref()
                .is_some_and(|recorded| !found.starts_with(recorded))
        {
            let mut updated = load_config_at(config_path)?;
            updated.container.id = Some(found.to_string());
            save_config_at(config_path, &updated)?;
        }
        if lacks_restart_policy(&info)
            && let Some(id) = info["Id"].as_str()
            && let Err(e) = docker_ok(&["update", "--restart", RESTART_POLICY, id])
        {
            eprintln!(
                "[db] the database container will not start by itself after a reboot ({e}); \
                 run `crossfyre db start` after one"
            );
        }
        return Ok(false);
    }

    let id = info["Id"]
        .as_str()
        .ok_or("the database container has no id")?
        .to_string();
    let was_running = info["State"]["Running"].as_bool().unwrap_or(false) || resumed_running;
    println!(
        "Securing the toolchain database container ({}): loopback only, with a password.",
        &id[..id.len().min(12)]
    );
    let local = is_local_host(&config.postgres.host);
    let (config, password) = if local {
        let (config, _) = ensure_postgres_password_at(config_path)?;
        let password = config.postgres.password.clone().unwrap_or_default();
        (config, password)
    } else {
        // config.toml points the engines at another database, which this password
        // must not reach. The container gets one of its own that is not kept.
        (config, new_postgres_password()?)
    };

    let new_id = if exposure.trust {
        // Stopped first, so nobody connected through the open door stays connected
        // while it is closed, and so a failure below leaves it stopped rather than
        // open. It has no restart policy, so it stays stopped.
        if was_running {
            println!("Stopping it while it is secured: it lets clients in without a password.");
            docker_ok(&["stop", &id]).map_err(|e| {
                format!("{e}. It may still let clients in without a password; stop it by hand")
            })?;
        }
        rebuild(
            &info,
            &id,
            &scratch,
            &staged,
            name,
            &config.postgres,
            &password,
            was_running,
        )
        .map_err(|e| format!("{e}. {STOPPED}"))?
    } else {
        replace(
            &info,
            &id,
            &staged,
            name,
            &config.postgres,
            &password,
            was_running,
        )?
    };
    let mut updated = load_config_at(config_path)?;
    updated.container.id = Some(new_id.clone());
    save_config_at(config_path, &updated)?;

    if !was_running {
        let _ = docker().args(["stop", &new_id]).output();
    }
    println!("The toolchain database now listens on 127.0.0.1 only and needs its password.");
    if !local {
        println!(
            "config.toml uses the database at {}, so the engines do not use this container. \
             Its data is kept; its new password was not saved.",
            config.postgres.host
        );
    }
    Ok(true)
}

/// Said when the repair of a container that let anyone in fails.
const STOPPED: &str = "The toolchain database container let clients in without a password, so it \
     is stopped and stays stopped until it can be secured. If something passing caused this, \
     such as Docker restarting, run `crossfyre db restart` to try again. To start again with \
     an empty database instead (scan state is lost): crossfyre db down, then crossfyre db up";

/// The label on a container this toolchain made in place of another, saying how.
const MADE_AS: &str = "io.crossfyre.db";
/// A new cluster on a data volume of its own, holding the engines' rows from a
/// container that let anyone in. The old container is removed only once it is complete
/// and has its password.
const REBUILT: &str = "rebuilt";
/// The data volume of a container that already needed a password, published on
/// loopback instead. The old container is removed once it is made.
const MOVED: &str = "moved";
/// Holds the data volume of a container that let anyone in, and never runs a server.
const KEPT: &str = "kept-open-data";
/// The label on a container made in place of another that was running, so a run that
/// stops after stopping the old one still leaves the database running in the end.
const WAS_RUNNING: &str = "io.crossfyre.db.was-running";
/// The label on a container that keeps old data, naming the container it was made for.
const KEPT_FROM: &str = "io.crossfyre.db.from";

/// How a container was made in place of another, from its `docker inspect` record.
fn made_as(info: &serde_json::Value) -> Option<&str> {
    info["Config"]["Labels"][MADE_AS].as_str()
}

fn was_running_label(info: &serde_json::Value) -> bool {
    info["Config"]["Labels"][WAS_RUNNING].as_str() == Some("true")
}

/// The `docker run` arguments that label a container as made for one that was running.
fn was_running_args(was_running: bool) -> Vec<String> {
    if was_running {
        vec!["--label".to_string(), format!("{WAS_RUNNING}=true")]
    } else {
        Vec::new()
    }
}

/// The superuser a container's cluster was made with, which is who reads it: the
/// image's `POSTGRES_USER`, or its default. config.toml may name another user, for a
/// database elsewhere.
fn made_with_user(info: &serde_json::Value) -> String {
    info["Config"]["Env"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.as_str()?.strip_prefix("POSTGRES_USER="))
        .find(|u| !u.is_empty())
        .unwrap_or("postgres")
        .to_string()
}

/// `docker run` arguments as [`run_args`] makes them, with the container labelled as
/// made `how` and the extra arguments `more` given before the image.
fn labelled_run_args(
    name: &str,
    pg: &PostgresSection,
    image: &str,
    volumes_from: Option<&str>,
    how: &str,
    more: &[String],
) -> Vec<String> {
    let mut args = run_args(name, pg, image, volumes_from);
    let image = args.pop().unwrap_or_default();
    args.push("--label".to_string());
    args.push(format!("{MADE_AS}={how}"));
    args.extend(more.iter().cloned());
    args.push(image);
    args
}

/// The databases the engines keep their scan state in, each with the statements its
/// engine runs to make its tables, in that order, which their foreign keys allow. They
/// are the engines' own `create_tables` statements, and a test holds the two together.
const ENGINE_SCHEMA: &[(&str, &[&str])] = &[
    (
        "mach",
        &[
            "CREATE TABLE IF NOT EXISTS wordlists ( id BIGSERIAL PRIMARY KEY, name TEXT NOT \
             NULL, hash TEXT UNIQUE )",
            "CREATE TABLE IF NOT EXISTS words ( id BIGSERIAL PRIMARY KEY, word TEXT NOT NULL, \
             wordlist_id BIGINT NOT NULL, FOREIGN KEY (wordlist_id) REFERENCES wordlists(id) )",
            "CREATE TABLE IF NOT EXISTS scans ( id BIGSERIAL PRIMARY KEY, config_hash TEXT NOT \
             NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT \
             NOW()::TEXT, updated_at TEXT NOT NULL DEFAULT NOW()::TEXT, notifications TEXT NOT \
             NULL DEFAULT '{}', wordlist_id BIGINT, method TEXT NOT NULL, FOREIGN KEY \
             (wordlist_id) REFERENCES wordlists(id) )",
            "CREATE TABLE IF NOT EXISTS urls ( id BIGSERIAL PRIMARY KEY, url TEXT NOT NULL, \
             scan_id BIGINT NOT NULL, FOREIGN KEY (scan_id) REFERENCES scans(id) )",
            "CREATE TABLE IF NOT EXISTS scan_entries ( id BIGSERIAL PRIMARY KEY, scan_id \
             BIGINT, url_id BIGINT, word_id BIGINT, status TEXT, request_status INTEGER NOT \
             NULL DEFAULT 0, headers TEXT, headers_length BIGINT NOT NULL, body BYTEA, \
             body_length BIGINT NOT NULL, FOREIGN KEY (scan_id) REFERENCES scans(id), FOREIGN \
             KEY (url_id) REFERENCES urls(id), FOREIGN KEY (word_id) REFERENCES words(id) )",
            "CREATE INDEX IF NOT EXISTS scan_entries_scan_status_idx ON scan_entries(scan_id, \
             status)",
            "CREATE TABLE IF NOT EXISTS logs ( id BIGSERIAL PRIMARY KEY, scan_id BIGINT NOT \
             NULL, level TEXT NOT NULL DEFAULT 'debug', description TEXT NOT NULL, created_at \
             TEXT NOT NULL DEFAULT NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS operations ( id TEXT PRIMARY KEY, operation TEXT NOT \
             NULL, params TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', result TEXT, \
             created_at TEXT NOT NULL DEFAULT NOW()::TEXT, updated_at TEXT NOT NULL DEFAULT \
             NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS probe_results ( id BIGSERIAL PRIMARY KEY, operation_id \
             TEXT NOT NULL, url TEXT NOT NULL, status TEXT NOT NULL, code INTEGER NOT NULL \
             DEFAULT 0, body_length BIGINT NOT NULL DEFAULT 0, headers_length BIGINT NOT NULL \
             DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), delete_after \
             TIMESTAMPTZ NOT NULL )",
        ],
    ),
    (
        "voyage",
        &[
            "CREATE TABLE IF NOT EXISTS scans ( id TEXT PRIMARY KEY, config_hash TEXT NOT NULL \
             UNIQUE, domain TEXT NOT NULL, wordlist_path TEXT NOT NULL DEFAULT '', status TEXT \
             NOT NULL DEFAULT 'created', created_at TEXT NOT NULL DEFAULT NOW()::TEXT, \
             updated_at TEXT NOT NULL DEFAULT NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS scan_entries ( id BIGSERIAL PRIMARY KEY, scan_id TEXT \
             NOT NULL REFERENCES scans(id), full_subdomain TEXT NOT NULL, status TEXT NOT NULL \
             DEFAULT 'queued', method TEXT NOT NULL DEFAULT 'active', source TEXT NOT NULL \
             DEFAULT '', created_at TEXT NOT NULL DEFAULT NOW()::TEXT, updated_at TEXT NOT \
             NULL DEFAULT NOW()::TEXT, UNIQUE (scan_id, full_subdomain) )",
            "CREATE TABLE IF NOT EXISTS logs ( id BIGSERIAL PRIMARY KEY, scan_id TEXT, level \
             TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL, created_at TEXT NOT NULL \
             DEFAULT NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS operations ( id TEXT PRIMARY KEY, operation TEXT NOT \
             NULL, params TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'queued', \
             result TEXT, created_at TEXT NOT NULL DEFAULT NOW()::TEXT, updated_at TEXT NOT \
             NULL DEFAULT NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS probe_results ( id BIGSERIAL PRIMARY KEY, operation_id \
             TEXT NOT NULL, domain TEXT NOT NULL, found BOOLEAN NOT NULL DEFAULT false, \
             technique TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
             delete_after TIMESTAMPTZ NOT NULL )",
        ],
    ),
    (
        "pulse",
        &[
            "CREATE TABLE IF NOT EXISTS scans ( id TEXT PRIMARY KEY, config_hash TEXT NOT \
             NULL, targets TEXT NOT NULL, ports TEXT NOT NULL, technique TEXT NOT NULL DEFAULT \
             'connect', status TEXT NOT NULL DEFAULT 'pending', created_at TEXT DEFAULT \
             NOW()::TEXT, updated_at TEXT DEFAULT NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS scan_entries ( id BIGSERIAL PRIMARY KEY, scan_id TEXT \
             NOT NULL REFERENCES scans(id), host TEXT NOT NULL, port INTEGER NOT NULL, status \
             TEXT NOT NULL DEFAULT 'queued', service TEXT, banner TEXT, latency_ms BIGINT \
             DEFAULT 0, created_at TEXT DEFAULT NOW()::TEXT, updated_at TEXT DEFAULT \
             NOW()::TEXT, UNIQUE (scan_id, host, port) )",
            "CREATE TABLE IF NOT EXISTS logs ( id BIGSERIAL PRIMARY KEY, scan_id TEXT, level \
             TEXT DEFAULT 'info', message TEXT NOT NULL, created_at TEXT DEFAULT NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS operations ( id TEXT PRIMARY KEY, operation TEXT NOT \
             NULL, params TEXT DEFAULT '{}', status TEXT DEFAULT 'queued', result TEXT, \
             created_at TEXT DEFAULT NOW()::TEXT, updated_at TEXT DEFAULT NOW()::TEXT )",
            "CREATE TABLE IF NOT EXISTS probe_results ( id BIGSERIAL PRIMARY KEY, operation_id \
             TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, status TEXT NOT NULL, \
             service TEXT, banner TEXT, latency_ms BIGINT DEFAULT 0, created_at TIMESTAMPTZ \
             DEFAULT NOW(), delete_after TIMESTAMPTZ NOT NULL )",
        ],
    ),
];

/// The table a statement in [`ENGINE_SCHEMA`] makes, if it makes one.
fn table_of(statement: &str) -> Option<&str> {
    statement
        .strip_prefix("CREATE TABLE IF NOT EXISTS ")?
        .split_whitespace()
        .next()
}

/// Sets every sequence a column owns to carry on after the largest value copied in.
const RESET_SEQUENCES: &str = "DO $$\n\
DECLARE r record;\n\
BEGIN\n\
  FOR r IN SELECT s.oid::regclass AS seq, d.refobjid::regclass AS tbl, a.attname\n\
    FROM pg_class s\n\
    JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = s.oid\n\
      AND d.refclassid = 'pg_class'::regclass AND d.deptype = 'a'\n\
    JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid\n\
    WHERE s.relkind = 'S'\n\
  LOOP\n\
    EXECUTE format('SELECT setval(%L, coalesce(max(%I), 0) + 1, false) FROM %s',\n\
      r.seq, r.attname, r.tbl);\n\
  END LOOP;\n\
END $$;\n";

/// What [`copy_engine_rows`] copied.
#[derive(Debug, Default)]
struct Copied {
    tables: usize,
    rows: u64,
    /// The engines' tables that were in the old database but are left empty, and why.
    left_empty: Vec<String>,
}

/// Rebuild the database of the stopped container `id`, which let anyone in. Anyone
/// could change that cluster as its superuser, in more ways than a check of it can be
/// sure to find, so nothing of it is used again but the rows of the engines' tables: a
/// new container gets a new cluster made by the image, the toolchain makes the engines'
/// tables in it, and only their rows are copied over, as data, from a copy of the old
/// server with no network. The old data volume is kept, in a container that never runs
/// a server. Returns the new container's id.
#[allow(clippy::too_many_arguments)]
fn rebuild(
    info: &serde_json::Value,
    id: &str,
    scratch: &str,
    staged: &str,
    name: &str,
    pg: &PostgresSection,
    password: &str,
    was_running: bool,
) -> Result<String, String> {
    let image = info["Image"]
        .as_str()
        .ok_or("the database container has no image")?;
    let old_user = made_with_user(info);
    // What else shapes what initdb makes, so the new cluster matches the old one.
    let mut initdb = was_running_args(was_running);
    for e in info["Config"]["Env"].as_array().into_iter().flatten() {
        let Some(e) = e.as_str() else { continue };
        if ["POSTGRES_INITDB_ARGS=", "LANG=", "LC_ALL="]
            .iter()
            .any(|p| e.starts_with(p))
        {
            initdb.push("-e".to_string());
            initdb.push(e.to_string());
        }
    }
    // The new container is published on the database port, which the stopped one no
    // longer holds. Until the rows are in, it has a password nobody knows, so no engine
    // starts on a half filled database.
    let loading = new_postgres_password().map_err(|e| e.to_string())?;
    let out = docker()
        .args(labelled_run_args(staged, pg, image, None, REBUILT, &initdb))
        .env(PASSWORD_ENV, &loading)
        .output()
        .map_err(|e| format!("docker run: {e}"))?;
    if !out.status.success() {
        let _ = docker().args(["rm", "-f", "-v", staged]).output();
        return Err(format!(
            "could not make the new database container: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let new_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let done = wait_initialized(staged, &pg.user)
        .and_then(|()| {
            on_server(info, id, scratch, &old_user, |old| {
                copy_engine_rows(old, &old_user, staged, &pg.user)
            })
        })
        .and_then(|copied| set_password(staged, &pg.user, password).map(|()| copied))
        .and_then(|copied| keep_old_data(image, id, name).map(|kept| (copied, kept)));
    let (copied, kept) = match done {
        Ok(done) => done,
        Err(e) => {
            // Its volume is its own, and holds nothing the old one does not.
            let _ = docker().args(["rm", "-f", "-v", staged]).output();
            return Err(e);
        }
    };
    // Without -v: the old data volume now belongs to the container that keeps it.
    docker_ok(&["rm", id])?;
    docker_ok(&["rename", staged, name])?;
    let mut holders = kept_for(name);
    if !holders.contains(&kept) {
        holders.push(kept);
    }
    tell_rebuilt(Some(&copied), &holders);
    Ok(new_id)
}

/// Wait until the image has made the cluster in a new container and runs its server
/// for good. While it sets up, it runs one on its socket only.
fn wait_initialized(id: &str, user: &str) -> Result<(), String> {
    wait_until(id, || {
        docker()
            .args(["exec", "-u", "postgres", id, "pg_isready", "-q", "-h"])
            .args(["127.0.0.1", "-U", user, "-d", "postgres"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Make the engines' databases and tables on the new server `new`, for each engine
/// whose database the old server `old` has, and copy their rows over, reading the old
/// one as `old_user` and writing the new one as `new_user`. A table whose rows do not
/// fit the engine's is left empty and named in what is returned. Any other failure,
/// such as Docker, a pipe or the new server's disk running out, stops the rebuild, so
/// the old container stays as it is rather than the engines starting on empty tables.
fn copy_engine_rows(
    old: &str,
    old_user: &str,
    new: &str,
    new_user: &str,
) -> Result<Copied, String> {
    let mut copied = Copied::default();
    for (db, statements) in ENGINE_SCHEMA {
        let found = psql_rows(
            old,
            old_user,
            "postgres",
            &format!(
                "SELECT datallowconn FROM pg_catalog.pg_database WHERE datname = {}",
                sql_literal(db)
            ),
        )?;
        // The engine never ran here.
        let Some(allowed) = found.first() else {
            continue;
        };
        psql(
            new,
            new_user,
            "postgres",
            &format!("CREATE DATABASE {};\n", sql_ident(db)),
        )?;
        let mut ddl = "SET search_path = public;\n".to_string();
        for s in *statements {
            ddl.push_str(s);
            ddl.push_str(";\n");
        }
        psql(new, new_user, db, &ddl)?;
        for table in statements.iter().filter_map(|s| table_of(s)) {
            let result = if allowed == "t" {
                copy_table(old, old_user, new, new_user, db, table)
            } else {
                Err(CopyFailed::DoNotFit(
                    "its database takes no connections".to_string(),
                ))
            };
            match result {
                Ok(rows) => {
                    copied.tables += 1;
                    copied.rows += rows;
                }
                Err(CopyFailed::DoNotFit(e)) => {
                    copied.left_empty.push(format!("{db}.{table}: {e}"))
                }
                Err(CopyFailed::Broken(e)) => return Err(format!("copying {db}.{table}: {e}")),
            }
        }
        psql(new, new_user, db, RESET_SEQUENCES)?;
    }
    Ok(copied)
}

/// Why the rows of a table were not copied.
#[derive(Debug, PartialEq, Eq)]
enum CopyFailed {
    /// They do not fit the engine's table, which is left empty.
    DoNotFit(String),
    /// Anything else, which stops the rebuild.
    Broken(String),
}

/// Whether psql's error output says the new server refused the rows themselves: a value
/// of the wrong type or out of range (SQLSTATE class 22), a constraint (23), or a row
/// too large for an index (54). Only the code of the first error counts, which psql
/// writes before any value from the rows the message quotes.
fn rows_refused(stderr: &str) -> bool {
    let Some(rest) = stderr.lines().find_map(|l| l.split_once("ERROR:")) else {
        return false;
    };
    let rest = rest.1.trim_start();
    let code = rest.get(..5).unwrap_or_default();
    code.len() == 5
        && code.bytes().all(|b| b.is_ascii_alphanumeric())
        && rest[5..].starts_with(':')
        && ["22", "23", "54"].contains(&&code[..2])
}

/// What has been seen of a line of COPY's text format, so it can be checked without
/// being held whole.
#[derive(Default)]
struct Line {
    len: usize,
    tabs: usize,
    cr: bool,
    head: [u8; 2],
}

impl Line {
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len < 2 {
                self.head[self.len] = b;
            }
            self.len += 1;
            match b {
                b'\t' => self.tabs += 1,
                b'\r' => self.cr = true,
                _ => {}
            }
        }
    }

    /// Whether the line is one row of `fields` columns and nothing else. COPY writes a
    /// tab, newline or carriage return inside a value as an escape, so a row is one line
    /// with one tab between each two values; and a line that is only `\.` would end the
    /// data early.
    fn is_row(&self, fields: usize) -> bool {
        let end_marker = self.len == 2 && &self.head == b"\\.";
        !end_marker && !self.cr && self.tabs + 1 == fields
    }
}

/// Whether `line`, without its newline, is one row of `fields` columns; see [`Line`].
#[cfg(test)]
fn one_row(line: &[u8], fields: usize) -> bool {
    let mut l = Line::default();
    l.feed(line);
    l.is_row(fields)
}

/// Pass the rows of COPY's text format from `source` to `sink` as they come, each line
/// checked before the newline that ends it is passed on, so no row is held whole however
/// large it is. Returns the number of rows passed, or, as `Err`, the number of the first
/// line that is not one row of `fields` values. A line cut short there never ends the
/// data, since nothing is committed unless every row was passed.
fn pass_rows(
    source: impl std::io::Read,
    sink: &mut impl std::io::Write,
    fields: usize,
) -> std::io::Result<Result<u64, u64>> {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::with_capacity(1 << 16, source);
    let mut line = Line::default();
    let mut rows = 0u64;
    loop {
        let used = {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                if line.len == 0 {
                    return Ok(Ok(rows));
                }
                // A last line without its newline.
                if !line.is_row(fields) {
                    return Ok(Err(rows + 1));
                }
                sink.write_all(b"\n")?;
                return Ok(Ok(rows + 1));
            }
            let end = buf.iter().position(|&b| b == b'\n');
            let part = &buf[..end.unwrap_or(buf.len())];
            line.feed(part);
            sink.write_all(part)?;
            if end.is_some() {
                if !line.is_row(fields) {
                    return Ok(Err(rows + 1));
                }
                sink.write_all(b"\n")?;
                rows += 1;
                line = Line::default();
            }
            part.len() + usize::from(end.is_some())
        };
        reader.consume(used);
    }
}

/// How much of what a copy's psql says on stderr is kept for the node log.
const SAID_CAP: usize = 16 * 1024;

/// Copy the rows of the engines' table `table` in database `db` from the old server to
/// the new one, as data only: the columns the toolchain's table has that the old one
/// has too, in COPY's text format, each line checked by [`pass_rows`] on its way to the
/// new server. The new server loads them in one transaction that commits only if the
/// table then holds as many rows as were sent. Returns that number.
fn copy_table(
    old: &str,
    old_user: &str,
    new: &str,
    new_user: &str,
    db: &str,
    table: &str,
) -> Result<u64, CopyFailed> {
    use CopyFailed::{Broken, DoNotFit};
    use std::io::Write;
    let qualified = format!("public.{}", sql_ident(table));
    let ours = psql_rows(
        new,
        new_user,
        db,
        &format!(
            "SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid = \
             {}::pg_catalog.regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum",
            sql_literal(&qualified)
        ),
    )
    .map_err(Broken)?;
    let theirs = psql_rows(
        old,
        old_user,
        db,
        &format!(
            "SELECT a.attname FROM pg_catalog.pg_attribute a \
             JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relname = {} AND c.relkind = 'r' \
             AND a.attnum > 0 AND NOT a.attisdropped",
            sql_literal(table)
        ),
    )
    .map_err(Broken)?;
    if theirs.is_empty() {
        return Err(DoNotFit(
            "it is not a table in the old database".to_string(),
        ));
    }
    let columns: Vec<String> = ours
        .iter()
        .filter(|c| theirs.contains(c))
        .map(|c| sql_ident(c))
        .collect();
    if columns.is_empty() {
        return Err(DoNotFit("it has none of the engine's columns".to_string()));
    }
    let target = format!("{qualified} ({})", columns.join(", "));

    let mut export = docker()
        .args(["exec", "-u", "postgres", "-e", &session_options(old)])
        .args(["-e", "PGCLIENTENCODING=UTF8", old, "psql", "-X", "-q"])
        .args([
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            old_user,
            "-d",
            &conninfo(db),
            "-c",
        ])
        .arg(format!("COPY {target} TO STDOUT"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Broken(format!("docker exec: {e}")))?;
    let export_err = drain_capped(export.stderr.take(), SAID_CAP);
    let mut import = match docker()
        .args([
            "exec",
            "-i",
            "-u",
            "postgres",
            "-e",
            "PGCLIENTENCODING=UTF8",
        ])
        .args([new, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1"])
        .args(["-v", "VERBOSITY=verbose", "-U", new_user])
        .args(["-d", &conninfo(db)])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let _ = export.kill();
            let _ = export.wait();
            return Err(Broken(format!("docker exec: {e}")));
        }
    };
    let import_err = drain_capped(import.stderr.take(), SAID_CAP);
    let said = |handle: std::thread::JoinHandle<Vec<u8>>| {
        String::from_utf8_lossy(&handle.join().unwrap_or_default())
            .trim()
            .to_string()
    };
    // Why the new server stopped loading, from what it said.
    let refused = |err: String, otherwise: String| {
        if rows_refused(&err) {
            DoNotFit(format!("its rows do not fit the engine's table: {err}"))
        } else if err.is_empty() {
            Broken(otherwise)
        } else {
            Broken(format!("{otherwise}: {err}"))
        }
    };

    // Ends with what was sent, or why it stopped. Without a COMMIT the new server keeps
    // none of it, whatever happens to either side.
    let mut sink = import
        .stdin
        .take()
        .map(|s| std::io::BufWriter::with_capacity(1 << 16, s));
    let passed = (|| -> std::io::Result<Result<u64, u64>> {
        let sink = sink
            .as_mut()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let source = export
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        writeln!(sink, "BEGIN;\nCOPY {target} FROM STDIN;")?;
        pass_rows(source, sink, columns.len())
    })();
    let sent = match passed {
        Ok(Ok(rows)) => rows,
        Ok(Err(row)) => {
            let _ = export.kill();
            let _ = export.wait();
            let _ = import.kill();
            drop(sink);
            let _ = import.wait();
            return Err(DoNotFit(format!(
                "row {row} is not one row of {} values",
                columns.len()
            )));
        }
        // Most likely the new server stopped reading, and says why.
        Err(e) => {
            let _ = export.kill();
            let _ = export.wait();
            drop(sink);
            let _ = import.wait();
            return Err(refused(said(import_err), format!("copying rows: {e}")));
        }
    };
    let exported = export
        .wait()
        .map_err(|e| Broken(format!("docker exec: {e}")))?;
    if !exported.success() {
        let _ = import.kill();
        drop(sink);
        let _ = import.wait();
        return Err(Broken(format!("reading it failed: {}", said(export_err))));
    }
    let finish = format!(
        "\\.\nDO $$ BEGIN IF (SELECT count(*) FROM {qualified}) <> {sent} THEN \
         RAISE EXCEPTION 'it holds a different number of rows than were sent'; \
         END IF; END $$;\nCOMMIT;\n"
    );
    let wrote = match sink.as_mut() {
        Some(s) => s.write_all(finish.as_bytes()).and_then(|()| s.flush()),
        None => Err(std::io::Error::other("no stdin")),
    };
    drop(sink);
    let imported = import
        .wait()
        .map_err(|e| Broken(format!("docker exec: {e}")))?;
    if wrote.is_err() || !imported.success() {
        return Err(refused(said(import_err), "loading it failed".to_string()));
    }
    Ok(sent)
}

/// The containers that keep the old data of a container named `name`.
fn kept_for(name: &str) -> Vec<String> {
    let prefix = format!("{name}-old-");
    labelled(&format!("{MADE_AS}={KEPT}"))
        .into_iter()
        .filter(|n| n.starts_with(&prefix))
        .collect()
}

/// The names of the containers with label `label`, whether running or not.
fn labelled(label: &str) -> Vec<String> {
    docker()
        .args(["ps", "-a", "--format", "{{.Names}}", "--filter"])
        .arg(format!("label={label}"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Keep the data volume of the old container `id` in a container that holds it and
/// never runs a server, and return that container's name. One an interrupted run made
/// for the same container is used again, so the volume is only ever held once.
fn keep_old_data(image: &str, id: &str, name: &str) -> Result<String, String> {
    if let Some(kept) = labelled(&format!("{KEPT_FROM}={id}")).into_iter().next() {
        return Ok(kept);
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let kept = format!("{name}-old-{secs}");
    docker_ok(&[
        "create",
        "--name",
        &kept,
        "--network",
        "none",
        "--label",
        &format!("{MADE_AS}={KEPT}"),
        "--label",
        &format!("{KEPT_FROM}={id}"),
        "--volumes-from",
        id,
        "--entrypoint",
        "true",
        image,
    ])?;
    Ok(kept)
}

/// Say that the database was rebuilt, what was copied when that is known (a run that
/// finishes an interrupted one does not know), and which containers keep the old data.
fn tell_rebuilt(copied: Option<&Copied>, kept: &[String]) {
    for line in rebuilt_notice(copied, kept) {
        eprintln!("[db] {line}");
    }
}

fn rebuilt_notice(copied: Option<&Copied>, kept: &[String]) -> Vec<String> {
    let rows = copied
        .map(|c| format!(" ({} in {} tables)", c.rows, c.tables))
        .unwrap_or_default();
    let mut lines = vec![format!(
        "WARNING the toolchain database accepted connections without a password, so it \
         was rebuilt: a new database with the engines' tables, holding only their \
         rows{rows}. Roles, settings and anything else in the old database were not \
         carried over; set again any you made yourself."
    )];
    for t in copied.map(|c| c.left_empty.as_slice()).unwrap_or_default() {
        lines.push(format!("  left empty: {t}"));
    }
    lines.push(
        "Anyone could write to it while it was open, so review scan results from that \
         time before relying on them."
            .to_string(),
    );
    for k in kept {
        lines.push(format!(
            "The old data is kept in the stopped container {k}, which never runs a \
             server. It may hold credentials from authenticated scans. Remove it when you \
             no longer need it: docker rm -v {k}"
        ));
    }
    lines
}

/// The pg_hba.conf the copy of an old server is started with: clients on its socket
/// only, which is how the repair reads it.
const KNOWN_HBA: &str = "# Written by crossfyre to copy the engines' rows from this data.\n\
local all all trust\n";

/// Starts a server on the data directory with [`KNOWN_HBA`] in place. Settings given
/// on the command line win over postgresql.conf and ALTER SYSTEM, so whatever was set
/// there neither keeps psql out nor runs anything while the engines' rows are read: no
/// libraries loaded at start, no archiving, no background vacuum running expressions,
/// no event triggers. It has no network, so even code it does run reaches nothing but
/// the old data and what it hands back, which is read as rows and nothing else. A recovery signal file would make it run restore_command, and
/// this database is never a standby. The file is removed before it is written, so a
/// link in its place is not followed.
const SCRATCH_SCRIPT: &str = r#"set -e
umask 077
rm -f "$PGDATA/pg_hba.conf" "$PGDATA/recovery.signal" "$PGDATA/standby.signal" "$PGDATA/recovery.conf"
printf '%s' "$1" > "$PGDATA/pg_hba.conf"
set --
if [ "$(cat "$PGDATA/PG_VERSION")" -ge 17 ] 2>/dev/null; then set -- -c event_triggers=off; fi
exec postgres "$@" -c hba_file="$PGDATA/pg_hba.conf" -c ident_file="$PGDATA/pg_ident.conf" \
  -c port=5432 -c unix_socket_directories=/var/run/postgresql -c unix_socket_permissions=0777 \
  -c shared_preload_libraries= -c archive_mode=off -c autovacuum=off -c jit=off -c ssl=off \
  -c logging_collector=off
"#;

/// Run `f` against a copy of the container's server with no network, which is removed
/// afterwards. The container itself must be stopped: two servers never share a data
/// directory, and a container that lets anyone in is never started.
fn on_server<T>(
    info: &serde_json::Value,
    id: &str,
    scratch: &str,
    user: &str,
    f: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, String> {
    let image = info["Image"]
        .as_str()
        .ok_or("the database container has no image")?;
    if let Err(e) = docker_ok(&[
        "run",
        "-d",
        "--name",
        scratch,
        "--network",
        "none",
        "--volumes-from",
        id,
        "-u",
        "postgres",
        "--entrypoint",
        "sh",
        image,
        "-c",
        SCRATCH_SCRIPT,
        "sh",
        KNOWN_HBA,
    ]) {
        let _ = docker().args(["rm", "-f", scratch]).output();
        return Err(e);
    }
    let result = wait_ready(scratch, user).and_then(|()| f(scratch));
    // A clean shutdown first, so the next start needs no recovery. It must be gone
    // either way before another server starts on this data.
    let _ = docker().args(["stop", scratch]).output();
    let removed = docker_ok(&["rm", "-f", scratch]);
    let value = result?;
    removed?;
    Ok(value)
}

fn is_up(id: &str) -> bool {
    matches!(inspect(id), Ok(Some(info)) if info["State"]["Running"].as_bool() == Some(true))
}

/// The last lines a container logged, to say why it stopped.
fn last_words(id: &str) -> String {
    docker()
        .args(["logs", "--tail", "3", id])
        .output()
        .map(|o| {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s.split_whitespace().collect::<Vec<_>>().join(" ")
        })
        .unwrap_or_default()
}

/// Wait until `ready` says the server in `id` answers, giving up early when the
/// container has stopped.
fn wait_until(id: &str, mut ready: impl FnMut() -> bool) -> Result<(), String> {
    // Crash recovery after an unclean stop can take a while on a large database.
    for i in 0..360 {
        if ready() {
            return Ok(());
        }
        if i % 10 == 9 && !is_up(id) {
            return Err(format!(
                "the database container {id} stopped: {}",
                last_words(id)
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("the database container {id} did not become ready"))
}

fn wait_ready(id: &str, user: &str) -> Result<(), String> {
    let options = session_options(id);
    wait_until(id, || {
        docker()
            .args([
                "exec",
                "-u",
                "postgres",
                "-e",
                &options,
                id,
                "pg_isready",
                "-q",
            ])
            .args(["-U", user, "-d", "postgres"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// The `PGOPTIONS` entry for every session the repair opens in a container. Settings
/// made for a role or a database apply to a session unless the client sets them
/// itself, and could load a library, put another schema's functions ahead of the
/// built-in ones, or fire an event trigger at login. The output formats are the image's
/// defaults, which the new server reads, whatever the old one was set to write.
fn session_options(id: &str) -> String {
    let mut options = "PGOPTIONS=-c session_preload_libraries= -c local_preload_libraries= \
         -c search_path=pg_catalog -c jit=off -c default_transaction_read_only=off \
         -c DateStyle=ISO,MDY -c IntervalStyle=postgres -c bytea_output=hex \
         -c extra_float_digits=1"
        .to_string();
    if server_major(id).is_some_and(|v| v >= 17) {
        options.push_str(" -c event_triggers=off");
    }
    options
}

/// The major version of the postgres binary in the container.
fn server_major(id: &str) -> Option<u32> {
    let out = docker()
        .args(["exec", id, "postgres", "-V"])
        .output()
        .ok()?;
    // "postgres (PostgreSQL) 18.1 (Debian 18.1-1.pgdg13+1)"
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(2)?
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// A psql connection string for database `db`, so a name that looks like one is
/// still only a database name.
fn conninfo(db: &str) -> String {
    format!("dbname='{}'", db.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// Psql run inside the container over its local socket, with `sql` on stdin so a
/// password in it is never an argument. Returns what it printed.
fn psql(id: &str, user: &str, db: &str, sql: &str) -> Result<String, String> {
    use std::io::Write;
    let mut child = docker()
        .args([
            "exec",
            "-i",
            "-u",
            "postgres",
            "-e",
            &session_options(id),
            id,
        ])
        .args([
            "psql",
            "-X",
            "-q",
            "-tA",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            user,
        ])
        .args(["-d", &conninfo(db)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("docker exec: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(sql.as_bytes())
            .map_err(|e| format!("docker exec: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("docker exec: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(format!(
            "psql in the database container failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// The rows of a fixed query in database `db`, one per line.
fn psql_rows(id: &str, user: &str, db: &str, sql: &str) -> Result<Vec<String>, String> {
    Ok(psql(id, user, db, sql)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

fn sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn sql_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn set_password(id: &str, user: &str, password: &str) -> Result<(), String> {
    psql(
        id,
        user,
        "postgres",
        &format!(
            "SET password_encryption = 'scram-sha-256';\nALTER ROLE {} WITH PASSWORD {};\n",
            sql_ident(user),
            sql_literal(password)
        ),
    )
    .map(|_| ())
}

/// Replace the container `old`, which already needed a password, with one named `name`
/// that is published on loopback, mounts the same volumes and runs the same image.
/// `was_running` says whether `old` was running before this or an interrupted run.
/// Returns the new container's id.
fn replace(
    info: &serde_json::Value,
    old: &str,
    staged: &str,
    name: &str,
    pg: &PostgresSection,
    password: &str,
    was_running: bool,
) -> Result<String, String> {
    let image = info["Image"]
        .as_str()
        .ok_or("the database container has no image")?;
    // Two servers must never share a data directory, and the new one needs the port.
    docker_ok(&["stop", old])?;
    let out = docker()
        .args(labelled_run_args(
            staged,
            pg,
            image,
            Some(old),
            MOVED,
            &was_running_args(was_running),
        ))
        .env(PASSWORD_ENV, password)
        .output()
        .map_err(|e| format!("docker run: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let _ = docker().args(["rm", "-f", staged]).output();
        if was_running {
            let _ = docker().args(["start", old]).output();
        }
        return Err(format!(
            "could not make the loopback-only database container: {err}"
        ));
    }
    let new_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // Without -v: the data volume now belongs to the new container as well.
    docker_ok(&["rm", old])?;
    docker_ok(&["rename", staged, name])?;
    Ok(new_id)
}

/// Remove the database container with its data, for `crossfyre uninstall`, and with it
/// every container made beside it: copies an interrupted repair left, and those that
/// keep the old data of a container that let anyone in, which may hold credentials
/// from authenticated scans. Returns the names of those removed.
pub fn remove_all() -> Vec<String> {
    remove_all_named(CONTAINER_NAME)
}

fn remove_all_named(name: &str) -> Vec<String> {
    let mut names = vec![
        name.to_string(),
        format!("{name}-new"),
        format!("{name}-fix"),
    ];
    let prefix = format!("{name}-");
    for other in labelled(MADE_AS) {
        if other.starts_with(&prefix) && !names.contains(&other) {
            names.push(other);
        }
    }
    names
        .into_iter()
        .filter(|n| matches!(inspect(n), Ok(Some(_))))
        .filter(|n| docker_ok(&["rm", "-f", "-v", n]).is_ok())
        .collect()
}

/// Restart the installed engine daemons, which read the database password only when
/// they start.
fn restart_engines() {
    for ext in super::EXTENSIONS {
        if super::config::is_extension_installed(ext) && super::service::has_service_file(ext) {
            if let Err(e) = super::service::restart(ext) {
                eprintln!(
                    "[db] {} did not restart ({e}); restart it so it uses the database password: \
                     crossfyre extension restart {}",
                    super::public_name(ext),
                    super::public_name(ext)
                );
            }
        }
    }
}

fn resolve_container(config: &ToolchainConfig) -> String {
    config
        .container
        .id
        .clone()
        .unwrap_or_else(|| CONTAINER_NAME.to_string())
}

fn down(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    let target = resolve_container(config);
    let status = docker().args(["rm", "-f", &target]).status()?;
    if status.success() {
        println!("Postgres container removed.");
        let mut updated = load_config()?;
        updated.container.id = None;
        save_config(&updated)?;
    } else {
        eprintln!("Failed to remove Postgres container. It may not exist.");
    }
    Ok(())
}

/// Whether the container started.
fn start(config: &ToolchainConfig) -> Result<bool, Box<dyn std::error::Error>> {
    let target = resolve_container(config);
    let status = docker().args(["start", &target]).status()?;
    if status.success() {
        println!("Postgres container started.");
    } else {
        eprintln!("Failed to start Postgres container. Try running 'crossfyre db up' first.");
    }
    Ok(status.success())
}

fn stop(config: &ToolchainConfig) -> Result<(), Box<dyn std::error::Error>> {
    let target = resolve_container(config);
    let status = docker().args(["stop", &target]).status()?;
    if status.success() {
        println!("Postgres container stopped.");
    } else {
        eprintln!("Failed to stop Postgres container.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg() -> PostgresSection {
        PostgresSection {
            host: "localhost".to_string(),
            port: 4440,
            user: "postgres".to_string(),
            password: Some("s3cret-value".to_string()),
            db_name: "crossfyre".to_string(),
        }
    }

    fn flag_value<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        args.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].as_str())
            .collect()
    }

    #[test]
    fn the_container_is_published_on_loopback_only() {
        let args = run_args(CONTAINER_NAME, &pg(), IMAGE, None);
        assert_eq!(flag_value(&args, "-p"), vec!["127.0.0.1:4440:5432"]);
    }

    #[test]
    fn the_container_requires_a_password_that_is_not_on_its_command_line() {
        let args = run_args(CONTAINER_NAME, &pg(), IMAGE, None);
        let env = flag_value(&args, "-e");
        assert!(env.contains(&PASSWORD_ENV), "{env:?}");
        assert!(
            !env.iter()
                .any(|e| e.starts_with("POSTGRES_HOST_AUTH_METHOD")),
            "{env:?}"
        );
        assert!(
            !args.iter().any(|a| a.contains("s3cret-value")),
            "the password must not be an argument: {args:?}"
        );
    }

    #[test]
    fn a_replacement_keeps_the_old_volumes_and_image() {
        let args = run_args("x-new", &pg(), "sha256:abc", Some("oldid"));
        assert_eq!(flag_value(&args, "--volumes-from"), vec!["oldid"]);
        assert_eq!(args.last().map(String::as_str), Some("sha256:abc"));
        assert_eq!(flag_value(&args, "--name"), vec!["x-new"]);
    }

    #[test]
    fn the_container_comes_back_after_a_reboot() {
        let args = run_args(CONTAINER_NAME, &pg(), IMAGE, None);
        assert_eq!(flag_value(&args, "--restart"), vec!["unless-stopped"]);
    }

    /// Something else on the database port while the container is stopped is not the
    /// database: the container is started, and never replaced, which would leave its
    /// data behind.
    #[test]
    fn the_container_says_whether_the_database_is_up_not_the_port() {
        let stopped = serde_json::json!({"State": {"Running": false}});
        let running = serde_json::json!({"State": {"Running": true}});
        assert_eq!(plan(Some(&stopped), true, true), Plan::Start);
        assert_eq!(plan(Some(&stopped), false, true), Plan::Start);
        assert_eq!(plan(Some(&stopped), true, false), Plan::Start);
        assert_eq!(plan(Some(&running), true, true), Plan::Up);
        assert_eq!(plan(Some(&running), true, false), Plan::Up);
        // A container config.toml names that is gone is made again.
        assert_eq!(plan(None, true, true), Plan::Make);
        assert_eq!(plan(None, true, false), Plan::Make);
        // With no container of ours, a database on the port is the operator's own.
        assert_eq!(plan(None, false, true), Plan::Up);
        assert_eq!(plan(None, false, false), Plan::Make);
    }

    #[test]
    fn a_container_without_a_restart_policy_is_given_one() {
        let policy =
            |name: &str| serde_json::json!({"HostConfig": {"RestartPolicy": {"Name": name}}});
        assert!(lacks_restart_policy(&policy("no")));
        assert!(lacks_restart_policy(&policy("")));
        assert!(lacks_restart_policy(&serde_json::json!({"HostConfig": {}})));
        assert!(!lacks_restart_policy(&policy("unless-stopped")));
        assert!(!lacks_restart_policy(&policy("always")));
    }

    fn inspected(host_ip: &str, env: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "Id": "abc",
            "Image": "sha256:abc",
            "State": { "Running": true },
            "Config": { "Env": env },
            "HostConfig": { "PortBindings": {
                "5432/tcp": [ { "HostIp": host_ip, "HostPort": "4440" } ]
            } }
        })
    }

    #[test]
    fn a_container_made_by_0_1_42_is_open_on_the_network_and_trusting() {
        let info = inspected(
            "",
            &[
                "POSTGRES_USER=postgres",
                "POSTGRES_DB=crossfyre",
                "POSTGRES_HOST_AUTH_METHOD=trust",
            ],
        );
        assert_eq!(
            assess(&info),
            Exposure {
                on_network: true,
                trust: true
            }
        );
    }

    #[test]
    fn a_binding_on_any_other_address_counts_as_open() {
        for ip in ["0.0.0.0", "::", "192.168.1.20"] {
            assert!(
                assess(&inspected(ip, &["POSTGRES_PASSWORD"])).on_network,
                "{ip}"
            );
        }
    }

    #[test]
    fn a_loopback_container_with_a_password_is_left_alone() {
        let info = inspected("127.0.0.1", &["POSTGRES_PASSWORD=x"]);
        assert_eq!(
            assess(&info),
            Exposure {
                on_network: false,
                trust: false
            }
        );
    }

    #[test]
    fn sql_quoting_doubles_quotes() {
        assert_eq!(sql_literal("a'b"), "'a''b'");
        assert_eq!(sql_ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn only_local_hosts_count_as_this_machine() {
        for h in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "::1",
            "[::1]",
            "",
            "0.0.0.0",
        ] {
            assert!(is_local_host(h), "{h}");
        }
        for h in ["db.example.internal", "192.0.2.10"] {
            assert!(!is_local_host(h), "{h}");
        }
    }

    #[test]
    fn the_copy_of_an_old_server_takes_no_network_clients() {
        let rules: Vec<&str> = KNOWN_HBA
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .collect();
        assert!(!rules.is_empty());
        for r in rules {
            assert!(r.starts_with("local "), "{r}");
        }
    }

    #[test]
    fn a_docker_that_cannot_run_is_an_error_not_a_missing_container() {
        let err = inspect_cmd(Command::new("/nonexistent/bin/docker"), "anything");
        assert!(err.is_err(), "{err:?}");
    }

    fn config_with_id(dir: &Path, id: Option<&str>) -> PathBuf {
        let path = dir.join("config.toml");
        let id_line = id.map(|i| format!("id = \"{i}\"\n")).unwrap_or_default();
        std::fs::write(
            &path,
            format!(
                "[postgres]\nhost = \"localhost\"\nport = 4440\nuser = \"postgres\"\n\
                 db_name = \"crossfyre\"\n\n[container]\n{id_line}"
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn a_recorded_container_docker_cannot_be_asked_about_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_id(dir.path(), Some("0123456789ab"));
        let missing = DockerCli {
            program: PathBuf::from("/nonexistent/bin/docker"),
            as_operator: false,
            host: None,
        };
        for cands in [vec![], vec![missing]] {
            let result = secure_using(&cands, "cfx-unreached", &cfg);
            assert!(result.is_err(), "{cands:?}: {result:?}");
        }
    }

    #[test]
    fn no_docker_and_no_recorded_container_is_nothing_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_id(dir.path(), None);
        assert!(!secure_using(&[], "cfx-unreached", &cfg).unwrap());
    }

    #[test]
    fn docker_is_found_where_a_service_path_does_not_look() {
        let dir = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        };
        std::fs::write(dir.path().join(name), "").unwrap();
        let short = std::env::join_paths(["/nonexistent-a", "/nonexistent-b"]).unwrap();
        assert_eq!(
            find_docker(Some(&short), &[dir.path().to_path_buf()]),
            Some(dir.path().join(name))
        );
        // A relative PATH entry is never used.
        let rel = tempfile::tempdir_in(".").unwrap();
        std::fs::write(rel.path().join(name), "").unwrap();
        let rel_name = rel.path().file_name().unwrap().to_os_string();
        let path = std::env::join_paths([PathBuf::from(&rel_name)]).unwrap();
        assert_eq!(find_docker(Some(&path), &[]), None);
    }

    #[test]
    fn only_one_run_works_on_the_container_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        let held = lock_db(&cfg, Duration::ZERO).expect("the first run gets the lock");
        let cfg2 = cfg.clone();
        let other = std::thread::spawn(move || lock_db(&cfg2, Duration::from_millis(300)).is_ok())
            .join()
            .unwrap();
        assert!(!other, "a second run got the lock while the first held it");
        drop(held);
        assert!(lock_db(&cfg, Duration::ZERO).is_ok(), "released on drop");
    }

    #[test]
    fn a_database_reached_by_another_name_for_this_machine_is_local() {
        for h in ["127.0.1.1", "127.1.2.3"] {
            assert!(is_local_host(h), "{h}");
        }
        // Some hosts cannot resolve their own name, which makes no claim to test.
        let name = hostname();
        let resolves = {
            use std::net::ToSocketAddrs;
            !name.is_empty() && (name.as_str(), 0u16).to_socket_addrs().is_ok()
        };
        if resolves {
            assert!(is_local_host(&name), "this machine's own name, {name}");
        }
        // An address of this machine on its network, if it has one.
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if sock.connect("192.0.2.1:9").is_ok() {
            let ip = sock.local_addr().unwrap().ip();
            if !ip.is_unspecified() {
                assert!(is_local_host(&ip.to_string()), "{ip}");
            }
        }
    }

    fn hostname() -> String {
        Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }

    #[test]
    fn a_new_container_for_an_external_database_does_not_write_its_password() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[postgres]\nhost = \"db.example.internal\"\nport = 5432\nuser = \"postgres\"\n\
             db_name = \"crossfyre\"\n\n[container]\n",
        )
        .unwrap();
        let (_, password, generated) = up_password(&cfg).unwrap();
        assert!(!password.is_empty(), "the container still gets a password");
        assert!(
            !generated,
            "the engines use another database and need no restart"
        );
        assert_eq!(
            load_config_at(&cfg).unwrap().postgres.password,
            None,
            "a password for the local container was put in the external database's config"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_docker_others_could_replace_is_not_run_by_an_elevated_process() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("docker");
        std::fs::write(&fake, "").unwrap();
        // The test runs as an ordinary user, so the directory is not root's.
        let dirs = vec![dir.path().to_path_buf()];
        let as_self: Vec<bool> = candidates_in(None, dirs.clone(), false, None)
            .iter()
            .map(|c| c.as_operator)
            .collect();
        assert_eq!(
            as_self,
            vec![false],
            "an unprivileged run uses it as itself"
        );

        let elevated = candidates_in(None, dirs.clone(), true, None);
        assert!(
            elevated.iter().all(|c| c.as_operator),
            "run with full rights from a directory a user can write: {elevated:?}"
        );
        let home = tempfile::tempdir().unwrap();
        let with_operator = candidates_in(None, dirs, true, Some(home.path()));
        assert_eq!(
            with_operator,
            vec![DockerCli {
                program: fake,
                as_operator: true,
                host: None,
            }],
            "it is still used, as the operator"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_file_is_handed_to_the_operator_only_when_it_is_safe_to() {
        // Run with sudo: the file is given to the operator, so it must be a file of
        // its own that belongs to root or the operator.
        assert!(lock_file_usable(true, 1, 0, 0, Some(1000)));
        assert!(lock_file_usable(true, 1, 1000, 0, Some(1000)));
        assert!(!lock_file_usable(true, 2, 1000, 0, Some(1000)));
        assert!(!lock_file_usable(true, 1, 1001, 0, Some(1000)));
        assert!(!lock_file_usable(false, 1, 0, 0, Some(1000)));
        // Root with no operator to hand it to, from a root login shell say, only locks
        // it, which is harmless on any file of its own.
        assert!(lock_file_usable(true, 1, 1000, 0, None));
        assert!(!lock_file_usable(true, 2, 1000, 0, None));
        assert!(!lock_file_usable(false, 1, 1000, 0, None));
    }

    /// The statements the engines run to make their tables, from their sources, with
    /// whitespace made single spaces.
    fn engine_statements(source: &str) -> Vec<String> {
        let text = source.replace("\r\n", "\n").replace("\\\n", "");
        let mut out = Vec::new();
        for start in ["CREATE TABLE IF NOT EXISTS", "CREATE INDEX IF NOT EXISTS"] {
            for (i, _) in text.match_indices(start) {
                let end = text[i..].find(['"', '#']).map_or(text.len(), |e| i + e);
                out.push(
                    text[i..end]
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
        }
        out.sort();
        out
    }

    const ENGINE_SOURCES: [(&str, &str); 3] = [
        (
            "mach",
            include_str!("../../../ambulo/src/libs/ambulo_db.rs"),
        ),
        (
            "voyage",
            include_str!("../../../voyage/src/libs/voyage_db.rs"),
        ),
        (
            "pulse",
            include_str!("../../../doorward/src/libs/doorward_db.rs"),
        ),
    ];

    /// A Windows checkout may have CRLF line endings, which must not change what the
    /// engines' statements are read as.
    #[test]
    fn the_engines_statements_read_the_same_with_crlf_line_endings() {
        for (db, source) in ENGINE_SOURCES {
            let lf = source.replace("\r\n", "\n");
            assert_eq!(
                engine_statements(&lf.replace('\n', "\r\n")),
                engine_statements(&lf),
                "{db}"
            );
        }
    }

    #[test]
    fn the_engines_tables_are_made_as_the_engines_make_them() {
        assert_eq!(ENGINE_SCHEMA.len(), ENGINE_SOURCES.len());
        for (db, source) in ENGINE_SOURCES {
            let (_, ours) = ENGINE_SCHEMA
                .iter()
                .find(|(d, _)| *d == db)
                .unwrap_or_else(|| panic!("no tables for {db}"));
            let mut ours: Vec<String> = ours
                .iter()
                .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect();
            ours.sort();
            assert_eq!(ours, engine_statements(source), "{db}");
        }
    }

    #[test]
    fn every_table_is_made_after_the_tables_it_refers_to() {
        for (db, statements) in ENGINE_SCHEMA {
            let mut made: Vec<&str> = Vec::new();
            for s in *statements {
                for (i, _) in s.match_indices("REFERENCES ") {
                    let target = s[i + "REFERENCES ".len()..]
                        .split(['(', ' '])
                        .next()
                        .unwrap();
                    assert!(made.contains(&target), "{db}: {target} before {s}");
                }
                if let Some(t) = table_of(s) {
                    made.push(t);
                }
            }
        }
        assert_eq!(
            table_of("CREATE TABLE IF NOT EXISTS logs ( id TEXT )"),
            Some("logs")
        );
        assert_eq!(table_of("CREATE INDEX IF NOT EXISTS i ON logs(id)"), None);
    }

    #[test]
    fn only_a_line_that_is_one_whole_row_is_passed_on() {
        assert!(one_row(b"1\tcommon\t\\N", 3));
        assert!(one_row(b"1\ta\\tb\\nc\\\\d\th", 3));
        assert!(one_row(b"", 1));
        assert!(!one_row(b"1\tcommon", 3));
        assert!(!one_row(b"1\tcommon\th\textra", 3));
        assert!(!one_row(b"\\.", 1));
        assert!(!one_row(b"\\.\r", 1));
        assert!(!one_row(b"1\ta\rb\th", 3));
    }

    /// A reader that hands out one byte at a time, so every row is split across reads.
    struct ByteAtATime<'a>(&'a [u8]);
    impl std::io::Read for ByteAtATime<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some((&b, rest)) = self.0.split_first() else {
                return Ok(0);
            };
            buf[0] = b;
            self.0 = rest;
            Ok(1)
        }
    }

    #[test]
    fn rows_are_checked_however_they_are_split() {
        let mut out = Vec::new();
        let rows = pass_rows(ByteAtATime(b"1\ta\n2\t\\N\n3\tlast"), &mut out, 2).unwrap();
        assert_eq!(rows, Ok(3));
        assert_eq!(out, b"1\ta\n2\t\\N\n3\tlast\n");

        // The newline that would end a line that is not a row is never passed on.
        let mut out = Vec::new();
        let rows = pass_rows(ByteAtATime(b"x\n\\.\nCOMMIT;\n"), &mut out, 1).unwrap();
        assert_eq!(rows, Err(2));
        assert_eq!(out, b"x\n\\.");
        let mut out = Vec::new();
        let rows = pass_rows(ByteAtATime(b"1\ta\n2\tb\r\n"), &mut out, 2).unwrap();
        assert_eq!(rows, Err(2));
        assert_eq!(out, b"1\ta\n2\tb\r");
        assert_eq!(pass_rows(&b""[..], &mut Vec::new(), 2).unwrap(), Ok(0));
    }

    #[test]
    fn rows_the_new_server_refuses_are_told_from_other_failures() {
        for (said, refused) in [
            (
                "psql:<stdin>:2: ERROR:  22P02: invalid input syntax for type integer: \"none\"\n\
                 CONTEXT:  COPY probe_results, line 1, column port: \"none\"",
                true,
            ),
            (
                "psql:<stdin>:2: ERROR:  23503: insert or update on table \"words\" violates \
                 foreign key constraint",
                true,
            ),
            (
                "psql:<stdin>:2: ERROR:  54000: index row size 9000 exceeds btree version 4 \
                 maximum 2704",
                true,
            ),
            (
                "psql:<stdin>:2: ERROR:  53100: could not extend file \"base/16384/16390\": \
                 No space left on device",
                false,
            ),
            (
                "psql:<stdin>:3: ERROR:  P0001: it holds a different number of rows than were \
                 sent",
                false,
            ),
            (
                "psql:<stdin>:2: ERROR:  53100: could not extend file: ERROR:  22P02: x",
                false,
            ),
            (
                "Error response from daemon: container is not running",
                false,
            ),
            ("", false),
        ] {
            assert_eq!(rows_refused(said), refused, "{said}");
        }
    }

    #[test]
    fn the_old_cluster_is_read_as_the_user_it_was_made_with() {
        let info = |env: &[&str]| serde_json::json!({ "Config": { "Env": env } });
        assert_eq!(
            made_with_user(&info(&["POSTGRES_USER=scan", "LANG=C"])),
            "scan"
        );
        assert_eq!(made_with_user(&info(&["POSTGRES_USER="])), "postgres");
        assert_eq!(made_with_user(&info(&["POSTGRES_DB=x"])), "postgres");
    }

    #[test]
    fn the_rebuild_notice_names_every_container_that_keeps_old_data() {
        let kept = ["db-old-1".to_string(), "db-old-2".to_string()];
        let lines = rebuilt_notice(None, &kept);
        let all = lines.join("\n");
        assert!(all.contains("accepted connections without a password"));
        assert!(all.contains("review scan results"));
        for k in &kept {
            assert!(all.contains(&format!("docker rm -v {k}")), "{all}");
        }
        let copied = Copied {
            tables: 2,
            rows: 5,
            left_empty: vec!["pulse.probe_results: x".to_string()],
        };
        let all = rebuilt_notice(Some(&copied), &kept[..1]).join("\n");
        assert!(all.contains("5 in 2 tables") && all.contains("left empty: pulse.probe_results"));
    }

    #[test]
    fn a_failed_repair_says_how_to_try_again_before_how_to_start_over() {
        let retry = STOPPED
            .find("crossfyre db restart")
            .expect("names db restart");
        let over = STOPPED.find("crossfyre db down").expect("names db down");
        assert!(retry < over);
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_is_not_followed_through_a_hard_link() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("someone-elses-file");
        std::fs::write(&target, "x").unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::hard_link(&target, lock_path(&cfg)).unwrap();
        assert!(try_lock(&lock_path(&cfg)).is_err());
    }

    // Against a real Docker daemon. Run with:
    //   cargo test -p cfx_core toolchain::db::docker -- --ignored --test-threads=1
    mod docker {
        use super::super::*;
        use std::net::{SocketAddr, TcpStream};
        use std::time::Duration;

        struct Cleanup(Vec<String>);
        impl Cleanup {
            fn for_name(name: &str) -> Self {
                Cleanup(vec![
                    name.to_string(),
                    format!("{name}-new"),
                    format!("{name}-fix"),
                ])
            }
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let mut volumes = Vec::new();
                let mut names = self.0.clone();
                // The containers that keep old data, named after the time they were made.
                if let Ok(out) = docker()
                    .args(["ps", "-a", "--format", "{{.Names}}", "--filter"])
                    .arg(format!("name={}-old-", self.0[0]))
                    .output()
                {
                    names.extend(
                        String::from_utf8_lossy(&out.stdout)
                            .lines()
                            .map(str::to_string),
                    );
                }
                for name in &names {
                    if let Ok(Some(info)) = inspect(name) {
                        for m in info["Mounts"].as_array().into_iter().flatten() {
                            if let Some(v) = m["Name"].as_str() {
                                volumes.push(v.to_string());
                            }
                        }
                    }
                    let _ = docker().args(["rm", "-f", "-v", name]).output();
                }
                for v in volumes {
                    let _ = docker().args(["volume", "rm", "-f", &v]).output();
                }
            }
        }

        fn free_port() -> u16 {
            std::net::TcpListener::bind("0.0.0.0:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }

        fn write_config(path: &Path, port: u16, id: Option<&str>) {
            let id_line = id.map(|i| format!("id = \"{i}\"\n")).unwrap_or_default();
            std::fs::write(
                path,
                format!(
                    "[postgres]\nhost = \"localhost\"\nport = {port}\nuser = \"postgres\"\n\
                     db_name = \"crossfyre\"\n\n[container]\n{id_line}"
                ),
            )
            .unwrap();
        }

        fn bridge(name: &str) -> (String, String) {
            let info = inspect(name).unwrap().expect("container exists");
            let net = &info["NetworkSettings"]["Networks"]["bridge"];
            (
                net["IPAddress"].as_str().unwrap().to_string(),
                net["Gateway"].as_str().unwrap().to_string(),
            )
        }

        fn wait_tcp_ready(name: &str) {
            for _ in 0..120 {
                let ok = docker()
                    .args(["exec", name, "pg_isready", "-q", "-h", "127.0.0.1"])
                    .status()
                    .is_ok_and(|s| s.success());
                if ok {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            panic!("{name} never became ready");
        }

        /// Psql over TCP to the container's own bridge address, which is matched by
        /// the same `host all all all` rule a client from the network is.
        fn psql_over_tcp(name: &str, password: Option<&str>, sql: &str) -> Result<String, String> {
            let (ip, _) = bridge(name);
            let mut cmd = docker();
            cmd.args(["exec"]);
            if let Some(p) = password {
                cmd.args(["-e", &format!("PGPASSWORD={p}")]);
            }
            let out = cmd
                .args([name, "psql", "-w", "-X", "-h", &ip, "-U", "postgres"])
                .args(["-d", "crossfyre", "-tAc", sql])
                .output()
                .unwrap();
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).to_string())
            }
        }

        fn reachable(ip: &str, port: u16) -> bool {
            let addr: SocketAddr = format!("{ip}:{port}").parse().unwrap();
            TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
        }

        fn host_ips(name: &str) -> Vec<String> {
            let info = inspect(name).unwrap().unwrap();
            info["HostConfig"]["PortBindings"]["5432/tcp"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b["HostIp"].as_str().unwrap_or("").to_string())
                .collect()
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_container_from_0_1_42_is_moved_to_loopback_with_a_password_and_keeps_its_data() {
            let name = format!("cfx-dbtest-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();

            // Exactly what `db up` ran in 0.1.42 for a config without a password.
            let out = docker()
                .args(["run", "-d", "--name", &name, "-p", &format!("{port}:5432")])
                .args([
                    "-e",
                    "POSTGRES_USER=postgres",
                    "-e",
                    "POSTGRES_DB=crossfyre",
                ])
                .args(["-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres"])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let old_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            write_config(&cfg, port, Some(&old_id));
            wait_tcp_ready(&name);
            psql_over_tcp(&name, None, "SELECT 1").expect("the 0.1.42 container lets anyone in");
            seed_mach(&name);
            let (_, gateway) = bridge(&name);
            assert!(
                reachable(&gateway, port),
                "0.1.42 published beyond loopback"
            );

            assert!(
                secure_at(&name, &cfg).expect("secured"),
                "reported a change"
            );

            let config = load_config_at(&cfg).unwrap();
            let password = config.postgres.password.clone().expect("a password");
            assert_eq!(password.len(), 64);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&cfg).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "config.toml holds the password");
            }
            let new_id = config.container.id.clone().expect("the new container's id");
            assert_ne!(new_id, old_id);
            assert!(
                inspect(&old_id).unwrap().is_none(),
                "the old container is gone"
            );
            assert_eq!(host_ips(&name), vec!["127.0.0.1"]);
            let info = inspect(&name).unwrap().unwrap();
            assert!(!assess(&info).trust);

            assert!(
                !reachable(&gateway, port),
                "still published beyond loopback"
            );
            assert!(reachable("127.0.0.1", port), "not published on loopback");
            wait_tcp_ready(&name);
            assert!(
                psql_over_tcp(&name, None, "SELECT 1").is_err(),
                "still lets a client in without a password"
            );
            assert!(psql_over_tcp(&name, Some("wrong"), "SELECT 1").is_err());
            assert_eq!(
                sql_in(
                    &name,
                    "mach",
                    "SELECT name FROM wordlists WHERE hash = 'h1'"
                )
                .unwrap(),
                "common",
                "the data survived"
            );

            assert!(
                !secure_at(&name, &cfg).unwrap(),
                "a second run changes nothing"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_new_container_is_on_loopback_and_needs_the_generated_password() {
            let name = format!("cfx-dbtest-up-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let mut config = super::super::super::config::load_or_create_config_at(&cfg).unwrap();
            config.postgres.port = port;
            save_config_at(&cfg, &config).unwrap();

            up_at(&name, &cfg).unwrap();
            let config = load_config_at(&cfg).unwrap();
            let password = config.postgres.password.clone().expect("a password");

            assert_eq!(host_ips(&name), vec!["127.0.0.1"]);
            let (_, gateway) = bridge(&name);
            assert!(!reachable(&gateway, port), "published beyond loopback");
            wait_tcp_ready(&name);
            assert!(
                psql_over_tcp(&name, None, "SELECT 1").is_err(),
                "no password needed"
            );
            assert_eq!(
                psql_over_tcp(&name, Some(&password), "SELECT 1").unwrap(),
                "1"
            );
            assert!(!secure_at(&name, &cfg).unwrap(), "nothing left to secure");
            let info = inspect(&name).unwrap().unwrap();
            assert_eq!(info["HostConfig"]["RestartPolicy"]["Name"], RESTART_POLICY);
        }

        /// A loopback container with a password but no restart policy, as made before
        /// the policy, is given one and otherwise left alone.
        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_safe_container_without_a_restart_policy_is_given_one() {
            let name = format!("cfx-dbtest-policy-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let out = docker()
                .args([
                    "run",
                    "-d",
                    "--name",
                    &name,
                    "-p",
                    &format!("127.0.0.1:{port}:5432"),
                ])
                .args(["-e", "POSTGRES_PASSWORD=pw", IMAGE])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            write_config(&cfg, port, Some(&id));
            assert!(lacks_restart_policy(&inspect(&id).unwrap().unwrap()));

            assert!(
                !secure_at(&name, &cfg).unwrap(),
                "a safe container was replaced"
            );
            let info = inspect(&id).unwrap().unwrap();
            assert_eq!(info["HostConfig"]["RestartPolicy"]["Name"], RESTART_POLICY);
            assert_eq!(info["Id"], id.as_str());
        }

        /// A container made exactly as `db up` made it in 0.1.42 for a config without
        /// a password, ready for connections. Returns its id.
        fn open_0_1_42(name: &str, port: u16) -> String {
            let out = docker()
                .args(["run", "-d", "--name", name, "-p", &format!("{port}:5432")])
                .args([
                    "-e",
                    "POSTGRES_USER=postgres",
                    "-e",
                    "POSTGRES_DB=crossfyre",
                ])
                .args(["-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres"])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            wait_tcp_ready(name);
            id
        }

        fn is_running(target: &str) -> bool {
            inspect(target).unwrap().expect("container exists")["State"]["Running"]
                .as_bool()
                .unwrap()
        }

        fn write_config_as(path: &Path, port: u16, id: &str, host: &str, user: &str) {
            std::fs::write(
                path,
                format!(
                    "[postgres]\nhost = \"{host}\"\nport = {port}\nuser = \"{user}\"\n\
                     db_name = \"crossfyre\"\n\n[container]\nid = \"{id}\"\n"
                ),
            )
            .unwrap();
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_stopped_container_that_cannot_be_secured_is_left_stopped() {
            let name = format!("cfx-dbtest-stopped-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            // A data directory no server will start on, so its rows cannot be read.
            sh_as_postgres(&name, "echo 1 > \"$PGDATA/PG_VERSION\"");
            docker_ok(&["stop", &id]).unwrap();
            write_config(&cfg, port, Some(&id));

            assert!(secure_at(&name, &cfg).is_err());

            assert!(
                !is_running(&id),
                "a stopped container was left running while it still lets anyone in"
            );
            assert!(
                inspect(&format!("{name}-fix")).unwrap().is_none(),
                "the offline copy is removed"
            );
            assert!(!reachable("127.0.0.1", port));
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_stopped_container_is_secured_and_stays_stopped() {
            let name = format!("cfx-dbtest-stopped-ok-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            seed_mach(&name);
            docker_ok(&["stop", &id]).unwrap();
            write_config(&cfg, port, Some(&id));

            assert!(secure_at(&name, &cfg).unwrap());

            assert!(
                !is_running(&name),
                "it was stopped before, so it stays stopped"
            );
            assert_eq!(host_ips(&name), vec!["127.0.0.1"]);
            let password = load_config_at(&cfg).unwrap().postgres.password.unwrap();
            docker_ok(&["start", &name]).unwrap();
            wait_tcp_ready(&name);
            assert!(psql_over_tcp(&name, None, "SELECT 1").is_err());
            assert_eq!(
                psql_over_tcp(&name, Some(&password), "SELECT 1").unwrap(),
                "1"
            );
            assert_eq!(
                sql_in(&name, "mach", "SELECT count(*) FROM wordlists").unwrap(),
                "2"
            );
        }

        /// A container made with `labelled_run_args`, as `rebuild` makes it, on a data
        /// volume of its own, for an old container that was running or not. Returns its
        /// id.
        fn rebuilt_copy(
            name: &str,
            config: &ToolchainConfig,
            image: &str,
            password: &str,
            was_running: bool,
        ) -> String {
            let more: Vec<String> = if was_running {
                vec![
                    "--label".to_string(),
                    "io.crossfyre.db.was-running=true".to_string(),
                ]
            } else {
                Vec::new()
            };
            let out = docker()
                .args(labelled_run_args(
                    &format!("{name}-new"),
                    &config.postgres,
                    image,
                    None,
                    REBUILT,
                    &more,
                ))
                .env(PASSWORD_ENV, password)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn image_of(target: &str) -> String {
            inspect(target).unwrap().unwrap()["Image"]
                .as_str()
                .unwrap()
                .to_string()
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_rebuild_stopped_before_the_old_container_was_removed_starts_again() {
            let name = format!("cfx-dbtest-resume-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let old_id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&old_id));
            seed_mach(&name);
            let (config, _) = ensure_postgres_password_at(&cfg).unwrap();
            let password = config.postgres.password.clone().unwrap();
            // The run stopped the old container, which was running, and made a copy
            // whose rows were not all in when it was cut short.
            docker_ok(&["stop", &old_id]).unwrap();
            let leftover = rebuilt_copy(&name, &config, &image_of(&old_id), "half-done", true);
            let leftover_volumes = mounts(&leftover);

            assert!(secure_at(&name, &cfg).unwrap());

            assert!(
                is_running(&name),
                "the old container was running before the first run stopped it"
            );
            assert!(
                inspect(&old_id).unwrap().is_none(),
                "the old container is gone"
            );
            let now = inspect(&name).unwrap().unwrap();
            assert_ne!(now["Id"].as_str(), Some(leftover.as_str()));
            for v in &leftover_volumes {
                assert!(
                    docker_ok(&["volume", "inspect", v]).is_err(),
                    "the half filled copy's volume {v} is left behind"
                );
            }
            docker_ok(&["start", &name]).unwrap();
            wait_tcp_ready(&name);
            assert_eq!(
                sql_in(&name, "mach", "SELECT count(*) FROM wordlists").unwrap(),
                "2"
            );
            assert_eq!(
                psql_over_tcp(&name, Some(&password), "SELECT 1").unwrap(),
                "1"
            );
        }

        #[test]
        #[ignore = "needs Docker"]
        fn a_daemon_that_cannot_be_reached_is_an_error() {
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            write_config(&cfg, 4440, Some("0123456789ab"));
            let program = find_docker(std::env::var_os("PATH").as_deref(), &[]).expect("docker");
            let dead = DockerCli {
                program,
                as_operator: false,
                host: Some("unix:///nonexistent/docker.sock".to_string()),
            };
            assert!(inspect_cmd(dead.command(), "anything").is_err());
            assert!(secure_using(&[dead], "cfx-unreached", &cfg).is_err());
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_leftover_container_does_not_put_a_password_in_an_external_config() {
            let name = format!("cfx-dbtest-ext-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config_as(&cfg, port, &id, "db.example.internal", "postgres");

            assert!(secure_at(&name, &cfg).unwrap());

            assert_eq!(load_config_at(&cfg).unwrap().postgres.password, None);
            assert_eq!(host_ips(&name), vec!["127.0.0.1"]);
            wait_tcp_ready(&name);
            assert!(psql_over_tcp(&name, None, "SELECT 1").is_err());
        }

        /// Every engine table's rows as text, in one value per table.
        fn engine_rows(name: &str) -> Vec<String> {
            let mut out = Vec::new();
            for (db, statements) in ENGINE_SCHEMA {
                for table in statements.iter().filter_map(|s| table_of(s)) {
                    out.push(format!(
                        "{db}.{table}: {}",
                        sql_in(
                            name,
                            db,
                            &format!(
                                "SELECT count(*) || ' ' || coalesce(md5(string_agg(t::text, '|' \
                                 ORDER BY t::text)), '') FROM public.{table} t"
                            ),
                        )
                        .unwrap()
                    ));
                }
            }
            out
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn the_rows_of_every_engine_are_carried_over() {
            let name = format!("cfx-dbtest-rows-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            for (db, statements) in ENGINE_SCHEMA {
                sql_in(&name, "postgres", &format!("CREATE DATABASE {db}")).unwrap();
                sql_in(&name, db, &statements.join("; ")).unwrap();
            }
            let later = "NOW() + INTERVAL '1 day'";
            for (db, sql) in [
                (
                    "mach",
                    "INSERT INTO wordlists (name, hash) VALUES ('common', 'h1'); \
                     INSERT INTO words (word, wordlist_id) VALUES ('admin', 1), \
                     (E'odd\\tword\\n', 1), ('\\x', 1); \
                     INSERT INTO scans (config_hash, method, wordlist_id) VALUES ('c', 'GET', 1); \
                     INSERT INTO urls (url, scan_id) VALUES ('https://a.example/', 1); \
                     INSERT INTO scan_entries (scan_id, url_id, word_id, status, headers, \
                     headers_length, body, body_length) VALUES (1, 1, 2, 'found', \
                     E'a: b\\r\\n', 6, '\\x00090a0d5c2e'::bytea, 6), \
                     (1, 1, 1, 'queued', NULL, 0, NULL, 0); \
                     INSERT INTO logs (scan_id, description) VALUES (1, 'started'); \
                     INSERT INTO operations (id, operation, params) VALUES ('op1', 'fuzz', '{}')",
                ),
                (
                    "voyage",
                    "INSERT INTO scans (id, config_hash, domain) VALUES ('s1', 'c', 'a.example'); \
                     INSERT INTO scan_entries (scan_id, full_subdomain, source) VALUES \
                     ('s1', 'www.a.example', 'crt'); \
                     INSERT INTO logs (message) VALUES ('x')",
                ),
                (
                    "pulse",
                    "INSERT INTO scans (id, config_hash, targets, ports) VALUES \
                     ('p1', 'c', '10.0.0.1', '22'); \
                     INSERT INTO scan_entries (scan_id, host, port, banner) VALUES \
                     ('p1', '10.0.0.1', 22, E'SSH-2.0\\r\\n')",
                ),
            ] {
                sql_in(&name, db, sql).unwrap();
            }
            sql_in(
                &name,
                "mach",
                &format!(
                    "INSERT INTO probe_results (operation_id, url, status, delete_after) \
                     VALUES ('op1', 'https://a.example/x', 'found', {later}); \
                     INSERT INTO probe_results (operation_id, url, status, created_at, \
                     delete_after) VALUES ('op1', 'https://a.example/y', 'found', \
                     '2026-01-31 10:00:00+00', {later})"
                ),
            )
            .unwrap();
            let before = engine_rows(&name);
            // Dates written another way than the new server reads them by default.
            sql_in(
                &name,
                "postgres",
                "ALTER DATABASE mach SET DateStyle = 'SQL, DMY'",
            )
            .unwrap();
            // A column an older engine did not have yet, and a table whose rows no
            // longer fit the engine's.
            sql_in(
                &name,
                "voyage",
                "ALTER TABLE scan_entries DROP COLUMN source",
            )
            .unwrap();
            sql_in(
                &name,
                "pulse",
                "ALTER TABLE probe_results ALTER COLUMN port TYPE text; \
                 INSERT INTO probe_results (operation_id, host, port, status, delete_after) \
                 VALUES ('o', 'h', 'none', 'open', NOW())",
            )
            .unwrap();

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            let after = engine_rows(&name);
            for (b, a) in before.iter().zip(&after) {
                if b.starts_with("voyage.scan_entries") || b.starts_with("pulse.probe_results") {
                    continue;
                }
                assert_eq!(a, b);
            }
            assert_eq!(
                sql_in(
                    &name,
                    "voyage",
                    "SELECT full_subdomain || '|' || source FROM scan_entries"
                )
                .unwrap(),
                "www.a.example|",
                "a column the old table lacks gets the engine's default"
            );
            assert_eq!(
                sql_in(&name, "pulse", "SELECT count(*) FROM probe_results").unwrap(),
                "0",
                "rows that do not fit are left out"
            );
            assert_eq!(
                sql_in(
                    &name,
                    "mach",
                    "INSERT INTO words (word, wordlist_id) VALUES ('next', 1) RETURNING id"
                )
                .unwrap(),
                "4"
            );
        }

        /// A shell script run in the container as the postgres account.
        fn sh_as_postgres(name: &str, script: &str) {
            let out = docker()
                .args(["exec", "-u", "postgres", name, "sh", "-c", script])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        /// One value from the server over its local socket.
        fn local_value(name: &str, sql: &str) -> String {
            let out = docker()
                .args([
                    "exec", "-u", "postgres", name, "psql", "-X", "-U", "postgres",
                ])
                .args(["-d", "postgres", "-tAc", sql])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn running_open(target: &str) -> bool {
            matches!(inspect(target), Ok(Some(info)) if info["State"]["Running"].as_bool() == Some(true))
                && psql_over_tcp(target, None, "SELECT 1").is_ok()
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_running_container_that_cannot_be_secured_ends_up_stopped() {
            let name = format!("cfx-dbtest-runfail-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            // A data directory no server will start on again, so its rows cannot be read.
            sh_as_postgres(&name, "echo 1 > \"$PGDATA/PG_VERSION\"");
            write_config(&cfg, port, Some(&id));

            assert!(secure_at(&name, &cfg).is_err());

            assert!(
                !is_running(&id),
                "a container that lets anyone in was left running after the repair failed"
            );
            assert!(!reachable("127.0.0.1", port));
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_server_set_to_refuse_the_repair_is_still_closed() {
            let name = format!("cfx-dbtest-refuse-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            psql_over_tcp(
                &name,
                None,
                "COPY (SELECT 1) TO PROGRAM 'sed -i \"1i local all all reject\" \"$PGDATA/pg_hba.conf\"'",
            )
            .unwrap();
            psql_over_tcp(&name, None, "SELECT pg_reload_conf()").unwrap();

            let result = secure_at(&name, &cfg);

            assert!(
                !running_open(&id) && !running_open(&name),
                "still lets a client in without a password after {result:?}"
            );
            assert!(result.unwrap(), "the repair goes ahead regardless");
            let password = load_config_at(&cfg).unwrap().postgres.password.unwrap();
            wait_tcp_ready(&name);
            assert_eq!(
                psql_over_tcp(&name, Some(&password), "SELECT 1").unwrap(),
                "1"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_moved_auth_file_does_not_survive_the_repair() {
            let name = format!("cfx-dbtest-hbafile-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            sh_as_postgres(
                &name,
                "printf 'local all all trust\\nhost all all all trust\\n' > \"$PGDATA/x_hba.conf\" && \
                 echo \"hba_file = '$PGDATA/x_hba.conf'\" >> \"$PGDATA/postgresql.conf\"",
            );
            let pgdata = local_value(&name, "SHOW data_directory");
            psql_over_tcp(
                &name,
                None,
                &format!("ALTER SYSTEM SET hba_file = '{pgdata}/x_hba.conf'"),
            )
            .unwrap();

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            assert!(
                psql_over_tcp(&name, None, "SELECT 1").is_err(),
                "the moved file still lets a client in without a password"
            );
            assert_eq!(
                local_value(&name, "SHOW hba_file"),
                format!("{pgdata}/pg_hba.conf")
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn only_password_rules_are_left_for_network_clients() {
            let name = format!("cfx-dbtest-ldap-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            sh_as_postgres(
                &name,
                "sed -i '1i host all all 0.0.0.0/0 ldap ldapserver=ldap.invalid' \"$PGDATA/pg_hba.conf\"",
            );

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            assert_eq!(
                local_value(
                    &name,
                    // The image's own rules for the container's loopback, which no
                    // client outside the container connects from, are allowed.
                    "SELECT string_agg(DISTINCT auth_method, ',') FROM pg_hba_file_rules \
                     WHERE type LIKE 'host%' AND auth_method NOT IN ('scram-sha-256', 'reject') \
                     AND coalesce(address, '') NOT IN ('127.0.0.1', '::1')"
                ),
                "",
                "a rule for network clients that does not check the password is left"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_rebuild_stopped_after_the_old_container_was_removed_is_finished() {
            let name = format!("cfx-dbtest-resume2-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let old_id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&old_id));
            let (config, _) = ensure_postgres_password_at(&cfg).unwrap();
            let password = config.postgres.password.clone().unwrap();
            docker_ok(&["stop", &old_id]).unwrap();
            let staged_id = rebuilt_copy(&name, &config, &image_of(&old_id), &password, true);
            // The run had already handed the old data to a container that keeps it.
            docker_ok(&["rm", "-v", &old_id]).unwrap();

            assert!(
                secure_at(&name, &cfg).unwrap(),
                "the password is new to the engines, so they need a restart"
            );

            let now = inspect(&name).unwrap().unwrap();
            assert_eq!(now["Id"].as_str(), Some(staged_id.as_str()));
            assert!(is_running(&name), "it was running, so it is left running");
            assert_eq!(
                load_config_at(&cfg).unwrap().container.id.as_deref(),
                Some(staged_id.as_str())
            );
            wait_tcp_ready(&name);
            assert!(psql_over_tcp(&name, None, "SELECT 1").is_err());
            assert_eq!(
                psql_over_tcp(&name, Some(&password), "SELECT 1").unwrap(),
                "1"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_copy_left_open_by_an_interrupted_move_is_secured_before_it_starts() {
            let name = format!("cfx-dbtest-resume3-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let old_id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&old_id));
            let (config, _) = ensure_postgres_password_at(&cfg).unwrap();
            let password = config.postgres.password.clone().unwrap();
            set_password(&name, "postgres", &password).unwrap();
            sh_as_postgres(
                &name,
                "printf 'local all all trust\\nhost all all all trust\\n' > \"$PGDATA/pg_hba.conf\"",
            );
            let image = inspect(&old_id).unwrap().unwrap()["Image"]
                .as_str()
                .unwrap()
                .to_string();
            docker_ok(&["stop", &old_id]).unwrap();
            let out = docker()
                .args(run_args(
                    &format!("{name}-new"),
                    &config.postgres,
                    &image,
                    Some(&old_id),
                ))
                .env(PASSWORD_ENV, &password)
                .output()
                .unwrap();
            assert!(out.status.success());
            docker_ok(&["rm", &old_id]).unwrap();

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            assert!(psql_over_tcp(&name, None, "SELECT 1").is_err());
            assert_eq!(
                psql_over_tcp(&name, Some(&password), "SELECT 1").unwrap(),
                "1"
            );
        }

        /// SQL in database `db` over the container's socket. One statement per call
        /// when it is one that cannot run in a transaction.
        fn sql_in(name: &str, db: &str, sql: &str) -> Result<String, String> {
            let out = docker()
                .args(["exec", "-u", "postgres", name, "psql", "-X", "-q"])
                .args([
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-U",
                    "postgres",
                    "-d",
                    db,
                    "-tAc",
                    sql,
                ])
                .output()
                .unwrap();
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).to_string())
            }
        }

        /// Some of ambulo's tables and rows, as the engine makes them.
        fn seed_mach(name: &str) {
            sql_in(name, "postgres", "CREATE DATABASE mach").unwrap();
            sql_in(
                name,
                "mach",
                "CREATE TABLE wordlists (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, \
                 hash TEXT UNIQUE); \
                 CREATE TABLE scans (id BIGSERIAL PRIMARY KEY, config_hash TEXT NOT NULL, \
                 status TEXT NOT NULL DEFAULT 'pending', \
                 created_at TEXT NOT NULL DEFAULT NOW()::TEXT, \
                 updated_at TEXT NOT NULL DEFAULT NOW()::TEXT, \
                 notifications TEXT NOT NULL DEFAULT '{}', wordlist_id BIGINT, \
                 method TEXT NOT NULL, FOREIGN KEY (wordlist_id) REFERENCES wordlists(id)); \
                 INSERT INTO wordlists (name, hash) VALUES ('common', 'h1'), \
                 (E'tab\\there', NULL); \
                 INSERT INTO scans (config_hash, method, wordlist_id) VALUES ('c1', 'GET', 2)",
            )
            .unwrap();
        }

        fn mounts(target: &str) -> Vec<String> {
            inspect(target).unwrap().expect("container exists")["Mounts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m["Name"].as_str().map(str::to_string))
                .collect()
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_type_added_to_an_engine_table_does_not_outlast_the_repair() {
            let name = format!("cfx-dbtest-domain-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            seed_mach(&name);
            sql_in(
                &name,
                "mach",
                "CREATE DOMAIN tag AS text DEFAULT 'planted'; ALTER TABLE scans ADD COLUMN t tag",
            )
            .unwrap();

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            assert_eq!(
                sql_in(
                    &name,
                    "mach",
                    "SELECT count(*) FROM pg_type WHERE oid >= 16384 AND typtype NOT IN ('c', 'b')"
                )
                .unwrap(),
                "0",
                "a type added while it was open is still there"
            );
            assert_eq!(
                sql_in(
                    &name,
                    "mach",
                    "SELECT count(*) FROM pg_attribute WHERE attrelid = 'scans'::regclass \
                     AND attname = 't'"
                )
                .unwrap(),
                "0"
            );
            assert_eq!(
                sql_in(
                    &name,
                    "mach",
                    "SELECT string_agg(coalesce(hash, '-') || ':' || name, ',' ORDER BY id) \
                     FROM wordlists"
                )
                .unwrap(),
                "h1:common,-:tab\there",
                "the engines' rows are kept as they were"
            );
            assert_eq!(
                sql_in(
                    &name,
                    "mach",
                    "INSERT INTO scans (config_hash, method) VALUES ('c2', 'GET') RETURNING id"
                )
                .unwrap(),
                "2",
                "new rows carry on from the old ids"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn settings_files_added_while_it_was_open_do_not_outlast_the_repair() {
            let name = format!("cfx-dbtest-confd-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            seed_mach(&name);
            sh_as_postgres(
                &name,
                "mkdir -p \"$PGDATA/conf.d\" && \
                 printf \"archive_mode = on\\narchive_command = 'touch archived'\\n\" \
                 > \"$PGDATA/conf.d/extra.conf\" && \
                 echo \"include_dir 'conf.d'\" >> \"$PGDATA/postgresql.conf\"",
            );

            let result = secure_at(&name, &cfg);

            assert!(result.unwrap());
            wait_tcp_ready(&name);
            assert_eq!(local_value(&name, "SHOW archive_mode"), "off");
            assert_eq!(
                local_value(
                    &name,
                    "SELECT count(*) FROM pg_file_settings WHERE sourcefile LIKE '%conf.d%'"
                ),
                "0"
            );
            sql_in(&name, "mach", "INSERT INTO wordlists (name) VALUES ('w')").unwrap();
            local_value(&name, "SELECT pg_switch_wal()");
            std::thread::sleep(Duration::from_secs(5));
            let ran = docker()
                .args(["exec", &name, "sh", "-c", "test -e \"$PGDATA/archived\""])
                .status()
                .unwrap();
            assert!(!ran.success(), "a command from the old settings ran");
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn only_the_engines_rows_are_carried_over() {
            let name = format!("cfx-dbtest-rebuild-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            seed_mach(&name);
            sql_in(&name, "postgres", "CREATE DATABASE extra").unwrap();
            for (db, sql) in [
                (
                    "crossfyre",
                    "CREATE TABLE notes(v text); INSERT INTO notes VALUES ('x')",
                ),
                (
                    "mach",
                    "CREATE OR REPLACE FUNCTION pg_catalog.now() RETURNS timestamptz \
                     LANGUAGE sql AS 'SELECT statement_timestamp()'",
                ),
                (
                    "mach",
                    "CREATE FUNCTION noop() RETURNS event_trigger LANGUAGE plpgsql AS \
                     'BEGIN END'; \
                     CREATE EVENT TRIGGER noop ON ddl_command_end EXECUTE FUNCTION noop()",
                ),
                ("mach", "SELECT lo_from_bytea(424242, 'x')"),
                (
                    "postgres",
                    "CREATE ROLE visitor LOGIN PASSWORD 'visitor'; \
                     ALTER ROLE postgres SET work_mem = '7MB'",
                ),
                ("postgres", "ALTER SYSTEM SET work_mem = '9MB'"),
            ] {
                sql_in(&name, db, sql).unwrap();
            }
            let old_volumes = mounts(&id);
            assert!(!old_volumes.is_empty());

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            let new_volumes = mounts(&name);
            assert!(
                new_volumes.iter().all(|v| !old_volumes.contains(v)),
                "the repaired container still runs on the old data directory"
            );
            for v in &old_volumes {
                assert!(
                    docker_ok(&["volume", "inspect", v]).is_ok(),
                    "the old data volume {v} was deleted"
                );
            }
            for (db, sql, want) in [
                (
                    "postgres",
                    "SELECT count(*) FROM pg_database WHERE datname = 'extra'",
                    "0",
                ),
                (
                    "crossfyre",
                    "SELECT count(*) FROM pg_class WHERE relname = 'notes'",
                    "0",
                ),
                (
                    "mach",
                    "SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang \
                     WHERE p.proname = 'now'",
                    "internal",
                ),
                ("mach", "SELECT count(*) FROM pg_event_trigger", "0"),
                (
                    "mach",
                    "SELECT count(*) FROM pg_proc WHERE proname = 'noop'",
                    "0",
                ),
                ("mach", "SELECT count(*) FROM pg_largeobject_metadata", "0"),
                (
                    "postgres",
                    "SELECT count(*) FROM pg_roles WHERE rolname = 'visitor'",
                    "0",
                ),
                ("postgres", "SELECT count(*) FROM pg_db_role_setting", "0"),
                (
                    "postgres",
                    "SELECT count(*) FROM pg_file_settings WHERE name = 'work_mem'",
                    "0",
                ),
                (
                    "mach",
                    "SELECT count(*) FROM scans WHERE config_hash = 'c1'",
                    "1",
                ),
            ] {
                assert_eq!(sql_in(&name, db, sql).unwrap(), want, "{db}: {sql}");
            }
            let password = load_config_at(&cfg).unwrap().postgres.password.unwrap();
            assert!(psql_over_tcp(&name, None, "SELECT 1").is_err());
            assert_eq!(
                psql_over_tcp(&name, Some(&password), "SELECT 1").unwrap(),
                "1"
            );
            assert!(
                !secure_at(&name, &cfg).unwrap(),
                "a second run changes nothing"
            );
        }

        /// The containers that keep old data for the container named `name`.
        fn holders(name: &str) -> Vec<String> {
            let out = docker()
                .args(["ps", "-a", "--format", "{{.Names}}", "--filter"])
                .arg(format!("name={name}-old-"))
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::to_string)
                .collect()
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_table_that_cannot_be_read_stops_the_rebuild_and_keeps_the_old_container() {
            let name = format!("cfx-dbtest-unread-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            seed_mach(&name);
            let file = sql_in(&name, "mach", "SELECT pg_relation_filepath('scans')").unwrap();
            docker_ok(&["stop", &id]).unwrap();
            // The table's file is gone, as a failing disk would leave it.
            let out = docker()
                .args(["run", "--rm", "--network", "none", "--volumes-from", &id])
                .args(["--entrypoint", "sh", &image_of(&id), "-c"])
                .arg(format!("rm \"$PGDATA/{file}\""))
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );

            let result = secure_at(&name, &cfg);

            assert!(result.is_err(), "the rebuild went ahead: {result:?}");
            assert!(
                inspect(&id).unwrap().is_some(),
                "the old container, which holds the only copy of the rows, was removed"
            );
            assert!(!is_running(&id));
            assert!(inspect(&format!("{name}-new")).unwrap().is_none());
            assert!(holders(&name).is_empty());
            assert_eq!(
                load_config_at(&cfg).unwrap().container.id.as_deref(),
                Some(id.as_str())
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_database_made_for_another_user_than_config_names_is_rebuilt() {
            let name = format!("cfx-dbtest-user-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            seed_mach(&name);
            write_config_as(&cfg, port, &id, "localhost", "scanner");

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            let out = docker()
                .args([
                    "exec", "-u", "postgres", &name, "psql", "-X", "-U", "scanner",
                ])
                .args(["-d", "mach", "-tAc", "SELECT count(*) FROM wordlists"])
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "2",
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_container_found_by_its_name_is_recorded_in_config() {
            let name = format!("cfx-dbtest-stale-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            // A container that is gone, as the one a run had just replaced would be.
            let gone = docker()
                .args(["create", IMAGE])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap();
            docker_ok(&["rm", "-v", &gone]).unwrap();
            write_config(&cfg, port, Some(&gone));
            let config = load_config_at(&cfg).unwrap();
            let out = docker()
                .args(labelled_run_args(
                    &name,
                    &config.postgres,
                    IMAGE,
                    None,
                    REBUILT,
                    &[],
                ))
                .env(PASSWORD_ENV, "pw")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let made = String::from_utf8_lossy(&out.stdout).trim().to_string();

            assert!(!secure_at(&name, &cfg).unwrap());

            assert_eq!(
                load_config_at(&cfg).unwrap().container.id.as_deref(),
                Some(made.as_str()),
                "config.toml still names a container that is gone"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn an_interrupted_rebuild_keeps_the_old_data_in_one_container() {
            let name = format!("cfx-dbtest-holders-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            seed_mach(&name);
            let old_volumes = mounts(&id);
            // The run had made the container that keeps the old data, and stopped
            // before the old container was removed.
            docker_ok(&["stop", &id]).unwrap();
            keep_old_data(&image_of(&id), &id, &name).unwrap();

            assert!(secure_at(&name, &cfg).unwrap());

            let kept = holders(&name);
            assert_eq!(kept.len(), 1, "{kept:?}");
            assert_eq!(mounts(&kept[0]), old_volumes);
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn uninstalling_removes_every_container_the_repair_made_with_its_data() {
            let name = format!("cfx-dbtest-uninst-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            seed_mach(&name);
            let old_volumes = mounts(&id);
            assert!(secure_at(&name, &cfg).unwrap());
            let kept = holders(&name);
            assert_eq!(kept.len(), 1);
            let mut volumes = mounts(&name);
            volumes.extend(old_volumes);

            remove_all_named(&name);

            assert!(inspect(&name).unwrap().is_none());
            assert!(inspect(&kept[0]).unwrap().is_none(), "{} is left", kept[0]);
            for v in &volumes {
                assert!(
                    docker_ok(&["volume", "inspect", v]).is_err(),
                    "the data volume {v} is left"
                );
            }
        }
    }
}
