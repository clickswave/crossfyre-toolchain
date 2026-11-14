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
    if running(&config) {
        println!("Postgres container already running.");
        return Ok(());
    }
    // A container that starts is never recreated here, which would leave its data
    // behind: a server recovering after an unclean stop can take a while to answer.
    if start(&config).unwrap_or(false) {
        let deadline = Instant::now() + START_WAIT;
        while Instant::now() < deadline {
            if running(&config) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        return Err(format!(
            "the database container started but does not answer on 127.0.0.1:{}; see \
             `docker logs {}`, or make a new, empty one with `crossfyre db up`",
            config.postgres.port,
            resolve_container(&config)
        )
        .into());
    }
    up()
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
/// on every interface and let anyone in without a password. Its data is kept. Returns
/// whether anything changed. Runs at every node start, which is how an upgraded host
/// is repaired, and before the database is started. An error means a container may
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
    use std::io::Read;
    fn drain(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    }
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

    // A server left from an interrupted run below, on the same data volume. It has
    // to be gone before anything else starts on that volume.
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
    match (current.as_ref(), inspect(&staged)?) {
        // A move that stopped after the old container was removed: finish it. The copy
        // is the only container left with the data, so a copy that fails is stopped but
        // kept. Which kind of container it was moved from is not known any more, so the
        // copy is repaired offline as one that let anyone in before it is started.
        (None, Some(info)) => {
            let staged_id = info["Id"]
                .as_str()
                .ok_or("the database container has no id")?;
            let password = if is_local_host(&config.postgres.host) {
                let (config, _) = ensure_postgres_password_at(config_path)?;
                config.postgres.password.unwrap_or_default()
            } else {
                new_postgres_password()?
            };
            let was_running = info["State"]["Running"].as_bool().unwrap_or(false);
            docker_ok(&["stop", staged_id])
                .and_then(|()| repair_offline(&info, staged_id, &scratch, &user, &password))
                .and_then(|()| check_moved(&staged, &user, false))
                .and_then(|()| match was_running {
                    true => docker_ok(&["start", staged_id]),
                    false => Ok(()),
                })
                .map_err(|e| format!("{e}. {STOPPED}"))?;
            docker_ok(&["rename", &staged, name])?;
            let mut updated = load_config_at(config_path)?;
            updated.container.id = info["Id"].as_str().map(str::to_string);
            save_config_at(config_path, &updated)?;
            println!("Finished moving the toolchain database to 127.0.0.1 with a password.");
            // The interrupted run may have made the password the engines now need.
            return Ok(true);
        }
        // A move that stopped after the copy was made but before the old container
        // was removed. The copy is only ever made once the old one is stopped and its
        // password is set, so it is the one to keep, once it passes the check the
        // interrupted run did not get to.
        (Some(old), Some(info)) if assess(&info).safe() => {
            let old_id = old["Id"]
                .as_str()
                .ok_or("the database container has no id")?;
            if assess(old).trust {
                check_moved(&staged, &user, true).map_err(|e| format!("{e}. {STOPPED}"))?;
            }
            docker_ok(&["rm", old_id])?;
            docker_ok(&["rename", &staged, name])?;
            let mut updated = load_config_at(config_path)?;
            updated.container.id = info["Id"].as_str().map(str::to_string);
            save_config_at(config_path, &updated)?;
            println!("Finished moving the toolchain database to 127.0.0.1 with a password.");
            return Ok(true);
        }
        // Not one of ours to finish. Removing it without -v leaves the data volume,
        // which the old container still holds.
        (Some(_), Some(_)) => {
            docker_ok(&["rm", "-f", &staged])?;
        }
        _ => {}
    }
    let Some(info) = current else {
        return Ok(false);
    };
    let exposure = assess(&info);
    if exposure.safe() {
        return Ok(false);
    }

    let id = info["Id"]
        .as_str()
        .ok_or("the database container has no id")?
        .to_string();
    let was_running = info["State"]["Running"].as_bool().unwrap_or(false);
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
        secure_trusting(
            &info,
            &id,
            &scratch,
            &staged,
            name,
            &config.postgres,
            &password,
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
            false,
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

/// Secure a stopped container that was made to let anyone in: repair it offline, then
/// replace it with a loopback-only one that is checked before the old one is removed.
fn secure_trusting(
    info: &serde_json::Value,
    id: &str,
    scratch: &str,
    staged: &str,
    name: &str,
    pg: &PostgresSection,
    password: &str,
) -> Result<String, String> {
    repair_offline(info, id, scratch, &pg.user, password)?;
    // Port bindings are fixed when a container is made, so the loopback-only one is a
    // new container on the same data volume and the same image.
    replace(info, id, staged, name, pg, password, true)
}

/// Make the data of the stopped container `id`, which let anyone in, fit to serve the
/// engines again, on a copy of its server with no network. Anyone could change that
/// database as its superuser, and the engines connect as the superuser too, so
/// anything added that would run in their sessions makes it refuse the database
/// outright. Otherwise it sets the password, takes login away from every other role,
/// and resets settings made with ALTER SYSTEM or for a role or database.
fn repair_offline(
    info: &serde_json::Value,
    id: &str,
    scratch: &str,
    user: &str,
    password: &str,
) -> Result<(), String> {
    let reference = format!("{scratch}-ref");
    let undone = on_server(info, id, scratch, user, |server| {
        let found = examine(server, user, info, &reference)?;
        if !found.added.is_empty() {
            return Err(format!(
                "it holds things the toolchain never makes, which someone may have added \
                 while it let anyone in, and which could run code when the engines use it: \
                 {}. It is not started again",
                found.added.join("; ")
            ));
        }
        set_password(server, user, password)?;
        let mut sql = String::new();
        for role in &found.logins {
            sql.push_str(&format!(
                "ALTER ROLE {} NOLOGIN PASSWORD NULL;\n",
                sql_ident(role)
            ));
        }
        sql.push_str("DELETE FROM pg_catalog.pg_db_role_setting;\nALTER SYSTEM RESET ALL;\n");
        psql(server, user, "postgres", &sql)?;
        Ok(found.undone)
    })?;
    warn_about(&undone);
    Ok(())
}

/// The pg_hba.conf a repaired container gets: the image's own socket rules, and a
/// password for every client that connects over the network.
const KNOWN_HBA: &str = "# Written by crossfyre when this database was secured.\n\
local all all trust\n\
local replication all trust\n\
host all all all scram-sha-256\n\
host replication all all scram-sha-256\n";

/// Starts a server on the data directory with [`KNOWN_HBA`] in place. Settings given
/// on the command line win over postgresql.conf and ALTER SYSTEM, so whatever was set
/// there neither keeps psql out nor runs anything while the repair looks at it: no
/// libraries loaded at start, no archiving, no background vacuum running expressions,
/// no event triggers. A recovery signal file would make it run restore_command, and
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
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// The `PGOPTIONS` entry for every session the repair opens in a container. Settings
/// made for a role or a database apply to a session unless the client sets them
/// itself, and could load a library, put another schema's functions ahead of the
/// built-in ones, or fire an event trigger at login.
fn session_options(id: &str) -> String {
    let mut options = "PGOPTIONS=-c session_preload_libraries= -c local_preload_libraries= \
         -c search_path=pg_catalog -c jit=off -c default_transaction_read_only=off"
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

/// The rows of `select` as COPY writes them: fields as COPY's text format has them,
/// with `\N` for a null. A query given to COPY calls no function or operator but the
/// ones it names, and these name none.
fn copy_rows(id: &str, user: &str, db: &str, select: &str) -> Result<Vec<Vec<String>>, String> {
    Ok(parse_copy(&psql(
        id,
        user,
        db,
        &format!("COPY ({select}) TO STDOUT;\n"),
    )?))
}

fn parse_copy(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// A text field from COPY as the value it stands for.
fn unescape_copy(field: &str) -> String {
    let mut out = String::new();
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
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

/// Network rules that let a client in without its password: anything but a password
/// check or a refusal. The image's own trust rules for the container's loopback are
/// allowed, since no client outside the container connects from there. A file with
/// errors counts too, since the server keeps its previous rules.
const OPEN_RULES: &str = "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL \
     OR (type LIKE 'host%' AND auth_method NOT IN ('scram-sha-256', 'md5', 'reject') \
     AND NOT (auth_method = 'trust' AND coalesce(address, '') IN ('127.0.0.1', '::1') \
     AND coalesce(netmask, '') IN ('255.255.255.255', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')))";

/// Check a moved container's running server: no network rule may let a client in
/// without the password, whatever its settings made it read. A container that was
/// not running is started for the check and stopped again, and one that fails it is
/// stopped, and removed too when `remove` says the old container still holds the data.
fn check_moved(target: &str, user: &str, remove: bool) -> Result<(), String> {
    let running =
        inspect(target)?.ok_or("the moved database container is gone")?["State"]["Running"]
            .as_bool()
            .unwrap_or(false);
    if !running {
        docker_ok(&["start", target])?;
    }
    let result = wait_ready(target, user).and_then(|()| {
        match psql_rows(target, user, "postgres", OPEN_RULES)?
            .first()
            .map(String::as_str)
        {
            Some("0") => Ok(()),
            n => Err(format!(
                "the moved database container still has {} rule(s) in pg_hba.conf that let \
                 a client in without a password, or errors",
                n.unwrap_or("?")
            )),
        }
    });
    if result.is_err() || !running {
        let _ = docker().args(["stop", target]).output();
    }
    if result.is_err() && remove {
        let _ = docker().args(["rm", "-f", target]).output();
    }
    result
}

/// Objects numbered below this were made by initdb; anything numbered from it on was
/// added later.
const FIRST_NORMAL_OID: u32 = 16384;

/// What an object added after initdb may be.
#[derive(Clone, Copy)]
enum Added {
    /// Nothing the engines make, so anything added is refused.
    Refused,
    /// The row types of the engines' tables.
    Allowed,
    /// Only the internal triggers behind a foreign key.
    ForeignKey,
    /// Only a column default the engines use: a constant, now() or a sequence.
    PlainDefault,
    /// Only one without an expression.
    NoExpression,
}

/// The catalogs that hold code a session can end up running, and what the engines
/// add to each. In every database, rows made by initdb must match a new database's
/// from the same image exactly, which also covers a built-in function that was
/// replaced or edited in place.
const CATALOGS: &[(&str, &str, Added)] = &[
    (
        "functions",
        "SELECT * FROM pg_catalog.pg_proc",
        Added::Refused,
    ),
    (
        "aggregates",
        "SELECT * FROM pg_catalog.pg_aggregate",
        Added::Refused,
    ),
    ("types", "SELECT * FROM pg_catalog.pg_type", Added::Allowed),
    (
        "operators",
        "SELECT * FROM pg_catalog.pg_operator",
        Added::Refused,
    ),
    ("casts", "SELECT * FROM pg_catalog.pg_cast", Added::Refused),
    (
        "rules and views",
        "SELECT * FROM pg_catalog.pg_rewrite",
        Added::Refused,
    ),
    (
        "languages",
        "SELECT * FROM pg_catalog.pg_language",
        Added::Refused,
    ),
    (
        "access methods",
        "SELECT * FROM pg_catalog.pg_am",
        Added::Refused,
    ),
    (
        "operator classes",
        "SELECT * FROM pg_catalog.pg_opclass",
        Added::Refused,
    ),
    (
        "operator families",
        "SELECT * FROM pg_catalog.pg_opfamily",
        Added::Refused,
    ),
    (
        "index operators",
        "SELECT * FROM pg_catalog.pg_amop",
        Added::Refused,
    ),
    (
        "index support functions",
        "SELECT * FROM pg_catalog.pg_amproc",
        Added::Refused,
    ),
    (
        "conversions",
        "SELECT * FROM pg_catalog.pg_conversion",
        Added::Refused,
    ),
    (
        "text search parsers",
        "SELECT * FROM pg_catalog.pg_ts_parser",
        Added::Refused,
    ),
    (
        "text search templates",
        "SELECT * FROM pg_catalog.pg_ts_template",
        Added::Refused,
    ),
    (
        "extensions",
        "SELECT * FROM pg_catalog.pg_extension",
        Added::Refused,
    ),
    (
        "event triggers",
        "SELECT * FROM pg_catalog.pg_event_trigger",
        Added::Refused,
    ),
    (
        "row security policies",
        "SELECT * FROM pg_catalog.pg_policy",
        Added::Refused,
    ),
    (
        "publications",
        "SELECT * FROM pg_catalog.pg_publication",
        Added::Refused,
    ),
    (
        "transforms",
        "SELECT * FROM pg_catalog.pg_transform",
        Added::Refused,
    ),
    (
        "foreign data wrappers",
        "SELECT * FROM pg_catalog.pg_foreign_data_wrapper",
        Added::Refused,
    ),
    (
        "foreign servers",
        "SELECT * FROM pg_catalog.pg_foreign_server",
        Added::Refused,
    ),
    (
        "extended statistics",
        "SELECT * FROM pg_catalog.pg_statistic_ext",
        Added::Refused,
    ),
    (
        "partitioned tables",
        "SELECT * FROM pg_catalog.pg_partitioned_table",
        Added::Refused,
    ),
    (
        "triggers",
        "SELECT oid, tgfoid, tgisinternal, tgconstraint FROM pg_catalog.pg_trigger",
        Added::ForeignKey,
    ),
    (
        "column defaults",
        "SELECT oid, adbin FROM pg_catalog.pg_attrdef",
        Added::PlainDefault,
    ),
    (
        "constraints",
        "SELECT oid, conbin FROM pg_catalog.pg_constraint",
        Added::NoExpression,
    ),
    (
        "indexes",
        "SELECT indexrelid, indexprs, indpred FROM pg_catalog.pg_index",
        Added::NoExpression,
    ),
];

/// Settings that run commands, load code, or pick the files the server reads its
/// rules from or writes its log to. The image sets none of them in a file.
const RISKY_SETTINGS: &[&str] = &[
    "archive_command",
    "archive_library",
    "restore_command",
    "archive_cleanup_command",
    "recovery_end_command",
    "shared_preload_libraries",
    "session_preload_libraries",
    "local_preload_libraries",
    "dynamic_library_path",
    "jit_provider",
    "ssl_passphrase_command",
    "hba_file",
    "ident_file",
    "logging_collector",
    "log_directory",
    "log_filename",
];

/// Functions a column default the engines make may call.
const DEFAULT_FUNCTIONS: &[&str] = &["now", "nextval", "int8", "int4", "int2"];

/// Expression nodes such a default is made of.
const DEFAULT_NODES: &[&str] = &[
    "FUNCEXPR",
    "CONST",
    "COERCEVIAIO",
    "RELABELTYPE",
    "SQLVALUEFUNCTION",
];

#[derive(Default, Debug)]
struct Examined {
    /// Things that may run code: the database is refused.
    added: Vec<String>,
    /// Things the repair undoes, said once it has.
    undone: Vec<String>,
    /// Roles besides the engines' own that can log in.
    logins: Vec<String>,
}

/// Look over a database that was open to anyone, on the offline copy `server`,
/// against a new one made from the same image in a container named `reference`.
fn examine(
    server: &str,
    user: &str,
    info: &serde_json::Value,
    reference: &str,
) -> Result<Examined, String> {
    let mut found = Examined::default();
    let roles = copy_rows(
        server,
        user,
        "postgres",
        "SELECT oid, rolname, rolcanlogin FROM pg_catalog.pg_authid",
    )?;
    let mut bootstrap = None;
    for r in &roles {
        let [oid, name, login] = &r[..] else { continue };
        let name = unescape_copy(name);
        if oid == "10" {
            bootstrap = Some(name.clone());
        }
        if login == "t" && name != user {
            found
                .undone
                .push(format!("role {name} could log in; it no longer can"));
            found.logins.push(name);
        }
    }
    let bootstrap = bootstrap.ok_or("the database has no bootstrap superuser")?;
    for r in copy_rows(
        server,
        user,
        "postgres",
        "SELECT setconfig FROM pg_catalog.pg_db_role_setting",
    )? {
        found.undone.push(format!(
            "settings for a role or database, now reset: {}",
            r[0]
        ));
    }
    for r in copy_rows(
        server,
        user,
        "postgres",
        "SELECT name, sourcefile FROM pg_catalog.pg_file_settings",
    )? {
        let [name, file] = &r[..] else { continue };
        if file.ends_with("postgresql.auto.conf") {
            found
                .undone
                .push(format!("setting {name} made with ALTER SYSTEM, now reset"));
        } else if RISKY_SETTINGS.contains(&name.as_str()) {
            found.added.push(format!("setting {name} in {file}"));
        }
    }
    for r in copy_rows(
        server,
        user,
        "postgres",
        "SELECT subname FROM pg_catalog.pg_subscription",
    )? {
        found.added.push(format!("subscription {}", r[0]));
    }
    let databases = copy_rows(
        server,
        user,
        "postgres",
        "SELECT datname, datallowconn FROM pg_catalog.pg_database",
    )?;
    let fresh = with_reference(info, reference, &bootstrap, |r| {
        dump_catalogs(r, &bootstrap, "template1")
    })?;
    let known = Known::from(&fresh);
    for d in &databases {
        let [db, allowed] = &d[..] else { continue };
        let db = unescape_copy(db);
        if allowed != "t" {
            if db != "template0" {
                found.added.push(format!(
                    "database {db} refuses connections, so it cannot be checked"
                ));
            }
            continue;
        }
        let ours = dump_catalogs(server, user, &db)?;
        found.added.extend(compare(&db, &ours, &fresh, &known));
    }
    Ok(found)
}

type Catalogs = Vec<Vec<Vec<String>>>;

/// Every catalog in [`CATALOGS`] in database `db`, in that order, in one session.
fn dump_catalogs(id: &str, user: &str, db: &str) -> Result<Catalogs, String> {
    // Unguessable, so no row can pass for the line between two catalogs.
    let marker = new_postgres_password().map_err(|e| e.to_string())?;
    let mut script = String::new();
    for (_, select, _) in CATALOGS {
        script.push_str(&format!("\\echo {marker}\nCOPY ({select}) TO STDOUT;\n"));
    }
    let out = psql(id, user, db, &script)?;
    let mut sections: Catalogs = Vec::new();
    for line in out.lines() {
        if line == marker {
            sections.push(Vec::new());
        } else if let Some(rows) = sections.last_mut() {
            rows.extend(parse_copy(line));
        }
    }
    if sections.len() != CATALOGS.len() {
        return Err(format!("the catalogs of database {db} could not be read"));
    }
    Ok(sections)
}

/// What a new database says about the functions an engine's table may use.
struct Known {
    defaults: std::collections::BTreeSet<String>,
    foreign_keys: std::collections::BTreeSet<String>,
}

impl Known {
    fn from(fresh: &Catalogs) -> Self {
        let mut known = Known {
            defaults: Default::default(),
            foreign_keys: Default::default(),
        };
        for row in &fresh[0] {
            let (Some(oid), Some(name)) = (row.first(), row.get(1)) else {
                continue;
            };
            if DEFAULT_FUNCTIONS.contains(&name.as_str()) {
                known.defaults.insert(oid.clone());
            }
            if name.starts_with("RI_FKey_") {
                known.foreign_keys.insert(oid.clone());
            }
        }
        known
    }

    fn accepts(&self, added: Added, row: &[String]) -> bool {
        match added {
            Added::Refused => false,
            Added::Allowed => true,
            Added::ForeignKey => {
                matches!(row, [_, func, internal, constraint]
                    if internal == "t" && constraint != "0" && self.foreign_keys.contains(func))
            }
            Added::PlainDefault => {
                matches!(row, [_, tree] if plain_default(tree, &self.defaults))
            }
            Added::NoExpression => row.iter().skip(1).all(|f| f == "\\N"),
        }
    }
}

/// Whether a stored default expression is only a constant, a cast, now() or a
/// sequence, as the engines' defaults are.
fn plain_default(tree: &str, functions: &std::collections::BTreeSet<String>) -> bool {
    let after =
        |i: usize, f: fn(&char) -> bool| -> String { tree[i..].chars().take_while(f).collect() };
    let nodes_ok = tree.match_indices('{').all(|(i, _)| {
        let tag = after(i + 1, char::is_ascii_uppercase);
        tag.is_empty() || DEFAULT_NODES.contains(&tag.as_str())
    });
    let functions_ok = tree
        .match_indices(":funcid ")
        .all(|(i, m)| functions.contains(&after(i + m.len(), char::is_ascii_digit)));
    nodes_ok && functions_ok
}

/// Where database `db`'s catalogs differ from a new database's, besides what the
/// engines add.
fn compare(db: &str, ours: &Catalogs, fresh: &Catalogs, known: &Known) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut found = Vec::new();
    for (i, (label, _, added)) in CATALOGS.iter().enumerate() {
        let built_in: BTreeSet<&Vec<String>> = fresh[i].iter().collect();
        let mut kept = BTreeSet::new();
        let mut names = BTreeSet::new();
        let (mut changed, mut extra) = (0, 0);
        for row in &ours[i] {
            let initdb = row
                .first()
                .and_then(|k| k.parse::<u32>().ok())
                .is_none_or(|k| k < FIRST_NORMAL_OID);
            if initdb && built_in.contains(row) {
                kept.insert(row);
                continue;
            }
            if initdb {
                changed += 1;
            } else if known.accepts(*added, row) {
                continue;
            } else {
                extra += 1;
            }
            // The function's name says the most about what it is.
            if i == 0 {
                if let Some(name) = row.get(1) {
                    names.insert(unescape_copy(name));
                }
            }
        }
        // A row edited in place is one that is new and one that is gone.
        let changed = changed.max(built_in.len() - kept.len());
        if changed + extra == 0 {
            continue;
        }
        let mut line = format!("{db}: {label}:");
        if changed > 0 {
            line.push_str(&format!(" {changed} built-in row(s) changed"));
        }
        if extra > 0 {
            line.push_str(&format!(" {extra} added"));
        }
        if !names.is_empty() {
            let shown: Vec<_> = names.into_iter().take(5).collect();
            line.push_str(&format!(" ({})", shown.join(", ")));
        }
        found.push(line);
    }
    found
}

/// Run `f` against a new database made from the same image as the container `info`
/// describes, as initdb makes it for the same bootstrap user, in a container with no
/// network that is removed afterwards with its volume.
fn with_reference<T>(
    info: &serde_json::Value,
    name: &str,
    bootstrap: &str,
    f: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, String> {
    let image = info["Image"]
        .as_str()
        .ok_or("the database container has no image")?;
    let _ = docker().args(["rm", "-f", "-v", name]).output();
    let mut args: Vec<String> = ["run", "-d", "--name", name, "--network", "none"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.push("-e".to_string());
    args.push(format!("POSTGRES_USER={bootstrap}"));
    args.push("-e".to_string());
    args.push("POSTGRES_HOST_AUTH_METHOD=trust".to_string());
    // What else shapes what initdb makes.
    for e in info["Config"]["Env"].as_array().into_iter().flatten() {
        let Some(e) = e.as_str() else { continue };
        if ["POSTGRES_INITDB_ARGS=", "LANG=", "LC_ALL="]
            .iter()
            .any(|p| e.starts_with(p))
        {
            args.push("-e".to_string());
            args.push(e.to_string());
        }
    }
    args.push(image.to_string());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = docker_ok(&arg_refs).and_then(|()| {
        // The image's first start runs a server on its socket only while it sets up,
        // then the real one, which also listens on the container's own loopback.
        wait_until(name, || {
            docker()
                .args(["exec", "-u", "postgres", name, "pg_isready", "-q", "-h"])
                .args(["127.0.0.1", "-U", bootstrap, "-d", "template1"])
                .status()
                .is_ok_and(|s| s.success())
        })
        .and_then(|()| f(name))
    });
    let _ = docker().args(["rm", "-f", "-v", name]).output();
    result
}

fn warn_about(undone: &[String]) {
    if undone.is_empty() {
        return;
    }
    eprintln!(
        "[db] WARNING the toolchain database accepted connections without a password, and \
         someone may have changed it while it was open. The repair undid these:"
    );
    for c in undone {
        eprintln!("[db]   {c}");
    }
    eprintln!(
        "[db] Set again any of these you made yourself. To start again with an empty \
         database instead (scan state is lost): crossfyre db down, then crossfyre db up."
    );
}

/// Replace the container `old` with one named `name` that is published on loopback,
/// mounts the same volumes and runs the same image. Returns the new container's id.
/// With `check`, the old container let anyone in: the new one must pass
/// [`check_moved`] before the old one is removed, and a failure leaves the old one
/// stopped rather than starting it again.
fn replace(
    info: &serde_json::Value,
    old: &str,
    staged: &str,
    name: &str,
    pg: &PostgresSection,
    password: &str,
    check: bool,
) -> Result<String, String> {
    let image = info["Image"]
        .as_str()
        .ok_or("the database container has no image")?;
    let was_running = info["State"]["Running"].as_bool().unwrap_or(false);
    // Two servers must never share a data directory, and the new one needs the port.
    docker_ok(&["stop", old])?;
    let out = docker()
        .args(run_args(staged, pg, image, Some(old)))
        .env(PASSWORD_ENV, password)
        .output()
        .map_err(|e| format!("docker run: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let _ = docker().args(["rm", "-f", staged]).output();
        if was_running && !check {
            let _ = docker().args(["start", old]).output();
        }
        return Err(format!(
            "could not make the loopback-only database container: {err}"
        ));
    }
    let new_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if check {
        check_moved(staged, &pg.user, true)?;
    }
    // Without -v: the data volume now belongs to the new container as well.
    docker_ok(&["rm", old])?;
    docker_ok(&["rename", staged, name])?;
    Ok(new_id)
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
    fn a_repaired_database_asks_every_network_client_for_its_password() {
        let rules: Vec<Vec<&str>> = KNOWN_HBA
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(|l| l.split_whitespace().collect())
            .collect();
        assert!(rules.iter().any(|r| r[0] == "host"));
        for r in &rules {
            match r[0] {
                "local" => {}
                "host" => assert_eq!(r.last(), Some(&"scram-sha-256"), "{r:?}"),
                other => panic!("unexpected rule type {other}"),
            }
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

    #[test]
    fn only_the_defaults_the_engines_use_count_as_plain() {
        let ok: std::collections::BTreeSet<String> = ["1299", "1574", "481"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let now = "{FUNCEXPR :funcid 1299 :funcresulttype 1184 :funcretset false \
                   :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 0 \
                   :args <> :location 70}";
        assert!(plain_default(now, &ok));
        assert!(plain_default(
            &format!("{{COERCEVIAIO :arg {now} :resulttype 25 :resultcollid 100}}"),
            &ok
        ));
        assert!(plain_default(
            "{CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 \
             :constbyval false :constisnull false :location 63 :constvalue 11 [ 44 0 0 0 112 \
             101 110 100 105 110 103 ]}",
            &ok
        ));
        assert!(!plain_default(
            "{FUNCEXPR :funcid 2311 :funcresulttype 25 :args ({CONST :consttype 25})}",
            &ok
        ));
        assert!(!plain_default(
            "{OPEXPR :opno 98 :opfuncid 0 :opresulttype 16 :args <>}",
            &ok
        ));
        assert!(!plain_default("{SUBLINK :subLinkType 4}", &ok));
    }

    #[test]
    fn a_catalog_that_differs_from_a_new_database_is_named() {
        fn rows(r: &[&[&str]]) -> Vec<Vec<String>> {
            r.iter()
                .map(|row| row.iter().map(|f| f.to_string()).collect())
                .collect()
        }
        let mut fresh: Catalogs = vec![Vec::new(); CATALOGS.len()];
        fresh[0] = rows(&[
            &["1299", "now", "internal"],
            &["1574", "nextval", "internal"],
            &["1644", "RI_FKey_check_ins", "internal"],
        ]);
        let known = Known::from(&fresh);
        let trig = CATALOGS.iter().position(|c| c.0 == "triggers").unwrap();
        let defaults = CATALOGS
            .iter()
            .position(|c| c.0 == "column defaults")
            .unwrap();
        let types = CATALOGS.iter().position(|c| c.0 == "types").unwrap();

        // The engines' own: a row type, a foreign key's trigger, a sequence default.
        let mut ours = fresh.clone();
        ours[types] = rows(&[&["16390", "scans"]]);
        ours[trig] = rows(&[&["16400", "1644", "t", "16399"]]);
        ours[defaults] = rows(&[&["16401", "{FUNCEXPR :funcid 1574 :args <>}"]]);
        assert!(compare("mach", &ours, &fresh, &known).is_empty());

        // A built-in replaced, a function added, a trigger of someone's own.
        let mut ours = fresh.clone();
        ours[0][0] = vec!["1299".into(), "now".into(), "sql".into()];
        ours[0].push(vec!["16500".into(), "helper".into(), "plpgsql".into()]);
        ours[trig] = rows(&[&["16400", "16500", "f", "0"]]);
        let found = compare("mach", &ours, &fresh, &known);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].starts_with("mach: functions: 1 built-in row(s) changed 1 added"));
        assert!(
            found[0].contains("helper") && found[0].contains("now"),
            "{}",
            found[0]
        );
        assert!(found[1].starts_with("mach: triggers:"), "{}", found[1]);
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
                    format!("{name}-fix-ref"),
                ])
            }
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let mut volumes = Vec::new();
                for name in &self.0 {
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
            psql_over_tcp(
                &name,
                None,
                "CREATE TABLE kept(v text); INSERT INTO kept VALUES ('row')",
            )
            .expect("the 0.1.42 container lets anyone in");
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
                psql_over_tcp(&name, Some(&password), "SELECT v FROM kept").unwrap(),
                "row",
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
            docker_ok(&["stop", &id]).unwrap();
            // A user that is not a role in the cluster, so setting its password fails.
            write_config_as(&cfg, port, &id, "localhost", "not_a_role");

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
            psql_over_tcp(
                &name,
                None,
                "CREATE TABLE kept(v text); INSERT INTO kept VALUES ('row')",
            )
            .unwrap();
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
                psql_over_tcp(&name, Some(&password), "SELECT v FROM kept").unwrap(),
                "row"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_move_interrupted_after_the_copy_started_is_finished() {
            let name = format!("cfx-dbtest-resume-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let old_id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&old_id));
            let (config, _) = ensure_postgres_password_at(&cfg).unwrap();
            let password = config.postgres.password.clone().unwrap();
            // Everything up to removing the old container, as `replace` does it.
            set_password(&name, "postgres", &password).unwrap();
            sh_as_postgres(
                &name,
                "printf 'local all all trust\\nhost all all all scram-sha-256\\n' > \"$PGDATA/pg_hba.conf\"",
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
            let staged_id = String::from_utf8_lossy(&out.stdout).trim().to_string();

            assert!(secure_at(&name, &cfg).unwrap());

            assert!(
                inspect(&old_id).unwrap().is_none(),
                "the old container is gone"
            );
            let now = inspect(&name).unwrap().unwrap();
            assert_eq!(now["Id"].as_str(), Some(staged_id.as_str()));
            assert!(is_running(&name), "the database that was running still is");
            assert_eq!(
                load_config_at(&cfg).unwrap().container.id.as_deref(),
                Some(staged_id.as_str())
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

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn the_engines_own_tables_are_not_taken_for_anything_added() {
            let name = format!("cfx-dbtest-fresh-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let port = free_port();
            let id = open_0_1_42(&name, port);
            // As the engines make them: a database of their own, tables with foreign
            // keys, the defaults they use, and an index.
            psql_over_tcp(&name, None, "CREATE DATABASE mach").unwrap();
            let (ip, _) = bridge(&name);
            let out = docker()
                .args([
                    "exec", &name, "psql", "-w", "-X", "-h", &ip, "-U", "postgres",
                ])
                .args(["-d", "mach", "-v", "ON_ERROR_STOP=1", "-c"])
                .arg(
                    "CREATE TABLE wordlists (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, \
                     hash TEXT UNIQUE); \
                     CREATE TABLE scans (id BIGSERIAL PRIMARY KEY, \
                     status TEXT NOT NULL DEFAULT 'pending', \
                     created_at TEXT NOT NULL DEFAULT NOW()::TEXT, \
                     notifications TEXT NOT NULL DEFAULT '{}', wordlist_id BIGINT, \
                     FOREIGN KEY (wordlist_id) REFERENCES wordlists(id)); \
                     CREATE TABLE probe_results (id BIGSERIAL PRIMARY KEY, \
                     code INTEGER NOT NULL DEFAULT 0, body_length BIGINT NOT NULL DEFAULT 0, \
                     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); \
                     CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(wordlist_id, status); \
                     INSERT INTO wordlists (name) VALUES ('w'); ANALYZE",
                )
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            docker_ok(&["stop", &id]).unwrap();
            let info = inspect(&id).unwrap().unwrap();

            let found = on_server(&info, &id, &format!("{name}-fix"), "postgres", |s| {
                examine(s, "postgres", &info, &format!("{name}-fix-ref"))
            })
            .unwrap();

            assert!(found.added.is_empty(), "{:?}", found.added);
            assert!(found.undone.is_empty(), "{:?}", found.undone);
            assert!(inspect(&format!("{name}-fix-ref")).unwrap().is_none());
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
            // A user that is not a role in the cluster, so setting its password fails.
            write_config_as(&cfg, port, &id, "localhost", "not_a_role");

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
                "printf 'local all all trust\\nhost all all all trust\\n' > \"$PGDATA/x_hba.conf\"",
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
                    "SELECT string_agg(DISTINCT auth_method, ',') FROM pg_hba_file_rules \
                     WHERE type LIKE 'host%' AND auth_method NOT IN ('scram-sha-256', 'reject')"
                ),
                "",
                "a rule for network clients that does not check the password is left"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn an_auth_file_the_repair_cannot_replace_leaves_the_database_stopped() {
            let name = format!("cfx-dbtest-conf-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            // Named in postgresql.conf itself, which the repair does not rewrite.
            sh_as_postgres(
                &name,
                "printf 'local all all trust\\nhost all all all trust\\n' > \"$PGDATA/x_hba.conf\" && \
                 echo \"hba_file = '$PGDATA/x_hba.conf'\" >> \"$PGDATA/postgresql.conf\"",
            );

            let result = secure_at(&name, &cfg);

            assert!(
                !running_open(&id) && !running_open(&name) && !running_open(&format!("{name}-new")),
                "a container lets a client in without a password after {result:?}"
            );
            assert!(result.is_err(), "{result:?}");
            assert!(!reachable("127.0.0.1", port));
            assert!(
                inspect(&format!("{name}-new")).unwrap().is_none(),
                "a copy that failed the check is not kept for the next run to finish"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn a_move_interrupted_after_the_old_container_was_removed_restarts_the_engines() {
            let name = format!("cfx-dbtest-resume2-{}", std::process::id());
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
                "printf 'local all all trust\\nhost all all all scram-sha-256\\n' > \"$PGDATA/pg_hba.conf\"",
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
            let staged_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            docker_ok(&["rm", &old_id]).unwrap();

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
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn settings_made_while_it_was_open_do_not_outlast_the_repair() {
            let name = format!("cfx-dbtest-settings-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            psql_over_tcp(
                &name,
                None,
                "CREATE ROLE visitor LOGIN PASSWORD 'visitor'; \
                 ALTER ROLE postgres SET work_mem = '7MB'",
            )
            .unwrap();
            for sql in [
                "ALTER SYSTEM SET archive_mode = 'on'",
                "ALTER SYSTEM SET archive_command = 'touch \"$PGDATA/archived\"'",
            ] {
                psql_over_tcp(&name, None, sql).unwrap();
            }

            assert!(secure_at(&name, &cfg).unwrap());

            wait_tcp_ready(&name);
            // A finished WAL segment is what an archive command runs for.
            local_value(&name, "SELECT pg_switch_wal()");
            std::thread::sleep(Duration::from_secs(5));
            let out = docker()
                .args(["exec", &name, "sh", "-c", "test -e \"$PGDATA/archived\""])
                .status()
                .unwrap();
            assert!(
                !out.success(),
                "a command set while it was open ran after the repair"
            );
            assert_eq!(local_value(&name, "SHOW archive_mode"), "off");
            assert_eq!(
                local_value(&name, "SELECT count(*) FROM pg_db_role_setting"),
                "0"
            );
            let (ip, _) = bridge(&name);
            let visitor = docker()
                .args([
                    "exec",
                    "-e",
                    "PGPASSWORD=visitor",
                    &name,
                    "psql",
                    "-w",
                    "-X",
                ])
                .args([
                    "-h", &ip, "-U", "visitor", "-d", "postgres", "-c", "SELECT 1",
                ])
                .output()
                .unwrap();
            assert!(
                !visitor.status.success(),
                "a role made while it was open can still log in"
            );
            assert!(psql_over_tcp(&name, None, "SELECT 1").is_err());
        }

        /// A 0.1.42 container that `change` altered while it was open: the repair must
        /// refuse it and leave it stopped, with nothing published.
        fn is_refused_and_stopped(tag: &str, change: impl Fn(&str)) {
            let name = format!("cfx-dbtest-{tag}-{}", std::process::id());
            let _cleanup = Cleanup::for_name(&name);
            let dir = tempfile::tempdir().unwrap();
            let cfg = dir.path().join("config.toml");
            let port = free_port();
            let id = open_0_1_42(&name, port);
            write_config(&cfg, port, Some(&id));
            change(&name);

            let result = secure_at(&name, &cfg);

            assert!(result.is_err(), "{tag}: {result:?}");
            assert!(!is_running(&id), "{tag}: left running");
            assert!(!reachable("127.0.0.1", port), "{tag}: still published");
            assert!(
                inspect(&format!("{name}-new")).unwrap().is_none(),
                "{tag}: a copy was made"
            );
        }

        #[test]
        #[ignore = "needs Docker and the postgres image"]
        fn code_added_while_it_was_open_leaves_it_stopped() {
            is_refused_and_stopped("builtin", |name| {
                psql_over_tcp(
                    name,
                    None,
                    "CREATE OR REPLACE FUNCTION pg_catalog.now() RETURNS timestamptz \
                     LANGUAGE sql AS 'SELECT statement_timestamp()'",
                )
                .unwrap();
            });
            is_refused_and_stopped("default", |name| {
                psql_over_tcp(name, None, "CREATE TABLE notes(body text DEFAULT md5('x'))")
                    .unwrap();
            });
            is_refused_and_stopped("evtrig", |name| {
                psql_over_tcp(
                    name,
                    None,
                    "CREATE FUNCTION noop() RETURNS event_trigger LANGUAGE plpgsql AS \
                     'BEGIN END'; \
                     CREATE EVENT TRIGGER noop ON ddl_command_end EXECUTE FUNCTION noop()",
                )
                .unwrap();
            });
            is_refused_and_stopped("conf", |name| {
                sh_as_postgres(
                    name,
                    "echo \"archive_command = 'true'\" >> \"$PGDATA/postgresql.conf\"",
                );
            });
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
    }
}
