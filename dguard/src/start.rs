//! Starting an engine's daemon for its client.
//!
//! A client that finds nothing on its port starts the daemon: on Linux the engine's
//! systemd user unit when crossfyre registered one for this user, and otherwise the
//! engine's own binary as a daemon, detached from the terminal, with what it writes
//! appended to a log in the toolchain directory. Either way it waits until the daemon
//! answers `capabilities`. A daemon started from the binary exits once nothing has used
//! it for a while (see [`crate::exit_when_idle`]); one started by its unit, or by hand,
//! runs until it is stopped.

use crate::idle::{IDLE_EXIT_DEFAULT, IDLE_EXIT_ENV};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Set to `1`, it turns starting a daemon off, as `--no-autostart` does.
pub const NO_AUTOSTART_ENV: &str = "CFX_NO_AUTOSTART";

/// How long a client waits for the daemon it started to answer.
const START_WAIT: Duration = Duration::from_secs(60);

/// How long one `capabilities` question may take. ambulo holds a connection for up to
/// ten seconds while its database comes up, and then answers it.
const ASK_WAIT: Duration = Duration::from_secs(15);

/// After this long without an answer, the client says what it is waiting for.
const SAY_AFTER: Duration = Duration::from_secs(1);

/// How many of the last lines a daemon wrote are shown when it does not answer.
const LAST_LINES: usize = 20;

/// How large a daemon's log may grow. It is only ever appended to, so a client starting a
/// daemon into a larger one starts it over, and keeps no older copy.
const LOG_LIMIT: u64 = 10 * 1024 * 1024;

/// The arguments that run an engine's binary as its daemon on `port`, as its unit, its
/// service on macOS and Windows, `node init` and a client starting one all give them.
pub fn daemon_args(port: u16) -> [String; 3] {
    ["daemon".to_string(), "--port".to_string(), port.to_string()]
}

/// The name of engine `engine`'s systemd user unit, which crossfyre writes to
/// `~/.config/systemd/user` when it installs the engine.
pub fn unit_name(engine: &str) -> String {
    format!("crossfyre-{engine}.service")
}

/// What a client says when no daemon answers on `port` and none is started for it.
pub fn not_running(engine: &str, port: u16) -> String {
    format!(
        "{} daemon is not running on port {port}.\nStart it with `{engine} daemon`, or with \
         `crossfyre extension start {engine}` if crossfyre installed it.",
        capitalised(engine)
    )
}

/// What a client run as root says when no daemon answers on `port`.
fn not_for_root(engine: &str, port: u16) -> String {
    format!(
        "{} daemon is not running on port {port}, and it is not started as root: the daemon \
         and its database belong to your user.\nRun this without sudo and it starts as you.",
        capitalised(engine)
    )
}

fn capitalised(engine: &str) -> String {
    let mut name = engine.to_string();
    if let Some(first) = name.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    name
}

/// Whether engine `engine`'s daemon makes or opens the database before it answers, which
/// the first time takes some seconds.
fn sets_up_database(engine: &str) -> bool {
    matches!(engine, "ambulo" | "doorward" | "voyage")
}

/// An engine's daemon, as the engine's client reaches it.
pub struct Daemon {
    engine: &'static str,
    port: u16,
    autostart: bool,
}

/// A daemon being started.
enum Start {
    /// By the systemd user unit `name`, at `since`.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "a unit is started on Linux only")
    )]
    Unit {
        name: String,
        since: std::time::SystemTime,
    },
    /// From the engine's binary, writing to `log` from byte `from` on. `child` is None
    /// once it has stopped with another daemon on the port, as when two clients start
    /// one at once.
    Spawned {
        child: Option<std::process::Child>,
        log: PathBuf,
        from: u64,
    },
}

/// What a daemon said when asked for its capabilities.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// It is up, as the process with this pid.
    Ready(u32),
    /// It is up, and refuses this client's token.
    Refused,
    /// Nothing yet, or not that it is ready: ambulo answers while its database comes up.
    NotYet,
}

impl Daemon {
    /// Engine `engine`'s daemon on 127.0.0.1:`port`, started when nothing answers there,
    /// unless `autostart` is false or [`NO_AUTOSTART_ENV`] is `1`.
    pub fn new(engine: &'static str, port: u16, autostart: bool) -> Self {
        Self {
            engine,
            port,
            autostart,
        }
    }

    fn addr(&self) -> (Ipv4Addr, u16) {
        (Ipv4Addr::LOCALHOST, self.port)
    }

    /// A connection to the daemon, which is started first when nothing answers on its
    /// port. Saying it started goes to stderr, since scripts read stdout as JSON.
    pub async fn connect(&self) -> Result<TcpStream, String> {
        if let Ok(stream) = TcpStream::connect(self.addr()).await {
            return Ok(stream);
        }
        if !self.autostart || std::env::var(NO_AUTOSTART_ENV).is_ok_and(|v| v.trim() == "1") {
            return Err(not_running(self.engine, self.port));
        }
        // A daemon root started would make its log, and its database, as root, in a home
        // that may be the user's.
        if is_root() {
            return Err(not_for_root(self.engine, self.port));
        }
        let start = self.start()?;
        let pid = self.wait(start, START_WAIT).await?;
        eprintln!("started {} daemon (pid {pid})", self.engine);
        TcpStream::connect(self.addr()).await.map_err(|e| {
            format!(
                "the {} daemon started, and then took no connection on port {}: {e}",
                self.engine, self.port
            )
        })
    }

    /// Start the daemon: its unit when one serves this port, or its binary.
    fn start(&self) -> Result<Start, String> {
        #[cfg(target_os = "linux")]
        if let Some(name) = registered_unit(self.engine, self.port) {
            let since = std::time::SystemTime::now();
            start_unit(self.engine, &name)?;
            return Ok(Start::Unit { name, since });
        }
        self.spawn()
    }

    /// The engine's binary, which is this one, as a daemon on this port, with what it
    /// writes appended to `logs/<engine>.log` in the toolchain directory. It gets this
    /// process's environment, so `CFX_DAEMON_TOKEN` and `CFX_DAEMON_BIND` apply to it.
    fn spawn(&self) -> Result<Start, String> {
        let engine = self.engine;
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot find the {engine} binary to start its daemon: {e}"))?;
        let dir = crate::toolchain_dir()
            .ok_or_else(|| {
                format!(
                    "there is no home directory to keep the {engine} daemon's log in. Set {} \
                     to the toolchain directory",
                    crate::TOOLCHAIN_DIR_ENV
                )
            })?
            .join("logs");
        let log = dir.join(format!("{engine}.log"));
        let file =
            open_log(&dir, &log).map_err(|e| format!("cannot open {}: {e}", log.display()))?;
        let from = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut cmd = daemon_command(&exe, self.port, file, std::env::var_os(IDLE_EXIT_ENV))
            .map_err(|e| format!("cannot open {}: {e}", log.display()))?;
        if let Some(home) = dirs::home_dir() {
            cmd.current_dir(home);
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("could not start the {engine} daemon: {e}"))?;
        Ok(Start::Spawned {
            child: Some(child),
            log,
            from,
        })
    }

    /// Wait up to `limit` for the daemon `start` began to answer, and say which process
    /// it is. While it takes a moment, say why; when it does not answer, say what it
    /// wrote.
    async fn wait(&self, mut start: Start, limit: Duration) -> Result<u32, String> {
        let engine = self.engine;
        let begun = Instant::now();
        let mut said = false;
        loop {
            match ask(self.port).await {
                Answer::Ready(pid) => {
                    // Another client's daemon got the port first, as when two clients
                    // start one at once; this one would find it taken and stop.
                    if let Start::Spawned {
                        child: Some(running),
                        ..
                    } = &mut start
                        && running.id() != pid
                    {
                        let _ = running.kill();
                        let _ = running.wait();
                    }
                    return Ok(pid);
                }
                Answer::Refused => {
                    return Err(format!(
                        "the {engine} daemon started, and refused this command's token. Give it \
                         the {} the daemon has",
                        crate::TOKEN_ENV
                    ));
                }
                Answer::NotYet => {}
            }
            if let Start::Spawned { child, log, from } = &mut start
                && let Some(running) = child
                && let Ok(Some(status)) = running.try_wait()
            {
                // With another daemon on the port, this one had nothing to listen on, and
                // that one is waited for instead.
                if TcpStream::connect(self.addr()).await.is_err() {
                    return Err(format!(
                        "the {engine} daemon stopped before it answered ({status}). The end of \
                         what it wrote, in {}:\n{}",
                        log.display(),
                        tail(log, *from)
                    ));
                }
                *child = None;
            }
            // A daemon that cannot have what it needs, such as its database, says so and
            // waits for it, which no wait here would see the end of.
            if let Start::Spawned {
                child: Some(running),
                log,
                from,
            } = &mut start
                && waits_for_something(log, *from)
            {
                let _ = running.kill();
                let _ = running.wait();
                return Err(format!(
                    "the {engine} daemon cannot start yet, so it was stopped. What it wrote, in \
                     {}:\n{}",
                    log.display(),
                    tail(log, *from)
                ));
            }
            if !said && begun.elapsed() >= SAY_AFTER {
                eprintln!(
                    "waiting for the {engine} daemon to start{}",
                    if sets_up_database(engine) {
                        "; the first start also sets up its database, which takes a few seconds"
                    } else {
                        ""
                    }
                );
                said = true;
            }
            if begun.elapsed() >= limit {
                return Err(self.gave_up(start, limit));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Why a daemon that did not answer within `limit` is not there, with the end of
    /// what it wrote. A daemon this client spawned is stopped, so none is left behind
    /// that nobody asked for.
    fn gave_up(&self, start: Start, limit: Duration) -> String {
        let (engine, secs) = (self.engine, limit.as_secs());
        match start {
            Start::Spawned {
                child: Some(mut child),
                log,
                from,
            } => {
                let _ = child.kill();
                let _ = child.wait();
                format!(
                    "the {engine} daemon did not answer within {secs} seconds, so it was \
                     stopped. The end of what it wrote, in {}:\n{}",
                    log.display(),
                    tail(&log, from)
                )
            }
            Start::Spawned { child: None, .. } => format!(
                "the {engine} daemon on port {} did not answer within {secs} seconds",
                self.port
            ),
            Start::Unit { name, since } => match journal_tail(&name, since) {
                Some(said) => format!(
                    "{name} did not answer within {secs} seconds. The end of what it wrote:\n\
                     {said}"
                ),
                None => format!(
                    "{name} did not answer within {secs} seconds. See what it wrote with \
                     `journalctl --user -u {name}`"
                ),
            },
        }
    }
}

/// What the daemon on 127.0.0.1:`port` says when asked for its capabilities.
async fn ask(port: u16) -> Answer {
    let question = async {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        let (reader, mut writer) = stream.into_split();
        let mut line = crate::encode(&serde_json::json!({"operation": "capabilities"}));
        line.push('\n');
        writer.write_all(line.as_bytes()).await.ok()?;
        BufReader::new(reader).lines().next_line().await.ok()?
    };
    match tokio::time::timeout(ASK_WAIT, question).await {
        Ok(Some(line)) => answer_to(&line),
        _ => Answer::NotYet,
    }
}

/// What the line a daemon answered `capabilities` with says.
fn answer_to(line: &str) -> Answer {
    if line.trim() == crate::UNAUTHORIZED.trim() {
        return Answer::Refused;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return Answer::NotYet;
    };
    match (v["type"].as_str(), v["pid"].as_u64()) {
        (Some("capabilities"), Some(pid)) => {
            u32::try_from(pid).map_or(Answer::NotYet, Answer::Ready)
        }
        _ => Answer::NotYet,
    }
}

/// Open the daemon log at `log` in `dir` to append to, readable by the user alone, and
/// empty once it has grown past [`LOG_LIMIT`].
fn open_log(dir: &Path, log: &Path) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(dir)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(log)?;
    if file.metadata()?.len() > LOG_LIMIT {
        file.set_len(0)?;
    }
    Ok(file)
}

/// The command that runs `exe` as a daemon on `port`, writing to `log`. It is told when
/// to exit unused: after what `idle_exit`, the client's own [`IDLE_EXIT_ENV`], says, or
/// else after [`IDLE_EXIT_DEFAULT`].
fn daemon_command(
    exe: &Path,
    port: u16,
    log: std::fs::File,
    idle_exit: Option<std::ffi::OsString>,
) -> std::io::Result<std::process::Command> {
    use std::process::Stdio;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(daemon_args(port))
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if idle_exit.is_none() {
        cmd.env(IDLE_EXIT_ENV, IDLE_EXIT_DEFAULT.as_secs().to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // A session of its own, so the terminal's hangup and its Ctrl-C reach the client
        // and not the daemon.
        // SAFETY: setsid is async-signal-safe, and nothing else runs between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS and CREATE_NEW_PROCESS_GROUP: no console, and Ctrl-C in the
        // client's stays there.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    Ok(cmd)
}

/// What was written to `log` from byte `from` on.
fn written(log: &Path, from: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut text = Vec::new();
    if let Ok(mut file) = std::fs::File::open(log) {
        let _ = file.seek(SeekFrom::Start(from));
        let _ = file.read_to_end(&mut text);
    }
    String::from_utf8_lossy(&text).into_owned()
}

/// Whether the daemon writing to `log` from byte `from` on has twice said it waits for
/// something it cannot start without. Once can be a moment's race, such as two daemons
/// making the same database at once, which its next try gets past.
fn waits_for_something(log: &Path, from: u64) -> bool {
    written(log, from)
        .lines()
        .filter(|l| l.starts_with(crate::WAITING))
        .count()
        >= 2
}

/// The last lines of what was written to `log` from byte `from` on.
fn tail(log: &Path, from: u64) -> String {
    let text = written(log, from);
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return "(nothing)".to_string();
    }
    lines[lines.len().saturating_sub(LAST_LINES)..].join("\n")
}

/// Whether this process runs as root, for whom no daemon is started. Windows has none:
/// an elevated prompt is its user's own account.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Engine `engine`'s systemd user unit, when crossfyre registered one for this user that
/// serves `port`, and the user's service manager runs to start it.
#[cfg(target_os = "linux")]
fn registered_unit(engine: &str, port: u16) -> Option<String> {
    let unit = unit_name(engine);
    let path = dirs::home_dir()?.join(".config/systemd/user").join(&unit);
    let text = std::fs::read_to_string(path).ok()?;
    (unit_serves(&text, port) && runtime_dir().join("bus").exists()).then_some(unit)
}

/// Whether the unit file `text` starts its daemon on `port`.
#[cfg(any(target_os = "linux", test))]
fn unit_serves(text: &str, port: u16) -> bool {
    let port = port.to_string();
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("ExecStart="))
        .any(|exec| {
            let words: Vec<&str> = exec.split_whitespace().collect();
            words.windows(2).any(|w| w[0] == "--port" && w[1] == port)
                || words
                    .iter()
                    .any(|w| w.strip_prefix("--port=") == Some(&port))
        })
}

/// The last lines the unit `unit` wrote to the user's journal since `since`, when the
/// journal keeps them where the user may read them.
fn journal_tail(unit: &str, since: std::time::SystemTime) -> Option<String> {
    let secs = since.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let out = std::process::Command::new("journalctl")
        .args(["--user", "-u", unit, "--no-pager", "-o", "cat"])
        .arg(format!("--since=@{secs}"))
        .arg(format!("--lines={LAST_LINES}"))
        .output()
        .ok()?;
    let said = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
    (out.status.success() && !said.is_empty()).then_some(said)
}

/// Where the user's service manager listens.
#[cfg(target_os = "linux")]
fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        // SAFETY: getuid has no preconditions and cannot fail.
        None => PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })),
    }
}

/// Start the unit `unit` of engine `engine` with the user's service manager.
#[cfg(target_os = "linux")]
fn start_unit(engine: &str, unit: &str) -> Result<(), String> {
    let out = std::process::Command::new("systemctl")
        .args(["--user", "start", unit])
        .env("XDG_RUNTIME_DIR", runtime_dir())
        .output()
        .map_err(|e| format!("could not run systemctl to start {unit}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "{unit}, the {engine} daemon's unit, did not start: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own under the system's temporary one, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("dguard-start-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A port nothing listens on, which stays this test's while the socket that comes
    /// with it is held: bound and not listening, so no test running meanwhile is given
    /// it by the system and answers on it.
    fn closed_port() -> (u16, tokio::net::TcpSocket) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        (socket.local_addr().unwrap().port(), socket)
    }

    /// A daemon on a port of its own that answers every line with `reply`.
    async fn answering(reply: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (r, mut w) = sock.into_split();
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(_)) = lines.next_line().await {
                        let _ = w.write_all(reply.as_bytes()).await;
                    }
                });
            }
        });
        port
    }

    #[test]
    fn the_message_without_a_daemon_names_the_two_ways_to_start_one() {
        assert_eq!(
            not_running("ambulo", 4441),
            "Ambulo daemon is not running on port 4441.\nStart it with `ambulo daemon`, or \
             with `crossfyre extension start ambulo` if crossfyre installed it."
        );
    }

    #[test]
    fn the_unit_is_named_for_its_engine() {
        assert_eq!(unit_name("voyage"), "crossfyre-voyage.service");
    }

    #[tokio::test]
    async fn with_starting_off_a_client_says_the_daemon_is_not_running() {
        let (port, _held) = closed_port();
        let e = Daemon::new("voyage", port, false)
            .connect()
            .await
            .unwrap_err();
        assert_eq!(e, not_running("voyage", port));
    }

    #[test]
    fn a_unit_serves_the_port_its_exec_line_names() {
        let unit = format!(
            "[Service]\nType=simple\nExecStart=/opt/crossfyre/bin/voyage {}\nRestart=on-failure\n",
            daemon_args(4442).join(" ")
        );
        let unit = unit.as_str();
        assert!(unit_serves(unit, 4442));
        assert!(!unit_serves(unit, 14442));
        assert!(!unit_serves(unit, 442));
        assert!(unit_serves(
            "ExecStart=/x/voyage daemon --port=5000\n",
            5000
        ));
        assert!(!unit_serves("Description=port 4442\n", 4442));
    }

    #[test]
    fn a_log_past_its_limit_is_started_over_and_one_within_it_is_kept() {
        let dir = Scratch::new("log-limit");
        let logs = dir.path().join("logs");
        let log = logs.join("voyage.log");
        open_log(&logs, &log).unwrap();

        std::fs::write(&log, "an earlier run\n").unwrap();
        std::fs::File::options()
            .append(true)
            .open(&log)
            .unwrap()
            .set_len(LOG_LIMIT)
            .unwrap();
        let file = open_log(&logs, &log).unwrap();
        assert_eq!(
            file.metadata().unwrap().len(),
            LOG_LIMIT,
            "within the limit"
        );

        std::fs::File::options()
            .append(true)
            .open(&log)
            .unwrap()
            .set_len(LOG_LIMIT + 1)
            .unwrap();
        let mut file = open_log(&logs, &log).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0, "past the limit");
        use std::io::Write;
        writeln!(file, "this run").unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "this run\n");
        assert_eq!(
            std::fs::read_dir(&logs).unwrap().count(),
            1,
            "an older copy was kept"
        );
    }

    #[test]
    fn the_daemon_is_the_engine_binary_on_the_port_and_told_when_to_exit_unused() {
        let dir = Scratch::new("command");
        let log = || std::fs::File::create(dir.path().join("x.log")).unwrap();
        let exe = Path::new("/opt/crossfyre/bin/voyage");
        let idle = |cmd: &std::process::Command| {
            cmd.get_envs()
                .find(|(k, _)| *k == IDLE_EXIT_ENV)
                .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
        };

        let cmd = daemon_command(exe, 4442, log(), None).unwrap();
        assert_eq!(cmd.get_program(), exe);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["daemon", "--port", "4442"]);
        assert_eq!(idle(&cmd).as_deref(), Some("1800"));

        // A client that was given its own limit passes that on with the rest of its
        // environment.
        let cmd = daemon_command(exe, 4442, log(), Some("20".into())).unwrap();
        assert_eq!(idle(&cmd), None);
    }

    #[test]
    fn a_daemon_is_ready_once_it_answers_capabilities_with_its_pid() {
        assert_eq!(
            answer_to(r#"{"type":"capabilities","egress":1,"pid":4242}"#),
            Answer::Ready(4242)
        );
        assert_eq!(
            answer_to(r#"{"type":"capabilities","egress":1}"#),
            Answer::NotYet
        );
        assert_eq!(
            answer_to(
                r#"{"type":"error","message":"ambulo is not ready, waiting for its database"}"#
            ),
            Answer::NotYet
        );
        assert_eq!(answer_to(crate::UNAUTHORIZED), Answer::Refused);
        assert_eq!(answer_to("HTTP/1.1 400 Bad Request"), Answer::NotYet);
    }

    #[tokio::test]
    async fn waiting_ends_when_the_daemon_answers() {
        let port = answering("{\"type\":\"capabilities\",\"pid\":4242}\n").await;
        let daemon = Daemon::new("voyage", port, true);
        let start = Start::Spawned {
            child: None,
            log: PathBuf::new(),
            from: 0,
        };
        assert_eq!(daemon.wait(start, Duration::from_secs(5)).await, Ok(4242));
    }

    #[cfg(unix)]
    fn spawned(script: &str, log: &Path) -> Start {
        let out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .unwrap();
        let from = out.metadata().unwrap().len();
        let child = std::process::Command::new("sh")
            .args(["-c", script])
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .unwrap();
        Start::Spawned {
            child: Some(child),
            log: log.to_path_buf(),
            from,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_that_stops_before_it_answers_is_reported_with_what_it_wrote() {
        let dir = Scratch::new("stopped");
        let log = dir.path().join("voyage.log");
        std::fs::write(&log, "a line from an earlier run\n").unwrap();
        let start = spawned("echo 'the database is not there'; exit 3", &log);
        let (port, _held) = closed_port();
        let daemon = Daemon::new("voyage", port, true);
        let e = daemon
            .wait(start, Duration::from_secs(10))
            .await
            .unwrap_err();
        assert!(
            e.starts_with("the voyage daemon stopped before it answered"),
            "{e}"
        );
        assert!(e.ends_with(":\nthe database is not there"), "{e}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_waiting_for_its_database_is_stopped_with_what_it_said() {
        let dir = Scratch::new("waiting");
        let log = dir.path().join("voyage.log");
        let said = "[dguard] waiting for the database: PostgreSQL is not installed here \
                    (attempt 1, retrying in 1s)\n[dguard] waiting for the database: \
                    PostgreSQL is not installed here (attempt 2, retrying in 2s)";
        let start = spawned(&format!("printf '%s\\n' '{said}'; exec sleep 30"), &log);
        let (port, _held) = closed_port();
        let daemon = Daemon::new("voyage", port, true);
        let begun = Instant::now();
        let e = daemon
            .wait(start, Duration::from_secs(20))
            .await
            .unwrap_err();
        assert!(
            begun.elapsed() < Duration::from_secs(10),
            "waited out the limit"
        );
        assert_eq!(
            e,
            format!(
                "the voyage daemon cannot start yet, so it was stopped. What it wrote, in {}:\n\
                 {said}",
                log.display()
            )
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn one_try_that_waits_is_not_enough_to_stop_a_daemon() {
        let dir = Scratch::new("one-try");
        let log = dir.path().join("doorward.log");
        let start = spawned(
            "echo '[dguard] waiting for the database: could not make the doorward database \
             (attempt 1, retrying in 1s)'; exec sleep 30",
            &log,
        );
        let (port, _held) = closed_port();
        let daemon = Daemon::new("doorward", port, true);
        let e = daemon
            .wait(start, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(e.contains("did not answer within 2 seconds"), "{e}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_of_this_client_is_stopped_when_another_answers_first() {
        let port = answering("{\"type\":\"capabilities\",\"pid\":4242}\n").await;
        let dir = Scratch::new("second");
        let start = spawned("exec sleep 30", &dir.path().join("voyage.log"));
        let Start::Spawned {
            child: Some(child), ..
        } = &start
        else {
            unreachable!()
        };
        let pid = child.id() as libc::pid_t;
        let daemon = Daemon::new("voyage", port, true);
        let begun = Instant::now();
        assert_eq!(daemon.wait(start, Duration::from_secs(20)).await, Ok(4242));
        assert!(
            begun.elapsed() < Duration::from_secs(10),
            "waited for it to end"
        );
        // SAFETY: kill with signal 0 only asks whether the process is there.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "left running");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_that_does_not_answer_in_time_is_stopped() {
        let dir = Scratch::new("in-time");
        let log = dir.path().join("doorward.log");
        let start = spawned("echo 'waiting for the database'; exec sleep 30", &log);
        let Start::Spawned {
            child: Some(child), ..
        } = &start
        else {
            unreachable!()
        };
        let pid = child.id() as libc::pid_t;
        let (port, _held) = closed_port();
        let daemon = Daemon::new("doorward", port, true);
        let begun = Instant::now();
        let e = daemon
            .wait(start, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(
            begun.elapsed() < Duration::from_secs(10),
            "waited for it to end"
        );
        assert_eq!(
            e,
            format!(
                "the doorward daemon did not answer within 1 seconds, so it was stopped. The \
                 end of what it wrote, in {}:\nwaiting for the database",
                log.display()
            )
        );
        // SAFETY: kill with signal 0 only asks whether the process is there.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "left running");
    }
}
