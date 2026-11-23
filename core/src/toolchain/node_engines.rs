//! The engines `crossfyre node up` runs itself, where no service manager runs them: WSL
//! without systemd, and most containers (see [`super::service::user_manager_runs`]).
//!
//! The node supervisor runs each installed engine that no running service manager has a
//! unit for, as its daemon, as the unit would: on its configured port, as the operator and
//! never as root, with no idle exit, and with what it writes in its log in the toolchain
//! directory, where its client puts it too. An engine that exits is started again after a
//! wait that doubles from 2 seconds to a minute, and is back at 2 once it has run for a
//! minute. One whose binary, port or database changes, as after `crossfyre update` or a
//! port set in the dashboard, is started again at once; one that is removed, or that a
//! service manager now runs, is stopped; and one installed meanwhile is started. All of
//! them stop with the supervisor. While one runs, its client finds it answering and
//! starts none.

use super::{config, service, sudo_user};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// The wait before an engine that exited is started again, the first time.
const FIRST_WAIT: Duration = Duration::from_secs(2);
/// The longest wait before an engine that exited is started again.
const LONGEST_WAIT: Duration = Duration::from_secs(60);
/// How long an engine runs before the wait after its next exit is the first one again.
const SETTLED: Duration = Duration::from_secs(60);
/// How long an engine that is stopped has to end before it is killed.
const STOP_WAIT: Duration = Duration::from_secs(5);

/// The engines the node supervisor runs.
pub struct NodeEngines {
    /// Who they run as, or why there is nobody to run them as.
    account: Result<Account, String>,
    engines: Vec<Engine>,
    /// Whether it was said that nobody can run them.
    said_nobody: bool,
}

impl NodeEngines {
    /// Start every installed engine that no service manager runs. Off Linux, where the
    /// engines' services always run them, it runs none.
    pub fn start() -> Self {
        let account = Account::operator();
        if let Ok(account) = &account
            && !service::user_manager_runs()
        {
            println!(
                "[engines] No service manager runs here, so this supervisor runs the engines, \
                 as {}",
                account.name
            );
        }
        let names = super::ENGINES.iter().map(|e| e.name);
        let mut engines = Self {
            account,
            engines: if cfg!(target_os = "linux") {
                names.map(Engine::new).collect()
            } else {
                Vec::new()
            },
            said_nobody: false,
        };
        engines.tend();
        engines
    }

    /// Start the engines that are due, start again the ones that exited or changed, and
    /// stop the ones that were removed or that a service manager runs now. The supervisor
    /// calls it each time it looks at its nodes.
    pub fn tend(&mut self) {
        let now = Instant::now();
        for engine in &mut self.engines {
            let name = engine.name;
            let wanted = wanted(name);
            let account = match &self.account {
                Ok(account) => account,
                Err(why) => {
                    if wanted.is_ok() && !self.said_nobody {
                        eprintln!("[engines] {why}");
                        self.said_nobody = true;
                    }
                    continue;
                }
            };
            let said = engine.tend(wanted, now, super::status::port_open, || {
                spawn(name, account)
            });
            for line in said {
                println!("[engines] {line}");
            }
        }
    }

    /// Stop every engine: asked to stop, and killed when it has not after a few seconds.
    pub fn stop(self) {
        let mut running: Vec<(&str, Child)> = self
            .engines
            .into_iter()
            .filter_map(|e| e.running.map(|r| (e.name, r.child)))
            .collect();
        for (_, child) in &mut running {
            crate::os::ask_to_stop(child);
        }
        let deadline = Instant::now() + STOP_WAIT;
        for (name, mut child) in running {
            println!("[engines] {}", stop_by(name, &mut child, deadline));
        }
    }
}

/// The account the engines run as: the one that ran the supervisor through sudo, or the
/// supervisor's own when it is not root.
struct Account {
    /// The uid and gid to run them with, when the supervisor is root.
    ids: Option<(u32, u32)>,
    home: PathBuf,
    name: String,
}

impl Account {
    fn operator() -> Result<Self, String> {
        if let Some((uid, gid, home, name)) = sudo_user::sudo_user_info() {
            return Ok(Self {
                ids: Some((uid, gid)),
                home,
                name,
            });
        }
        if is_root() {
            return Err(
                "the engines do not run as root, and no other account ran this \
                        through sudo, so none run. Run `crossfyre node up` from the account \
                        the engines run as: it uses sudo where it needs root"
                    .to_string(),
            );
        }
        Ok(Self {
            ids: None,
            home: dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")),
            name: std::env::var("USER").unwrap_or_else(|_| "this account".to_string()),
        })
    }
}

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

/// How engine `name` is to run now, or why this supervisor does not run it.
fn wanted(name: &str) -> Result<Wanted, &'static str> {
    if !config::is_extension_installed(name) {
        return Err("it was removed");
    }
    if service::has_service_file(name) && service::user_manager_runs() {
        return Err("its service manager runs it now");
    }
    Ok(Wanted {
        port: config::engine_port(name),
        binary: Stamp::of(&config::ext_bin_path(name)).ok_or("it was removed")?,
        database: config::load_config().ok().map(|c| c.postgres),
    })
}

/// Engine `name`'s daemon, started as `account` with what it writes appended to its log.
fn spawn(name: &str, account: &Account) -> std::io::Result<Child> {
    let mut cmd = service::engine_command(name).map_err(std::io::Error::other)?;
    let log = open_log(name)?;
    cmd.env_remove(dguard::IDLE_EXIT_ENV)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .current_dir(&account.home);
    #[cfg(unix)]
    if let Some((uid, gid)) = account.ids {
        use std::os::unix::process::CommandExt;
        cmd.uid(uid)
            .gid(gid)
            .env("HOME", &account.home)
            .env("USER", &account.name)
            .env("LOGNAME", &account.name);
    }
    // Only root, on Unix, has another account's ids to take.
    #[cfg(not(unix))]
    let _ = account.ids;
    cmd.spawn()
}

/// Engine `name`'s log in the toolchain directory, the operator's, to append to: empty
/// once it has grown past [`dguard::LOG_LIMIT`], as when its client starts it.
fn open_log(name: &str) -> std::io::Result<std::fs::File> {
    let dir = config::logs_dir();
    sudo_user::create_dir_all_for_invoking_user(&dir)?;
    let file = sudo_user::append_for_invoking_user(&dir.join(format!("{name}.log")), 0o600)?;
    if file.metadata()?.len() > dguard::LOG_LIMIT {
        file.set_len(0)?;
    }
    Ok(file)
}

/// How an engine is to run: on which port, from which binary, with which database.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Wanted {
    port: u16,
    binary: Stamp,
    database: Option<cfx_db::Settings>,
}

/// Which file a binary is, so one replaced, or written over, is told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    modified: Option<SystemTime>,
}

impl Stamp {
    fn of(path: &Path) -> Option<Self> {
        let m = std::fs::metadata(path).ok()?;
        #[cfg(unix)]
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            (m.dev(), m.ino())
        };
        #[cfg(not(unix))]
        let (dev, ino) = (0, 0);
        Some(Self {
            dev,
            ino,
            len: m.len(),
            modified: m.modified().ok(),
        })
    }
}

/// One engine, as the supervisor keeps it.
struct Engine {
    name: &'static str,
    running: Option<Running>,
    /// When it may be started again, after it exited or could not be started.
    not_before: Option<Instant>,
    /// The wait after its next exit.
    wait: Duration,
    /// Whether something else answered on its port when it was due to start.
    port_taken: bool,
}

struct Running {
    child: Child,
    wanted: Wanted,
    since: Instant,
}

impl Engine {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            running: None,
            not_before: None,
            wait: FIRST_WAIT,
            port_taken: false,
        }
    }

    /// Bring the engine to `wanted` at `now`, or when it is an error, to stopped, for the
    /// reason it gives: start it when it is due, with `spawn`, unless `answers` says
    /// something else listens on its port; note an exit and when it is started again; and
    /// stop it when it changed. The lines to log.
    fn tend(
        &mut self,
        wanted: Result<Wanted, &'static str>,
        now: Instant,
        answers: impl Fn(u16) -> bool,
        spawn: impl FnOnce() -> std::io::Result<Child>,
    ) -> Vec<String> {
        let mut said = Vec::new();
        let name = self.name;
        if let Some(run) = self.running.as_mut() {
            match run.child.try_wait() {
                Ok(Some(status)) => {
                    if now.saturating_duration_since(run.since) >= SETTLED {
                        self.wait = FIRST_WAIT;
                    }
                    said.push(format!(
                        "{name} exited ({status}); starting it again in {}s",
                        self.wait.as_secs()
                    ));
                    self.not_before = Some(now + self.wait);
                    self.wait = (self.wait * 2).min(LONGEST_WAIT);
                    self.running = None;
                }
                _ if wanted.as_ref().ok() != Some(&run.wanted) => {
                    let why = match &wanted {
                        Err(why) => why,
                        Ok(w) if w.binary != run.wanted.binary => "its binary changed",
                        Ok(w) if w.port != run.wanted.port => "its port changed",
                        Ok(_) => "its database changed",
                    };
                    let deadline = Instant::now() + STOP_WAIT;
                    crate::os::ask_to_stop(&mut run.child);
                    said.push(format!(
                        "{why}, so {}",
                        stop_by(name, &mut run.child, deadline)
                    ));
                    self.running = None;
                    self.not_before = None;
                }
                _ => {}
            }
        }
        let Ok(wanted) = wanted else {
            return said;
        };
        if self.running.is_some() || self.not_before.is_some_and(|t| now < t) {
            return said;
        }
        if answers(wanted.port) {
            if !self.port_taken {
                said.push(format!(
                    "something answers on port {} already, so {name} is left to it",
                    wanted.port
                ));
                self.port_taken = true;
            }
            return said;
        }
        self.port_taken = false;
        match spawn() {
            Ok(child) => {
                said.push(format!(
                    "{name} started on port {} (pid {})",
                    wanted.port,
                    child.id()
                ));
                self.running = Some(Running {
                    child,
                    wanted,
                    since: now,
                });
                self.not_before = None;
            }
            Err(e) => {
                said.push(format!(
                    "{name} did not start: {e}; trying again in {}s",
                    self.wait.as_secs()
                ));
                self.not_before = Some(now + self.wait);
                self.wait = (self.wait * 2).min(LONGEST_WAIT);
            }
        }
        said
    }
}

/// Wait until `deadline` for engine `name`, asked to stop, to end, and kill it when it
/// has not. What became of it.
fn stop_by(name: &str, child: &mut Child, deadline: Instant) -> String {
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return format!("{name} stopped");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    format!(
        "{name} did not stop in {}s, and was killed",
        STOP_WAIT.as_secs()
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A stand-in for an engine's daemon: a process that runs until it is stopped. Its
    /// output goes nowhere, so one a failed test leaves running holds no pipe of the
    /// test's open.
    fn daemon() -> std::io::Result<Child> {
        std::process::Command::new("sleep")
            .arg("600")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }

    fn wanted(port: u16, binary: u64) -> Result<Wanted, &'static str> {
        Ok(Wanted {
            port,
            binary: Stamp {
                dev: 1,
                ino: binary,
                len: 1,
                modified: None,
            },
            database: None,
        })
    }

    fn free(_: u16) -> bool {
        false
    }

    fn pid(engine: &Engine) -> Option<u32> {
        engine.running.as_ref().map(|r| r.child.id())
    }

    /// Kill the engine's process, as a crash or `kill -9` would, and wait for it to end.
    fn crash(engine: &mut Engine) {
        let child = &mut engine.running.as_mut().expect("running").child;
        child.kill().expect("kill");
        while child.try_wait().expect("try_wait").is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn an_engine_that_exits_is_started_again_once_its_wait_is_over() {
        let mut e = Engine::new("voyage");
        let t0 = Instant::now();
        let said = e.tend(wanted(4442, 1), t0, free, daemon);
        let first = pid(&e).expect("started");
        assert_eq!(said, [format!("voyage started on port 4442 (pid {first})")]);

        crash(&mut e);
        let said = e.tend(wanted(4442, 1), t0, free, daemon);
        assert_eq!(
            said,
            ["voyage exited (signal: 9 (SIGKILL)); starting it again in 2s"]
        );
        assert_eq!(pid(&e), None);
        // Not before the wait is over.
        assert!(
            e.tend(wanted(4442, 1), t0 + Duration::from_secs(1), free, daemon)
                .is_empty()
        );
        assert_eq!(pid(&e), None);
        e.tend(wanted(4442, 1), t0 + FIRST_WAIT, free, daemon);
        let second = pid(&e).expect("started again");
        assert_ne!(first, second);
        e.running.take().expect("running").child.kill().ok();
    }

    #[test]
    fn the_wait_doubles_to_a_minute_and_starts_over_once_an_engine_has_run_a_while() {
        let mut e = Engine::new("doorward");
        let mut now = Instant::now();
        let mut waits = Vec::new();
        for _ in 0..7 {
            e.tend(wanted(4443, 1), now, free, daemon);
            crash(&mut e);
            e.tend(wanted(4443, 1), now, free, daemon);
            let at = e.not_before.expect("a wait");
            waits.push(at.duration_since(now).as_secs());
            now = at;
        }
        assert_eq!(waits, [2, 4, 8, 16, 32, 60, 60]);
        // One that ran for a minute waits 2 seconds again.
        e.tend(wanted(4443, 1), now, free, daemon);
        crash(&mut e);
        e.tend(wanted(4443, 1), now + SETTLED, free, daemon);
        assert_eq!(e.not_before, Some(now + SETTLED + FIRST_WAIT));
    }

    #[test]
    fn an_engine_whose_binary_or_port_changed_is_started_again_at_once() {
        let mut e = Engine::new("ambulo");
        let t0 = Instant::now();
        e.tend(wanted(4441, 1), t0, free, daemon);
        let first = pid(&e).expect("started");

        // `crossfyre update` put a new binary in its place.
        let said = e.tend(wanted(4441, 2), t0, free, daemon);
        let second = pid(&e).expect("started again");
        assert_ne!(first, second);
        assert_eq!(
            said,
            [
                "its binary changed, so ambulo stopped".to_string(),
                format!("ambulo started on port 4441 (pid {second})"),
            ]
        );

        // The dashboard moved it to another port.
        let said = e.tend(wanted(14441, 2), t0, free, daemon);
        let third = pid(&e).expect("started again");
        assert_eq!(said[0], "its port changed, so ambulo stopped");
        assert_eq!(
            said[1],
            format!("ambulo started on port 14441 (pid {third})")
        );
        e.running.take().expect("running").child.kill().ok();
    }

    #[test]
    fn an_engine_that_was_removed_is_stopped_and_not_started_again() {
        let mut e = Engine::new("toolmark");
        let t0 = Instant::now();
        e.tend(wanted(4444, 1), t0, free, daemon);
        let child_pid = pid(&e).expect("started") as libc::pid_t;
        let said = e.tend(Err("it was removed"), t0, free, daemon);
        assert_eq!(said, ["it was removed, so toolmark stopped"]);
        assert_eq!(pid(&e), None);
        assert!(
            e.tend(Err("it was removed"), t0 + LONGEST_WAIT, free, daemon)
                .is_empty()
        );
        // SAFETY: kill with signal 0 only asks whether the process is there.
        assert_eq!(unsafe { libc::kill(child_pid, 0) }, -1, "left running");
    }

    #[test]
    fn a_port_something_else_answers_on_is_left_to_it() {
        let mut e = Engine::new("plessor");
        let t0 = Instant::now();
        let taken = |_| true;
        let said = e.tend(wanted(4445, 1), t0, taken, daemon);
        assert_eq!(
            said,
            ["something answers on port 4445 already, so plessor is left to it"]
        );
        // Said once while it stays so, and started once the port is free.
        assert!(e.tend(wanted(4445, 1), t0, taken, daemon).is_empty());
        e.tend(wanted(4445, 1), t0, free, daemon);
        assert!(pid(&e).is_some());
        e.running.take().expect("running").child.kill().ok();
    }

    #[test]
    fn stopping_the_engines_ends_every_one_of_them() {
        let mut engines = NodeEngines {
            account: Ok(Account {
                ids: None,
                home: PathBuf::from("/"),
                name: "op".to_string(),
            }),
            engines: vec![Engine::new("voyage"), Engine::new("doorward")],
            said_nobody: false,
        };
        let t0 = Instant::now();
        let mut pids = Vec::new();
        for (i, e) in engines.engines.iter_mut().enumerate() {
            e.tend(wanted(4442 + i as u16, 1), t0, free, daemon);
            pids.push(pid(e).expect("started") as libc::pid_t);
        }
        engines.stop();
        for p in pids {
            // SAFETY: kill with signal 0 only asks whether the process is there.
            assert_eq!(unsafe { libc::kill(p, 0) }, -1, "{p} left running");
        }
    }
}
