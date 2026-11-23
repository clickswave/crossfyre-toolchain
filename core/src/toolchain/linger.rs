//! Lingering for the user whose engines crossfyre runs, on Linux.
//!
//! The engines are units of the user's own service manager (`systemctl --user`).
//! systemd starts that manager when the user logs in and stops it when their last
//! session ends, unless lingering is on for them. Without it the engines do not start
//! under sudo from a login that has no manager running ("Failed to connect to user
//! scope bus"), and they stop at logout, while the node, a system unit, stays online.
//!
//! So when crossfyre creates the first engine unit for a user, it turns lingering on
//! for them and waits for their manager to answer. It records in the toolchain
//! directory that it did, and `crossfyre uninstall` turns lingering off only when that
//! record is there: lingering that someone else turned on stays on.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The record, in the toolchain directory, that crossfyre turned lingering on.
const RECORD: &str = "lingering";

/// How long to wait for the user's service manager once lingering is on. It usually
/// answers within a second.
const BUS_WAIT: Duration = Duration::from_secs(10);

/// What is asked of logind, so the decisions here can be tested without it.
trait Logind {
    /// Is lingering on for `user`?
    fn lingering(&self, user: &str) -> bool;
    fn enable(&self, user: &str) -> Result<(), String>;
    fn disable(&self, user: &str) -> Result<(), String>;
}

/// logind itself: its own list of who lingers, and loginctl to change it.
struct Loginctl;

impl Logind for Loginctl {
    fn lingering(&self, user: &str) -> bool {
        Path::new("/var/lib/systemd/linger").join(user).exists()
    }

    fn enable(&self, user: &str) -> Result<(), String> {
        loginctl("enable-linger", user)
    }

    fn disable(&self, user: &str) -> Result<(), String> {
        loginctl("disable-linger", user)
    }
}

fn loginctl(verb: &str, user: &str) -> Result<(), String> {
    let out = std::process::Command::new("loginctl")
        .args([verb, user])
        .output()
        .map_err(|e| format!("loginctl could not be run: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(if said.is_empty() {
        format!("loginctl {verb} exited with {}", out.status)
    } else {
        said
    })
}

/// What turning lingering on came to.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// It was on already, and stays on whatever crossfyre does later.
    AlreadyOn,
    /// Crossfyre turned it on, and recorded that it did.
    TurnedOn,
    /// It could not be turned on, for the reason given.
    Refused(String),
}

/// Turn lingering on for `user` unless it is on already, and record at `record` that
/// crossfyre did.
fn turn_on(logind: &impl Logind, user: &str, record: &Path) -> Outcome {
    if logind.lingering(user) {
        return Outcome::AlreadyOn;
    }
    if let Err(why) = logind.enable(user) {
        return Outcome::Refused(why);
    }
    if let Err(e) = write_record(record, user) {
        super::ui::warn(&format!(
            "Lingering is on for {user}, but {} could not be written ({e}), so \
             `crossfyre uninstall` will leave it on.",
            record.display()
        ));
    }
    Outcome::TurnedOn
}

/// Turn lingering off for `user` if the record at `record` says crossfyre turned it on,
/// and remove the record once it is off. None when there is no record.
fn turn_off(logind: &impl Logind, user: &str, record: &Path) -> Option<Result<(), String>> {
    std::fs::symlink_metadata(record).ok()?;
    let off = logind.disable(user);
    if off.is_ok() {
        let _ = super::sudo_user::remove_file(record);
    }
    Some(off)
}

fn write_record(record: &Path, user: &str) -> std::io::Result<()> {
    if let Some(dir) = record.parent() {
        super::sudo_user::create_dir_all_for_invoking_user(dir)?;
    }
    let text = format!(
        "crossfyre turned on lingering for {user}, so that the engines keep running while \
         {user} is not logged in. `crossfyre uninstall` turns it off again while this file \
         is here.\n"
    );
    super::sudo_user::write_for_invoking_user(record, text.as_bytes(), 0o644)
}

/// Wait up to `limit` for `path` to exist. Whether it does.
fn wait_for(path: &Path, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while !path.exists() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

fn record_path() -> PathBuf {
    super::config::get_toolchain_dir().join(RECORD)
}

/// The account whose service manager runs the engines: the one that ran crossfyre,
/// under sudo as well. Its uid and name.
fn engine_account() -> Option<(u32, String)> {
    if let Some((uid, _, _, name)) = super::sudo_user::sudo_user_info() {
        return Some((uid, name));
    }
    // SAFETY: getpwuid returns a pointer into static storage or null, and the name is
    // copied out before anything else could call it again.
    unsafe {
        let uid = libc::getuid();
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() || (*pwd).pw_name.is_null() {
            return None;
        }
        let name = std::ffi::CStr::from_ptr((*pwd).pw_name)
            .to_string_lossy()
            .into_owned();
        Some((uid, name))
    }
}

/// For the first engine unit made for a user: turn lingering on for them unless it is
/// on already, then wait for their service manager to answer on its bus, so the
/// `systemctl --user` calls after this reach it. One line says when it was turned on,
/// and one when it could not be, with the command that would.
pub fn keep_engines_running() {
    if !super::service::systemd_runs() {
        return;
    }
    let Some((_, name)) = engine_account() else {
        return;
    };
    match turn_on(&Loginctl, &name, &record_path()) {
        Outcome::TurnedOn => {
            if !super::service::quiet() {
                super::ui::ok(&format!(
                    "Lingering turned on for {name}, so the engines keep running after {name} \
                     logs out"
                ));
            }
        }
        Outcome::AlreadyOn => {}
        Outcome::Refused(why) => {
            super::ui::warn(&format!(
                "The engines will stop when {name} logs out: lingering could not be turned \
                 on ({why}). To keep them running: sudo loginctl enable-linger {name}"
            ));
            return;
        }
    }
    wait_for_manager();
}

/// Where the engine account's service manager listens when it runs: on a bus in its
/// runtime directory.
pub fn user_bus() -> Option<PathBuf> {
    engine_account().map(|(uid, _)| PathBuf::from(format!("/run/user/{uid}/bus")))
}

/// Wait a few seconds for the engine account's service manager to answer on its bus, as
/// it does once lingering is turned on, or at boot once it has started. Whether it does.
pub fn wait_for_manager() -> bool {
    user_bus().is_some_and(|bus| wait_for(&bus, BUS_WAIT))
}

/// For `crossfyre uninstall`: turn lingering off for the invoking user when crossfyre
/// turned it on. The user's name once it is off, the error when it could not be
/// turned off, and None when crossfyre did not turn it on.
pub fn undo() -> Option<Result<String, String>> {
    let (_, name) = engine_account()?;
    turn_off(&Loginctl, &name, &record_path()).map(|off| off.map(|()| name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// logind as these tests need it: who lingers, what it was asked, and whether it
    /// refuses.
    #[derive(Default)]
    struct Fake {
        lingering: RefCell<Vec<String>>,
        refuse: Option<String>,
        asked: RefCell<Vec<String>>,
    }

    impl Logind for Fake {
        fn lingering(&self, user: &str) -> bool {
            self.lingering.borrow().iter().any(|u| u == user)
        }

        fn enable(&self, user: &str) -> Result<(), String> {
            self.asked.borrow_mut().push(format!("enable {user}"));
            if let Some(why) = &self.refuse {
                return Err(why.clone());
            }
            self.lingering.borrow_mut().push(user.to_string());
            Ok(())
        }

        fn disable(&self, user: &str) -> Result<(), String> {
            self.asked.borrow_mut().push(format!("disable {user}"));
            self.lingering.borrow_mut().retain(|u| u != user);
            Ok(())
        }
    }

    #[test]
    fn lingering_crossfyre_turns_on_is_recorded_and_turned_off_at_uninstall() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = dir.path().join("toolchain").join(RECORD);
        let logind = Fake::default();

        assert_eq!(turn_on(&logind, "tester", &record), Outcome::TurnedOn);
        assert!(logind.lingering("tester"));
        let text = std::fs::read_to_string(&record).expect("the record");
        assert!(text.contains("tester"), "{text}");

        assert_eq!(turn_off(&logind, "tester", &record), Some(Ok(())));
        assert!(!logind.lingering("tester"));
        assert!(!record.exists(), "the record stayed");
        assert_eq!(
            *logind.asked.borrow(),
            ["enable tester", "disable tester"],
            "asked logind"
        );
    }

    /// Lingering that was on before crossfyre came is someone else's: nothing is
    /// recorded, so uninstall leaves it on.
    #[test]
    fn lingering_that_was_already_on_is_left_on_at_uninstall() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = dir.path().join(RECORD);
        let logind = Fake::default();
        logind.lingering.borrow_mut().push("tester".to_string());

        assert_eq!(turn_on(&logind, "tester", &record), Outcome::AlreadyOn);
        assert!(
            !record.exists(),
            "recorded lingering crossfyre did not turn on"
        );
        assert_eq!(turn_off(&logind, "tester", &record), None);
        assert!(
            logind.lingering("tester"),
            "turned off lingering it did not turn on"
        );
        assert!(
            logind.asked.borrow().is_empty(),
            "{:?}",
            logind.asked.borrow()
        );
    }

    #[test]
    fn a_refusal_is_reported_and_recorded_nowhere() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = dir.path().join(RECORD);
        let logind = Fake {
            refuse: Some("Access denied".to_string()),
            ..Fake::default()
        };

        assert_eq!(
            turn_on(&logind, "tester", &record),
            Outcome::Refused("Access denied".to_string())
        );
        assert!(!record.exists());
        assert_eq!(turn_off(&logind, "tester", &record), None);
    }

    #[test]
    fn the_wait_for_the_bus_ends_when_it_appears_and_is_bounded_when_it_does_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bus = dir.path().join("bus");
        let started = Instant::now();
        assert!(!wait_for(&bus, Duration::from_millis(300)));
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );

        let later = bus.clone();
        let maker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            std::fs::write(later, "").expect("bus");
        });
        assert!(wait_for(&bus, Duration::from_secs(10)));
        maker.join().expect("thread");
    }
}
