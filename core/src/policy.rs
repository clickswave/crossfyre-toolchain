//! The privacy policy this machine runs under, as the CLI keeps and changes it.
//!
//! The policies, the state in `policy.toml` and how `CROSSFYRE_POLICY` tightens a run are
//! cfx_policy's, so every program on the machine reads the one file one way. Here the CLI
//! reads and writes that file as the invoking user, under sudo too, and talks to Crossfyre
//! about the account's policy.

use std::path::Path;

pub use cfx_policy::{
    ALL, ENV, InForce, Machine, Offline, PRIVATE_STOPS, Policy, Reason, in_force, path,
};

/// This machine's state, the default one (connected) when there is none.
pub fn load(data_dir: &Path) -> Machine {
    crate::toolchain::sudo_user::read_to_string(&path(data_dir))
        .map(|raw| Machine::from_toml(&raw))
        .unwrap_or_default()
}

pub fn save(data_dir: &Path, machine: &Machine) -> Result<(), String> {
    if !data_dir.exists() {
        crate::toolchain::sudo_user::create_dir_all_for_invoking_user(data_dir)
            .map_err(|e| format!("{}: {e}", data_dir.display()))?;
    }
    let body = machine.to_toml()?;
    let file = path(data_dir);
    crate::toolchain::sudo_user::write_for_invoking_user(&file, body.as_bytes(), 0o600)
        .map_err(|e| format!("{}: {e}", file.display()))
}

/// Crossfyre refused `key`. When that is this machine's session, the machine goes
/// offline with the reason, as every tool on the session's key then is; a node's own key
/// is not the session and changes nothing here. A machine already offline stays as it
/// is. The line to show, when the key was the session's.
pub fn session_ended(data_dir: &Path, key: &str) -> Option<String> {
    let account = crate::auth::load_account(data_dir)?;
    if account.api_key != key {
        return None;
    }
    let mut machine = load(data_dir);
    let offline = machine.offline.get_or_insert_with(|| Offline {
        reason: Reason::SessionEnded,
        since: utc_now(),
    });
    let line = format!("policy: offline ({})", offline.reason.says());
    Some(match save(data_dir, &machine) {
        Ok(()) => line,
        Err(e) => format!("{line}, though it could not be recorded: {e}"),
    })
}

/// This machine's policy for this run, with CROSSFYRE_POLICY read from the environment.
pub fn for_this_run(data_dir: &Path) -> InForce {
    cfx_policy::in_force_now(&load(data_dir))
}

/// `policy: offline (why)`, when this run is offline.
pub fn offline_line(data_dir: &Path) -> Option<String> {
    let machine = load(data_dir);
    cfx_policy::offline_line(&machine, &cfx_policy::in_force_now(&machine))
}

/// For something that would contact Crossfyre, `what`: why it does not run on this
/// machine now, when the machine is offline.
pub fn offline_refuses(data_dir: &Path, what: &str) -> Option<String> {
    let machine = load(data_dir);
    let run = cfx_policy::in_force_now(&machine);
    (run.policy == Policy::Offline)
        .then(|| cfx_policy::turned_off(&machine, &run, what))
        .flatten()
}

/// For a local tool that sends data about a target, `what`: why it does not run on this
/// machine now, when it does not.
pub fn turned_off(data_dir: &Path, what: &str) -> Option<String> {
    let machine = load(data_dir);
    cfx_policy::turned_off(&machine, &cfx_policy::in_force_now(&machine), what)
}

/// The time now, as Crossfyre writes one: `2026-11-22T05:30:00Z`.
pub fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc(secs)
}

fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days, after Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

pub mod cloud;
pub mod command;

#[cfg(test)]
mod tests;
