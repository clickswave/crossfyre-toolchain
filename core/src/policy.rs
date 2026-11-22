//! The privacy policy this machine runs under.
//!
//! Two of the three are an account's, kept in Crossfyre and copied here when the machine
//! fetches them: `connected`, under which local tools send what their features need, and
//! `private`, under which they send nothing about targets. The third, `offline`, is a mode
//! of this machine alone: it makes no contact with Crossfyre except a `crossfyre login` or
//! `crossfyre update` the user runs, and when the user chose it, a node does not start on
//! it.
//!
//! The copy and the mode live in `policy.toml` beside auth.toml, in the CLI's own state,
//! and not in the config the engines read: engines check no policy. `CROSSFYRE_POLICY`
//! tightens the policy for one run and never loosens it.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A policy, in order of what it allows: each one after the first sends less.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Connected,
    Private,
    Offline,
}

/// The policies, as `policy list` shows them.
pub const ALL: [Policy; 3] = [Policy::Connected, Policy::Private, Policy::Offline];

impl Policy {
    pub fn key(self) -> &'static str {
        match self {
            Policy::Connected => "connected",
            Policy::Private => "private",
            Policy::Offline => "offline",
        }
    }

    pub fn parse(name: &str) -> Option<Policy> {
        ALL.into_iter().find(|p| p.key() == name.trim())
    }

    /// What it lets this machine send, in a sentence.
    pub fn sends(self) -> &'static str {
        match self {
            Policy::Connected => {
                "Local tools send what their features need: Web Tracer shapes, Mobile captures, \
                 MCP's Cloud tools, and the managed OAST pool's callbacks."
            }
            Policy::Private => {
                "Local tools send nothing about targets. Login, updates and downloads still work, \
                 and nodes still run and report what you launch from Cloud."
            }
            Policy::Offline => {
                "This machine contacts Crossfyre only when you run crossfyre login or crossfyre \
                 update. When you choose it, a node here stops too."
            }
        }
    }

    /// Whether it is one an account can have, which offline is not.
    pub fn is_account(self) -> bool {
        self != Policy::Offline
    }
}

/// Why this machine is offline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The user chose it.
    Chosen,
    /// The session expired.
    SessionExpired,
    /// The session was revoked.
    SessionRevoked,
}

impl Reason {
    pub fn says(self) -> &'static str {
        match self {
            Reason::Chosen => "you chose it",
            Reason::SessionExpired => "your session expired; run crossfyre login",
            Reason::SessionRevoked => "your session was revoked; run crossfyre login",
        }
    }
}

/// When and why this machine went offline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offline {
    pub reason: Reason,
    pub since: String,
}

/// What this machine holds: the account's policy as it last had it, and its own mode.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Machine {
    /// The account's policy, none until the account has one here. Never offline.
    #[serde(default)]
    pub account: Option<Policy>,
    /// When the account's policy last changed, and where, as Crossfyre recorded it, or
    /// as this machine did when it set it alone.
    #[serde(default)]
    pub changed_at: Option<String>,
    #[serde(default)]
    pub changed_via: Option<String>,
    /// A tightening set here while Crossfyre could not be reached, sent at the next
    /// contact.
    #[serde(default)]
    pub unsent: bool,
    #[serde(default)]
    pub offline: Option<Offline>,
}

impl Machine {
    /// The policy this machine runs under, before CROSSFYRE_POLICY.
    pub fn active(&self) -> Policy {
        if self.offline.is_some() {
            Policy::Offline
        } else {
            self.account.unwrap_or(Policy::Connected)
        }
    }
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("policy.toml")
}

/// This machine's state, the default one (connected, not chosen) when there is none.
pub fn load(data_dir: &Path) -> Machine {
    crate::toolchain::sudo_user::read_to_string(&path(data_dir))
        .ok()
        .and_then(|raw| toml::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save(data_dir: &Path, machine: &Machine) -> Result<(), String> {
    if !data_dir.exists() {
        crate::toolchain::sudo_user::create_dir_all_for_invoking_user(data_dir)
            .map_err(|e| format!("{}: {e}", data_dir.display()))?;
    }
    let body = toml::to_string(machine).map_err(|e| e.to_string())?;
    let file = path(data_dir);
    crate::toolchain::sudo_user::write_for_invoking_user(&file, body.as_bytes(), 0o600)
        .map_err(|e| format!("{}: {e}", file.display()))
}

/// The variable that tightens the policy for one run.
pub const ENV: &str = "CROSSFYRE_POLICY";

/// The policy a run is under, and what CROSSFYRE_POLICY did to it, when it said
/// something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InForce {
    pub policy: Policy,
    pub note: Option<String>,
}

/// `machine`'s policy, tightened by `env` (CROSSFYRE_POLICY's value) when that is
/// stricter, and never loosened by it.
pub fn in_force(machine: &Machine, env: Option<&str>) -> InForce {
    let mine = machine.active();
    let Some(asked) = env.map(str::trim).filter(|v| !v.is_empty()) else {
        return InForce {
            policy: mine,
            note: None,
        };
    };
    match Policy::parse(asked) {
        Some(p) if p > mine => InForce {
            policy: p,
            note: Some(format!(
                "{ENV}={asked} tightens this run from {}",
                mine.key()
            )),
        },
        Some(p) if p < mine => InForce {
            policy: mine,
            note: Some(format!(
                "{ENV}={asked} is looser than this machine's {}, so it is ignored",
                mine.key()
            )),
        },
        Some(_) => InForce {
            policy: mine,
            note: None,
        },
        None => InForce {
            policy: mine,
            note: Some(format!(
                "{ENV}={asked} names no policy (connected, private or offline), so it is ignored"
            )),
        },
    }
}

/// This machine's policy for this run, with CROSSFYRE_POLICY read from the environment.
pub fn for_this_run(data_dir: &Path) -> InForce {
    in_force(&load(data_dir), std::env::var(ENV).ok().as_deref())
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
