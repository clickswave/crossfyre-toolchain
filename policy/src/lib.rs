//! The privacy policy a machine runs under.
//!
//! Two of the three are an account's, kept in Crossfyre and copied to a machine when it
//! fetches them: `connected`, under which local tools send what their features need, and
//! `private`, under which they send nothing about targets. The third, `offline`, is a
//! mode of one machine alone: it makes no contact with Crossfyre except a `crossfyre
//! login` or `crossfyre update` the user runs, and when the user chose it, a node does not
//! start on it.
//!
//! The copy and the mode live in `policy.toml` in the CLI's own state, beside auth.toml,
//! and not in the config the engines read: engines check no policy. The CLI writes the
//! file; every program on the machine reads it through here, so it is read one way.
//! `CROSSFYRE_POLICY` tightens the policy for one run and never loosens it.

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
                "Local tools send what their features need: Web Tracer shapes, Mobile captures \
                 and MCP's Cloud tools."
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

    /// Whether local tools may send data about a target under it.
    pub fn sends_targets(self) -> bool {
        self == Policy::Connected
    }
}

/// Why this machine is offline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The user chose it.
    Chosen,
    /// Crossfyre stopped taking the session: an account key ends only when it is
    /// revoked, and Crossfyre's answer does not say how.
    SessionEnded,
}

impl Reason {
    pub fn says(self) -> &'static str {
        match self {
            Reason::Chosen => "you chose it",
            Reason::SessionEnded => "your session ended; run crossfyre login",
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

    /// The state as policy.toml holds it, the default (connected, not chosen) when it
    /// does not read.
    pub fn from_toml(raw: &str) -> Machine {
        toml::from_str(raw).unwrap_or_default()
    }

    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string(self).map_err(|e| e.to_string())
    }
}

/// Where the state is kept: `policy.toml` in the CLI's data directory.
pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("policy.toml")
}

/// The state in `data_dir`, the default when there is none, for a program that reads it
/// as the user it runs as. The CLI reads and writes it through cfx_core, which minds
/// sudo.
pub fn read(data_dir: &Path) -> Machine {
    std::fs::read_to_string(path(data_dir))
        .map(|raw| Machine::from_toml(&raw))
        .unwrap_or_default()
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

/// `machine`'s policy for this run, with CROSSFYRE_POLICY read from the environment.
pub fn in_force_now(machine: &Machine) -> InForce {
    in_force(machine, std::env::var(ENV).ok().as_deref())
}

/// What a local tool that sends data about a target says when `run` turns it off, with
/// `what` naming the tool. None under connected.
pub fn turned_off(machine: &Machine, run: &InForce, what: &str) -> Option<String> {
    let why = match (&run.note, &machine.offline) {
        (Some(note), _) => note.clone(),
        (None, Some(o)) if run.policy == Policy::Offline => o.reason.says().to_string(),
        (None, _) => "the account's".to_string(),
    };
    match run.policy {
        Policy::Connected => None,
        Policy::Private => Some(format!(
            "policy: private ({why}). This machine's tools send nothing about targets to \
             Crossfyre, so {what} does not run. Change it in account settings or with \
             crossfyre policy set connected."
        )),
        Policy::Offline => Some(format!(
            "policy: offline ({why}). This machine makes no contact with Crossfyre, so {what} \
             does not run. Leave offline with crossfyre policy set connected."
        )),
    }
}

#[cfg(test)]
mod tests;
