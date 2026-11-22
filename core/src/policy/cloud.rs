//! The account's policy at Crossfyre, fetched and set with the account key. Each fetch is
//! recorded against the key, which is this machine.

use super::{Machine, Policy};
use crate::api::SendApi;

/// The account's policy as Crossfyre answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remote {
    pub policy: Policy,
    /// Whether the account has chosen one; one that has not runs as connected.
    pub chosen: bool,
    pub changed_at: Option<String>,
    pub changed_via: Option<String>,
}

/// Why Crossfyre did not answer with a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failed {
    /// It could not be reached, or answered as though it could not.
    Unreachable(String),
    /// It does not take the key: expired or revoked.
    NotLoggedIn(String),
    /// It answered, and said no.
    Refused(String),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Unreachable(why) | Failed::NotLoggedIn(why) | Failed::Refused(why) => {
                f.write_str(why)
            }
        }
    }
}

/// What a machine needs to ask: where Crossfyre is and the account key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub api_url: String,
    pub key: String,
}

impl Session {
    pub fn of(account: &crate::auth::Account) -> Session {
        Session {
            api_url: account.api_url.clone(),
            key: account.api_key.clone(),
        }
    }
}

/// Crossfyre as the policy commands talk to it, so tests can stand in for it.
pub trait Cloud {
    fn fetch(&self, s: &Session) -> impl Future<Output = Result<Remote, Failed>>;
    fn set(&self, s: &Session, policy: Policy) -> impl Future<Output = Result<Remote, Failed>>;
}

/// Crossfyre itself.
pub struct Crossfyre;

fn endpoint(api_url: &str, path: &str) -> String {
    format!("{}/api/v1/cli/{path}", api_url.trim_end_matches('/'))
}

async fn ask(s: &Session, path: &str, body: serde_json::Value) -> Result<Remote, Failed> {
    let resp = crate::api::client()
        .post(endpoint(&s.api_url, path))
        .json(&body)
        .send_api()
        .await
        .map_err(|e| Failed::Unreachable(format!("Crossfyre could not be reached: {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let message = body["errors"][0]
        .as_str()
        .or_else(|| body["message"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Crossfyre answered {status}"));
    if status.is_server_error() {
        return Err(Failed::Unreachable(message));
    }
    if status.as_u16() == 401 {
        return Err(Failed::NotLoggedIn(message));
    }
    if !status.is_success() {
        return Err(Failed::Refused(message));
    }
    remote(&body["data"])
        .ok_or_else(|| Failed::Unreachable("Crossfyre's answer did not read".into()))
}

/// A policy answer's data, as /cli/policy gives it.
pub fn remote(data: &serde_json::Value) -> Option<Remote> {
    let policy = Policy::parse(data["policy"].as_str()?).filter(|p| p.is_account())?;
    Some(Remote {
        policy,
        chosen: data["chosen"].as_bool().unwrap_or(false),
        changed_at: data["changed_at"].as_str().map(str::to_string),
        changed_via: data["changed_via"].as_str().map(str::to_string),
    })
}

impl Cloud for Crossfyre {
    async fn fetch(&self, s: &Session) -> Result<Remote, Failed> {
        ask(s, "policy", serde_json::json!({ "api_key": s.key })).await
    }

    async fn set(&self, s: &Session, policy: Policy) -> Result<Remote, Failed> {
        ask(
            s,
            "policy/set",
            serde_json::json!({ "api_key": s.key, "policy": policy.key() }),
        )
        .await
    }
}

impl Machine {
    /// Take the account's policy as Crossfyre gave it.
    pub fn take(&mut self, r: &Remote) {
        self.account = r.chosen.then_some(r.policy);
        self.changed_at = r.changed_at.clone();
        self.changed_via = r.changed_via.clone();
        self.unsent = false;
    }
}
