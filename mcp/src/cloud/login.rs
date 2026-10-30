//! `crossfyre mcp cloud login`, `status` and `logout`: the only code that writes or
//! removes the key file. They answer a person at a terminal, and are never reached
//! while the server is serving, where stdout is the protocol.

use super::client::{self, Client};
use super::file::{self, Cached, Key, Loaded};
use crate::untrusted;
use cfx_cloud_wire::{self as wire, Whoami};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the commands find the key file, and the version they report as.
#[derive(Debug, Clone)]
pub struct CloudCommand {
    /// `<data-dir>/mcp`, where the default key file lives.
    pub default_dir: PathBuf,
    /// `--cloud-file`.
    pub cloud_file: Option<PathBuf>,
    pub version: String,
}

impl CloudCommand {
    fn path(&self) -> PathBuf {
        self.cloud_file
            .clone()
            .unwrap_or_else(|| self.default_dir.join(file::FILE_NAME))
    }
}

/// Ask `whoami` with this key, once more if the first request may never have arrived.
/// The answer and the platform's id for the call, or a sentence saying why not that
/// never holds the key.
async fn whoami(
    api_url: &str,
    key: Key,
    version: &str,
    tool: &str,
) -> Result<(Whoami, Option<String>), String> {
    let c = Client::new(api_url, key, version)?;
    let session = crate::jobs::new_id("m");
    let meta = client::Meta {
        tool,
        client: "crossfyre-cli",
        session: &session,
        local_scope: "none",
    };
    let mut tries = 0;
    let a = loop {
        tries += 1;
        match c
            .post(wire::route::WHOAMI, &meta, &json!({}), Duration::ZERO)
            .await
        {
            Ok(a) => break a,
            Err(f) if tries < 2 && f.transient() => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(f) => return Err(format!("could not reach {api_url}: {}", f.describe())),
        }
    };
    if (200..300).contains(&a.status) {
        return serde_json::from_value(a.envelope.data)
            .map(|w| (w, a.call_id))
            .map_err(|_| {
                format!(
                    "{api_url} answered whoami in a shape this crossfyre does not read; update it"
                )
            });
    }
    let reason = serde_json::from_value::<wire::Refusal>(a.envelope.data)
        .map(|r| r.reason)
        .unwrap_or(wire::Reason::Other);
    let what = match reason {
        wire::Reason::RateLimited => format!(". Try again in {} s", a.retry_after.unwrap_or(60)),
        r if r.rejects_key() || a.status == 401 => {
            ". Make a new one in Settings, Agent access".to_string()
        }
        _ => String::new(),
    };
    Err(format!(
        "the Cloud refused the key with {} (HTTP {}){what}",
        reason.as_str(),
        a.status
    ))
}

/// An RFC 3339 time printed again in UTC, or `None` when it is not one.
fn when(s: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|t| {
            t.with_timezone(&chrono::Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
}

/// What a person needs to know about a key, one fact a line.
fn describe(w: &Whoami) -> Vec<String> {
    let name = |s: &str| untrusted::clean(s, 200);
    let expires = when(&w.key.expires_at);
    let mut out = vec![
        format!(
            "Workspace: {} ({})",
            name(&w.workspace.name),
            name(&w.workspace.id)
        ),
        format!(
            "Key: {} \"{}\", {}, expires {}",
            name(&w.key.prefix),
            name(&w.key.name),
            w.key.permission.as_str(),
            expires.as_deref().unwrap_or("at an unreadable time")
        ),
        format!(
            "Scope: {} entr{} a launch may target ({} in the workspace, {} confirmed for this key)",
            w.scope.effective,
            if w.scope.effective == 1 { "y" } else { "ies" },
            w.scope.current,
            w.scope.attested
        ),
        format!(
            "Approval: {}{}",
            match w.approval.policy {
                wire::ApprovalMode::Always => "every launch waits for a person",
                wire::ApprovalMode::Risky => "launches on several nodes wait for your phone",
                wire::ApprovalMode::Other => "a policy this crossfyre does not know",
            },
            match (w.approval.phone_registered, w.approval.fallback) {
                (true, _) => ", and a phone is registered to approve them",
                (false, true) => "; with no phone registered, the agent's client asks you",
                (false, false) => "; with no phone registered, such launches are refused",
            }
        ),
    ];
    if w.scope.effective == 0 {
        out.push(
            "This key can launch nothing yet: add destinations on the workspace's Scope page, \
             then confirm them for the key in Settings, Agent access."
                .into(),
        );
    }
    out
}

/// Check the key with the platform, then save it with what `whoami` said. Nothing is
/// written when the platform does not accept it.
pub async fn login(c: &CloudCommand, api_url: &str, key: &str) -> Result<Vec<String>, String> {
    let key = key.trim();
    if !wire::valid_key(key) {
        return Err(
            "that is not an MCP key: it starts with cfm_ and has 32 hex characters after it. \
             Make one in Settings, Agent access."
                .into(),
        );
    }
    let api_url = file::check_api_url(api_url)?;
    let (w, _) = whoami(&api_url, Key::new(key), &c.version, "cloud_login").await?;
    let path = c.path();
    if c.cloud_file.is_none() {
        crate::create_private_dir(&c.default_dir)
            .map_err(|e| format!("could not create {}: {e}", c.default_dir.display()))?;
    }
    let cached = Cached {
        key_prefix: wire::key_prefix(key),
        workspace_id: Some(untrusted::clean(&w.workspace.id, 64)),
        workspace_name: Some(untrusted::clean(&w.workspace.name, 200)),
        permission: Some(w.key.permission.as_str().to_string()),
        expires_at: when(&w.key.expires_at),
    };
    file::save(&path, &api_url, key, &cached)
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    let mut out = describe(&w);
    out.push(format!(
        "Saved to {} (readable by you alone). Restart the MCP server to use it.",
        path.display()
    ));
    Ok(out)
}

fn loaded(c: &CloudCommand) -> Result<file::Config, String> {
    match file::load(
        &c.default_dir.join(file::FILE_NAME),
        c.cloud_file.as_deref(),
    ) {
        Loaded::Ready(config) => Ok(config),
        Loaded::None => Err(format!(
            "No Cloud key: {} does not exist and {} is not set. Run `crossfyre mcp cloud login`.",
            c.path().display(),
            file::KEY_ENV
        )),
        Loaded::Refused(why) => Err(why),
    }
}

fn source(config: &file::Config) -> String {
    match &config.source {
        file::Source::File(p) => p.display().to_string(),
        file::Source::Env => file::KEY_ENV.to_string(),
    }
}

/// What the platform says about the configured key, without serving.
pub async fn status(c: &CloudCommand) -> Result<Vec<String>, String> {
    let config = loaded(c)?;
    let mut out = vec![format!(
        "Key {} from the {} ({}), for {}",
        config.key.prefix(),
        config.source.as_str(),
        source(&config),
        config.api_url
    )];
    match whoami(
        &config.api_url,
        config.key.clone(),
        &c.version,
        "cloud_status",
    )
    .await
    {
        Ok((w, call)) => {
            out.extend(describe(&w));
            if let Some(id) = call {
                out.push(format!("The platform's record of this check: {id}"));
            }
            Ok(out)
        }
        Err(why) => {
            let k = &config.cached;
            if let (Some(ws), Some(p)) = (&k.workspace_name, &k.permission) {
                out.push(format!(
                    "At the last login: workspace {}, {}, expires {}",
                    untrusted::clean(ws, 200),
                    untrusted::clean(p, 16),
                    k.expires_at.as_deref().unwrap_or("at an unknown time")
                ));
            }
            out.push(why);
            Err(out.join("\n"))
        }
    }
}

/// Remove the key file, after revoking the key on the platform when asked to.
pub async fn logout(c: &CloudCommand, revoke: bool) -> Result<Vec<String>, String> {
    let config = loaded(c)?;
    let mut out = Vec::new();
    if revoke {
        let client = Client::new(&config.api_url, config.key.clone(), &c.version)?;
        let session = crate::jobs::new_id("m");
        let meta = client::Meta {
            tool: "cloud_logout",
            client: "crossfyre-cli",
            session: &session,
            local_scope: "none",
        };
        let a = client
            .post(wire::route::KEY_REVOKE, &meta, &json!({}), Duration::ZERO)
            .await
            .map_err(|f| {
                format!(
                    "could not reach {} to revoke the key ({}); nothing was removed",
                    config.api_url,
                    f.describe()
                )
            })?;
        let reason = serde_json::from_value::<wire::Refusal>(a.envelope.data.clone())
            .ok()
            .map(|r| r.reason);
        match (a.status, reason) {
            (200..=299, _) => out.push(format!("Revoked {} on the platform.", config.key.prefix())),
            (_, Some(r)) if r.rejects_key() => out.push(format!(
                "{} was already refused by the platform ({}).",
                config.key.prefix(),
                r.as_str()
            )),
            (s, r) => {
                return Err(format!(
                    "the platform did not revoke the key (HTTP {s}, {}); nothing was removed",
                    r.map(|r| r.as_str()).unwrap_or("no reason given")
                ));
            }
        }
    }
    match &config.source {
        file::Source::File(p) => {
            remove(p)?;
            out.push(format!("Removed {}.", p.display()));
        }
        file::Source::Env => out.push(format!(
            "The key comes from {}; unset it in the MCP client's configuration.",
            file::KEY_ENV
        )),
    }
    Ok(out)
}

fn remove(p: &Path) -> Result<(), String> {
    std::fs::remove_file(p).map_err(|e| format!("could not remove {}: {e}", p.display()))
}
