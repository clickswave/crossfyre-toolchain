//! The `start_*` tools: a scan on the workspace's nodes.
//!
//! A launch carries only its targets, node ids and the few options its type allows.
//! Before anything is sent it passes the scope file when that file has entries, the
//! audit log's health and the person's confirmation; the platform then checks it
//! against the scope the key's owner confirmed, and that check is the one that counts.

use super::read::decode;
use super::route::{scan_done, scan_now};
use super::{Cloud, narrow, shape};
use crate::core::{CallNote, Done, Mcp, Reason, Refusal, RefusedDest};
use crate::peer::ClientPeer;
use crate::tools::{in_range, parse_args};
use crate::untrusted;
use cfx_cloud_wire::{self as wire, IdKind, LaunchType, ReconMode, StartOptions};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recon {
    domain: String,
    #[serde(default)]
    mode: Option<ReconMode>,
    #[serde(default)]
    node_ids: Vec<String>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortScan {
    targets: Vec<String>,
    #[serde(default)]
    ports: Option<String>,
    #[serde(default)]
    node_ids: Vec<String>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Crawl {
    url: String,
    #[serde(default)]
    max_depth: Option<u32>,
    #[serde(default)]
    max_pages: Option<u32>,
    #[serde(default)]
    node_ids: Vec<String>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentDiscovery {
    url: String,
    #[serde(default)]
    wordlist: Option<String>,
    #[serde(default)]
    extensions: Option<Vec<String>>,
    #[serde(default)]
    recurse: Option<bool>,
    #[serde(default)]
    node_ids: Vec<String>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VulnScan {
    urls: Vec<String>,
    #[serde(default)]
    severity_min: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    node_ids: Vec<String>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzScan {
    url: String,
    identities: Vec<String>,
    #[serde(default)]
    node_ids: Vec<String>,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

/// One launch, as the tool's arguments describe it.
struct Ask {
    kind: LaunchType,
    targets: Vec<String>,
    node_ids: Vec<String>,
    options: StartOptions,
    wait: u64,
}

fn ask(tool: &str, args: &Value) -> Result<Ask, Refusal> {
    let o = StartOptions::default;
    let (kind, targets, node_ids, options, wait) = match tool {
        "start_recon" => {
            let a: Recon = parse_args(args)?;
            let options = StartOptions {
                mode: a.mode,
                ..o()
            };
            (
                LaunchType::Recon,
                vec![a.domain],
                a.node_ids,
                options,
                a.wait_seconds,
            )
        }
        "start_port_scan" => {
            let a: PortScan = parse_args(args)?;
            let options = StartOptions {
                ports: a.ports,
                ..o()
            };
            (
                LaunchType::PortScan,
                a.targets,
                a.node_ids,
                options,
                a.wait_seconds,
            )
        }
        "start_crawl" => {
            let a: Crawl = parse_args(args)?;
            let options = StartOptions {
                max_depth: a.max_depth,
                max_pages: a.max_pages,
                ..o()
            };
            (
                LaunchType::Crawl,
                vec![a.url],
                a.node_ids,
                options,
                a.wait_seconds,
            )
        }
        "start_content_discovery" => {
            let a: ContentDiscovery = parse_args(args)?;
            let options = StartOptions {
                wordlist: a.wordlist,
                extensions: a.extensions,
                recurse: a.recurse,
                ..o()
            };
            let t = LaunchType::ContentDiscovery;
            (t, vec![a.url], a.node_ids, options, a.wait_seconds)
        }
        "start_vuln_scan" => {
            let a: VulnScan = parse_args(args)?;
            let options = StartOptions {
                severity_min: a.severity_min,
                tags: a.tags,
                ..o()
            };
            (
                LaunchType::VulnScan,
                a.urls,
                a.node_ids,
                options,
                a.wait_seconds,
            )
        }
        "start_authz_scan" => {
            let a: AuthzScan = parse_args(args)?;
            let options = StartOptions {
                identities: Some(a.identities),
                ..o()
            };
            (
                LaunchType::AuthzScan,
                vec![a.url],
                a.node_ids,
                options,
                a.wait_seconds,
            )
        }
        _ => return Err(Refusal::new(Reason::UnknownTool, "unknown tool")),
    };
    let wait = in_range("wait_seconds", wait.unwrap_or(0), 0, 50)?;
    let allowed = kind.targets_allowed();
    if !allowed.contains(&targets.len()) {
        return Err(Refusal::invalid(if *allowed.end() == 1 {
            format!("{} takes one target", kind.as_str())
        } else {
            format!(
                "{} takes between 1 and {} targets",
                kind.as_str(),
                allowed.end()
            )
        }));
    }
    options
        .check(kind)
        .map_err(|e| Refusal::invalid(untrusted::clean(&e, 200)))?;
    for words in [&options.extensions, &options.tags, &options.identities]
        .into_iter()
        .flatten()
    {
        if words
            .iter()
            .any(|w| w.is_empty() || w.len() > 64 || w.chars().any(|c| c.is_control()))
        {
            return Err(Refusal::invalid(
                "extensions, tags and identities are short words of 1 to 64 characters",
            ));
        }
    }
    if node_ids.len() > 20 {
        return Err(Refusal::invalid("at most 20 node_ids"));
    }
    let node_ids = node_ids
        .iter()
        .map(|n| decode(n, IdKind::Node, "a node id"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Ask {
        kind,
        targets: targets.iter().map(|t| t.trim().to_string()).collect(),
        node_ids,
        options,
        wait,
    })
}

/// Every target read as its type reads it, and, when the scope file has entries,
/// admitted by it. Nothing is sent when any is not: the refusal names each one.
fn narrow_locally(mcp: &Mcp, a: &Ask) -> Result<(), Refusal> {
    let active = a.options.mode == Some(ReconMode::Active);
    let mut refused = Vec::new();
    for t in &a.targets {
        let kind = narrow::launch_kind(a.kind, t);
        let v = narrow::judge(&mcp.scope.scope, kind, t, active);
        if let Some(e) = &v.error {
            return Err(Refusal::invalid(format!(
                "{}: {}",
                untrusted::clean(t, 200),
                untrusted::clean(e, 200)
            )));
        }
        if mcp.scope.has_entries() && !v.admitted() {
            refused.push(RefusedDest {
                host: untrusted::clean(v.host.as_deref().unwrap_or(t), 200),
                port: v.port.unwrap_or(0),
                at: "local_scope",
            });
        }
    }
    if refused.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = refused
        .iter()
        .map(|r| {
            if r.port == 0 {
                r.host.clone()
            } else {
                format!("{}:{}", r.host, r.port)
            }
        })
        .collect();
    let how = match a.kind {
        LaunchType::Recon if active => {
            " Active recon needs a *. entry over the domain, since it contacts the names under it."
        }
        LaunchType::PortScan => {
            " A port scan needs an entry that covers every port on the host: a host:port entry \
             is not one, and a range needs one entry that contains all of it."
        }
        _ => "",
    };
    Err(Refusal::new(
        Reason::OutOfLocalScope,
        format!(
            "Not in the scope file: {}. Nothing was sent to the Cloud. When the scope file {} \
             has entries, a Cloud launch must be admitted by it as well as by the scope the \
             key's owner confirmed; only the person authorised to test a destination can add \
             it, and the server reads the file when it starts.{how}",
            list.join(", "),
            mcp.scope.path.display()
        ),
    )
    .with_refused(refused))
}

pub(super) async fn run(
    mcp: &Mcp,
    cloud: &Cloud,
    tool: &str,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    if cloud.permission() == Some(wire::Permission::Read) {
        return Err(Refusal::new(
            Reason::PermissionDenied,
            "This MCP key can read but not launch scans, so nothing was sent. A launch key is \
             made in Settings, Agent access.",
        ));
    }
    let a = ask(tool, args)?;
    narrow_locally(mcp, &a)?;
    if !mcp.audit.healthy() {
        return Err(Refusal::new(
            Reason::AuditUnavailable,
            "The audit log could not be written, so nothing is launched until the MCP server is \
             restarted with a writable audit log. Read-only tools still work.",
        ));
    }
    // The approval replaces this question in a workspace that asks a person about every
    // launch.
    let always = cloud
        .whoami()
        .is_some_and(|w| w.approval.policy == wire::ApprovalMode::Always);
    if !always {
        note.confirmation = Some(cloud.confirm_launch(mcp, peer, ct, note).await?);
    }
    if ct.is_cancelled() {
        return Err(Refusal::new(
            Reason::Cancelled,
            "The call was cancelled before anything was started.",
        ));
    }
    let req = wire::StartRequest {
        kind: a.kind,
        targets: a.targets.clone(),
        node_ids: a.node_ids.clone(),
        options: a.options.clone(),
        request_id: crate::jobs::new_id("r"),
    };
    let (status, data): (u16, Value) = cloud
        .request(
            mcp,
            peer,
            tool,
            wire::route::SCANS_START,
            serde_json::to_value(&req).unwrap_or_default(),
            Duration::ZERO,
            note,
        )
        .await?;
    if status == 202 {
        let w: wire::AwaitingApproval = serde_json::from_value(data).map_err(|_| shape_error())?;
        let d = super::approval::wait(mcp, cloud, tool, &w.approval, peer, ct, note).await?;
        return Ok(with_poll(d));
    }
    let started: wire::Started = serde_json::from_value(data).map_err(|_| shape_error())?;
    let mut d = started_now(cloud, &started.scan, mcp.settings.redact);
    let id = d.value["scan_id"].as_str().unwrap_or("").to_string();
    note.set_scan(id.clone());
    note.result = Some(json!({"status": d.value["status"], "scan_id": id}));
    if a.wait > 0 {
        let uuid = started.scan.id.clone().unwrap_or_default();
        d = follow(mcp, cloud, peer, tool, &uuid, a.wait, ct, note, d).await?;
    }
    Ok(with_poll(d))
}

/// A launch always says when to look again: 0 once there is nothing left to wait for.
fn with_poll(mut d: Done) -> Done {
    if d.value.get("poll_after_seconds").is_none() {
        d.value["poll_after_seconds"] = json!(0);
    }
    d
}

fn shape_error() -> Refusal {
    Refusal::new(
        Reason::CloudUnavailable,
        "The Cloud answered scans/start in a shape this crossfyre does not read; the launch may \
         have been made. list_scans shows it if it was.",
    )
}

/// A scan the platform just created.
fn started_now(cloud: &Cloud, scan: &wire::ScanRow, redact: bool) -> Done {
    let g = wire::ScanGet {
        scan: scan.clone(),
        progress: wire::Progress::default(),
        warnings: Vec::new(),
    };
    let mut d = scan_done(cloud, &g, redact);
    d.value["poll_after_seconds"] = json!(10);
    d.summary = format!(
        "Started Cloud scan {} ({}) on {}. Follow it with get_scan and list_findings; \
         cancel_scan stops it.",
        d.value["scan_id"].as_str().unwrap_or(""),
        d.value["type"].as_str().unwrap_or("other"),
        d.value["target"].as_str().unwrap_or("its target")
    );
    d
}

/// Read the scan every few seconds for up to `wait` seconds, reporting its progress,
/// and return it as it was last seen. A cancelled call stops waiting; the scan goes on.
#[allow(clippy::too_many_arguments)]
async fn follow(
    mcp: &Mcp,
    cloud: &Cloud,
    peer: &dyn ClientPeer,
    tool: &str,
    uuid: &str,
    wait: u64,
    ct: &CancellationToken,
    note: &mut CallNote,
    first: Done,
) -> Result<Done, Refusal> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    let mut last = first;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok(last);
        }
        tokio::select! {
            _ = tokio::time::sleep(cloud.poll_every.min(left)) => {}
            _ = ct.cancelled() => {
                return Err(Refusal::new(
                    Reason::Cancelled,
                    "The call was cancelled while it waited. The Cloud scan goes on; \
                     cancel_scan stops it.",
                ));
            }
        }
        let d = scan_now(mcp, cloud, peer, tool, uuid, note).await?;
        let p = &d.value["progress"];
        let phase = p["phase"].as_str().unwrap_or("running");
        peer.progress(
            p["done"].as_f64().unwrap_or(0.0),
            p["total"].as_f64().filter(|t| *t > 0.0),
            &format!("Cloud scan {phase}"),
        )
        .await;
        let ended = shape::scan_ended(d.value["status"].as_str().unwrap_or(""));
        last = d;
        if ended {
            return Ok(last);
        }
    }
}
