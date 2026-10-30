//! The tools a Cloud backend shares with the local one. One name for both, so an
//! agent's loop is the same whichever backend ran the scan; the id says which backend a
//! handle belongs to (`s_` and `f_` here, `cs_`, `cf_`, `cv_` and `ap_` on the Cloud),
//! and a local id never leaves this machine.

use super::read::{cursor, decode};
use super::{Cloud, CloudNote, fit_count, narrow, shape, shrink};
use crate::core::{CallNote, Done, Mcp, Reason, Refusal};
use crate::jobs::{self, JobMeta};
use crate::peer::ClientPeer;
use crate::tools::{in_range, info, parse_args, scans};
use crate::untrusted::{self, EVIDENCE_DEFAULT, EVIDENCE_MAX};
use cfx_cloud_wire::{self as wire, IdKind, TargetKind, vocab};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) async fn run(
    mcp: &Mcp,
    cloud: &Cloud,
    tool: &str,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    match tool {
        "get_scope" => get_scope(mcp, cloud, args, peer, note).await,
        "check_scope" => check_scope(mcp, cloud, args, peer, note).await,
        "list_scans" => list_scans(mcp, cloud, args, peer, note).await,
        "get_scan" => get_scan(mcp, cloud, args, peer, note).await,
        "list_findings" => list_findings(mcp, cloud, args, peer, note).await,
        "get_finding" => get_finding(mcp, cloud, args, peer, note).await,
        "cancel_scan" => cancel_scan(mcp, cloud, args, peer, note).await,
        _ => Err(Refusal::new(Reason::UnknownTool, "unknown tool")),
    }
}

/// A local tool's answer, marked as the local backend's.
fn local(r: Result<Done, Refusal>) -> Result<Done, Refusal> {
    r.map(|mut d| {
        d.value["backend"] = json!("local");
        d
    })
}

fn backend_arg(b: Option<&str>) -> Result<Option<&str>, Refusal> {
    match b {
        None => Ok(None),
        Some(b @ ("local" | "cloud")) => Ok(Some(b)),
        Some(_) => Err(Refusal::invalid("backend must be local or cloud")),
    }
}

// ---------------------------------------------------------------------------
// Scope

async fn get_scope(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let Done { mut value, summary } = info::get_scope(mcp, args)?;
    let mut c = match cloud
        .request::<wire::ScopeList>(
            mcp,
            peer,
            "get_scope",
            wire::route::SCOPE_LIST,
            json!({}),
            Duration::ZERO,
            note,
        )
        .await
    {
        Ok((_, list)) => shape::scope_list(&list),
        Err(r) => json!({"reason": r.reason.as_str(), "error": untrusted::clean(&r.message, 400)}),
    };
    let n = mcp.scope.entries.len();
    let narrows = mcp.scope.has_entries();
    c["narrowed_by_local_file"] = json!(narrows);
    c["narrowing"] = json!(if narrows {
        format!(
            "The scope file has {n} entr{}, so a Cloud launch must be admitted by it as well as \
             by the entries the key's owner confirmed. It can only narrow what the Cloud \
             admits, never widen it.",
            if n == 1 { "y" } else { "ies" }
        )
    } else {
        "The scope file has no entries, so it does not narrow Cloud launches: the entries the \
         key's owner confirmed are the only limit. Writing entries into it narrows them."
            .to_string()
    });
    let effective = c["effective"].as_array().map(|a| a.len());
    value["cloud"] = c;
    let summary = match effective {
        Some(e) => format!(
            "{summary} Cloud: {e} entr{} a launch may target.",
            plural(e)
        ),
        None => format!("{summary} The Cloud's scope could not be read."),
    };
    Ok(Done { value, summary })
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "y" } else { "ies" }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckArgs {
    targets: Vec<String>,
    #[serde(default)]
    kind: Option<TargetKind>,
}

async fn check_scope(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: CheckArgs = parse_args(args)?;
    if a.targets.is_empty() || a.targets.len() > wire::MAX_CHECK_TARGETS {
        return Err(Refusal::invalid(
            "targets must hold between 1 and 100 entries",
        ));
    }
    // The scope file's answer: as the local tool gives it, or, for a kind, as a launch
    // of that kind would be judged.
    let mut results: Vec<Value> = match a.kind {
        None => {
            let d = info::check_scope(mcp, &json!({"targets": a.targets}))?;
            d.value["results"].as_array().cloned().unwrap_or_default()
        }
        Some(k) => a
            .targets
            .iter()
            .map(|t| {
                let v = narrow::judge(&mcp.scope.scope, k, t, false);
                let mut r = json!({
                    "input": untrusted::clean(t.trim(), 200),
                    "kind": narrow::kind_str(k),
                    "host": v.host.as_deref().map(|h| untrusted::clean(h, 200)),
                    "port": v.port,
                    "admitted": v.admitted() && mcp.scope.has_entries(),
                    "rule": v.entry,
                    "port_rules": [],
                });
                if let Some(e) = &v.error {
                    r["error"] = json!(untrusted::clean(e, 200));
                }
                r
            })
            .collect(),
    };
    let req = wire::ScopeCheckRequest {
        targets: a.targets.iter().map(|t| t.trim().to_string()).collect(),
        kind: a.kind,
    };
    let answer = cloud
        .request::<wire::ScopeCheck>(
            mcp,
            peer,
            "check_scope",
            wire::route::SCOPE_CHECK,
            serde_json::to_value(&req).unwrap_or_default(),
            Duration::ZERO,
            note,
        )
        .await;
    let (verdicts, cloud_error) = match answer {
        Ok((_, c)) => (Some(c.results), None),
        Err(r) => (None, Some(untrusted::clean(&r.message, 400))),
    };
    let narrows = mcp.scope.has_entries();
    let mut allowed = 0;
    for (i, r) in results.iter_mut().enumerate() {
        let raw = a.targets.get(i).map(|t| t.trim()).unwrap_or("");
        let v = verdicts.as_ref().and_then(|v| v.get(i));
        let cloud_v = v.map(shape::scope_verdict).unwrap_or(Value::Null);
        let kind = a.kind.unwrap_or_else(|| narrow::kind_of(raw));
        let local_ok = !narrows || narrow::judge(&mcp.scope.scope, kind, raw, false).admitted();
        let ok = v.is_some_and(|v| v.admitted) && local_ok;
        allowed += usize::from(ok);
        r["cloud"] = cloud_v;
        r["cloud_launch_allowed"] = json!(ok);
    }
    let in_file = results
        .iter()
        .filter(|r| r["admitted"] == json!(true))
        .count();
    let mut value = json!({"scope_state": mcp.scope.state.as_str(), "results": results});
    if let Some(e) = &cloud_error {
        value["cloud_error"] = json!(e);
    }
    let summary = format!(
        "{in_file} of {} target(s) are in the scope file; a Cloud launch would be allowed \
         against {allowed}. Nothing was sent to a target.",
        a.targets.len()
    );
    Ok(Done { value, summary })
}

// ---------------------------------------------------------------------------
// Scans

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListScansArgs {
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
}

const LOCAL_STATUSES: [&str; 5] = [
    jobs::RUNNING,
    jobs::COMPLETED,
    jobs::FAILED,
    jobs::CANCELLED,
    jobs::INTERRUPTED,
];

/// Where each backend's list stands in a merged page: from the start, read to the
/// end, or after a cursor of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Side {
    Start,
    Done,
    After(String),
}

impl Side {
    fn as_str(&self) -> &str {
        match self {
            Side::Start => "",
            Side::Done => "~",
            Side::After(c) => c,
        }
    }
}

/// `<local>|<cloud>`, each empty for the start and `~` when read to the end.
fn parse_merged(c: &str) -> Option<(Side, Side)> {
    if c.len() > 600 {
        return None;
    }
    let (l, r) = c.split_once('|')?;
    let side = |s: &str, ok: &dyn Fn(&str) -> bool| match s {
        "" => Some(Side::Start),
        "~" => Some(Side::Done),
        s if ok(s) => Some(Side::After(s.to_string())),
        _ => None,
    };
    let local = side(l, &|s| jobs::parse_scan_cursor(s).is_some())?;
    let cloud = side(r, &|s| cursor(Some(s)).is_ok())?;
    Some((local, cloud))
}

struct Row {
    ms: i64,
    id: String,
    value: Value,
    /// Where its own backend's list continues after it.
    after: Option<String>,
    cloud: bool,
}

async fn list_scans(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: ListScansArgs = parse_args(args)?;
    let backend = backend_arg(a.backend.as_deref())?;
    let limit = in_range("limit", a.limit.unwrap_or(20), 1, 50)? as usize;
    let status = a.status.as_deref();
    if let Some(s) = status
        && !LOCAL_STATUSES.contains(&s)
        && !vocab::SCAN_STATUSES.contains(&s)
    {
        return Err(Refusal::invalid(format!(
            "status must be one of {}",
            vocab::SCAN_STATUSES
                .iter()
                .chain(&["interrupted"])
                .copied()
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let (mut l_side, mut c_side) = match &a.cursor {
        Some(c) => parse_merged(c)
            .ok_or_else(|| Refusal::invalid("cursor is not one this server returned"))?,
        None => (Side::Start, Side::Start),
    };
    if backend == Some("cloud") || status.is_some_and(|s| !LOCAL_STATUSES.contains(&s)) {
        l_side = Side::Done;
    }
    if backend == Some("local") || status.is_some_and(|s| !vocab::SCAN_STATUSES.contains(&s)) {
        c_side = Side::Done;
    }

    // Each side fetches a page after its own position.
    let mut rows: Vec<Row> = Vec::new();
    let mut local_more = false;
    if l_side != Side::Done {
        let after = match &l_side {
            Side::After(c) => jobs::parse_scan_cursor(c),
            _ => None,
        };
        let mut all: Vec<JobMeta> = mcp
            .jobs
            .list()
            .into_iter()
            .filter(|m| status.is_none_or(|s| m.status == s))
            .filter(|m| {
                after
                    .as_ref()
                    .is_none_or(|(ms, id)| (m.created_ms, &m.id) < (*ms, id))
            })
            .collect();
        all.sort_by(|x, y| (y.created_ms, &y.id).cmp(&(x.created_ms, &x.id)));
        local_more = all.len() > limit;
        all.truncate(limit);
        for m in &all {
            let mut v = scans::scan_row(m, mcp.settings.redact);
            v["backend"] = json!("local");
            rows.push(Row {
                ms: m.created_ms,
                id: m.id.clone(),
                value: v,
                after: Some(jobs::scan_cursor(m)),
                cloud: false,
            });
        }
    }
    let mut cloud_next: Option<String> = None;
    let mut cloud_rows = 0;
    let mut cloud_error = None;
    if c_side != Side::Done {
        let req = wire::ScansRequest {
            status: status.map(str::to_string),
            kind: None,
            cursor: match &c_side {
                Side::After(c) => Some(c.clone()),
                _ => None,
            },
            limit: Some(limit as u32),
        };
        match cloud
            .request::<wire::Scans>(
                mcp,
                peer,
                "list_scans",
                wire::route::SCANS_LIST,
                serde_json::to_value(&req).unwrap_or_default(),
                Duration::ZERO,
                note,
            )
            .await
        {
            Ok((_, page)) => {
                for r in page.scans.iter().take(limit) {
                    let v = shape::scan_row(r, mcp.settings.redact);
                    rows.push(Row {
                        ms: shape::millis(&r.created_at),
                        id: v["scan_id"].as_str().unwrap_or("").to_string(),
                        value: v,
                        after: r.cursor.clone().filter(|c| cursor(Some(c)).is_ok()),
                        cloud: true,
                    });
                    cloud_rows += 1;
                }
                cloud_next = page.next_cursor.filter(|c| cursor(Some(c)).is_ok());
            }
            // Asked for the Cloud's alone: its refusal is the answer.
            Err(r) if backend == Some("cloud") => return Err(r),
            Err(r) => cloud_error = Some(untrusted::clean(&r.message, 400)),
        }
    }
    if l_side != Side::Done && c_side != Side::Done {
        note.cloud.get_or_insert_with(CloudNote::default).local = true;
    }

    rows.sort_by(|x, y| (y.ms, &y.id).cmp(&(x.ms, &x.id)));
    let n = rows.len().min(limit);
    let page =
        |k: usize| -> Value { Value::Array(rows[..k].iter().map(|r| r.value.clone()).collect()) };
    let k = fit_count(n, |k| (String::new(), json!({"scans": page(k)})));
    let taken = &rows[..k];

    // Where each side continues: after the last of its rows that was kept, or where it
    // was when none was.
    let local_taken = taken.iter().filter(|r| !r.cloud).count();
    let local_total = rows.iter().filter(|r| !r.cloud).count();
    if l_side != Side::Done {
        if local_taken == local_total && !local_more {
            l_side = Side::Done;
        } else if let Some(last) = taken.iter().rev().find(|r| !r.cloud) {
            l_side = Side::After(last.after.clone().unwrap_or_default());
        }
    }
    if c_side != Side::Done && cloud_error.is_none() {
        let cloud_taken = taken.iter().filter(|r| r.cloud).count();
        if cloud_taken == cloud_rows {
            c_side = match cloud_next {
                Some(c) => Side::After(c),
                None => Side::Done,
            };
        } else if let Some(last) = taken.iter().rev().find(|r| r.cloud) {
            // The platform says where its list continues after each row; without that,
            // this page is read again rather than skipped.
            if let Some(c) = &last.after {
                c_side = Side::After(c.clone());
            }
        }
    }

    let mut value = json!({"scans": page(k)});
    if !(l_side == Side::Done && c_side == Side::Done) {
        value["next_cursor"] = json!(format!("{}|{}", l_side.as_str(), c_side.as_str()));
    }
    if let Some(e) = cloud_error {
        value["cloud_error"] = json!(e);
    }
    let in_cloud = taken.iter().filter(|r| r.cloud).count();
    let summary = format!(
        "{k} scan(s), newest first: {} local, {in_cloud} Cloud.",
        k - in_cloud
    );
    Ok(Done { value, summary })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanIdArgs {
    scan_id: String,
}

fn bad_scan_id() -> Refusal {
    Refusal::invalid(
        "scan_id is s_ followed by 10 lowercase hex characters, or cs_ or ap_ followed by 32",
    )
}

async fn get_scan(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: ScanIdArgs = parse_args(args)?;
    if jobs::valid_scan_id(&a.scan_id) {
        return local(scans::get_scan(mcp, args));
    }
    match wire::decode(&a.scan_id) {
        Some((IdKind::Scan, uuid)) => {
            note.set_scan(a.scan_id.clone());
            scan_now(mcp, cloud, peer, "get_scan", &uuid, note).await
        }
        Some((IdKind::Approval, uuid)) => {
            note.cloud
                .get_or_insert_with(CloudNote::default)
                .approval_id = Some(a.scan_id.clone());
            let (_, got): (u16, wire::ApprovalAnswer) = cloud
                .request(
                    mcp,
                    peer,
                    "get_scan",
                    wire::route::APPROVALS_GET,
                    json!({"id": uuid}),
                    Duration::ZERO,
                    note,
                )
                .await?;
            approval_result(mcp, cloud, peer, "get_scan", &got.approval, note).await
        }
        _ => Err(bad_scan_id()),
    }
}

/// A Cloud scan as it is now, with when to ask again while it runs.
pub(super) async fn scan_now(
    mcp: &Mcp,
    cloud: &Cloud,
    peer: &dyn ClientPeer,
    tool: &str,
    uuid: &str,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let (_, g): (u16, wire::ScanGet) = cloud
        .request(
            mcp,
            peer,
            tool,
            wire::route::SCANS_GET,
            json!({"id": uuid}),
            Duration::ZERO,
            note,
        )
        .await?;
    Ok(scan_done(cloud, &g, mcp.settings.redact))
}

pub(super) fn scan_done(cloud: &Cloud, g: &wire::ScanGet, redact: bool) -> Done {
    let mut value = shape::scan_detail(g, redact);
    let id = value["scan_id"].as_str().unwrap_or("").to_string();
    let status = value["status"].as_str().unwrap_or("other").to_string();
    if !shape::scan_ended(&status) {
        value["poll_after_seconds"] = json!(cloud.poll_after(&id));
    }
    let summary = format!(
        "Cloud scan {id} ({}) is {status}: {} of {} done, {} result(s).",
        value["type"].as_str().unwrap_or("other"),
        g.progress.ops_done,
        g.progress.ops_expected,
        g.scan.findings_count
    );
    Done { value, summary }
}

/// What an approval's state means to the agent: still waiting, launching, launched (and
/// then the scan it became), or a refusal when it was denied, expired or failed.
pub(super) async fn approval_result(
    mcp: &Mcp,
    cloud: &Cloud,
    peer: &dyn ClientPeer,
    tool: &str,
    a: &wire::Approval,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let shown = shape::approval(a, &cloud.config.api_url);
    let id = shown["approval_id"].as_str().unwrap_or("").to_string();
    let waiting = |status: &str, poll: u64, summary: String| Done {
        value: json!({
            "scan_id": id,
            "backend": "cloud",
            "status": status,
            "poll_after_seconds": poll,
            "approval": shown.clone(),
        }),
        summary,
    };
    match (a.status, a.launch_state) {
        (wire::ApprovalStatus::Pending, _) => Ok(waiting(
            "awaiting_approval",
            15,
            format!(
                "Launch {id} is waiting for a person to approve it, until {}. It can be \
                 decided at {}.",
                shown["expires_at"].as_str().unwrap_or("it expires"),
                shown["approve_url"].as_str().unwrap_or("the approval page")
            ),
        )),
        (wire::ApprovalStatus::Approved, Some(wire::LaunchState::Launched)) => {
            let Some(w) = a.workflow_id.as_deref().filter(|w| wire::is_uuid(w)) else {
                return Ok(waiting(
                    "launching",
                    5,
                    format!("Launch {id} was approved and is starting."),
                ));
            };
            let mut d = match scan_now(mcp, cloud, peer, tool, w, note).await {
                Ok(d) => d,
                // It became a scan whatever this read says: the approval names it.
                Err(r) => {
                    let scan = shown["scan_id"].as_str().unwrap_or("").to_string();
                    let d = waiting(
                        "launching",
                        5,
                        format!("Launch {id} was approved and became Cloud scan {scan}."),
                    );
                    return Ok(super::made_but(d, "reading the scan it became", &r));
                }
            };
            d.value["approval"] = shown;
            d.summary = format!("Launch {id} was approved. {}", d.summary);
            Ok(d)
        }
        (wire::ApprovalStatus::Approved, Some(wire::LaunchState::Failed)) => {
            let reason = a
                .launch_error
                .as_ref()
                .map(|e| e.reason)
                .unwrap_or(wire::Reason::StartFailed);
            let msg = a
                .launch_error
                .as_ref()
                .map(|e| untrusted::clean(&e.message, 300))
                .unwrap_or_default();
            Err(Refusal::new(
                Reason::CloudRefused(reason.as_str()),
                format!(
                    "Launch {id} was approved, but the Cloud could not start it ({}). Nothing \
                     is running.",
                    reason.as_str()
                ),
            )
            .with_detail(json!({
                "status": "launch_failed",
                "approval": shown,
                "cloud_message": msg,
            })))
        }
        (wire::ApprovalStatus::Approved, _) => Ok(waiting(
            "launching",
            5,
            format!("Launch {id} was approved and is starting."),
        )),
        (wire::ApprovalStatus::Denied, _) => Err(Refusal::new(
            Reason::ApprovalDenied,
            format!("Launch {id} was denied. Nothing was started."),
        )
        .with_detail(json!({"status": "denied", "approval": shown}))),
        (wire::ApprovalStatus::Expired, _) => Err(Refusal::new(
            Reason::ApprovalExpired,
            format!("Launch {id} expired before anyone decided it. Nothing was started."),
        )
        .with_detail(json!({"status": "expired", "approval": shown}))),
        (wire::ApprovalStatus::Cancelled, _) => Ok(waiting(
            "cancelled",
            0,
            format!("Launch {id} was withdrawn. Nothing was started."),
        )),
        (wire::ApprovalStatus::Other, _) => Ok(waiting(
            "other",
            15,
            format!("Launch {id} is in a state this crossfyre does not know."),
        )),
    }
}

// ---------------------------------------------------------------------------
// Findings

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFindingsArgs {
    #[serde(default)]
    scan_id: Option<String>,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    severity_min: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
}

async fn list_findings(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: ListFindingsArgs = parse_args(args)?;
    let backend = backend_arg(a.backend.as_deref())?;
    let limit = in_range("limit", a.limit.unwrap_or(20), 1, 50)? as u32;
    if let Some(s) = &a.severity_min
        && !wire::SEVERITIES.contains(&s.as_str())
    {
        return Err(Refusal::invalid(format!(
            "severity_min must be one of {}",
            wire::SEVERITIES.join(", ")
        )));
    }
    let local_args = || {
        let mut v = json!({});
        for (k, x) in [
            ("scan_id", a.scan_id.as_ref().map(|s| json!(s))),
            ("severity_min", a.severity_min.as_ref().map(|s| json!(s))),
            ("cursor", a.cursor.as_ref().map(|s| json!(s))),
            ("limit", a.limit.map(|l| json!(l))),
        ] {
            if let Some(x) = x {
                v[k] = x;
            }
        }
        v
    };
    match (a.scan_id.as_deref(), backend) {
        (Some(id), None | Some("local")) if jobs::valid_scan_id(id) => {
            local(scans::list_findings(mcp, &local_args()))
        }
        (None, Some("local")) => local(scans::list_findings(mcp, &local_args())),
        (Some(id), None | Some("cloud")) if id.starts_with("cs_") => {
            let uuid = decode(id, IdKind::Scan, "scan_id")?;
            note.set_scan(id.to_string());
            results(mcp, cloud, peer, &uuid, &a, limit, note).await
        }
        (None, Some("cloud")) => verdicts(mcp, cloud, peer, &a, limit, note).await,
        (None, None) => Err(Refusal::invalid(
            "give scan_id (s_ or cs_), or backend: local for this machine's findings or cloud \
             for the workspace's verdicts",
        )),
        _ => Err(Refusal::invalid(
            "scan_id is s_ followed by 10 lowercase hex characters, or cs_ followed by 32, and \
             backend must match it when both are given",
        )),
    }
}

async fn results(
    mcp: &Mcp,
    cloud: &Cloud,
    peer: &dyn ClientPeer,
    uuid: &str,
    a: &ListFindingsArgs,
    limit: u32,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let given = cursor(a.cursor.as_deref())?;
    let mut lim = limit;
    loop {
        let req = wire::ResultsRequest {
            id: uuid.to_string(),
            cursor: given.clone(),
            limit: Some(lim),
            severity_min: a.severity_min.clone(),
        };
        let (_, page): (u16, wire::Results) = cloud
            .request(
                mcp,
                peer,
                "list_findings",
                wire::route::SCANS_RESULTS,
                serde_json::to_value(&req).unwrap_or_default(),
                Duration::ZERO,
                note,
            )
            .await?;
        let rows: Vec<Value> = page
            .results
            .iter()
            .take(lim as usize)
            .map(|r| shape::result(r, false, mcp.settings.redact, 0))
            .collect();
        let (status, _) = shape::scan_status(&page.scan_status);
        let next = cursor(page.next_cursor.as_deref())
            .ok()
            .flatten()
            .or_else(|| given.clone())
            .unwrap_or_default();
        let build = |k: usize| {
            let more = k as u32 >= lim;
            let summary = format!(
                "{k} result(s) of a Cloud scan that is {}{}. Pass next_cursor to read on, or \
                 later to see only newer ones.",
                status.as_str().unwrap_or("other"),
                if more { ", more available" } else { "" }
            );
            let value = json!({
                "findings": rows[..k],
                "next_cursor": next,
                "more": more,
                "backend": "cloud",
                "scan_status": status,
                "hidden_by_retention": page.hidden_by_retention,
            });
            (summary, value)
        };
        let k = fit_count(rows.len(), build);
        // A page cut to fit is asked for again at the size that fits, so the cursor
        // the platform gives continues exactly after the last row returned.
        if k < rows.len() && lim > 1 {
            lim = k as u32;
            continue;
        }
        let (summary, value) = build(k);
        return Ok(Done { value, summary });
    }
}

async fn verdicts(
    mcp: &Mcp,
    cloud: &Cloud,
    peer: &dyn ClientPeer,
    a: &ListFindingsArgs,
    limit: u32,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let given = cursor(a.cursor.as_deref())?;
    let mut lim = limit;
    loop {
        let req = wire::VerdictsRequest {
            status: None,
            severity_min: a.severity_min.clone(),
            kind: None,
            cursor: given.clone(),
            limit: Some(lim),
        };
        let (_, page): (u16, wire::Verdicts) = cloud
            .request(
                mcp,
                peer,
                "list_findings",
                wire::route::VERDICTS_LIST,
                serde_json::to_value(&req).unwrap_or_default(),
                Duration::ZERO,
                note,
            )
            .await?;
        let rows: Vec<Value> = page
            .verdicts
            .iter()
            .take(lim as usize)
            .map(|r| shape::verdict(r, None, mcp.settings.redact))
            .collect();
        let next = cursor(page.next_cursor.as_deref()).ok().flatten();
        let build = |k: usize| {
            let more = next.is_some();
            let summary = format!(
                "{k} verdict(s) on the workspace's assets, most recently seen first{}.",
                if more {
                    "; pass next_cursor to read on"
                } else {
                    ""
                }
            );
            let value = json!({
                "findings": rows[..k],
                "next_cursor": next.clone().unwrap_or_default(),
                "more": more,
                "backend": "cloud",
            });
            (summary, value)
        };
        let k = fit_count(rows.len(), build);
        if k < rows.len() && lim > 1 {
            lim = k as u32;
            continue;
        }
        let (summary, value) = build(k);
        return Ok(Done { value, summary });
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetFindingArgs {
    finding_id: String,
    #[serde(default)]
    evidence_bytes: Option<u64>,
}

async fn get_finding(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: GetFindingArgs = parse_args(args)?;
    if jobs::valid_finding_id(&a.finding_id) {
        return local(scans::get_finding(mcp, args));
    }
    let bytes = in_range(
        "evidence_bytes",
        a.evidence_bytes.unwrap_or(EVIDENCE_DEFAULT as u64),
        0,
        EVIDENCE_MAX as u64,
    )? as usize;
    let (mut value, summary) = match wire::decode(&a.finding_id) {
        Some((IdKind::Result, uuid)) => {
            let (_, got): (u16, wire::ResultGet) = cloud
                .request(
                    mcp,
                    peer,
                    "get_finding",
                    wire::route::RESULTS_GET,
                    json!({"id": uuid}),
                    Duration::ZERO,
                    note,
                )
                .await?;
            let v = shape::result(&got.result, true, mcp.settings.redact, bytes);
            let s = format!(
                "Result {} of Cloud scan {}: {} ({}).",
                a.finding_id,
                v["scan_id"].as_str().unwrap_or("unknown"),
                v["source"].as_str().unwrap_or("other"),
                v["severity"].as_str().unwrap_or("info")
            );
            (v, s)
        }
        Some((IdKind::Verdict, uuid)) => {
            let req = wire::VerdictGetRequest {
                id: uuid,
                evidence_bytes: Some(bytes as u32),
            };
            let (_, got): (u16, wire::VerdictGet) = cloud
                .request(
                    mcp,
                    peer,
                    "get_finding",
                    wire::route::VERDICTS_GET,
                    serde_json::to_value(&req).unwrap_or_default(),
                    Duration::ZERO,
                    note,
                )
                .await?;
            let d = &got.verdict;
            let v = shape::verdict(
                &d.row,
                Some((&d.description, &d.evidence, bytes)),
                mcp.settings.redact,
            );
            let s = format!(
                "Verdict {} on asset {}: {} ({}).",
                a.finding_id,
                v["asset_id"].as_str().unwrap_or("unknown"),
                v["kind"].as_str().unwrap_or("other"),
                v["severity"].as_str().unwrap_or("info")
            );
            (v, s)
        }
        _ => {
            return Err(Refusal::invalid(
                "finding_id is f_ followed by 10 lowercase hex characters, or cf_ or cv_ \
                 followed by 32",
            ));
        }
    };
    shrink(&summary, &mut value);
    Ok(Done { value, summary })
}

// ---------------------------------------------------------------------------
// Stopping

async fn cancel_scan(
    mcp: &Mcp,
    cloud: &Cloud,
    args: &Value,
    peer: &dyn ClientPeer,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: ScanIdArgs = parse_args(args)?;
    if jobs::valid_scan_id(&a.scan_id) {
        return local(scans::cancel_scan(mcp, args, note).await);
    }
    let (kind, uuid) = match wire::decode(&a.scan_id) {
        Some((IdKind::Scan, u)) => (wire::CancelKind::Scan, u),
        Some((IdKind::Approval, u)) => {
            note.cloud
                .get_or_insert_with(CloudNote::default)
                .approval_id = Some(a.scan_id.clone());
            (wire::CancelKind::Approval, u)
        }
        _ => return Err(bad_scan_id()),
    };
    note.set_scan(a.scan_id.clone());
    let req = wire::CancelRequest { id: uuid, kind };
    let (_, c): (u16, wire::Cancelled) = cloud
        .request(
            mcp,
            peer,
            "cancel_scan",
            wire::route::SCANS_CANCEL,
            serde_json::to_value(&req).unwrap_or_default(),
            Duration::ZERO,
            note,
        )
        .await?;
    let cancel = match c.result {
        wire::CancelResult::Stopped => Some("stopped"),
        wire::CancelResult::Cancelled => Some("withdrawn"),
        wire::CancelResult::NotRunning | wire::CancelResult::Other => None,
    };
    let words: &[&str] = match kind {
        wire::CancelKind::Scan => &vocab::SCAN_STATUSES,
        wire::CancelKind::Approval => &["pending", "approved", "denied", "expired", "cancelled"],
    };
    let status = match c.status.as_deref() {
        Some(s) if words.contains(&s) => s.to_string(),
        Some(_) => "other".into(),
        None if cancel == Some("withdrawn") => "cancelled".into(),
        None if cancel == Some("stopped") => "stopped".into(),
        None => "other".into(),
    };
    note.result = Some(json!({"status": status, "cancel": cancel}));
    let summary = match cancel {
        Some("withdrawn") => format!("Launch {} was withdrawn; nothing was started.", a.scan_id),
        Some(_) => format!(
            "Cloud scan {} was told to stop; status {status}.",
            a.scan_id
        ),
        None => format!("{} had already ended: {status}.", a.scan_id),
    };
    Ok(Done {
        value: json!({"scan_id": a.scan_id, "backend": "cloud", "status": status, "cancel": cancel}),
        summary,
    })
}
