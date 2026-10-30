//! Reading scans and findings back, and stopping a scan. Nothing here sends traffic.

use super::inject::scan_view;
use super::{in_range, parse_args, result_size};
use crate::core::{CallNote, Done, Mcp, Reason, Refusal};
use crate::findings;
use crate::jobs::{self, FindingKey, JobMeta};
use crate::redact;
use crate::untrusted::{self, EVIDENCE_DEFAULT, EVIDENCE_MAX, RESULT_CAP};
use serde::Deserialize;
use serde_json::{Value, json};

const STATUSES: [&str; 5] = [
    jobs::RUNNING,
    jobs::COMPLETED,
    jobs::FAILED,
    jobs::CANCELLED,
    jobs::INTERRUPTED,
];
const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

fn scan_id_arg(id: &str) -> Result<(), Refusal> {
    if jobs::valid_scan_id(id) {
        Ok(())
    } else {
        Err(Refusal::invalid(
            "scan_id is s_ followed by 10 lowercase hex characters",
        ))
    }
}

fn not_found(what: &str) -> Refusal {
    Refusal::new(Reason::NotFound, format!("no {what} with that id"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListScansArgs {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
}

fn scan_row(m: &JobMeta, redact: bool) -> Value {
    let target = untrusted::clean(&m.target, 200);
    json!({
        "scan_id": m.id,
        "tool": m.tool,
        "target": if redact { redact::redact_url(&target) } else { target },
        "status": m.status,
        "created_at": m.created_at,
        "counts": {"findings": m.counts.findings, "by_severity": m.counts.by_severity},
    })
}

pub(crate) fn list_scans(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let a: ListScansArgs = parse_args(args)?;
    let limit = in_range("limit", a.limit.unwrap_or(20), 1, 50)? as usize;
    if let Some(s) = &a.status
        && !STATUSES.contains(&s.as_str())
    {
        return Err(Refusal::invalid(format!(
            "status must be one of {}",
            STATUSES.join(", ")
        )));
    }
    let after = match &a.cursor {
        Some(c) => Some(
            jobs::parse_scan_cursor(c)
                .ok_or_else(|| Refusal::invalid("cursor is not one this server returned"))?,
        ),
        None => None,
    };
    let mut all: Vec<JobMeta> = mcp
        .jobs
        .list()
        .into_iter()
        .filter(|m| a.status.as_deref().is_none_or(|s| m.status == s))
        .filter(|m| {
            after
                .as_ref()
                .is_none_or(|(ms, id)| (m.created_ms, &m.id) < (*ms, id))
        })
        .collect();
    all.sort_by(|x, y| (y.created_ms, &y.id).cmp(&(x.created_ms, &x.id)));
    let more = all.len() > limit;
    all.truncate(limit);
    let rows: Vec<Value> = all
        .iter()
        .map(|m| scan_row(m, mcp.settings.redact))
        .collect();
    let (summary, value) = fit(rows.len(), |k| {
        let mut value = json!({"scans": rows[..k]});
        if (more || k < rows.len()) && k > 0 {
            value["next_cursor"] = json!(jobs::scan_cursor(&all[k - 1]));
        }
        (format!("{k} scan(s), newest first."), value)
    });
    Ok(Done { value, summary })
}

/// Build a page of the first `k` items for the largest `k` that fits the result cap.
/// A list drops items from its end, and the cursor it returns points at the last
/// item kept, so nothing is skipped.
fn fit(n: usize, build: impl Fn(usize) -> (String, Value)) -> (String, Value) {
    let mut k = n;
    loop {
        let (summary, value) = build(k);
        if k <= 1 || result_size(&summary, &value) <= RESULT_CAP {
            return (summary, value);
        }
        k -= 1;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanIdArgs {
    scan_id: String,
}

pub(crate) fn get_scan(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let a: ScanIdArgs = parse_args(args)?;
    scan_id_arg(&a.scan_id)?;
    let m = mcp
        .jobs
        .read_meta(&a.scan_id)
        .ok_or_else(|| not_found("scan"))?;
    let mut value = scan_view(&m, mcp.settings.redact);
    // Back off with each poll of the same scan: 5, 10, 20, then 30 s.
    let polls = mcp
        .polls
        .lock()
        .map(|mut p| {
            let n = p.entry(m.id.clone()).or_insert(0);
            *n += 1;
            *n
        })
        .unwrap_or(1);
    if !jobs::is_terminal(&m.status) {
        value["poll_after_seconds"] = json!(match polls {
            1 => 5,
            2 => 10,
            3 => 20,
            _ => 30,
        });
    }
    let target = untrusted::clean(&m.target, 200);
    value["tool"] = json!(m.tool);
    value["target"] = json!(if mcp.settings.redact {
        redact::redact_url(&target)
    } else {
        target
    });
    value["created_at"] = json!(m.created_at);
    value["finished_at"] = json!(m.finished_at);
    value["cancel"] = json!(m.cancel);
    let summary = format!(
        "Scan {} ({}) is {}: {} of {} done, {} findings.",
        m.id, m.tool, m.status, m.progress.done, m.progress.total, m.counts.findings
    );
    Ok(Done { value, summary })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFindingsArgs {
    #[serde(default)]
    scan_id: Option<String>,
    #[serde(default)]
    severity_min: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
}

pub(crate) fn list_findings(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let a: ListFindingsArgs = parse_args(args)?;
    let limit = in_range("limit", a.limit.unwrap_or(20), 1, 50)? as usize;
    let min = match &a.severity_min {
        Some(s) if SEVERITIES.contains(&s.as_str()) => findings::severity_rank(s),
        Some(_) => {
            return Err(Refusal::invalid(format!(
                "severity_min must be one of {}",
                SEVERITIES.join(", ")
            )));
        }
        None => 0,
    };
    let after = match &a.cursor {
        Some(c) => FindingKey::parse(c)
            .ok_or_else(|| Refusal::invalid("cursor is not one this server returned"))?,
        None => FindingKey::start(),
    };
    let scans: Vec<String> = match &a.scan_id {
        Some(id) => {
            scan_id_arg(id)?;
            if mcp.jobs.read_meta(id).is_none() {
                return Err(not_found("scan"));
            }
            vec![id.clone()]
        }
        None => mcp.jobs.list().into_iter().map(|m| m.id).collect(),
    };
    // Oldest first, after the cursor: the cursor from the last page always returns
    // only what was recorded since, which is how a running scan is followed.
    let mut found: Vec<(FindingKey, Value)> = Vec::new();
    for id in &scans {
        for f in mcp.jobs.read_findings(id) {
            let Some(k) = FindingKey::of(&f) else {
                continue;
            };
            if k > after && findings::severity_rank(f["severity"].as_str().unwrap_or("")) >= min {
                found.push((k, f));
            }
        }
    }
    found.sort_by(|x, y| x.0.cmp(&y.0));
    let more = found.len() > limit;
    found.truncate(limit);
    let items: Vec<Value> = found
        .iter()
        .map(|(_, f)| findings::list_view(f, mcp.settings.redact))
        .collect();
    let (summary, value) = fit(items.len(), |k| {
        let next = if k == 0 {
            after.clone()
        } else {
            found[k - 1].0.clone()
        };
        let more = more || k < items.len();
        let value = json!({
            "findings": items[..k],
            "next_cursor": next.cursor(),
            "more": more,
        });
        let summary = format!(
            "{k} finding(s){}. Pass next_cursor to read on, or later to see only newer ones.",
            if more { ", more available" } else { "" }
        );
        (summary, value)
    });
    Ok(Done { value, summary })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetFindingArgs {
    finding_id: String,
    #[serde(default)]
    evidence_bytes: Option<u64>,
}

pub(crate) fn get_finding(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let a: GetFindingArgs = parse_args(args)?;
    if !jobs::valid_finding_id(&a.finding_id) {
        return Err(Refusal::invalid(
            "finding_id is f_ followed by 10 lowercase hex characters",
        ));
    }
    let bytes = in_range(
        "evidence_bytes",
        a.evidence_bytes.unwrap_or(EVIDENCE_DEFAULT as u64),
        0,
        EVIDENCE_MAX as u64,
    )? as usize;
    let stored = mcp
        .jobs
        .find_finding(&a.finding_id)
        .ok_or_else(|| not_found("finding"))?;
    let mut value = findings::full_view(&stored, bytes, mcp.settings.redact);
    let summary = format!(
        "Finding {} from scan {}: {} ({}).",
        a.finding_id,
        value["scan_id"].as_str().unwrap_or(""),
        value["vuln_class"].as_str().unwrap_or(""),
        value["severity"].as_str().unwrap_or("")
    );
    while result_size(&summary, &value) > RESULT_CAP && findings::shrink_evidence(&mut value) {}
    Ok(Done { value, summary })
}

pub(crate) async fn cancel_scan(
    mcp: &Mcp,
    args: &Value,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: ScanIdArgs = parse_args(args)?;
    scan_id_arg(&a.scan_id)?;
    note.set_scan(a.scan_id.clone());
    let running = mcp
        .running
        .lock()
        .ok()
        .and_then(|r| r.get(&a.scan_id).cloned());
    let (status, cancel, note_text) = match running {
        Some(job) => {
            let how = mcp.cancel_running(&job).await;
            let status = mcp
                .jobs
                .read_meta(&a.scan_id)
                .map(|m| m.status)
                .unwrap_or_else(|| jobs::CANCELLED.into());
            let text = (how == "requested").then_some(
                "this plessor version keeps running until it finishes; update the engine to \
                 stop scans on request",
            );
            (status, Some(how), text)
        }
        None => {
            let m = mcp
                .jobs
                .read_meta(&a.scan_id)
                .ok_or_else(|| not_found("scan"))?;
            if m.status == jobs::RUNNING && m.owner.session != mcp.session {
                return Err(Refusal::new(
                    Reason::OtherProcess,
                    format!(
                        "scan {} belongs to another crossfyre mcp process (pid {}); cancel it \
                         from the client that started it",
                        m.id, m.owner.pid
                    ),
                ));
            }
            // Running, ours, and not a scan with a handle: a fingerprint whose call is
            // still open. It ends when that call returns.
            if m.status == jobs::RUNNING {
                return Err(Refusal::invalid(format!(
                    "scan {} is a {} call still in progress; it ends when that call returns \
                     and cannot be cancelled on its own",
                    m.id, m.tool
                )));
            }
            (m.status, None, None)
        }
    };
    note.result = Some(json!({"status": status, "cancel": cancel}));
    let summary = match cancel {
        Some(c) => format!("Scan {}: cancel {c}; status {status}.", a.scan_id),
        None => format!("Scan {} had already ended: {status}.", a.scan_id),
    };
    let mut value = json!({"scan_id": a.scan_id, "status": status, "cancel": cancel});
    if let Some(t) = note_text {
        value["note"] = json!(t);
    }
    Ok(Done { value, summary })
}
