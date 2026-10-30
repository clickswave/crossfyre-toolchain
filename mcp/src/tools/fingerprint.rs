//! `fingerprint`: toolmark's `fingerprint` operation on one target, inline.

use super::{in_range, parse_args};
use crate::core::{CallNote, Done, Intent, Mcp, Reason, Refusal, TrafficRequest};
use crate::engine::{self, Line, event_type};
use crate::findings::{self, Stamp};
use crate::jobs::{self, JobMeta, NewJob};
use crate::peer::ClientPeer;
use crate::{guard, redact, untrusted};
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    url: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

fn cancelled() -> Refusal {
    Refusal::new(
        Reason::Cancelled,
        "The call was cancelled before it finished.",
    )
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let timeout = in_range("timeout_seconds", a.timeout_seconds.unwrap_or(8), 1, 60)?;
    let dest = guard::parse_target(&a.url).map_err(|e| Refusal::invalid(format!("url: {e}")))?;

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "fingerprint",
            dests: vec![dest.clone()],
            intent: Intent::Read,
            point: Point::Request,
            pace: true,
            scan_start: false,
        })
        .await?;
    let port = mcp.engine("toolmark")?.port;
    let mut conn = engine::connect(port)
        .await
        .map_err(|_| mcp.engine_down("toolmark", port))?;
    mcp.require(
        &mut conn,
        "toolmark",
        port,
        "fingerprint",
        &["resolve", "block_internal"],
    )
    .await?;
    let clearance = mcp.confirm(pending, peer, None, note, ct).await?;
    if ct.is_cancelled() {
        return Err(cancelled());
    }
    peer.progress(0.0, Some(3.0), "connecting to toolmark")
        .await;

    // Redirects off: toolmark would otherwise follow up to five hops this server
    // never sees, to wherever the target points them. A name is pinned to the address
    // the guard cleared, so toolmark does not look it up again and get another one.
    let op = json!({
        "operation": "fingerprint",
        "response": "stream",
        "target": dest.url,
        "follow_redirects": false,
        "resolve": clearance.pins(),
        "block_internal": clearance.block_internal(mcp.scope.allow_private),
        "timeout_ms": timeout * 1000,
    });
    let mut meta = JobMeta::new(
        &mcp.session,
        NewJob {
            tool: "fingerprint",
            engine: "toolmark",
            target: &dest.url,
            endpoints: Vec::new(),
            scope_sha256: mcp.scope.sha256.clone(),
            cancellable: false,
            test_writes: false,
        },
    );
    let _ = mcp.jobs.write_meta(&meta);
    note.set_scan(meta.id.clone());

    let (mut reader, _writer) = conn.start(&clearance, &op).await.map_err(|e| {
        Refusal::new(
            Reason::EngineError,
            format!("could not send to toolmark: {e}"),
        )
    })?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout + 10);
    let mut events: Vec<Value> = Vec::new();
    let mut error: Option<String> = None;
    let mut finished = false;
    loop {
        let next = tokio::select! {
            _ = ct.cancelled() => {
                meta.finish(jobs::CANCELLED);
                let _ = mcp.jobs.write_meta(&meta);
                return Err(cancelled());
            }
            r = tokio::time::timeout_at(deadline, reader.next()) => r,
        };
        match next {
            Err(_) => {
                error = Some("toolmark did not finish in time".into());
                break;
            }
            Ok(Err(_)) | Ok(Ok(None)) => break,
            Ok(Ok(Some(Line::Event(v)))) => match event_type(&v) {
                "ack" => peer.progress(1.0, Some(3.0), "fetching the target").await,
                "finding" => {
                    if events.len() < 500 {
                        events.push(v.get("data").cloned().unwrap_or(Value::Null));
                    }
                }
                "error" => {
                    let m = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
                    error = Some(untrusted::clean(m, untrusted::NOTE_CAP));
                }
                "done" => {
                    finished = true;
                    break;
                }
                _ => {}
            },
            Ok(Ok(Some(_))) => {}
        }
    }
    peer.progress(2.0, Some(3.0), "reading the results").await;

    let service = events
        .iter()
        .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("service"));
    if service.is_none() {
        let why = error.unwrap_or_else(|| {
            if finished {
                "toolmark finished without describing the service".into()
            } else {
                "toolmark closed the connection before finishing".into()
            }
        });
        meta.error = Some(why.clone());
        meta.finish(jobs::FAILED);
        let _ = mcp.jobs.write_meta(&meta);
        return Err(Refusal::new(
            Reason::EngineError,
            format!("toolmark reported: {why}"),
        ));
    }

    let redact = mcp.settings.redact;
    let shown = |s: &str, cap: usize| {
        let (t, cut) = untrusted::sanitize(s, cap);
        (if redact { redact::redact_text(&t) } else { t }, cut)
    };
    let mut truncated = false;
    let mut technologies = Vec::new();
    let mut versions = Map::new();
    let mut evidence = Vec::new();
    let mut cve_leads = Vec::new();
    let mut stored = Vec::new();
    let mut seq = 0u64;
    for e in &events {
        let kind = e.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let name = untrusted::clean(e.get("name").and_then(|n| n.as_str()).unwrap_or(""), 200);
        match kind {
            "technology" => {
                technologies.push(json!({
                    "name": name,
                    "category": untrusted::clean(e.get("category").and_then(|c| c.as_str()).unwrap_or(""), 200),
                    "cpe": untrusted::clean(e.get("cpe").and_then(|c| c.as_str()).unwrap_or(""), 200),
                    "confidence": e.get("confidence").filter(|c| c.is_number()).cloned().unwrap_or(Value::Null),
                }));
                if let Some(v) = e
                    .get("version")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.is_empty())
                {
                    let (v, cut) = shown(v, 200);
                    truncated |= cut;
                    versions.insert(name.clone(), json!(v));
                }
                if let Some(ev) = e
                    .get("evidence")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.is_empty())
                    && evidence.len() < 20
                {
                    let (ev, cut) = shown(ev, 500);
                    truncated |= cut;
                    evidence.push(json!({"technology": name, "evidence": ev}));
                }
            }
            "vulnerability" => {
                let num = |k: &str| {
                    e.get(k)
                        .filter(|v| v.is_number())
                        .cloned()
                        .unwrap_or(Value::Null)
                };
                let s = |k: &str| {
                    untrusted::clean(e.get(k).and_then(|v| v.as_str()).unwrap_or(""), 200)
                };
                cve_leads.push(json!({
                    "cve": s("cve"),
                    "severity": findings::severity(&s("severity")),
                    "cvss": num("cvss"),
                    "product": s("product"),
                    "confidence": "version-inferred",
                    "reference": s("reference"),
                }));
            }
            _ => continue,
        }
        seq += 1;
        if let Some(f) = findings::from_toolmark(
            e,
            Stamp {
                id: jobs::new_id("f"),
                scan_id: &meta.id,
                seq,
                recorded_ms: jobs::now_ms(),
            },
        ) {
            meta.count(f["severity"].as_str().unwrap_or("info"));
            stored.push(f);
        }
    }
    let svc = service.cloned().unwrap_or(Value::Null);
    let status_code = svc.get("status_code").and_then(|s| s.as_u64());
    let mut text = |k: &str| -> Value {
        match svc.get(k).and_then(|v| v.as_str()) {
            Some(s) => {
                let (t, cut) = shown(s, 200);
                truncated |= cut;
                json!(t)
            }
            None => Value::Null,
        }
    };
    let title = text("title");
    let server = text("server");
    let target_data = json!({
        "untrusted": true,
        "title": title,
        "server": server,
        "versions": versions,
        "waf": untrusted::sanitize_value(svc.get("waf").unwrap_or(&Value::Null), 200, 3),
        "cdn": untrusted::sanitize_value(svc.get("cdn").unwrap_or(&Value::Null), 200, 3),
        "favicon": untrusted::sanitize_value(svc.get("favicon").unwrap_or(&Value::Null), 200, 3),
        "evidence": evidence,
        "truncated": truncated,
    });

    if !stored.is_empty() {
        let _ = mcp.jobs.append_findings(&meta.id, &stored);
    }
    meta.progress.done = 1;
    meta.progress.total = 1;
    meta.progress.phase = "done".into();
    meta.finish(jobs::COMPLETED);
    let _ = mcp.jobs.write_meta(&meta);
    peer.progress(3.0, Some(3.0), "done").await;

    let mut value = json!({
        "scan_id": meta.id,
        "url": if redact { redact::redact_url(&dest.url) } else { dest.url.clone() },
        "status_code": status_code,
        "technologies": technologies,
        "cve_leads": cve_leads,
        "target_data": target_data,
    });
    if status_code.is_some_and(|s| (300..400).contains(&s)) {
        value["note"] = json!(
            "toolmark does not follow redirects under crossfyre mcp; use send_http_request to \
             read Location."
        );
    }
    note.result = Some(json!({
        "status": status_code,
        "technologies": value["technologies"].as_array().map(|a| a.len()),
        "cve_leads": value["cve_leads"].as_array().map(|a| a.len()),
    }));
    let summary = format!(
        "toolmark fingerprinted {}: HTTP {}, {} technologies, {} CVE leads (inferred from \
         versions, so verify the build).",
        untrusted::clean(&dest.origin(), 200),
        status_code
            .map(|s| s.to_string())
            .unwrap_or_else(|| "?".into()),
        value["technologies"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        value["cve_leads"].as_array().map(|a| a.len()).unwrap_or(0),
    );
    Ok(Done { value, summary })
}
