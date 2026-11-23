//! `get_inventory`: what toolmark knows runs where, with the CVE leads of each product at
//! its version and what a template scan said of each lead. Read from toolmark's daemon,
//! and only the rows of hosts inside the loaded scope file. Sends no traffic.

use super::parse_args;
use crate::core::{Done, Mcp, Reason, Refusal};
use crate::{engine, kept, redact, untrusted};
use cfx_cve::inventory::{Answer, NOT_PROOF};
use serde::Deserialize;
use serde_json::{Value, json};

/// The most rows one answer carries.
const ROWS_MAX: usize = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(default)]
    host: Option<String>,
}

/// One lead as it is shown: the CVE, how bad and how exploited, and the answer a template
/// scan gave it, when one did.
fn lead(l: &Value) -> Value {
    let s = |k: &str| untrusted::clean(l[k].as_str().unwrap_or_default(), 200);
    let num = |k: &str| {
        l.get(k)
            .filter(|v| v.is_number())
            .cloned()
            .unwrap_or(Value::Null)
    };
    let mut out = json!({
        "cve": s("cve"),
        "severity": crate::findings::severity(&s("severity")),
        "cvss": num("cvss"),
        "kev": l["kev"].as_bool().unwrap_or(false),
        "epss": num("epss"),
        "possible": l["possible"].as_bool().unwrap_or(false),
        "backport": l["backport"].as_bool().unwrap_or(false),
    });
    if let Some(answer) = l["answer"].as_str() {
        out["answer"] = json!(untrusted::clean(answer, 40));
        for (k, from) in [
            ("answer_template", "answer_template"),
            ("answer_reason", "answer_reason"),
            ("answered_at", "answered_at"),
        ] {
            if let Some(v) = l[from].as_str() {
                out[k] = json!(untrusted::clean(v, 300));
            }
        }
        if let Some(scan) = l["answer_scan"].as_str().filter(|s| !s.is_empty()) {
            out["answer_scan"] = json!(kept::scan_id("plessor", &untrusted::clean(scan, 100)));
        }
        if answer == Answer::NotFound.as_str() {
            out["not_proof"] = json!(NOT_PROOF);
        }
    }
    out
}

pub(crate) async fn get_inventory(mcp: &Mcp, args: &Value) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let only = a.host.as_deref().map(|h| h.trim().to_ascii_lowercase());
    if only.as_ref().is_some_and(|h| h.is_empty() || h.len() > 253) {
        return Err(Refusal::invalid(
            "host is a host name or address of at most 253 bytes",
        ));
    }
    let toolmark = mcp.engine("toolmark")?;
    let port = toolmark.port;
    if !toolmark.installed {
        return Err(Refusal::new(
            Reason::EngineUnavailable,
            "toolmark is not installed, so there is no inventory. Install it with `crossfyre \
             extension install toolmark`.",
        ));
    }
    let conn = engine::connect(port)
        .await
        .map_err(|_| mcp.engine_down("toolmark", port))?;
    let answer = conn
        .local(&json!({"operation": "inventory", "response": "instant"}))
        .await
        .map_err(|e| {
            Refusal::new(
                Reason::EngineError,
                format!(
                    "toolmark did not answer: {}",
                    untrusted::clean(&e.to_string(), 200)
                ),
            )
        })?;
    if answer["status"] != "completed" {
        return Err(Refusal::new(
            Reason::EngineError,
            format!(
                "toolmark reported: {}",
                untrusted::clean(
                    answer["message"].as_str().unwrap_or("no reason given"),
                    untrusted::NOTE_CAP
                )
            ),
        ));
    }

    let redact = mcp.settings.redact;
    let shown = |v: &Value, cap: usize| {
        let t = untrusted::clean(v.as_str().unwrap_or_default(), cap);
        if redact { redact::redact_text(&t) } else { t }
    };
    let mut rows = Vec::new();
    let mut more = false;
    let mut unchecked = false;
    for row in answer["inventory"].as_array().into_iter().flatten() {
        let host = row["host"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let port = row["port"].as_u64().and_then(|p| u16::try_from(p).ok());
        let Some(port) = port else { continue };
        let at = if host.contains(':') {
            format!("http://[{host}]:{port}")
        } else {
            format!("http://{host}:{port}")
        };
        if only.as_ref().is_some_and(|h| *h != host) || !kept::in_scope(mcp, &at) {
            continue;
        }
        if rows.len() == ROWS_MAX {
            more = true;
            break;
        }
        let leads: Vec<Value> = row["leads"]
            .as_array()
            .into_iter()
            .flatten()
            .take(100)
            .map(lead)
            .collect();
        unchecked |= leads.iter().any(|l| l.get("not_proof").is_some());
        rows.push(json!({
            "host": untrusted::clean(&host, 253),
            "port": port,
            "vendor": shown(&row["vendor"], 200),
            "product": shown(&row["product"], 200),
            "version": shown(&row["version"], 200),
            "cpe": shown(&row["cpe"], 300),
            "distro": shown(&row["distro"], 100),
            "last_seen": untrusted::clean(row["last_seen"].as_str().unwrap_or_default(), 40),
            "cve_leads": leads,
        }));
    }
    let leads: usize = rows
        .iter()
        .map(|r| r["cve_leads"].as_array().map_or(0, Vec::len))
        .sum();
    let summary = format!(
        "toolmark's inventory in scope: {} products, {leads} CVE leads (inferred from versions, \
         so verify the build; a template scan's answer is with each lead it checked){}.",
        rows.len(),
        if more {
            ", and more than this answer holds"
        } else {
            ""
        }
    );
    let mut value = json!({
        "cve_data": untrusted::clean(answer["cve_data"].as_str().unwrap_or_default(), 300),
        "more": more,
        "target_data": {"untrusted": true, "inventory": rows},
    });
    if unchecked {
        value["note"] = json!(NOT_PROOF);
    }
    Ok(Done { value, summary })
}
