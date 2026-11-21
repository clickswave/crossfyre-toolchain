//! `scan_templates`: plessor's template scan of one target, run as a scan with a handle.
//!
//! The templates are chosen the way `plessor scan` chooses them: by what toolmark saw on
//! the target lately, which also gives the CVE leads the templates answer. toolmark is
//! asked, never started, and the answers go back to it.

use super::inject::{LeadsTo, Plan, Run, start_scan};
use super::{in_range, parse_args};
use crate::confirm::{AskKind, WriteAsk};
use crate::core::{CallNote, Done, Intent, Mcp, Refusal, TrafficRequest};
use crate::peer::ClientPeer;
use crate::{engine, guard, untrusted};
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    url: String,
    #[serde(default)]
    severity: Option<Vec<String>>,
    #[serde(default)]
    templates: Option<Vec<String>>,
    #[serde(default)]
    all_templates: bool,
    #[serde(default)]
    test_writes: bool,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

/// The template ids asked for, checked: at most 200, each a template id's characters.
fn template_ids(named: Option<Vec<String>>) -> Result<Vec<String>, Refusal> {
    let ids = named.unwrap_or_default();
    let fits = |id: &String| {
        !id.is_empty()
            && id.len() <= 200
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    };
    if ids.len() > 200 || !ids.iter().all(fits) {
        return Err(Refusal::invalid(
            "templates holds at most 200 template ids, each of letters, digits, '-', '_', '.' \
             and ':'",
        ));
    }
    Ok(ids)
}

fn severities(named: Option<Vec<String>>) -> Result<Vec<String>, Refusal> {
    let mut out: Vec<String> = Vec::new();
    for s in named.unwrap_or_default() {
        let s = s.trim().to_ascii_lowercase();
        if !SEVERITIES.contains(&s.as_str()) {
            return Err(Refusal::invalid(format!(
                "severity holds only {}",
                SEVERITIES.join(", ")
            )));
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

/// What toolmark saw on `host`:`port` lately, as the fields that choose the templates and
/// give the leads, and the line that says what chose them.
async fn what_toolmark_saw(
    mcp: &Mcp,
    host: &str,
    port: u16,
) -> (Map<String, Value>, Option<LeadsTo>, String) {
    let nothing = |why: String| (Map::new(), None, why);
    let toolmark = match mcp.engine("toolmark") {
        Ok(t) if t.installed => t,
        _ => {
            return nothing(
                "toolmark is not installed, so every template runs and no CVE leads are \
                 answered"
                    .into(),
            );
        }
    };
    let tport = toolmark.port;
    let answer = match engine::connect(tport).await {
        Ok(conn) => conn
            .local(&json!({"operation": "inventory", "response": "instant"}))
            .await
            .ok()
            .filter(|a| a["status"] == "completed"),
        Err(_) => None,
    };
    let Some(inventory) = answer else {
        return nothing(format!(
            "toolmark is not answering on port {tport}, so every template runs and no CVE \
             leads are answered"
        ));
    };
    let now = chrono::Utc::now().timestamp();
    match cfx_cve::inventory::fresh(&inventory, host, port, now) {
        Some(fresh) => {
            let said = format!(
                "the templates were chosen by {}, with {} CVE leads to answer",
                untrusted::clean(&fresh.from, 300),
                fresh.leads.len()
            );
            let mut fields = Map::new();
            fields.insert("products".into(), json!(fresh.products));
            fields.insert("products_from".into(), json!(fresh.from));
            let to = (!fresh.leads.is_empty()).then(|| LeadsTo {
                toolmark: tport,
                host: host.to_string(),
                port,
            });
            fields.insert("leads".into(), json!(fresh.leads));
            (fields, to, said)
        }
        None => nothing(format!(
            "toolmark has seen nothing on {}:{port} in the last week, so every template runs \
             and no CVE leads are answered; fingerprint it first to have them chosen",
            untrusted::clean(host, 200)
        )),
    }
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let wait = in_range("wait_seconds", a.wait_seconds.unwrap_or(0), 0, 50)?;
    let only = template_ids(a.templates)?;
    let severity = severities(a.severity)?;
    let dest = guard::parse_target(&a.url).map_err(|e| Refusal::invalid(format!("url: {e}")))?;

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "scan_templates",
            dests: vec![dest.clone()],
            intent: if a.test_writes {
                Intent::Write
            } else {
                Intent::Read
            },
            point: Point::Request,
            pace: false,
            scan_start: true,
        })
        .await?;

    let (mut fields, leads_to, chosen) = what_toolmark_saw(mcp, &dest.host, dest.port).await;
    fields.insert("pack".into(), json!(true));
    fields.insert("all_templates".into(), json!(a.all_templates));
    fields.insert("only".into(), json!(only));
    fields.insert("severity".into(), json!(severity));
    let write = a.test_writes.then(|| WriteAsk {
        remember: None,
        message: format!(
            "scan_templates with test_writes will also run the templates that send PUT, PATCH \
             and DELETE requests to {}. These can change or destroy data.",
            untrusted::clean(&dest.origin(), 200)
        ),
        kind: AskKind::Write,
    });
    let plan = Plan {
        tool: "scan_templates",
        target: dest.url.clone(),
        run: Run::Templates { fields, leads_to },
        shown_endpoints: Vec::new(),
        test_writes: a.test_writes,
        source: None,
        wait,
        write,
        on_start: None,
    };
    let mut done = start_scan(mcp, pending, plan, peer, ct, note).await?;
    done.summary = format!("{} {}.", done.summary, capitalised(&chosen));
    done.value["note"] = json!(chosen);
    Ok(done)
}

fn capitalised(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}
