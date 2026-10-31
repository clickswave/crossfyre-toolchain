//! One finding shape for both engines, with what the target wrote kept apart.
//!
//! The fields at the top level are the ones the engine decided: which class, how
//! severe, where. Anything the target supplied (a description quoting its page,
//! evidence, a version string read from a header) goes under `target_data`, which
//! says `untrusted: true` on every finding so a client never has to guess which half
//! is which.

use crate::redact;
use crate::untrusted::{self, DESCRIPTION_CAP, EVIDENCE_MAX, LIST_DESCRIPTION_CAP, NAME_CAP};
use serde_json::{Map, Value, json};

/// The fields of a stored finding that are not the engine's own.
const EXTRA_CAP: usize = 8 * 1024;

pub(crate) struct Stamp<'a> {
    pub id: String,
    pub scan_id: &'a str,
    pub seq: u64,
    pub recorded_ms: i64,
}

pub(crate) fn severity(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" | "informational" => "info",
        "low" => "low",
        "medium" | "moderate" => "medium",
        "high" => "high",
        "critical" => "critical",
        _ => "unknown",
    }
}

pub(crate) fn severity_rank(s: &str) -> u8 {
    match severity(s) {
        "info" => 1,
        "low" => 2,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 0,
    }
}

fn top(v: Option<&Value>) -> Value {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Value::String(untrusted::clean(s, NAME_CAP)),
        Some(Value::Number(n)) => Value::String(n.to_string()),
        _ => Value::Null,
    }
}

fn text_of(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn target_data(description: &str, evidence: &str, extra: Map<String, Value>) -> Value {
    let (description, d_cut) = untrusted::sanitize(description, DESCRIPTION_CAP);
    let (evidence, e_cut) = untrusted::sanitize(evidence, EVIDENCE_MAX);
    let (evidence, b_cut) = untrusted::cap_bytes(&evidence, EVIDENCE_MAX);
    let extra = untrusted::sanitize_value(&Value::Object(extra), 1000, 4);
    let extra = if extra.to_string().len() > EXTRA_CAP {
        json!({"omitted": "the engine's extra fields were larger than 8 KB"})
    } else {
        extra
    };
    json!({
        "untrusted": true,
        "description": description,
        "evidence": evidence,
        "extra": extra,
        "truncated": d_cut || e_cut || b_cut,
    })
}

fn base(st: Stamp<'_>, source: &str) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("id".into(), json!(st.id));
    o.insert("scan_id".into(), json!(st.scan_id));
    o.insert("seq".into(), json!(st.seq));
    o.insert("recorded_ms".into(), json!(st.recorded_ms));
    o.insert("source".into(), json!(source));
    o
}

/// A plessor finding, which already comes in the shared `finding` crate shape.
pub(crate) fn from_plessor(data: &Value, st: Stamp<'_>) -> Value {
    const KNOWN: &[&str] = &[
        "type",
        "vuln_class",
        "name",
        "severity",
        "confidence",
        "description",
        "source",
        "target",
        "url",
        "matched_at",
        "method",
        "param",
        "location",
        "template",
        "evidence",
    ];
    let mut o = base(st, "plessor");
    o.insert("source_detail".into(), top(data.get("source")));
    o.insert("vuln_class".into(), top(data.get("vuln_class")));
    o.insert("name".into(), top(data.get("name")));
    let sev = severity(data.get("severity").and_then(|s| s.as_str()).unwrap_or(""));
    o.insert("severity".into(), json!(sev));
    o.insert("confidence".into(), top(data.get("confidence")));
    o.insert(
        "url".into(),
        top(data.get("url").or_else(|| data.get("matched_at"))),
    );
    o.insert("method".into(), top(data.get("method")));
    o.insert("param".into(), top(data.get("param")));
    o.insert("location".into(), top(data.get("location")));
    o.insert("template".into(), top(data.get("template")));
    let extra: Map<String, Value> = data
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, _)| !KNOWN.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    o.insert(
        "target_data".into(),
        target_data(
            &text_of(data.get("description")),
            &text_of(data.get("evidence")),
            extra,
        ),
    );
    Value::Object(o)
}

/// A toolmark technology or version-matched CVE lead. Service and environment
/// records are summaries of the run rather than findings, and are not stored.
pub(crate) fn from_toolmark(data: &Value, st: Stamp<'_>) -> Option<Value> {
    let kind = data.get("type").and_then(|t| t.as_str())?;
    let mut o = base(st, "toolmark");
    o.insert("source_detail".into(), top(data.get("source")));
    o.insert("url".into(), top(data.get("target")));
    o.insert("method".into(), json!("GET"));
    o.insert("param".into(), Value::Null);
    o.insert("location".into(), Value::Null);
    o.insert("template".into(), Value::Null);
    let mut extra = Map::new();
    match kind {
        "technology" => {
            o.insert("vuln_class".into(), json!("technology"));
            o.insert("name".into(), top(data.get("name")));
            o.insert("severity".into(), json!("info"));
            o.insert("confidence".into(), top(data.get("confidence")));
            for k in ["category", "version", "cpe"] {
                if let Some(v) = data.get(k) {
                    extra.insert(k.into(), v.clone());
                }
            }
            o.insert(
                "target_data".into(),
                target_data("", &text_of(data.get("evidence")), extra),
            );
        }
        "vulnerability" => {
            o.insert("vuln_class".into(), json!("cve"));
            o.insert("name".into(), top(data.get("name")));
            let sev = severity(data.get("severity").and_then(|s| s.as_str()).unwrap_or(""));
            o.insert("severity".into(), json!(sev));
            o.insert("confidence".into(), json!("version-inferred"));
            for k in ["cve", "cvss", "product", "version", "reference"] {
                if let Some(v) = data.get(k) {
                    extra.insert(k.into(), v.clone());
                }
            }
            o.insert(
                "target_data".into(),
                target_data(&text_of(data.get("description")), "", extra),
            );
        }
        _ => return None,
    }
    Some(Value::Object(o))
}

fn redact_strings(v: &mut Value) {
    match v {
        Value::String(s) => *s = redact::redact_text(s),
        Value::Array(a) => a.iter_mut().for_each(redact_strings),
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                if redact::sensitive_name(k) && x.is_string() {
                    *x = json!(redact::MASK);
                } else {
                    redact_strings(x);
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn redact_finding(f: &mut Value) {
    if let Some(u) = f.get("url").and_then(|u| u.as_str()) {
        let r = redact::redact_url(u);
        f["url"] = json!(r);
    }
    if let Some(td) = f.get_mut("target_data") {
        redact_strings(td);
    }
}

/// A finding in a list: description shortened, no evidence and no extra fields.
pub(crate) fn list_view(stored: &Value, redact: bool) -> Value {
    let mut f = stored.clone();
    if let Some(o) = f.as_object_mut() {
        o.remove("recorded_ms");
    }
    if let Some(td) = f.get_mut("target_data").and_then(|t| t.as_object_mut()) {
        let d = td
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let (d, cut) = untrusted::sanitize(&d, LIST_DESCRIPTION_CAP);
        let was = td
            .get("truncated")
            .and_then(|t| t.as_bool())
            .unwrap_or(false);
        td.insert("description".into(), json!(d));
        td.remove("evidence");
        td.remove("extra");
        td.insert("truncated".into(), json!(was || cut));
    }
    if redact {
        redact_finding(&mut f);
    }
    f
}

/// One finding in full, with evidence cut to what the caller asked for.
pub(crate) fn full_view(stored: &Value, evidence_bytes: usize, redact: bool) -> Value {
    let mut f = stored.clone();
    if let Some(o) = f.as_object_mut() {
        o.remove("recorded_ms");
    }
    if let Some(td) = f.get_mut("target_data").and_then(|t| t.as_object_mut()) {
        let e = td
            .get("evidence")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let (e, cut) = untrusted::cap_bytes(&e, evidence_bytes.min(EVIDENCE_MAX));
        let was = td
            .get("truncated")
            .and_then(|t| t.as_bool())
            .unwrap_or(false);
        td.insert("evidence".into(), json!(e));
        td.insert("truncated".into(), json!(was || cut));
    }
    if redact {
        redact_finding(&mut f);
    }
    f
}

/// Shorten the evidence of a full finding until the result fits.
pub(crate) fn shrink_evidence(f: &mut Value) -> bool {
    let Some(td) = f.get_mut("target_data").and_then(|t| t.as_object_mut()) else {
        return false;
    };
    let e = td
        .get("evidence")
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();
    if e.is_empty() {
        return false;
    }
    let (e, _) = untrusted::cap_bytes(&e, e.len() / 2);
    td.insert("evidence".into(), json!(e));
    td.insert("truncated".into(), json!(true));
    true
}
