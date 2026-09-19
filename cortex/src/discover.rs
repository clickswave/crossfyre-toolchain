//! Request-shape discovery: for an operation with no (or partial) known request contract, learn
//! its body fields WITHOUT a spec, using the server's own responses as the oracle.
//!
//! Two techniques, cheap-to-expensive:
//!   1. ERROR-MINING (high confidence): send a minimal body and read the validation error, which on
//!      most frameworks names the missing/unexpected fields ("field `email` is required"). Satisfy
//!      the named fields and repeat, so fields hidden behind earlier-required ones surface too.
//!   2. CALIBRATED FIELD BRUTE-FORCE (candidate): probe a wordlist of common field names against a
//!      control-junk baseline. A candidate whose response deviates from the junk baseline (status /
//!      length / reflection) is likely a real field.
//!
//! Everything is GENERATE -> DETECT -> CONFIRM: an error-mined field must appear in a real error
//! response; a brute-forced field must beat a junk control. Discovered fields are emitted as
//! `finding` events carrying a `shape_field` payload, so they ride the node's existing result relay
//! and the control plane ingests them as inferred params (not vulnerabilities). Discovery sends real
//! requests (including writes) - the caller has opted into that.

use crate::engine::AuthSpec;
use crate::probe::{self, Resp};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::LazyLock;
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct DiscoverParams {
    #[serde(default)]
    pub endpoints: Vec<DiscEndpoint>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub target: String,
    #[serde(default = "d_true")]
    pub evasive: bool,
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// Refuse private and reserved destinations at connect time. Absent = false,
    /// which is what an authorised customer scan gets: reaching your own
    /// internal network from your own node is the product. The free public
    /// tools set it, because there the caller is anonymous and the egress is
    /// ours.
    #[serde(default)]
    pub block_internal: bool,
    /// Opt-in to endpoints whose method overwrites or destroys (DELETE, PUT,
    /// PATCH). Off by default, the same rail the injection, scan and
    /// authorization engines state.
    ///
    /// The module note above says discovery sends real requests including
    /// writes and that the caller has opted into that. The writes are inherent
    /// and that part is honest: body fields only exist on a request that has a
    /// body, which is why a GET is promoted to POST here. What was not honest
    /// is the opt-in, because nothing in this schema ever asked for one.
    /// Measured against a target that records what it receives: one DELETE
    /// endpoint in the list produced 59 DELETE requests at the same resource.
    #[serde(default)]
    pub test_writes: bool,
}
fn d_timeout() -> u64 {
    12_000
}
fn d_true() -> bool {
    true
}
fn d_post() -> String {
    "POST".to_string()
}
fn d_json() -> String {
    "json".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct DiscEndpoint {
    #[serde(default = "d_post")]
    pub method: String,
    pub url: String,
    /// "json" | "form"
    #[serde(default = "d_json")]
    pub content_type: String,
    /// Body field names we already know (from a spec / capture); skipped during discovery.
    #[serde(default)]
    pub known_fields: Vec<String>,
}

const MAX_ENDPOINTS: usize = 200;
const ERR_MINE_ROUNDS: usize = 5;
const MAX_NEW_PER_EP: usize = 40;

pub async fn run(params: DiscoverParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({"type":"ack","target": params.target}));
    if params.endpoints.is_empty() {
        let _ = tx.send(json!({"type":"error","message":"discovery needs at least one endpoint"}));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }
    let client = match probe::build_client(probe::ClientOpts {
        evasive: params.evasive,
        identify: params.identify.clone(),
        auth: params.auth.as_ref(),
        target: &params.target,
        timeout_ms: params.timeout_ms,
        min_timeout_ms: 0,
        block_internal: params.block_internal,
    }) {
        Some(c) => c,
        None => {
            let _ = tx.send(json!({"type":"error","message":"client build failed"}));
            return;
        }
    };

    let mut found = 0i64;
    let total = params.endpoints.len().min(MAX_ENDPOINTS) as i64;
    let mut done = 0i64;

    for ep in params.endpoints.iter().take(MAX_ENDPOINTS) {
        if crate::inject::destroys_a_resource(&ep.method) && !params.test_writes {
            let _ = tx.send(json!({"type":"log","message": format!(
                "skipped {} {} without sending anything at it: discovery learns a body shape by                  sending bodies, and on a method that overwrites or destroys the resource every                  one of those is the damage rather than a test. Its shape is untested here, not                  clean. Re-run with writes enabled against a target you are willing to change.",
                ep.method, ep.url
            )}));
            done += 1;
            let _ = tx.send(json!({"type":"progress","processed": done, "total": total}));
            continue;
        }
        let is_json = ep.content_type.eq_ignore_ascii_case("json");
        let method = {
            let m = ep.method.to_uppercase();
            if m == "GET" { "POST".to_string() } else { m }
        };
        // fields we treat as satisfied (known + discovered) so the next round reaches deeper.
        let mut known: HashSet<String> = ep.known_fields.iter().cloned().collect();
        let mut discovered: Vec<(String, &'static str)> = Vec::new(); // (field, confidence)

        // ---- 1. error-mining ----
        for _round in 0..ERR_MINE_ROUNDS {
            let body = render_body(&known, is_json, None);
            let r = match send(&client, &method, &ep.url, &body, is_json).await {
                Some(r) => r,
                None => break,
            };
            let mut added = false;
            for name in mine_fields(&r.body) {
                if is_probably_field(&name) && known.insert(name.clone()) {
                    discovered.push((name.clone(), "high"));
                    let _ = tx.send(discovery_event(
                        &method,
                        &ep.url,
                        &name,
                        "high",
                        "error-mining",
                        &r.body,
                    ));
                    found += 1;
                    added = true;
                    if discovered.len() >= MAX_NEW_PER_EP {
                        break;
                    }
                }
            }
            if !added || discovered.len() >= MAX_NEW_PER_EP {
                break;
            }
        }

        // ---- 2. calibrated field brute-force ----
        if discovered.len() < MAX_NEW_PER_EP {
            if let Some(base) = calibrate(&client, &method, &ep.url, &known, is_json).await {
                for cand in WORDLIST {
                    if known.contains(*cand) {
                        continue;
                    }
                    let body = render_body_probe(&known, cand, is_json);
                    let r = match send(&client, &method, &ep.url, &body, is_json).await {
                        Some(r) => r,
                        None => continue,
                    };
                    if accepted(&base, &r, cand) {
                        // confirm: reissue and require the same deviation.
                        let r2 = send(&client, &method, &ep.url, &body, is_json).await;
                        if r2.map(|x| accepted(&base, &x, cand)).unwrap_or(false) {
                            discovered.push(((*cand).to_string(), "medium"));
                            let _ = tx.send(discovery_event(
                                &method,
                                &ep.url,
                                cand,
                                "medium",
                                "brute-force",
                                &r.body,
                            ));
                            found += 1;
                            if discovered.len() >= MAX_NEW_PER_EP {
                                break;
                            }
                        }
                    }
                }
            }
        }

        done += 1;
        if done % 3 == 0 || done == total {
            let _ = tx.send(json!({"type":"progress","processed":done,"total":total}));
        }
    }
    let _ = tx.send(json!({"type":"done","found":found}));
}

/// Baseline signature from a control junk field: (status, body length). A real field must deviate
/// from this. We require two independent junk fields to agree, else the endpoint is too noisy to
/// give a clean oracle and brute-force is skipped.
struct Baseline {
    status: u16,
    len: usize,
    /// What the endpoint says when handed a field it does not know. The candidate
    /// names are ordinary English words, so the reflection test is only evidence
    /// when the word is NOT already here.
    body: String,
}
async fn calibrate(
    client: &Client,
    method: &str,
    url: &str,
    known: &HashSet<String>,
    is_json: bool,
) -> Option<Baseline> {
    let a = send(
        client,
        method,
        url,
        &render_body_probe(known, "cfxjunkfieldaa", is_json),
        is_json,
    )
    .await?;
    let b = send(
        client,
        method,
        url,
        &render_body_probe(known, "cfxjunkfieldbb", is_json),
        is_json,
    )
    .await?;
    // both junk fields should behave identically (neither is a real field).
    if a.status != b.status {
        return None;
    }
    if a.body.contains("cfxjunkfieldaa") || b.body.contains("cfxjunkfieldbb") {
        return None; // endpoint echoes arbitrary input -> reflection oracle unusable
    }
    let len_close = (a.body.len() as i64 - b.body.len() as i64).abs() <= 24;
    if !len_close {
        return None; // response length not stable enough to diff against
    }
    Some(Baseline {
        status: a.status,
        len: a.body.len(),
        body: a.body,
    })
}

/// A candidate field looks accepted if its response deviates from the junk baseline: a different
/// status, a materially different body length, or the field name echoed back.
///
/// "Echoed back" needs care, and did not get it. The candidates are ordinary
/// English words - `id`, `name`, `to`, `url`, `date`, `code`, `page`, `key` - and
/// a bare substring test against an HTML page matches almost all of them on
/// almost any page. Measured against RailsGoat's `POST /password_resets`, which
/// answers every request with the same redirect: 26 of the wordlist came back as
/// discovered fields, and one of them was real. Inferred parameters feed the
/// asset graph, so that is 25 fields a customer sees on an endpoint that has
/// none, and 25 more sites for the injector to spend requests on.
///
/// The junk baseline is the control, and it was already being fetched. A word
/// that is in the response AND in the response to a field the endpoint has never
/// heard of is a word the page contains, not a field the endpoint took. The
/// boundary check does the rest: without it `id` matches `video` and `to`
/// matches almost everything.
fn accepted(base: &Baseline, r: &Resp, cand: &str) -> bool {
    if r.status != base.status {
        return true;
    }
    if echoes_field(&r.body, cand) && !echoes_field(&base.body, cand) {
        return true;
    }
    (r.body.len() as i64 - base.len as i64).abs() > 40
}

/// Does `body` contain `field` as a word, rather than inside a longer one?
fn echoes_field(body: &str, field: &str) -> bool {
    let b = body.as_bytes();
    let f = field.as_bytes();
    if f.is_empty() {
        return false;
    }
    let wordish = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut from = 0usize;
    while let Some(rel) = body[from..].find(field) {
        let i = from + rel;
        let before_ok = i == 0 || !wordish(b[i - 1]);
        let after = i + f.len();
        let after_ok = after >= b.len() || !wordish(b[after]);
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

fn discovery_event(
    method: &str,
    url: &str,
    field: &str,
    confidence: &str,
    how: &str,
    evidence: &str,
) -> Value {
    // a short evidence snippet (never the whole body)
    let snippet: String = evidence.chars().take(200).collect();
    // Emitted as a `finding` event so it flows through the node's existing result relay + the
    // control-plane findings pipeline; the `shape_field` type routes it to shape ingestion (inferred
    // params), not the vulnerability table. `name`/`target` feed the findings dedup key.
    json!({
        "type": "finding",
        "data": {
            "type": "shape_field",
            "target": url,
            "name": field,
            "method": method,
            "url": url,
            "field": field,
            "location": "body",
            "confidence": confidence,
            "source": how,
            "evidence": snippet,
        }
    })
}

/// Render a JSON/form body from a set of field names, each with a benign placeholder. When `only`
/// is given, only that single field is included (used nowhere yet but kept for targeted probes).
fn render_body(fields: &HashSet<String>, is_json: bool, only: Option<&str>) -> String {
    let names: Vec<&String> = match only {
        Some(o) => fields.iter().filter(|f| f.as_str() == o).collect(),
        None => fields.iter().collect(),
    };
    if is_json {
        let mut m = serde_json::Map::new();
        for n in &names {
            m.insert((*n).clone(), Value::String("1".into()));
        }
        Value::Object(m).to_string()
    } else {
        names
            .iter()
            .map(|n| format!("{}=1", pct(n)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// Body = the known fields plus one extra candidate field.
fn render_body_probe(known: &HashSet<String>, candidate: &str, is_json: bool) -> String {
    let mut set = known.clone();
    set.insert(candidate.to_string());
    render_body(&set, is_json, None)
}

fn pct(s: &str) -> String {
    probe::pct_encode(s)
}

async fn send(client: &Client, method: &str, url: &str, body: &str, is_json: bool) -> Option<Resp> {
    let ct = if is_json {
        "application/json"
    } else {
        "application/x-www-form-urlencoded"
    };
    probe::send(client, method, url, Some((body, ct))).await
}

/// Extract field names a validation error names as missing / required / unknown, across the common
/// frameworks (DRF, Laravel, express-validator, Joi/celebrate, ajv/JSON-schema, FastAPI/pydantic,
/// Rails strong-params, fastify).
fn mine_fields(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |s: &str| {
        let s = s.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
        if !s.is_empty() && !out.iter().any(|x: &String| x == s) {
            out.push(s.to_string());
        }
    };
    for re in MINE_RES.iter() {
        for cap in re.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                push(m.as_str());
            }
        }
    }
    out
}

/// A mined token that is plausibly a request field (not a sentence fragment or type name).
fn is_probably_field(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty()
        && n.len() <= 48
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && n.chars().any(|c| c.is_ascii_alphabetic())
        && !matches!(
            n.to_ascii_lowercase().as_str(),
            "string"
                | "number"
                | "integer"
                | "boolean"
                | "object"
                | "array"
                | "null"
                | "true"
                | "false"
                | "body"
                | "error"
                | "value"
        )
}

static MINE_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // "field `email` is required" / "'email' is required" / "\"email\" is required" (also
        // covers Joi/celebrate). Tolerant of backslash-escaped quotes as they appear in raw JSON.
        r#"(?i)[`'"\\]*([A-Za-z_][\w.\-]{0,46})[`'"\\]*\s+is\s+required"#,
        // "missing required field: email" / "missing parameter email" / "missing property 'email'"
        r#"(?i)missing(?:\s+required)?\s+(?:field|parameter|property|key|argument)[:\s]+[`'"]?([A-Za-z_][\w.\-]{0,46})"#,
        // "required (field|property) email"
        r#"(?i)required\s+(?:field|property|parameter|key)[:\s]+[`'"]?([A-Za-z_][\w.\-]{0,46})"#,
        // JSON-schema / ajv: "must have required property 'email'"
        r#"(?i)must have required property\s+[`'"]([A-Za-z_][\w.\-]{0,46})"#,
        // DRF: "email": ["This field is required."]  ->  capture the key
        r#""([A-Za-z_][\w.\-]{0,46})"\s*:\s*\[\s*"This field is required"#,
        // Laravel: "The email field is required."
        r#"(?i)the\s+([A-Za-z_][\w.\-]{0,46})\s+field\s+is\s+required"#,
        // Joi/celebrate: "\"email\" is required"
        r#""([A-Za-z_][\w.\-]{0,46})"\s+is\s+required"#,
        // fastify: "body must have required property 'email'" already covered; "body/email"
        r#"(?i)body/([A-Za-z_][\w.\-]{0,46})"#,
        // "unknown|unexpected field 'email'"
        r#"(?i)(?:unknown|unexpected|unrecognized)\s+(?:field|key|property|argument|parameter)[:\s]+[`'"]?([A-Za-z_][\w.\-]{0,46})"#,
        // Spring: "Field error in object 'signUpForm' on field 'email'" / "on field `email`"
        r#"(?i)on field [`'"]([A-Za-z_][\w.\-]{0,46})"#,
        // pydantic/FastAPI: {"loc":["body","email"], ...}
        r#""loc"\s*:\s*\[\s*"body"\s*,\s*"([A-Za-z_][\w.\-]{0,46})""#,
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

/// Common request field names, for calibrated brute-force when error-mining is unproductive.
const WORDLIST: &[&str] = &[
    "id",
    "name",
    "email",
    "username",
    "password",
    "title",
    "description",
    "amount",
    "price",
    "quantity",
    "status",
    "role",
    "type",
    "date",
    "url",
    "phone",
    "address",
    "first_name",
    "last_name",
    "token",
    "code",
    "message",
    "content",
    "value",
    "user",
    "user_id",
    "product_id",
    "order_id",
    "category",
    "tags",
    "enabled",
    "active",
    "verified",
    "image",
    "file",
    "comment",
    "rating",
    "search",
    "query",
    "limit",
    "offset",
    "page",
    "sort",
    "filter",
    "country",
    "city",
    "zip",
    "currency",
    "method",
    "action",
    "data",
    "key",
    "start",
    "end",
    "from",
    "to",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mines_fields_across_frameworks() {
        let bodies = [
            (r#"{"email":["This field is required."]}"#, "email"),
            ("The password field is required.", "password"),
            (
                r#"{"message":"must have required property 'username'"}"#,
                "username",
            ),
            ("missing required field: order_id", "order_id"),
            (
                r#"Field error in object 'signUpForm' on field 'email': rejected value [null]"#,
                "email",
            ),
            (
                r#"{"detail":[{"loc":["body","phone_number"],"msg":"field required"}]}"#,
                "phone_number",
            ),
            (r#"{"detail":"\"amount\" is required"}"#, "amount"),
            ("body/quantity should be integer", "quantity"),
        ];
        for (body, want) in bodies {
            let fields = mine_fields(body);
            assert!(
                fields.iter().any(|f| f == want),
                "expected `{want}` from {body:?}, got {fields:?}"
            );
        }
    }

    #[test]
    fn field_plausibility_filters_noise() {
        assert!(is_probably_field("email"));
        assert!(is_probably_field("order_id"));
        assert!(!is_probably_field("string"));
        assert!(!is_probably_field(""));
        assert!(!is_probably_field("this is a sentence"));
    }

    #[test]
    fn accepted_oracle_uses_status_length_reflection() {
        let base = Baseline {
            status: 400,
            len: 100,
            body: String::new(),
        };
        // same status + similar length + no reflection -> not accepted
        assert!(!accepted(
            &base,
            &Resp {
                status: 400,
                body: "x".repeat(100),
                elapsed_ms: 0,
                location: None,
                headers: Vec::new(),
            },
            "email"
        ));
        // status change -> accepted
        assert!(accepted(
            &base,
            &Resp {
                status: 200,
                body: "x".repeat(100),
                elapsed_ms: 0,
                location: None,
                headers: Vec::new(),
            },
            "email"
        ));
        // reflection -> accepted
        assert!(accepted(
            &base,
            &Resp {
                status: 400,
                body: "email accepted".into(),
                elapsed_ms: 0,
                location: None,
                headers: Vec::new(),
            },
            "email"
        ));
        // big length delta -> accepted
        assert!(accepted(
            &base,
            &Resp {
                status: 400,
                body: "x".repeat(200),
                elapsed_ms: 0,
                location: None,
                headers: Vec::new(),
            },
            "email"
        ));
    }

    #[test]
    fn a_word_the_page_already_contains_is_not_a_discovered_field() {
        // RailsGoat's redirect body, and any HTML page, carries these words.
        let page = "<a href=\"/login\">login</a> id name to url".to_string();
        let base = Baseline {
            status: 302,
            len: page.len(),
            body: page.clone(),
        };
        let same = Resp {
            status: 302,
            body: page,
            elapsed_ms: 0,
            location: None,
            headers: Vec::new(),
        };
        for cand in ["id", "name", "to", "url"] {
            assert!(
                !accepted(&base, &same, cand),
                "{cand} should not be accepted"
            );
        }
    }

    #[test]
    fn a_word_the_endpoint_starts_echoing_is_a_discovered_field() {
        let base = Baseline {
            status: 400,
            len: 40,
            body: "missing required field".into(),
        };
        let echoed = Resp {
            status: 400,
            body: "missing required field: user".into(),
            elapsed_ms: 0,
            location: None,
            headers: Vec::new(),
        };
        assert!(accepted(&base, &echoed, "user"));
    }

    #[test]
    fn a_field_name_inside_a_longer_word_is_not_an_echo() {
        assert!(!echoes_field("a video element", "id"));
        assert!(!echoes_field("username", "user"));
        assert!(echoes_field("field: user", "user"));
        assert!(echoes_field("user_id=3", "user_id"));
        assert!(echoes_field("\"to\": 1", "to"));
    }
}
