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

/// As in `inject.rs` and `fuzz.rs`, and announced for the same reason: a capped
/// `total` reads as a completed pass. Handing this all 1007 of xssmaze's GET
/// endpoints reported 200 of 200 and looked like 16% recall, when it was 83% of
/// the 200 it actually examined.
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
    let handed_in = params.endpoints.len();
    let total = handed_in.min(MAX_ENDPOINTS) as i64;
    if handed_in > MAX_ENDPOINTS {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "endpoint list truncated: {handed_in} handed in, {MAX_ENDPOINTS} will be \
                 probed, {} dropped and not examined.",
                handed_in - MAX_ENDPOINTS
            ),
            "endpoints_handed_in": handed_in,
            "endpoints_tested": MAX_ENDPOINTS,
        }));
    }
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
        let orig = ep.method.to_uppercase();
        if orig == "GET" || orig == "HEAD" {
            // A GET carries its parameters in the query string, so that is where
            // to look. Turning it into a POST and probing a body, which is what
            // this did, can only learn a shape the endpoint does not have.
            //
            // Measured against OWASP VulnerableApp, whose levels are GET
            // endpoints each taking one undocumented query parameter: discovery
            // found none of them, so the injector had nothing to inject into and
            // scored 0 of 117, every finding it did report being passive. Handing
            // it those parameters took SQL injection from 0/9 to 4/9 with no
            // other change.
            let known: HashSet<String> = ep.known_fields.iter().cloned().collect();
            let cal = calibrate_query(&client, &orig, &ep.url, &known).await;
            if let QueryCal::EchoesAnything = cal {
                // Report one usable name rather than nothing. Any name reaches
                // the sink here, so the first candidate is as true as any other
                // and it gives the injector an injection point to work. Without
                // this the endpoint looks parameterless and is never tested.
                if let Some(cand) = QUERY_WORDLIST.first() {
                    let u = render_query_probe(&ep.url, &known, cand, QUERY_MARKER);
                    let evidence = probe::send(&client, &orig, &u, None)
                        .await
                        .map(|r| r.body)
                        .unwrap_or_default();
                    let _ = tx.send(discovery_event(
                        &orig,
                        &ep.url,
                        cand,
                        "medium",
                        "query-echoes-any-name",
                        &evidence,
                        "query",
                    ));
                    found += 1;
                }
            }
            if let QueryCal::Stable(base) = cal {
                let mut new_here = 0usize;
                let mut hits: Vec<(String, String)> = Vec::new();
                for cand in QUERY_WORDLIST {
                    if new_here >= MAX_NEW_PER_EP {
                        break;
                    }
                    if known.contains(*cand) {
                        continue;
                    }
                    let u = render_query_probe(&ep.url, &known, cand, QUERY_MARKER);
                    let Some(r) = probe::send(&client, &orig, &u, None).await else {
                        continue;
                    };
                    // The marker coming back is the strong signal: the endpoint
                    // took the value somewhere. Status and length deviation stay
                    // as the fallback for a parameter that changes behaviour
                    // without echoing, which is most of them.
                    let took_it = r.body.contains(QUERY_MARKER) || accepted(&base, &r, cand);
                    if !took_it {
                        continue;
                    }
                    // Confirm, as the body path does: reissue and require the
                    // same deviation, so one flaky response is not a parameter.
                    let same = probe::send(&client, &orig, &u, None)
                        .await
                        .map(|x| x.body.contains(QUERY_MARKER) || accepted(&base, &x, cand))
                        .unwrap_or(false);
                    if !same {
                        continue;
                    }
                    // Buffered rather than emitted, because whether any of this
                    // is trustworthy is only knowable once the pass is over.
                    hits.push(((*cand).to_string(), r.body.clone()));
                    new_here += 1;
                }

                // Re-probe the control. A baseline is captured once, and that is
                // only valid if probing does not change the thing being probed.
                // VulnerableApp's PersistentXSS levels store the value under any
                // name and append a record per request, so every candidate after
                // the first few deviates from a stale baseline purely because
                // earlier candidates grew the store: 21 reported parameters on an
                // endpoint whose name is not among them. If the control has moved,
                // the pass changed the endpoint and nothing it found can be
                // separated from that, so it is discarded rather than reported.
                let drifted = probe::send(
                    &client,
                    &orig,
                    &render_query_probe(&ep.url, &known, "cfxjunkparamcc", QUERY_MARKER),
                    None,
                )
                .await
                .map(|x| {
                    x.status != base.status
                        || (x.body.len() as i64 - base.len as i64).abs() > len_delta_floor()
                        || x.body.contains(QUERY_MARKER)
                })
                .unwrap_or(true);

                if drifted {
                    if !hits.is_empty() {
                        let _ = tx.send(json!({"type":"log","message": format!(
                            "{} {}: discarded {} candidate parameter(s). The control response moved \
                             during the pass, so this endpoint changes with each request and a \
                             deviation cannot be told apart from that.",
                            orig, ep.url, hits.len()
                        )}));
                    }
                } else {
                    for (cand, evidence) in &hits {
                        let _ = tx.send(discovery_event(
                            &orig,
                            &ep.url,
                            cand,
                            "medium",
                            "query-brute-force",
                            evidence,
                            "query",
                        ));
                        found += 1;
                    }
                }
            }
            done += 1;
            if done % 3 == 0 || done == total {
                let _ = tx.send(json!({"type":"progress","processed":done,"total":total}));
            }
            continue;
        }

        let is_json = ep.content_type.eq_ignore_ascii_case("json");
        let method = orig;
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
                        "body",
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
                                "body",
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
    (r.body.len() as i64 - base.len as i64).abs() > len_delta_floor()
}

/// How far a response length must move from the junk control before the
/// candidate counts as accepted.
///
/// Overridable so it can be calibrated against the lab rather than guessed.
/// xssmaze declares the parameters of all 1007 of its GET endpoints, which
/// makes it ground truth for both halves of this: a name discovery reports that
/// the endpoint does not declare is a false parameter, and a declared name it
/// misses is the threshold's cost. Inferred parameters feed the asset graph and
/// then the injector, so a false one is a site a customer sees and the engine
/// spends requests on.
fn len_delta_floor() -> i64 {
    std::env::var("CFX_DISCOVER_LEN_DELTA")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(40)
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
    location: &str,
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
            "location": location,
            "confidence": confidence,
            "source": how,
            "evidence": snippet,
        }
    })
}

/// Render `url` with the known query parameters plus one candidate.
///
/// Keeps anything already in the query string: an endpoint reached as
/// `/thing?lang=en` may only answer properly with it, and dropping it changes
/// the baseline rather than the parameter under test.
/// The value a query probe sends.
///
/// Not `1`, which is what this did and the reason it found almost nothing.
/// Measured against xssmaze's /advanced/level1/: the junk control answers in 91
/// bytes, `?query=1` in 92, so the response moves by a single byte and no
/// threshold above 1 can see it. The parameter name never appears in the body
/// either, so the name-echo test the body path relies on cannot fire.
///
/// A distinctive value fixes both. The same endpoint answers `?query=<marker>`
/// in 100 bytes and the marker is in the body, which is unambiguous: it is not
/// an English word, so unlike a candidate name it cannot be on the page by
/// accident. That is what the body path needs its baseline control for.
const QUERY_MARKER: &str = "cfxprm7m4zz";

fn render_query_probe(url: &str, known: &HashSet<String>, candidate: &str, value: &str) -> String {
    let mut out = String::from(url);
    let mut sep = if url.contains('?') { '&' } else { '?' };
    let mut names: Vec<&String> = known.iter().collect();
    names.sort();
    for n in names {
        out.push(sep);
        out.push_str(&pct(n));
        out.push_str("=1");
        sep = '&';
    }
    out.push(sep);
    out.push_str(&pct(candidate));
    out.push('=');
    out.push_str(&pct(value));
    out
}

/// The body calibration, against the query string.
///
/// Same discipline and for the same reason: two junk names that disagree mean
/// the endpoint answers differently to equivalent requests, and every candidate
/// will then read as a hit. Measured on OWASP VulnerableApp, its PersistentXSS
/// levels store on each request, so a probe without this check claimed
/// thirty-five parameters on each of them.
/// What a query-string calibration concluded.
enum QueryCal {
    /// A stable control to diff candidates against.
    Stable(Baseline),
    /// The endpoint reflected the marker under a name it has never seen, so it
    /// takes a value under ANY name. There is nothing to discover and that is
    /// not the same as nothing to report: an endpoint that reflects arbitrary
    /// input is an injection point, reachable with any name at all. Dropping
    /// this was why VulnerableApp's XSSWithHtmlTagInjection levels, which
    /// answer `<div>$value<div>` to every parameter, produced no injection
    /// point and scored zero on five reflected-XSS cases.
    EchoesAnything,
    /// No usable control: the endpoint answers differently to equivalent
    /// requests, or echoes the parameter NAME so the name test is meaningless.
    Unusable,
}

async fn calibrate_query(
    client: &Client,
    method: &str,
    url: &str,
    known: &HashSet<String>,
) -> QueryCal {
    let Some(a) = probe::send(
        client,
        method,
        &render_query_probe(url, known, "cfxjunkparamaa", QUERY_MARKER),
        None,
    )
    .await
    else {
        return QueryCal::Unusable;
    };
    let Some(b) = probe::send(
        client,
        method,
        &render_query_probe(url, known, "cfxjunkparambb", QUERY_MARKER),
        None,
    )
    .await
    else {
        return QueryCal::Unusable;
    };
    if a.status != b.status {
        return QueryCal::Unusable;
    }
    // Two ways an endpoint can echo something it never recognised, and both
    // make the oracle unusable. Checking only one of them was a regression I
    // made here and the benchmark caught it.
    //
    // The value: a response carrying the marker for a parameter the endpoint has
    // never heard of carries it for anything.
    if a.body.contains(QUERY_MARKER) || b.body.contains(QUERY_MARKER) {
        return QueryCal::EchoesAnything;
    }
    // The name: xssmaze's /realworld/level5/ answers `?amount=x` with
    // "Parameters: amount", so the name-echo test in `accepted` fires for every
    // candidate. Dropping this check made that one endpoint report all 39
    // wordlist entries, which was every false positive in a 1007-endpoint pass.
    if a.body.contains("cfxjunkparamaa") || b.body.contains("cfxjunkparambb") {
        return QueryCal::Unusable;
    }
    if (a.body.len() as i64 - b.body.len() as i64).abs() > 24 {
        return QueryCal::Unusable; // not stable enough to diff against
    }
    QueryCal::Stable(Baseline {
        status: a.status,
        len: a.body.len(),
        body: a.body,
    })
}

#[cfg(test)]
mod query_probe_tests {
    use super::*;

    #[test]
    fn the_candidate_carries_the_marker_and_known_params_carry_filler() {
        let known: HashSet<String> = ["lang".to_string()].into_iter().collect();
        let u = render_query_probe("http://h/p", &known, "id", QUERY_MARKER);
        assert_eq!(u, format!("http://h/p?lang=1&id={QUERY_MARKER}"));
    }

    #[test]
    fn an_existing_query_string_is_kept() {
        // An endpoint reached as /p?v=1 may only answer properly with it, so
        // dropping it would move the baseline rather than test the parameter.
        let known = HashSet::new();
        let u = render_query_probe("http://h/p?v=1", &known, "id", QUERY_MARKER);
        assert_eq!(u, format!("http://h/p?v=1&id={QUERY_MARKER}"));
    }

    #[test]
    fn the_marker_is_not_a_word_a_page_could_hold_by_accident() {
        // The point of a marker over a candidate name: `id` and `to` are on
        // half the pages on the web, this is on none of them.
        assert!(QUERY_MARKER.len() >= 8);
        assert!(!QUERY_MARKER.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn the_length_floor_defaults_to_the_tuned_value() {
        // Overridable for calibration against the lab, but the default is the
        // value body discovery was tuned to after it reported 26 fields on a
        // RailsGoat endpoint that has one.
        assert_eq!(len_delta_floor(), 40);
    }
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
/// Candidate names for QUERY-string discovery, which is a different vocabulary
/// from the body one below.
///
/// `WORDLIST` is a CRUD body shape: `first_name`, `order_id`, `verified`,
/// `currency`. Those are rare in a query string, and the names that are common
/// there were absent, so query discovery was probing for the wrong things.
/// Measured against xssmaze's 1007 GET endpoints, which declare their own
/// parameters: the body list covers 89.6% of parameter instances and 10 of 52
/// distinct names, this one covers 96.9% and 31 of 52.
///
/// Built from what is common in query strings generally, not from what this
/// benchmark happens to use. xssmaze's `wsurl`, `shortname`, `bio`, `q1`, `a`,
/// `b` and the rest of its long tail are deliberately absent: adding them would
/// raise the score here and nothing else, which is the definition of tuning to
/// the test. The redirect family is over-represented on purpose, because
/// open-redirect and SSRF live there.
const QUERY_WORDLIST: &[&str] = &[
    // value carriers
    "q",
    "s",
    "v",
    "id",
    "query",
    "search",
    "term",
    "keyword",
    "value",
    "text",
    "input",
    "data",
    "name",
    "key",
    "msg",
    "message",
    "comment",
    "note",
    "title",
    "desc",
    "description",
    // resources and paths
    "url",
    "uri",
    "src",
    "href",
    "file",
    "filename",
    "path",
    "page",
    "doc",
    "template",
    "include",
    "img",
    "image",
    // the redirect family
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "returnUrl",
    "next",
    "continue",
    "goto",
    "dest",
    "destination",
    "target",
    "ref",
    "referer",
    "callback",
    "callback_url",
    "jsonp",
    // presentation
    "lang",
    "locale",
    "theme",
    "color",
    "format",
    "output",
    "view",
    "mode",
    "style",
    // listing
    "sort",
    "order",
    "filter",
    "limit",
    "offset",
    "start",
    "end",
    "count",
    "type",
    "tag",
    "category",
    "slug",
    // identity
    "user",
    "username",
    "email",
    "token",
    "password",
    "session",
    "api_key",
    // diagnostics
    "debug",
    "error",
    "error_description",
    "test",
    "seed",
];

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
