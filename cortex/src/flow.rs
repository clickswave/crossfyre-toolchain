//! Multi-step flows: skipping a step, and repeating a step that should happen once.
//!
//! A checkout is five requests in an order. The order is the control, and plenty
//! of applications enforce it only by virtue of the browser doing them in order.
//! Ask for step five without step three and the discount is never charged, the
//! address is never validated, the approval never happens.
//!
//! # Why this needs a recording rather than a crawl
//!
//! A crawler sees endpoints. A flow is endpoints plus an ORDER plus the state
//! each step leaves behind, and none of that is recoverable from a list of URLs.
//! Guessing which requests form a checkout from their paths is the kind of
//! inference this codebase refuses, because the guess is invisible in the output
//! and a wrong one produces a confident finding about a flow that never existed.
//!
//! So the input is a recording: an ordered span of real exchanges that a person
//! marked as one flow. The Web Tracer already captures exactly this.
//!
//! # The control, which is not optional
//!
//! Before any conclusion, the unmodified flow must replay successfully from a
//! fresh session.
//!
//! Without that, "step three is skippable" and "my replay broke" are the same
//! observation, and the second is far more likely: tokens rotate, ids are
//! per-session, a captured `Cookie` header belongs to a session that ended. A
//! flow whose clean replay does not reproduce is reported as UNTESTABLE, by
//! name, rather than skipped quietly.
//!
//! # Replaying something recorded earlier
//!
//! Two things make a recording replayable:
//!
//!   * **A fresh cookie jar, and the captured `Cookie` header dropped.** Sending
//!     the recorded cookie would replay the original session, which is precisely
//!     the thing that must not happen: every experiment here asks what a caller
//!     who did NOT perform the earlier steps can do.
//!   * **Re-correlation.** A CSRF token or a cart id in step four came out of
//!     step two's response. On replay step two produces a different one, so the
//!     recorded value is found in the later request and replaced with the fresh
//!     one. That is mechanical, and where it cannot be done the clean replay
//!     fails and the flow is called untestable instead of being guessed at.

use serde::Deserialize;
use std::collections::HashMap;

/// One captured exchange, as the control plane recorded it.
#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    #[serde(default = "get")]
    pub method: String,
    pub url: String,
    /// Ordered, as captured.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: String,
    /// What the recording saw. The replay is compared against this.
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub response: String,
}

fn get() -> String {
    "GET".to_string()
}

/// Headers never replayed.
///
/// `cookie` is the important one and the reason this list exists: replaying it
/// would carry the original session into every experiment, so a step that only
/// "works" because the recorded user was already past step three would look
/// skippable to anyone.
///
/// The rest are transport details the client owns; sending a recorded
/// `content-length` with a re-correlated body is a good way to truncate it.
pub const DROP_HEADERS: &[&str] = &[
    "cookie",
    "content-length",
    "host",
    "connection",
    "transfer-encoding",
    "accept-encoding",
    "upgrade",
    "keep-alive",
    "proxy-authorization",
];

pub fn replayable_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !DROP_HEADERS.contains(&n.as_str())
}

/// A value a later request carries that an earlier response produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    /// Every earlier response that produced this value, nearest first, each with
    /// the name it appeared under.
    ///
    /// Every one, not just the nearest, and that is the whole point. A CSRF
    /// token is echoed by each step that renders a form, so the nearest source
    /// for the final step is usually the step immediately before it. Record only
    /// that one and the moment an experiment SKIPS that step the substitution
    /// has nowhere to read from, the stale recorded token goes out, the server
    /// answers 403, and the flow looks like it enforces an order it does not.
    /// That is a false negative produced by the test's own mechanics, and the
    /// fixture found it.
    pub sources: Vec<(usize, String)>,
    /// What it was in the recording.
    pub original: String,
}

impl Link {
    /// The freshest value this replay actually has for it.
    pub fn resolve<'a>(&self, fresh: &'a HashMap<(usize, String), String>) -> Option<&'a String> {
        self.sources.iter().find_map(|s| fresh.get(s))
    }
}

/// Named values a response hands to the steps after it.
///
/// Three sources, because these are the three ways a server passes state
/// forward in a form-and-JSON application: a JSON field, a hidden input, and an
/// attribute pair in markup. Cookies are absent on purpose - the jar carries
/// those, and re-correlating them by hand would fight it.
pub fn values_from(body: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |k: &str, v: &str| {
        // Short values are not identifiers, they are "1", "on" and "true", and
        // substituting those corrupts every request they appear in.
        if v.len() >= MIN_VALUE && !out.iter().any(|(_, ov)| ov == v) {
            out.push((k.to_string(), v.to_string()));
        }
    };

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        collect_json(&v, &mut push);
    }
    for (k, v) in html_pairs(body) {
        push(&k, &v);
    }
    out
}

/// Shortest value worth correlating.
///
/// Tokens, ids and nonces are longer than this; flags and counts are not.
pub const MIN_VALUE: usize = 6;

fn collect_json(v: &serde_json::Value, push: &mut impl FnMut(&str, &str)) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                match val {
                    serde_json::Value::String(s) => push(k, s),
                    serde_json::Value::Number(n) => push(k, &n.to_string()),
                    other => collect_json(other, push),
                }
            }
        }
        serde_json::Value::Array(a) => {
            for val in a {
                collect_json(val, push);
            }
        }
        _ => {}
    }
}

/// `name="x" ... value="y"` pairs out of markup, in either order.
fn html_pairs(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for tag in body.split('<') {
        let Some(end) = tag.find('>') else { continue };
        let tag = &tag[..end];
        let lower = tag.to_ascii_lowercase();
        if !lower.starts_with("input") && !lower.starts_with("meta") {
            continue;
        }
        let name = attr(tag, "name").or_else(|| attr(tag, "id"));
        let value = attr(tag, "value").or_else(|| attr(tag, "content"));
        if let (Some(n), Some(v)) = (name, value) {
            out.push((n, v));
        }
    }
    out
}

fn attr(tag: &str, key: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0usize;
    loop {
        let i = lower[from..].find(key)? + from;
        let after = &tag[i + key.len()..];
        let after_trim = after.trim_start();
        // Make sure this is the attribute and not a suffix of another one.
        let before_ok = i == 0
            || !tag[..i]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric() || c == '-' || c == '_')
                .unwrap_or(false);
        if before_ok && after_trim.starts_with('=') {
            let v = after_trim[1..].trim_start();
            let (quote, rest) = match v.chars().next() {
                Some(q @ ('"' | '\'')) => (Some(q), &v[1..]),
                _ => (None, v),
            };
            let endq = match quote {
                Some(q) => rest.find(q)?,
                None => rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len()),
            };
            return Some(rest[..endq].to_string());
        }
        from = i + key.len();
    }
}

/// Which earlier responses step `k`'s request depends on.
///
/// Sources are collected newest-first so the freshest copy is preferred, but
/// every source is kept: see [`Link::sources`].
pub fn links_for(steps: &[Step], k: usize) -> Vec<Link> {
    let request = request_text(&steps[k]);
    let mut out: Vec<Link> = Vec::new();
    for from in (0..k).rev() {
        for (key, value) in values_from(&steps[from].response) {
            if !request.contains(&value) {
                continue;
            }
            match out.iter_mut().find(|l| l.original == value) {
                Some(l) => l.sources.push((from, key)),
                None => out.push(Link {
                    sources: vec![(from, key)],
                    original: value,
                }),
            }
        }
    }
    out
}

/// Everything of a step that can carry a correlated value.
pub fn request_text(s: &Step) -> String {
    let mut t = format!("{} {}", s.method, s.url);
    for (k, v) in &s.headers {
        if replayable_header(k) {
            t.push('\n');
            t.push_str(k);
            t.push(':');
            t.push_str(v);
        }
    }
    t.push('\n');
    t.push_str(&s.body);
    t
}

/// Swap recorded values for the ones this replay actually produced.
pub fn substitute(text: &str, links: &[Link], fresh: &HashMap<(usize, String), String>) -> String {
    let mut out = text.to_string();
    for l in links {
        if let Some(v) = l.resolve(fresh) {
            out = out.replace(&l.original, v);
        }
    }
    out
}

/// Did this replay of a step land where the recording did?
///
/// Compared by class rather than exact code: a recording that saw `200` and a
/// replay that sees `201` did the same thing, and one that sees `403` did not.
pub fn same_outcome(recorded: u16, replayed: u16) -> bool {
    class(recorded) == class(replayed)
}

fn class(status: u16) -> u8 {
    match status {
        0 => 0,
        100..=199 => 1,
        // 2xx and 3xx are both "the application accepted this": a form POST that
        // redirects on success is the overwhelmingly common shape, and treating
        // its 302 as a different outcome from a 200 would make almost every
        // recorded flow untestable.
        200..=399 => 2,
        400..=499 => 4,
        _ => 5,
    }
}

/// Was the flow reproduced well enough to draw conclusions from?
///
/// Every step has to land where the recording did. Anything less and a later
/// "this step was skippable" is indistinguishable from the replay having broken
/// at that point, which is the failure this whole module is arranged to avoid.
pub fn reproduced(steps: &[Step], replayed: &[u16]) -> Result<(), usize> {
    for (i, s) in steps.iter().enumerate() {
        let got = replayed.get(i).copied().unwrap_or(0);
        if !same_outcome(s.status, got) {
            return Err(i);
        }
    }
    Ok(())
}

/// With step `k` left out, did the steps after it still land where they did in
/// the clean replay?
///
/// Compared against the CLEAN REPLAY rather than against the recording, because
/// the clean replay is what this engine established it can reproduce. Comparing
/// against the recording would re-admit every difference the replay itself
/// introduces.
pub fn steps_after_still_worked(k: usize, clean: &[u16], variant: &[u16]) -> bool {
    let after: Vec<usize> = (k + 1..clean.len()).collect();
    if after.is_empty() {
        return false;
    }
    after.iter().all(|&i| {
        let c = clean.get(i).copied().unwrap_or(0);
        let v = variant.get(i).copied().unwrap_or(0);
        class(c) == 2 && same_outcome(c, v)
    })
}

/// How many steps a single flow is allowed to carry.
///
/// Each skippable step costs a whole replay of the flow, so the work is
/// quadratic in this number and every request is a real state change on
/// somebody's application.
pub const MAX_STEPS: usize = 12;

/// How many steps are actually tested for being skippable.
pub const MAX_SKIP_TESTS: usize = 6;

#[cfg(test)]
mod tests {
    use super::*;

    fn step(url: &str, body: &str, status: u16, response: &str) -> Step {
        Step {
            method: "POST".into(),
            url: url.into(),
            headers: vec![("Cookie".into(), "session=abc".into())],
            body: body.into(),
            status,
            response: response.into(),
        }
    }

    #[test]
    fn the_recorded_session_cookie_is_never_replayed() {
        // The single most important line in this file: replaying it would carry
        // the original session into every experiment.
        assert!(!replayable_header("Cookie"));
        assert!(!replayable_header("cookie"));
        assert!(!replayable_header("Content-Length"));
        assert!(replayable_header("X-CSRF-Token"));
        assert!(replayable_header("Content-Type"));
    }

    #[test]
    fn a_csrf_token_in_markup_is_found() {
        let body = r#"<form><input type="hidden" name="csrf" value="tok-2f8a91bc"><input name="qty" value="1"></form>"#;
        let v = values_from(body);
        assert!(v.contains(&("csrf".to_string(), "tok-2f8a91bc".to_string())));
        // "1" is too short to be an identifier and substituting it would corrupt
        // every request it appears in.
        assert!(!v.iter().any(|(_, val)| val == "1"));
    }

    #[test]
    fn a_json_id_is_found_at_any_depth() {
        let body =
            r#"{"data":{"cart":{"id":"cart-77281f","items":[{"sku":"ABC-99213"}]}},"ok":true}"#;
        let v = values_from(body);
        assert!(v.iter().any(|(k, val)| k == "id" && val == "cart-77281f"));
        assert!(v.iter().any(|(k, val)| k == "sku" && val == "ABC-99213"));
    }

    #[test]
    fn a_later_step_links_to_the_response_that_produced_its_token() {
        let steps = vec![
            step("/login", "", 200, r#"{"session_note":"ignored"}"#),
            step(
                "/cart",
                "",
                200,
                r#"<input type="hidden" name="csrf" value="tok-2f8a91bc">"#,
            ),
            step("/checkout", "csrf=tok-2f8a91bc&pay=now", 200, "done"),
        ];
        let links = links_for(&steps, 2);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].sources, vec![(1usize, "csrf".to_string())]);
        assert_eq!(links[0].original, "tok-2f8a91bc");
    }

    #[test]
    fn the_nearest_response_wins_when_a_value_repeats() {
        let steps = vec![
            step("/a", "", 200, r#"{"token":"shared-value-1"}"#),
            step("/b", "", 200, r#"{"token":"shared-value-1"}"#),
            step("/c", "token=shared-value-1", 200, "ok"),
        ];
        let links = links_for(&steps, 2);
        // Nearest first...
        assert_eq!(links[0].sources[0].0, 1, "prefer the freshest copy");
        // ...but the earlier one is kept, so skipping step 1 does not strand the
        // substitution. This is the false negative the fixture found.
        assert_eq!(links[0].sources.len(), 2);
        assert_eq!(links[0].sources[1].0, 0);

        let mut fresh = HashMap::new();
        fresh.insert((0usize, "token".to_string()), "fresh-from-a".to_string());
        assert_eq!(
            links[0].resolve(&fresh).map(String::as_str),
            Some("fresh-from-a"),
            "with step 1 skipped it must fall back to step 0"
        );
    }

    #[test]
    fn substitution_swaps_the_recorded_value_for_the_replayed_one() {
        let links = vec![Link {
            sources: vec![(1usize, "csrf".to_string())],
            original: "tok-2f8a91bc".into(),
        }];
        let mut fresh = HashMap::new();
        fresh.insert((1usize, "csrf".to_string()), "tok-NEWNEW99".to_string());
        let out = substitute("csrf=tok-2f8a91bc&pay=now", &links, &fresh);
        assert_eq!(out, "csrf=tok-NEWNEW99&pay=now");
    }

    #[test]
    fn a_redirect_on_success_is_the_same_outcome_as_a_page() {
        // A form POST that 302s on success is the common shape; calling that a
        // different outcome from 200 would make most flows untestable.
        assert!(same_outcome(200, 302));
        assert!(!same_outcome(200, 403));
        assert!(!same_outcome(403, 200));
    }

    #[test]
    fn a_flow_that_did_not_reproduce_names_the_step_that_failed() {
        let steps = vec![step("/a", "", 200, ""), step("/b", "", 200, "")];
        assert!(reproduced(&steps, &[200, 302]).is_ok());
        assert_eq!(reproduced(&steps, &[200, 403]), Err(1));
        // A step that never answered is a failure to reproduce, not a pass.
        assert_eq!(reproduced(&steps, &[200]), Err(1));
    }

    #[test]
    fn skipping_matters_only_when_the_later_steps_still_succeed() {
        // Clean replay: everything succeeded.
        let clean = vec![200, 200, 200, 200];
        // Without step 1, the rest still succeed: the order is not enforced.
        assert!(steps_after_still_worked(1, &clean, &[200, 0, 200, 200]));
        // Without step 1 the rest are refused: it is enforced.
        assert!(!steps_after_still_worked(1, &clean, &[200, 0, 403, 403]));
        // The last step has nothing after it, so there is nothing to conclude.
        assert!(!steps_after_still_worked(3, &clean, &[200, 200, 200, 0]));
    }

    #[test]
    fn a_step_that_failed_in_the_clean_replay_proves_nothing_when_skipped() {
        // Step 2 was already failing before anything was skipped, so its
        // "success" without step 1 cannot mean the order is unenforced.
        let clean = vec![200, 200, 403, 200];
        assert!(!steps_after_still_worked(1, &clean, &[200, 0, 403, 200]));
    }
}

// ---------------------------------------------------------------------------
// The operation
// ---------------------------------------------------------------------------

use crate::probe::{self, ClientOpts};
use cfx_finding::Finding;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use transport::Client;

/// Note the absence of an `auth` field, which every other cortex operation has.
/// A recorded flow that begins with a login establishes its own session, and
/// handing one in up front would hide the thing being tested: whether a caller
/// who did NOT perform the earlier steps can reach the later ones. A credential
/// in the payload is accepted by serde and ignored.
#[derive(Debug, Deserialize)]
pub struct FlowParams {
    #[serde(default)]
    pub target: String,
    /// The flow, in the order it was recorded.
    #[serde(default)]
    pub steps: Vec<Step>,
    /// What the operator called it, for the finding to name.
    #[serde(default)]
    pub name: String,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub evasive: bool,
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default)]
    pub block_internal: bool,
}

fn d_timeout() -> u64 {
    15_000
}

/// A single replay of the flow, optionally with one step left out.
///
/// Returns the status of every step, `0` for the omitted one. A fresh client
/// each time is what makes it a fresh session: the jar starts empty, so the
/// flow's own login is the only thing that can authenticate it.
async fn replay(p: &FlowParams, skip: Option<usize>) -> Option<Vec<u16>> {
    let client: Client = probe::build_client(ClientOpts {
        evasive: p.evasive,
        identify: p.identify.clone(),
        // Deliberately no auth. A recorded flow that begins with a login
        // establishes its own session, and handing it one up front would hide
        // the very thing being tested.
        auth: None,
        target: &p.target,
        timeout_ms: p.timeout_ms,
        min_timeout_ms: 0,
        block_internal: p.block_internal,
    })?;

    let mut statuses = vec![0u16; p.steps.len()];
    // What each step's response produced this time round, keyed the same way
    // the links are, so a later step can find the fresh value.
    let mut fresh: HashMap<(usize, String), String> = HashMap::new();

    for (i, s) in p.steps.iter().enumerate() {
        if Some(i) == skip {
            continue;
        }
        let links = links_for(&p.steps, i);
        let url = substitute(&s.url, &links, &fresh);
        let body = substitute(&s.body, &links, &fresh);
        let headers: Vec<(String, String)> = s
            .headers
            .iter()
            .filter(|(k, _)| replayable_header(k))
            .map(|(k, v)| (k.clone(), substitute(v, &links, &fresh)))
            .collect();
        let ctype = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "application/x-www-form-urlencoded".to_string());

        let body_arg = (!body.is_empty()).then_some((body.as_str(), ctype.as_str()));
        let r = probe::send_with(&client, &s.method, &url, body_arg, &headers).await?;
        statuses[i] = r.status;
        for (k, v) in values_from(&r.body) {
            fresh.insert((i, k), v);
        }
    }
    Some(statuses)
}

/// Run the flow experiments and stream what they found.
pub async fn run(p: FlowParams, tx: mpsc::UnboundedSender<Value>) {
    let _ = tx.send(json!({"type":"ack","target": p.target}));
    let label = if p.name.is_empty() {
        "this flow".to_string()
    } else {
        format!("`{}`", p.name)
    };

    if p.steps.len() < 2 || p.steps.len() > MAX_STEPS {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{label} has {} step(s); a flow is tested between 2 and {MAX_STEPS}. Nothing was \
                 run, so this is not a clean result.",
                p.steps.len()
            )
        }));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }

    // The control. Everything below depends on it.
    let Some(clean) = replay(&p, None).await else {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{label} could not be replayed at all: the target stopped answering. No conclusion \
                 was drawn, and the absence of findings here is not evidence."
            )
        }));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    };
    if let Err(bad) = reproduced(&p.steps, &clean) {
        let _ = tx.send(json!({
            "type": "log",
            "message": format!(
                "{label} is UNTESTABLE: replaying it unchanged from a fresh session diverged at \
                 step {} ({} {}), which answered {} where the recording saw {}. Every experiment \
                 below it would be measuring the broken replay rather than the application, so \
                 none were run. Usually this is a value the recording carried that is not \
                 re-derivable from the responses: a token in a header the capture did not record, \
                 or a step performed outside the browser.",
                bad + 1,
                p.steps[bad].method,
                p.steps[bad].url,
                clean.get(bad).copied().unwrap_or(0),
                p.steps[bad].status
            )
        }));
        let _ = tx.send(json!({"type":"done","found":0}));
        return;
    }
    let _ = tx.send(json!({
        "type": "log",
        "message": format!(
            "{label} replayed cleanly from a fresh session across {} steps, so the experiments \
             below are measuring the application.",
            p.steps.len()
        )
    }));

    let mut found = 0i64;

    // Experiment one: leave a step out.
    let last = p.steps.len() - 1;
    for k in 0..last.min(MAX_SKIP_TESTS) {
        let Some(variant) = replay(&p, Some(k)).await else {
            continue;
        };
        if !steps_after_still_worked(k, &clean, &variant) {
            continue;
        }
        let f = Finding::new(
            "cortex-flow",
            "workflow",
            "Business logic: a required step in a flow can be skipped",
            "high",
            &p.steps[last].url,
        )
        .method(&p.steps[last].method)
        .describe(format!(
            "Replaying {label} from a fresh session WITHOUT step {} ({} {}) left every later step \
             working exactly as it did in the unmodified replay, including the final one. The \
             application does not enforce its own order here: it accepts the outcome of a flow \
             whose middle was never performed. Whatever step {} exists to do - charge the card, \
             validate the address, take the approval, apply the limit - can be left out by anyone \
             issuing the requests directly, because nothing but the browser was making it happen. \
             The unmodified flow was replayed first and reproduced, so this is the application \
             accepting the shortcut rather than a broken replay.",
            k + 1,
            p.steps[k].method,
            p.steps[k].url,
            k + 1
        ))
        .with("skipped_step", json!(k + 1))
        .with("skipped_url", json!(p.steps[k].url))
        .with("flow_steps", json!(p.steps.len()))
        .build();
        let _ = tx.send(json!({"type":"finding","data":f}));
        found += 1;
    }

    // Experiment two: do the last step twice.
    //
    // The sequential sibling of the race check. That one asks whether a limit
    // survives concurrency; this asks whether there is a limit at all.
    if let Some(twice) = replay_with_repeat(&p).await
        && class(twice.0) == 2
        && class(twice.1) == 2
    {
        let f = Finding::new(
            "cortex-flow",
            "workflow",
            "Business logic: a flow's final step is accepted twice",
            "medium",
            &p.steps[last].url,
        )
        .method(&p.steps[last].method)
        .describe(format!(
            "After {label} completed, its final step ({} {}) was sent once more on the same \
             session and accepted again ({} then {}). A terminal step is usually meant to happen \
             once per flow: submitting the order, redeeming the code, confirming the transfer. \
             Accepted twice, it can be accepted as many times as it is sent. This is the \
             sequential case; whether the same limit survives concurrent requests is what the \
             `race` class asks, and the two have different fixes.",
            p.steps[last].method, p.steps[last].url, twice.0, twice.1
        ))
        .with("repeated_step", json!(last + 1))
        .build();
        let _ = tx.send(json!({"type":"finding","data":f}));
        found += 1;
    }

    let _ = tx.send(json!({"type":"done","found":found}));
}

/// Replay the flow, then send its last step a second time on the same session.
/// Returns the two statuses of that final step.
async fn replay_with_repeat(p: &FlowParams) -> Option<(u16, u16)> {
    let client: Client = probe::build_client(ClientOpts {
        evasive: p.evasive,
        identify: p.identify.clone(),
        auth: None,
        target: &p.target,
        timeout_ms: p.timeout_ms,
        min_timeout_ms: 0,
        block_internal: p.block_internal,
    })?;
    let mut fresh: HashMap<(usize, String), String> = HashMap::new();
    let last = p.steps.len() - 1;
    let mut first_status = 0u16;
    let mut second_status = 0u16;

    for (i, s) in p.steps.iter().enumerate() {
        let links = links_for(&p.steps, i);
        let url = substitute(&s.url, &links, &fresh);
        let body = substitute(&s.body, &links, &fresh);
        let headers: Vec<(String, String)> = s
            .headers
            .iter()
            .filter(|(k, _)| replayable_header(k))
            .map(|(k, v)| (k.clone(), substitute(v, &links, &fresh)))
            .collect();
        let ctype = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "application/x-www-form-urlencoded".to_string());
        let body_arg = (!body.is_empty()).then_some((body.as_str(), ctype.as_str()));
        let r = probe::send_with(&client, &s.method, &url, body_arg, &headers).await?;
        for (k, v) in values_from(&r.body) {
            fresh.insert((i, k), v);
        }
        if i == last {
            first_status = r.status;
            // Same session, same body, immediately again.
            let again = probe::send_with(&client, &s.method, &url, body_arg, &headers).await?;
            second_status = again.status;
        }
    }
    Some((first_status, second_status))
}
