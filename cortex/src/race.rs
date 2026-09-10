//! Race conditions: a limit that holds one request at a time and not eight.
//!
//! Most application limits are written as read-then-write. Check the coupon has
//! not been redeemed, redeem it. Check the balance covers the withdrawal,
//! withdraw. Check this user has not already voted, record the vote. Between the
//! check and the write there is a window, and if two requests are inside it at
//! once, both read the same "not yet" and both write. The limit was never
//! enforced; it was merely usually observed.
//!
//! # Why this is opt-in, and stays opt-in
//!
//! The same rule as `smuggle` and prototype pollution, for the same reason: this
//! probe cannot leave the target as it found it. Proving a coupon can be
//! redeemed twice means redeeming it twice. So it runs only when the caller
//! names the class, it runs on a small number of endpoints per scan, and the
//! finding says plainly what was spent to produce it.
//!
//! # The oracle
//!
//! The ordering matters more than anything else here, and it is the opposite of
//! what seems natural. The obvious design - establish the limit exists, then try
//! to race it - destroys itself: establishing the limit consumes it, and there
//! is nothing left to race.
//!
//! So the burst goes first, into an unexhausted constraint, and the control
//! comes after:
//!
//!   1. Open [`BURST`] connections and warm them, so the burst is not really a
//!      race between TLS handshakes.
//!   2. Release all of them at a barrier with the SAME request: same identity,
//!      same body, no payload of any kind. Nothing here is an injection; the
//!      request is the one the application already expects.
//!   3. Once everything has settled, send the same request once more, alone,
//!      and again after that.
//!
//! Read the answers together:
//!
//! - The late requests are accepted too. Then this endpoint has no single-use
//!   constraint at all - it is simply repeatable - and there was never anything
//!   to race. Silent.
//! - The late requests are refused, and exactly one of the burst was accepted.
//!   The constraint exists and it held under concurrency. That is the negative
//!   case this oracle is built to be able to produce, and it is silent too.
//!   Without it the check would be a "does this endpoint change state" detector
//!   wearing a scarier name.
//! - The late requests are refused, and two or more of the burst were accepted.
//!   The constraint exists, and concurrent requests walked past it. That is the
//!   finding.
//!
//! # What it refuses to conclude from
//!
//! The whole risk in this check is mistaking some OTHER reason the late request
//! failed for a business limit, so the refusals that are not evidence are named
//! and dropped rather than counted:
//!
//! - `429` and anything carrying `Retry-After`: a rate limiter. A rate limiter
//!   that lets a burst through may well be worth reporting, but not as this.
//! - `401` / `403`: the burst may have invalidated the session or spent a
//!   one-time token, and then the refusal is about us, not about a limit.
//! - `5xx`: we may simply have broken the endpoint, and a scanner that reads its
//!   own damage as a finding is the failure mode this codebase keeps a list of.
//!
//! # The one discipline it cannot keep
//!
//! Every other oracle in cortex reproduces before it reports. This one cannot,
//! by construction: the state it needed is spent, and a second burst races an
//! already-exhausted limit and proves nothing. What replaces reproduction is the
//! margin (two or more accepted, not one), the stability check on the refusal
//! (asked twice, refused twice), and the exclusion list above. The description
//! says so, because a reader deciding how much to trust this should be told
//! which guarantee is missing.

use crate::inject::InjEndpoint;
use cfx_finding::Finding;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use transport::{AuthSpec, Client};

/// How many requests go into the window at once.
pub const BURST: usize = 8;
/// How many of the burst must actually answer before the result means anything.
const MIN_ANSWERS: usize = 6;
/// How many accepted answers make it a race rather than a working limit.
const MIN_ACCEPTED: usize = 2;
/// Let the burst finish landing before asking the control question.
const SETTLE: Duration = Duration::from_millis(750);

/// What a race probe needs to build its own connections.
///
/// The burst deliberately does not reuse the injection client. That client is
/// shared, pooled, and paced against the host - all three correct for a scan and
/// all three fatal here, since the pacer's job is to stop exactly the overlap
/// this check is trying to create.
#[derive(Clone)]
pub struct Recipe {
    pub evasive: bool,
    pub identify: Option<String>,
    /// One identity for the whole burst. A race is against one user's limit, so
    /// eight sessions would be eight users doing one thing each, which is not
    /// the question.
    pub auth: Option<AuthSpec>,
    pub target: String,
    pub timeout_ms: u64,
}

/// A finding, or an explanation of why there is not one.
pub struct Outcome {
    pub finding: Option<Value>,
    /// Operator-facing, for the cases where silence would be a lie. A class that
    /// quietly stops testing produces a report indistinguishable from a clean
    /// one.
    pub note: Option<String>,
}

impl Outcome {
    fn quiet() -> Self {
        Outcome {
            finding: None,
            note: None,
        }
    }
    fn note(msg: impl Into<String>) -> Self {
        Outcome {
            finding: None,
            note: Some(msg.into()),
        }
    }
}

/// One answer, reduced to what the comparison needs.
struct Answer {
    status: u16,
    /// The body with anything that legitimately varies between two identical
    /// requests taken out, so "different response" means different response and
    /// not a different timestamp or row id.
    shape: String,
    retry_after: bool,
}

impl Answer {
    fn same_as(&self, other: &Answer) -> bool {
        self.status == other.status && self.shape == other.shape
    }
}

/// Collapse digit runs and long hex runs, which is what ids, timestamps, CSRF
/// tokens and durations look like. Two renderings of "your order was placed"
/// then compare equal even though the order number differs.
fn shape_of(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut run: Option<char> = None;
    for c in body.chars() {
        let kind = if c.is_ascii_digit() {
            Some('#')
        } else if c.is_ascii_hexdigit() {
            Some('x')
        } else {
            None
        };
        match kind {
            Some(k) => {
                if run != Some(k) {
                    out.push(k);
                    run = Some(k);
                }
            }
            None => {
                run = None;
                out.push(c);
            }
        }
    }
    // Long bodies compare on a prefix: the tail of a page is chrome, and the
    // whole point is to compare the part that answers the request.
    out.chars().take(4000).collect()
}

/// Only methods that are expected to change something, and that a caller would
/// not be shocked to see repeated.
///
/// `DELETE` is left out on purpose. Racing a delete is a real class, but eight
/// concurrent deletes against a live application is a bigger thing to do to
/// somebody's data than this check is worth, and the same bug usually shows on a
/// POST somewhere in the same app.
pub fn eligible(ep: &InjEndpoint) -> bool {
    matches!(ep.method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH")
}

/// Render the endpoint's own baseline body: every field at the value discovery
/// captured. No payload, no marker, nothing the application did not already
/// expect - the request under test is the ordinary one.
fn baseline_body(ep: &InjEndpoint) -> Option<(String, &'static str)> {
    if ep.body.is_empty() {
        return None;
    }
    if ep.body_type.eq_ignore_ascii_case("json") {
        let mut obj = serde_json::Map::new();
        for f in &ep.body {
            obj.insert(
                f.name.clone(),
                crate::probe::json_typed(&f.value, f.ty.as_deref()),
            );
        }
        Some((Value::Object(obj).to_string(), "application/json"))
    } else {
        let form = ep
            .body
            .iter()
            .map(|f| {
                format!(
                    "{}={}",
                    crate::probe::pct_encode(&f.name),
                    crate::probe::pct_encode(&f.value)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        Some((form, "application/x-www-form-urlencoded"))
    }
}

/// Send one request outside the pacer, and read it into an [`Answer`].
async fn send_raw(
    client: &Client,
    method: &str,
    url: &str,
    body: Option<&(String, &'static str)>,
) -> Option<Answer> {
    let mut rb = match method {
        "PUT" => client.put(url),
        "PATCH" => client.patch(url),
        _ => client.post(url),
    };
    if let Some((b, ctype)) = body {
        rb = rb.header("content-type", *ctype).body(b.clone());
    }
    let r = rb.send().await.ok()?;
    crate::probe::meter::REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let status = r.status().as_u16();
    let retry_after = r.headers().get("retry-after").is_some();
    let body = crate::engine::read_body_capped(r).await;
    Some(Answer {
        status,
        shape: shape_of(&body),
        retry_after,
    })
}

/// A refusal we are willing to read as "the application enforced a limit".
///
/// Everything excluded here is excluded because it has a likelier explanation
/// than the one we would be reporting.
fn is_business_refusal(control: &Answer, accepted_shape: &Answer) -> Result<(), &'static str> {
    if control.same_as(accepted_shape) {
        return Err(
            "the endpoint answered the late requests exactly as it answered the burst, so \
                    it enforces no single-use limit here and there is nothing to race",
        );
    }
    if control.status == 429 || control.retry_after {
        return Err(
            "the endpoint refused the late requests with rate limiting (429/Retry-After), \
                    which is not the same as a business limit and is not reported as a race",
        );
    }
    if control.status == 401 || control.status == 403 {
        return Err(
            "the endpoint refused the late requests with 401/403, which is more likely the \
                    burst having spent a session or a one-time token than a limit holding",
        );
    }
    if control.status >= 500 {
        return Err(
            "the endpoint answered the late requests with a server error, so the refusal \
                    may be damage this probe caused rather than a limit it hit",
        );
    }
    Ok(())
}

/// Probe one endpoint for a limit that concurrency walks past.
pub async fn probe(recipe: &Recipe, ep: &InjEndpoint) -> Outcome {
    let method = ep.method.to_uppercase();
    if !eligible(ep) {
        return Outcome::quiet();
    }
    let body = baseline_body(ep);

    // One client per connection. Cloning a client shares its pool, so eight
    // clones would be eight requests queueing for one socket's worth of
    // scheduling luck; separate clients are separate connections.
    let clients: Vec<Client> = (0..BURST)
        .filter_map(|_| {
            crate::probe::build_client(
                recipe.evasive,
                recipe.identify.clone(),
                recipe.auth.as_ref(),
                &recipe.target,
                recipe.timeout_ms,
                0,
            )
        })
        .collect();
    if clients.len() < MIN_ANSWERS {
        return Outcome::note(format!(
            "race check on {}: could not build enough independent connections, so the concurrency \
             question was never asked",
            ep.url
        ));
    }

    // Warm every connection before the barrier. Without this the burst measures
    // how fast eight TCP+TLS handshakes complete, which is not a property of the
    // application, and on a remote target the spread is far wider than the
    // window being probed.
    let mut warm = tokio::task::JoinSet::new();
    for c in &clients {
        let c = c.clone();
        let u = ep.url.clone();
        warm.spawn(async move {
            let ok = c.get(&u).send().await.is_ok();
            // Metered like everything else. A check whose cost is invisible is
            // how a scan quietly grows an hour longer.
            crate::probe::meter::REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ok
        });
    }
    let mut warmed = 0usize;
    while let Some(r) = warm.join_next().await {
        if matches!(r, Ok(true)) {
            warmed += 1;
        }
    }
    if warmed < MIN_ANSWERS {
        return Outcome::note(format!(
            "race check on {}: only {warmed} of {BURST} connections came up, so the burst would \
             not have been concurrent and no conclusion was drawn",
            ep.url
        ));
    }

    let barrier = Arc::new(tokio::sync::Barrier::new(clients.len()));
    let url = Arc::new(ep.url.clone());
    let method = Arc::new(method);
    let body = Arc::new(body);
    let mut set = tokio::task::JoinSet::new();
    for c in &clients {
        let c = c.clone();
        let barrier = Arc::clone(&barrier);
        let url = Arc::clone(&url);
        let method = Arc::clone(&method);
        let body = Arc::clone(&body);
        set.spawn(async move {
            barrier.wait().await;
            send_raw(&c, &method, &url, body.as_ref().as_ref()).await
        });
    }
    let mut answers: Vec<Answer> = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(a)) = r {
            answers.push(a);
        }
    }
    if answers.len() < MIN_ANSWERS {
        return Outcome::note(format!(
            "race check on {}: only {} of {BURST} concurrent requests were answered, which is too \
             few to tell a race from a target that was busy",
            ep.url,
            answers.len()
        ));
    }

    tokio::time::sleep(SETTLE).await;

    // The control, alone, twice. Twice because a single refusal could be a blip,
    // and the entire finding rests on this refusal meaning "the limit is real".
    let Some(control) = send_raw(&clients[0], &method, &url, body.as_ref().as_ref()).await else {
        return Outcome::note(format!(
            "race check on {}: the endpoint stopped answering after the burst, so whether it \
             enforces a limit is unknown",
            ep.url
        ));
    };
    let Some(control2) = send_raw(&clients[0], &method, &url, body.as_ref().as_ref()).await else {
        return Outcome::note(format!(
            "race check on {}: the endpoint stopped answering after the burst, so whether it \
             enforces a limit is unknown",
            ep.url
        ));
    };
    if !control.same_as(&control2) {
        return Outcome::note(format!(
            "race check on {}: two identical late requests were answered two different ways \
             ({} then {}), so this endpoint's answer does not carry a stable meaning and no \
             conclusion was drawn",
            ep.url, control.status, control2.status
        ));
    }

    // Accepted: succeeded, and said something other than what the exhausted
    // endpoint says.
    let accepted: Vec<&Answer> = answers
        .iter()
        .filter(|a| a.status < 400 && !a.same_as(&control))
        .collect();
    let Some(sample) = accepted.first() else {
        // Every answer, concurrent and late alike, said the same thing. The
        // endpoint is simply repeatable, and saying so is worth a line: "no
        // race here" and "nothing here could race" are different results, and
        // an empty pass communicates neither.
        return Outcome::note(format!(
            "race check on {}: every request, concurrent and late, was answered the same way, so \
             this endpoint enforces no single-use limit and there is nothing to race",
            ep.url
        ));
    };
    if let Err(why) = is_business_refusal(&control, sample) {
        // Not silence: "no race here" and "this endpoint has no limit to race"
        // are different statements, and only one of them is about the target.
        return Outcome::note(format!("race check on {}: {why}", ep.url));
    }
    if accepted.len() < MIN_ACCEPTED {
        // The good negative. One accepted out of eight is a limit doing its job,
        // and it is worth saying so - it is evidence the check ran and found the
        // endpoint sound, which is not what an empty result communicates.
        return Outcome::note(format!(
            "race check on {}: {} concurrent requests, exactly one accepted, later ones refused. \
             The limit held under concurrency.",
            ep.url,
            answers.len()
        ));
    }

    let finding = Finding::new(
        "cortex-race",
        "race",
        "Race condition: a single-use limit that concurrency walks past",
        "high",
        &ep.url,
    )
    .method(method.as_str())
    .location("body")
    .describe(format!(
        "{} identical requests sent at once were accepted {} times; the same request sent \
         afterwards, twice, was refused ({}). So this endpoint does enforce a limit - it refuses \
         the repeat - but it checks and then writes without holding anything in between, and two \
         requests inside that window both read the state before either wrote it. Whatever the \
         limit protects (a redemption, a balance, a quota, a one-per-user record) can be exceeded \
         by exactly as much as an attacker can widen that window. Fix it where the state lives, \
         not in the handler: a conditional update, a unique constraint, or a row lock held across \
         the check and the write. Rate limiting does not fix this, because the requests are \
         concurrent rather than frequent. NOTE: unlike every other check here, this one cannot \
         re-run to confirm - the state it needed is spent - so it is reported on the margin \
         between {} accepted and one, and on the refusal being stable across two later requests.",
        answers.len(),
        accepted.len(),
        control.status,
        accepted.len(),
    ))
    .with("concurrent_requests", json!(answers.len()))
    .with("accepted", json!(accepted.len()))
    .with("late_request_status", json!(control.status))
    .build();

    Outcome {
        finding: Some(finding),
        note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole negative case for a "successful" endpoint rests on this: two
    /// answers to the same request differ only where ids, timestamps and tokens
    /// live, and the oracle must read that as the same answer. Get this wrong
    /// and every endpoint returning a row id looks like eight accepted requests.
    #[test]
    fn ids_and_timestamps_do_not_make_two_answers_different() {
        let a = shape_of(r#"{"ok":true,"id":1,"at":1757563201.482}"#);
        let b = shape_of(r#"{"ok":true,"id":9481,"at":1757563233.907}"#);
        assert_eq!(a, b);
    }

    /// ...and it must not go so far that a refusal reads like a success.
    #[test]
    fn a_different_answer_still_reads_as_different() {
        let ok = shape_of(r#"{"ok":true,"credit":50}"#);
        let no = shape_of(r#"{"error":"already redeemed"}"#);
        assert_ne!(ok, no);
    }

    #[test]
    fn only_state_changing_methods_are_raced() {
        let ep = |m: &str| InjEndpoint {
            method: m.to_string(),
            url: "http://x/y".into(),
            params: vec![],
            body: vec![],
            body_type: "form".into(),
            path_params: vec![],
        };
        assert!(eligible(&ep("POST")));
        assert!(eligible(&ep("patch")));
        assert!(!eligible(&ep("GET")));
        // Deliberate: see `eligible`.
        assert!(!eligible(&ep("DELETE")));
    }

    /// The exclusions are the safety of this check, so they are pinned.
    #[test]
    fn refusals_with_a_likelier_explanation_are_not_races() {
        let shape = |status, body: &str, retry_after| Answer {
            status,
            shape: shape_of(body),
            retry_after,
        };
        let accepted = shape(200, r#"{"ok":true}"#, false);
        assert!(is_business_refusal(&shape(409, "nope", false), &accepted).is_ok());
        assert!(is_business_refusal(&shape(429, "slow down", false), &accepted).is_err());
        assert!(is_business_refusal(&shape(200, "slow down", true), &accepted).is_err());
        assert!(is_business_refusal(&shape(403, "denied", false), &accepted).is_err());
        assert!(is_business_refusal(&shape(500, "boom", false), &accepted).is_err());
        // The same answer as the burst is not a refusal at all.
        assert!(is_business_refusal(&shape(200, r#"{"ok":true}"#, false), &accepted).is_err());
    }
}
