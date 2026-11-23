//! Every call a module answers, answered past its bounds: what the engines get is held
//! to them, an answer that is not clean leaves the baseline's, and the calls whose
//! answers cannot change are asked once. One module per process, so it answers by
//! what it is asked.

use adaptive::backend::{self, Backend};
use adaptive::challenge::{self, Challenge, Reaction};
use adaptive::identity::{self, Mode};
use adaptive::{Caps, HealthStats, HealthWindow, Posture, ProbeClass, ResilienceController};
use serde_json::{Value, json};
use std::sync::{Mutex, Once};

static ASKED: Mutex<Vec<(String, Value)>> = Mutex::new(Vec::new());

struct Scripted;

impl Backend for Scripted {
    fn version(&self) -> &str {
        "routing 1"
    }
    fn call(&self, op: &str, input: &[u8]) -> Option<Vec<u8>> {
        let asked: Value = serde_json::from_slice(input).unwrap();
        ASKED.lock().unwrap().push((op.to_string(), asked.clone()));
        let answer = match op {
            "coord.params" => {
                json!({"tick_every": 0, "window_cap": 1_000_000, "window_warmup": 1_000_000})
            }
            "congestion.params" => json!({"window_ms": 1}),
            "rate.params" => match asked["posture"].as_str().unwrap() {
                "stealth" => params(0.9, 0.95, 0.5, 0.5, 150, 4),
                "balanced" => params(2.0, 5.0, 1000.0, 1.0, 0, 99),
                _ => return Some(b"{\"healthy_wm\": 1e999}".to_vec()),
            },
            "resilience.decide" => match asked["attempt"].as_u64().unwrap() {
                0 => json!({"retry": true, "backoff_ms": 0}),
                1 => json!({"retry": true, "backoff_ms": 10_000_000}),
                2 => json!({"retry": false, "backoff_ms": 0}),
                _ => json!({"retry": true, "backoff_ms": 700}),
            },
            "coord.caps" => {
                json!({"min_concurrency": 0, "max_concurrency": 1000, "max_delay_ms": 0, "max_retries": 99})
            }
            "coord.posture_cap" => match asked["posture"].as_str().unwrap() {
                "throughput" => json!(100),
                _ => json!(0),
            },
            "identity.resolve" => identity_for(&asked),
            "challenge.markers" => {
                json!({"headers": ["Server", "X-Test"], "markers": ["Marker-One", "two"]})
            }
            "challenge.detect" => {
                let edge = asked["headers"]["server"] == "edge";
                let found = asked["found"].as_array().unwrap();
                match (edge, found.first().and_then(Value::as_u64)) {
                    (true, Some(0)) => json!({"challenge": "blocked"}),
                    (true, _) => json!({"challenge": "no such thing"}),
                    _ => json!({"challenge": "none"}),
                }
            }
            "challenge.react" => match asked["attempt"].as_u64().unwrap() {
                0 => {
                    json!({"reaction": "backoff", "delay_ms": 1_000_000_000u64, "rotate_identity": true})
                }
                1 => json!({"reaction": "broker"}),
                _ => json!({"reaction": "dance"}),
            },
            "evasion.variants" => json!([
                ["https://h.example/a?x=%3Cs%3E", null],
                ["https://evil.example/a", null],
                ["https://h.example.evil.example/a", null],
                ["https://h.example@evil.example/a", null],
                ["https://h.example/a?x=<s>", null],
                ["https://h.example/a\r\nHost: evil", null],
                ["https://h.example/a?x=%3Cs%3E", null],
                [format!("https://h.example/{}", "a".repeat(500)), null],
                ["https://h.example/a?x=%3Cs%3E", "b=1"],
                ["https://h.example/b", null],
            ]),
            _ => return None,
        };
        Some(answer.to_string().into_bytes())
    }
}

fn params(healthy: f64, stressed: f64, inc: f64, dec: f64, step: u64, retries: u32) -> Value {
    json!({
        "healthy_wm": healthy, "stressed_wm": stressed, "inc": inc, "dec": dec,
        "ss_growth": 1.3, "ss_exit_frac": 0.35, "delay_step_ms": step, "delay_relief_ms": 30,
        "w_rl": 0.4, "w_se": 0.25, "w_to": 0.2, "w_lat": 0.15,
        "rl_ref": 0.05, "se_ref": 0.1, "to_ref": 0.1, "lat_ref": 1.5, "max_retries": retries,
    })
}

fn identity_for(asked: &Value) -> Value {
    let headers = |extra: &[(&str, &str)]| {
        let mut h = vec![json!(["Accept", "*/*"])];
        h.extend(extra.iter().map(|(k, v)| json!([k, v])));
        h
    };
    let (ua, headers) = match asked["seed"].as_str() {
        Some("clean") => ("Browser/1", headers(&[("Accept-Language", "en")])),
        Some("crlf") => ("Browser/1", headers(&[("X-A", "a\r\nHost: evil")])),
        Some("host") => ("Browser/1", headers(&[("Host", "evil.example")])),
        Some("cookie") => ("Browser/1", headers(&[("cookie", "a=b")])),
        Some("name") => ("Browser/1", headers(&[("Bad Name", "v")])),
        Some("agent") => ("Browser/1", headers(&[("User-Agent", "Other/2")])),
        Some("many") => ("Browser/1", vec![json!(["X-A", "v"]); 33]),
        Some("empty") => ("", headers(&[])),
        Some("signed") => ("Browser/1", headers(&[("X-Bug-Bounty", "h1-handle")])),
        Some("unsigned") => ("Browser/1", headers(&[])),
        _ => ("Browser/1", headers(&[])),
    };
    json!({"user_agent": ua, "headers": headers})
}

fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| assert!(backend::install(Box::new(Scripted))));
}

fn asked(op: &str) -> Vec<Value> {
    ASKED
        .lock()
        .unwrap()
        .iter()
        .filter(|(o, _)| o == op)
        .map(|(_, v)| v.clone())
        .collect()
}

#[test]
fn cadence_and_window_are_held_and_asked_once() {
    install();
    assert_eq!(adaptive::coord::tick_every(), 1);
    assert_eq!(adaptive::coord::tick_every(), 1);
    assert_eq!(adaptive::congestion::window_ms(), 100);
    assert_eq!(adaptive::congestion::window_ms(), 100);
    let mut w = HealthWindow::for_target();
    for _ in 0..5000 {
        w.record(ProbeClass::Success, 10);
    }
    assert_eq!(w.len(), 4096);
    assert_eq!(asked("coord.params").len(), 1);
    assert_eq!(asked("congestion.params").len(), 1);
}

#[test]
fn posture_constants_are_held_and_an_unreadable_set_leaves_the_baseline() {
    install();
    let stealth = Posture::Stealth.params();
    assert_eq!(
        (
            stealth.healthy_wm,
            stealth.stressed_wm,
            stealth.dec,
            stealth.delay_step_ms
        ),
        (0.9, 0.9, 0.5, 150),
        "kept, but stressed held under healthy"
    );
    let balanced = Posture::Balanced.params();
    assert_eq!(balanced.healthy_wm, 1.0);
    assert_eq!(balanced.stressed_wm, 1.0);
    assert_eq!(balanced.inc, 16.0);
    assert_eq!(balanced.dec, 0.9);
    assert_eq!(balanced.delay_step_ms, 1);
    assert_eq!(balanced.max_retries, 10);
    let throughput = Posture::Throughput.params();
    assert_eq!(
        (
            throughput.healthy_wm,
            throughput.dec,
            throughput.max_retries
        ),
        (0.75, 0.5, 3)
    );
    let _ = Posture::Stealth.params();
    let _ = Posture::Throughput.params();
    assert_eq!(asked("rate.params").len(), 3);
}

#[test]
fn a_retry_is_held_to_the_ceiling_and_the_backoff_bounds() {
    install();
    let stats = HealthStats::empty();
    let rc = ResilienceController::new(Posture::Balanced, 3).with_backoff(200, 30_000);
    let d = rc.decide(ProbeClass::Timeout, 0, &stats, 1.0, None);
    assert!(d.retry);
    assert_eq!(d.backoff_ms, 200, "sooner than the base backoff");
    let d = rc.decide(ProbeClass::Timeout, 0, &stats, 1.0, Some(5_000));
    assert_eq!(d.backoff_ms, 5_000, "sooner than Retry-After");
    let d = rc.decide(ProbeClass::Timeout, 1, &stats, 1.0, None);
    assert_eq!(d.backoff_ms, 30_000, "later than the maximum");
    assert!(!rc.decide(ProbeClass::Timeout, 2, &stats, 1.0, None).retry);
    assert!(
        !rc.decide(ProbeClass::Timeout, 3, &stats, 1.0, None).retry,
        "past the ceiling"
    );
    let before = asked("resilience.decide").len();
    assert!(!rc.decide(ProbeClass::NotFound, 0, &stats, 1.0, None).retry);
    assert_eq!(
        asked("resilience.decide").len(),
        before,
        "a definite answer is not asked about"
    );
    let last = asked("resilience.decide").pop().unwrap();
    assert_eq!(last["class"], "timeout");
    assert_eq!(last["ceiling"], 3);
}

#[test]
fn an_envelope_never_allows_more_than_the_callers_maximum() {
    install();
    let caps = Caps::for_target(10);
    assert_eq!(
        (
            caps.min_concurrency,
            caps.max_concurrency,
            caps.max_delay_ms,
            caps.max_retries
        ),
        (1, 10, 1_000, 10)
    );
    assert_eq!(adaptive::coord::posture_cap("throughput"), 8);
    assert_eq!(adaptive::coord::posture_cap("balanced"), 1);
}

#[test]
fn an_identity_is_used_only_when_it_is_clean() {
    install();
    let baseline_ua = "Mozilla/5.0";
    let ua = |seed: &str| identity::resolve(&Mode::Evasive, Some(seed)).user_agent;
    let clean = identity::resolve(&Mode::Evasive, Some("clean"));
    assert_eq!(clean.user_agent, "Browser/1");
    assert!(
        clean
            .headers
            .contains(&("Accept-Language", "en".to_string()))
    );
    for dirty in ["crlf", "host", "cookie", "name", "agent", "many", "empty"] {
        assert!(ua(dirty).starts_with(baseline_ua), "{dirty} was used");
    }
    let signed = identity::resolve(&Mode::Identify("h1-handle".into()), Some("signed"));
    assert_eq!(signed.user_agent, "Browser/1");
    let unsigned = identity::resolve(&Mode::Identify("h1-handle".into()), Some("unsigned"));
    assert!(unsigned.user_agent.starts_with(baseline_ua));
    assert!(
        unsigned
            .headers
            .iter()
            .any(|(k, v)| *k == "X-Bug-Bounty" && v == "h1-handle")
    );
    let _ = identity::resolve(&Mode::Evasive, Some("clean"));
    let _ = identity::resolve(&Mode::Evasive, Some("crlf"));
    let cleans = asked("identity.resolve")
        .into_iter()
        .filter(|a| a["seed"] == "clean" && a["mode"] == "evasive")
        .count();
    assert_eq!(cleans, 1, "an identity is asked once per mode and seed");
}

#[test]
fn a_challenge_is_judged_from_what_the_module_reads() {
    install();
    let header = |n: &str| (n == "server").then(|| "edge".to_string());
    let blocked = challenge::detect(403, header, "  <p>MARKER-one and TWO</p>  ");
    assert_eq!(blocked, Challenge::Blocked);
    let last = asked("challenge.detect").pop().unwrap();
    assert_eq!(last["found"], json!([0, 1]));
    assert_eq!(last["headers"], json!({"server": "edge"}));
    assert_eq!(last["body_len"], 25);
    assert_eq!(last["status"], 403);
    // An answer that names no challenge leaves the baseline's.
    assert_eq!(
        challenge::detect(403, header, "only two, and access denied"),
        Challenge::Blocked
    );
    assert_eq!(challenge::detect(403, header, "only two"), Challenge::None);
    // A 429 is rate limiting whatever answers, and is not asked about.
    let before = asked("challenge.detect").len();
    assert_eq!(challenge::detect(429, header, ""), Challenge::RateLimited);
    assert_eq!(asked("challenge.detect").len(), before);
    assert_eq!(asked("challenge.markers").len(), 1);
}

#[test]
fn a_reaction_is_held_and_ends_in_an_abort() {
    install();
    assert_eq!(
        challenge::react(Challenge::Blocked, 0),
        Reaction::Backoff {
            delay_ms: 300_000,
            rotate_identity: true
        }
    );
    assert_eq!(
        challenge::react(Challenge::Interactive, 1),
        Reaction::Broker
    );
    // An answer that is no reaction leaves the baseline's.
    assert_eq!(challenge::react(Challenge::Blocked, 2), Reaction::Abort);
    assert_eq!(challenge::react(Challenge::None, 0), Reaction::Proceed);
    let before = asked("challenge.react").len();
    assert_eq!(challenge::react(Challenge::RateLimited, 8), Reaction::Abort);
    assert_eq!(
        asked("challenge.react").len(),
        before,
        "past the last attempt, no asking"
    );
}

#[test]
fn variants_keep_the_target_and_the_count() {
    install();
    let v = adaptive::evasion::variants("https://h.example/a?x=<s>", None, 3);
    assert_eq!(
        v,
        vec![
            ("https://h.example/a?x=%3Cs%3E".to_string(), None),
            (
                "https://h.example/a?x=%3Cs%3E".to_string(),
                Some("b=1".to_string())
            ),
            ("https://h.example/b".to_string(), None),
        ]
    );
    assert_eq!(
        adaptive::evasion::variants("https://h.example/a?x=<s>", None, 1).len(),
        1
    );
}
