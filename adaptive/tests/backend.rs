//! A module installed in place of the baseline: its answer is used, held to the bounds
//! the caller gave, and one that does not read leaves the baseline answering. Its own
//! process, as a module installed is installed for the rest of one.

use adaptive::backend::{self, Backend, Pacing};
use adaptive::congestion::{Estimator, Limits, Window, decide};
use std::sync::Mutex;

/// Answers every call with what the test last set, and records what it was asked.
struct Scripted;

static ANSWER: Mutex<Option<String>> = Mutex::new(None);
static ASKED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

impl Backend for Scripted {
    fn version(&self) -> &str {
        "test 1"
    }
    fn call(&self, op: &str, input: &[u8]) -> Option<Vec<u8>> {
        ASKED
            .lock()
            .unwrap()
            .push((op.to_string(), String::from_utf8_lossy(input).into_owned()));
        ANSWER.lock().unwrap().clone().map(String::into_bytes)
    }
}

fn window() -> Window {
    Window {
        sent: 100,
        lost: 0,
        delivered: 100,
        retried: 0,
        recovered: 0,
        rtt_sum_us: 2_000_000,
    }
}

#[test]
fn a_module_answers_within_the_bounds_and_a_bad_answer_leaves_the_baseline() {
    let limits = Limits::default();
    let baseline = decide(&mut Estimator::warmup(1000), 16, &window(), None, &limits);
    assert_eq!(backend::pacing(), Pacing::Baseline);
    assert!(backend::install(Box::new(Scripted)));
    assert!(!backend::install(Box::new(Scripted)), "installed twice");
    assert_eq!(backend::pacing(), Pacing::Module("test 1".into()));
    assert_eq!(backend::pacing().label(), "module test 1");

    // Past every bound the caller gave: held to them.
    *ANSWER.lock().unwrap() = Some(
        r#"{"srtt_us": 1500.0, "rttvar_us": 300.0, "warmup": false,
            "concurrency": 1000000, "timeout_ms": 0, "retries": 99}"#
            .into(),
    );
    let mut est = Estimator::warmup(1000);
    let d = decide(&mut est, 16, &window(), Some(900.0), &limits);
    assert_eq!(d.concurrency, limits.conc_ceil);
    assert_eq!(d.timeout_ms, limits.timeout_floor_ms);
    assert_eq!(d.retries, limits.retry_ceil);
    assert_eq!(
        (est.srtt_us, est.rttvar_us, est.warmup),
        (1500.0, 300.0, false)
    );
    let (op, asked) = ASKED.lock().unwrap().last().cloned().unwrap();
    assert_eq!(op, "congestion.decide");
    let asked: serde_json::Value = serde_json::from_str(&asked).unwrap();
    assert_eq!(asked["concurrency"], 16);
    assert_eq!(asked["min_rtt_us"], 900.0);

    // No answer, one that does not read, and one whose estimator is no time: the
    // baseline's decision, and the estimator as the baseline leaves it.
    for answer in [
        None,
        Some("not json".to_string()),
        Some(
            r#"{"srtt_us": -1.0, "rttvar_us": 300.0, "warmup": false,
                "concurrency": 8, "timeout_ms": 500, "retries": 1}"#
                .to_string(),
        ),
    ] {
        *ANSWER.lock().unwrap() = answer;
        let d = decide(&mut Estimator::warmup(1000), 16, &window(), None, &limits);
        assert_eq!(
            (d.concurrency, d.timeout_ms, d.retries),
            (baseline.concurrency, baseline.timeout_ms, baseline.retries)
        );
    }
}
