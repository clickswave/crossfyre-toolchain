//! A module whose every answer is unreadable leaves the baseline answering every call,
//! the ones asked once included. Its own process, as a module installed is installed
//! for the rest of one.

use adaptive::backend::{self, Backend};
use adaptive::challenge::{self, Challenge};
use adaptive::identity::{self, Mode};
use adaptive::{Caps, HealthStats, HealthWindow, Posture, ProbeClass, ResilienceController};

struct Unreadable;

impl Backend for Unreadable {
    fn version(&self) -> &str {
        "unreadable 1"
    }
    fn call(&self, _op: &str, _input: &[u8]) -> Option<Vec<u8>> {
        Some(b"{\"not\": \"an answer\"".to_vec())
    }
}

/// Everything the routed calls answer, as one comparable text.
fn answers() -> String {
    let stats = HealthStats::empty();
    let rc = ResilienceController::new(Posture::Balanced, 3);
    let mut w = HealthWindow::for_target();
    for _ in 0..5000 {
        w.record(ProbeClass::Success, 10);
    }
    let header = |n: &str| (n == "cf-mitigated").then(|| "challenge".to_string());
    let id = identity::resolve(&Mode::Identify("h1".into()), Some("example.com"));
    format!(
        "{} {} {} {:?} {:?} {:?} {} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        adaptive::coord::tick_every(),
        adaptive::congestion::window_ms(),
        w.len(),
        Posture::Stealth.params(),
        Posture::Throughput.params(),
        rc.decide(ProbeClass::Timeout, 1, &stats, 0.2, None),
        adaptive::coord::posture_cap("throughput"),
        Caps::for_target(10),
        (id.user_agent, id.headers),
        challenge::detect(403, header, "<title>Just a moment...</title>"),
        challenge::detect(200, header, "hello"),
        challenge::react(Challenge::Blocked, 1),
        challenge::react(Challenge::RateLimited, 9),
        adaptive::evasion::variants("https://h.example/../a?x=<s>", Some("q=<s>"), 8),
    )
}

#[test]
fn an_unreadable_module_leaves_the_baseline_everywhere() {
    let baseline = answers();
    assert!(backend::install(Box::new(Unreadable)));
    assert_eq!(answers(), baseline);
    // Asked again, the calls asked once still give the baseline's.
    assert_eq!(answers(), baseline);
}
