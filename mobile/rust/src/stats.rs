//! Live capture counters, surfaced to the UI so a user can SEE what the tracer is doing (and, crucially,
//! why nothing is showing up). The single most useful signal is `ca_rejected`: when an app refuses our
//! MITM leaf (it does not trust the user-installed CA, e.g. Chrome on an unrooted phone), the client
//! aborts the TLS handshake with a certificate alert. A high `ca_rejected` with zero `events` means
//! "capture is working, but the app you are using does not trust the CA" - install it in an app that
//! does (Firefox with enterprise roots), rather than a silent empty screen.
//!
//! All counters are process-global atomics, reset at the start of each capture. `snapshot_json` renders
//! them for the JNI `captureStats` call the UI polls.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use cfx_capture::TraceEvent;

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        $( pub static $name: AtomicU64 = AtomicU64::new(0); )*
        fn reset_counters() { $( $name.store(0, Ordering::Relaxed); )* }
    };
}

counters!(
    FLOWS,           // TCP flows captured off the TUN
    TLS_FLOWS,       // of those, TLS (port 443) flows
    CA_REJECTED,     // client aborted TLS: it does not trust our CA (the key diagnostic)
    FLOW_ERRORS,     // other per-flow errors (upstream unreachable, resets, etc.)
    EVENTS,          // privacy-safe request shapes captured
    INGEST_SENT,     // events acknowledged by the server
    INGEST_REJECTED, // server returned a non-2xx (e.g. 401 bad token)
    INGEST_FAILED,   // ingest POST could not be delivered (network/TLS)
    QUIC_DROPPED,    // HTTP/3 flows blackholed to force TCP fallback (invisible traffic)
);

fn last_event() -> &'static Mutex<String> {
    static V: Mutex<String> = Mutex::new(String::new());
    &V
}
fn last_error() -> &'static Mutex<String> {
    static V: Mutex<String> = Mutex::new(String::new());
    &V
}

pub fn reset() {
    reset_counters();
    if let Ok(mut r) = recent().lock() {
        r.clear();
    }
    SEQ.store(0, Ordering::Relaxed);
    SENT_THROUGH.store(0, Ordering::Relaxed);
    if let Ok(mut s) = last_event().lock() {
        s.clear();
    }
    if let Ok(mut s) = last_error().lock() {
        s.clear();
    }
}

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn set_last_event(s: String) {
    if let Ok(mut g) = last_event().lock() {
        *g = s;
    }
}
pub fn set_last_error(s: String) {
    if let Ok(mut g) = last_error().lock() {
        *g = s;
    }
}

/// Classify a per-flow error string: does it mean the client rejected our certificate (does not trust
/// the CA), or is it some other failure? rustls surfaces a client cert alert as an "alert" / "certificate
/// unknown" / "bad certificate" / "unknown ca" error on the accept side.
pub fn record_flow_error(err: &str) {
    let e = err.to_ascii_lowercase();
    let ca_reject = e.contains("certificateunknown")
        || e.contains("certificate_unknown")
        || e.contains("unknown_ca")
        || e.contains("unknownca")
        || e.contains("bad_certificate")
        || e.contains("badcertificate")
        || e.contains("access_denied")
        || (e.contains("alert") && e.contains("cert"))
        || e.contains("certificate required")
        || e.contains("handshakefailure")
        || e.contains("handshake_failure")
        // A client that opens TCP to :443 and dies mid-handshake has, in
        // practice, refused us. Leaving this in the generic bucket is why an app
        // pinning its API showed up as an unexplained "flow error" and the panel
        // had nothing to say about it.
        || e.contains("handshake eof")
        || (e.contains("handshake") && e.contains("eof"));
    if ca_reject {
        inc(&CA_REJECTED);
    } else {
        inc(&FLOW_ERRORS);
    }
    set_last_error(err.chars().take(160).collect());
}

fn g(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

/// Render the counters as a compact JSON object for the UI to parse.
pub fn snapshot_json() -> String {
    let le = last_event().lock().map(|s| s.clone()).unwrap_or_default();
    let lerr = last_error().lock().map(|s| s.clone()).unwrap_or_default();
    serde_json::json!({
        "flows": g(&FLOWS),
        "tls_flows": g(&TLS_FLOWS),
        "ca_rejected": g(&CA_REJECTED),
        "flow_errors": g(&FLOW_ERRORS),
        "events": g(&EVENTS),
        "ingest_sent": g(&INGEST_SENT),
        "ingest_rejected": g(&INGEST_REJECTED),
        "ingest_failed": g(&INGEST_FAILED),
        "quic_dropped": g(&QUIC_DROPPED),
        "last_event": le,
        "last_error": lerr,
    })
    .to_string()
}

/// How many captured requests the phone keeps to show. The Tracer screen lists them so a person can
/// see what was captured and exactly what of it left the phone; the dashboard holds the rest.
const RECENT_MAX: usize = 30;

/// One captured request, as reduced before it is sent: method, redacted URL, status, body field
/// names and whether a credential was present. Never a header value, a query value or a body.
struct Recent {
    seq: u64,
    at_ms: u64,
    method: String,
    url: String,
    status: Option<i64>,
    authed: bool,
    body_params: Vec<String>,
}

fn recent() -> &'static Mutex<VecDeque<Recent>> {
    static R: Mutex<VecDeque<Recent>> = Mutex::new(VecDeque::new());
    &R
}

/// Numbers events in the order they reach the shipper, so a successful flush can say which of the
/// kept requests have been delivered without holding on to the batch.
static SEQ: AtomicU64 = AtomicU64::new(0);
static SENT_THROUGH: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Keep a captured request for the Tracer screen. Returns its sequence number.
pub fn record_event(e: &TraceEvent) -> u64 {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    if let Ok(mut r) = recent().lock() {
        if r.len() >= RECENT_MAX {
            r.pop_front();
        }
        r.push_back(Recent {
            seq,
            at_ms: now_ms(),
            method: e.method.clone(),
            url: e.url.clone(),
            status: e.status,
            authed: e.authed,
            body_params: e.body_params.clone(),
        });
    }
    seq
}

/// Every event up to and including `seq` was accepted by the server.
pub fn mark_sent(seq: u64) {
    SENT_THROUGH.fetch_max(seq, Ordering::Relaxed);
}

/// The kept requests, newest first, as a JSON array for the UI.
pub fn recent_json() -> String {
    let sent = SENT_THROUGH.load(Ordering::Relaxed);
    let list: Vec<serde_json::Value> = recent()
        .lock()
        .map(|r| {
            r.iter()
                .rev()
                .map(|e| {
                    serde_json::json!({
                        "method": e.method,
                        "url": e.url,
                        "status": e.status,
                        "authed": e.authed,
                        "body_params": e.body_params,
                        "at_ms": e.at_ms,
                        "sent": e.seq <= sent,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    serde_json::Value::Array(list).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(path: &str) -> TraceEvent {
        TraceEvent {
            method: "GET".into(),
            url: format!("https://api.example.test{path}"),
            status: Some(200),
            full_url: Some("https://api.example.test/secret?token=abc".into()),
            req_body: Some("password=hunter2".into()),
            ..Default::default()
        }
    }

    // One test, because the ring and its counters are process globals and the
    // test harness runs tests on several threads.
    #[test]
    fn the_ring_keeps_the_newest_shapes_and_knows_what_was_sent() {
        reset();
        let mut last = 0;
        for i in 0..(RECENT_MAX + 5) {
            last = record_event(&event(&format!("/r/{i}")));
        }
        mark_sent(last - 3);
        let list: Vec<serde_json::Value> = serde_json::from_str(&recent_json()).unwrap();
        assert_eq!(list.len(), RECENT_MAX);
        assert_eq!(
            list[0]["url"],
            format!("https://api.example.test/r/{}", RECENT_MAX + 4)
        );
        assert_eq!(list[RECENT_MAX - 1]["url"], "https://api.example.test/r/5");
        // Newest first: the three newest were not in the delivered batch.
        let sent: Vec<bool> = list.iter().map(|e| e["sent"].as_bool().unwrap()).collect();
        assert_eq!(&sent[..4], &[false, false, false, true]);
        // Only the reduced shape is kept: nothing from the full-capture fields.
        let text = recent_json();
        assert!(
            !text.contains("secret") && !text.contains("hunter2"),
            "{text}"
        );

        reset();
        assert_eq!(recent_json(), "[]");
    }
}
