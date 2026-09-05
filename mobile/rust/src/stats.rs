//! Live capture counters, surfaced to the UI so a user can SEE what the tracer is doing (and, crucially,
//! why nothing is showing up). The single most useful signal is `ca_rejected`: when an app refuses our
//! MITM leaf (it does not trust the user-installed CA, e.g. Chrome on an unrooted phone), the client
//! aborts the TLS handshake with a certificate alert. A high `ca_rejected` with zero `events` means
//! "capture is working, but the app you are using does not trust the CA" - install it in an app that
//! does (Firefox with enterprise roots), rather than a silent empty screen.
//!
//! All counters are process-global atomics, reset at the start of each capture. `snapshot_json` renders
//! them for the JNI `captureStats` call the UI polls.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

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
