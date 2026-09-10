//! Shared request/response machinery for cortex's active operations (`inject`, `fuzz`, `discover`).
//!
//! These operations all speak the same language: build an evasion-aware HTTP client, send a request
//! with an optional typed body, read a capped response, and read simple oracles off it (server
//! error, JSON typing). Keeping that in one place is what lets each operation be a thin, focused
//! module instead of re-implementing the transport every time.

use crate::engine::{AuthSpec, read_body_capped};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use transport::Client;

/// Deserialize a `Vec<String>` that tolerates an explicit JSON `null` (treated as empty),
/// not just an absent field. Callers upstream (the node forwarder) pass `"classes": null`
/// when no classes are configured; plain `#[serde(default)]` rejects that with
/// "invalid type: null, expected a sequence". Use with `#[serde(default, deserialize_with = ...)]`.
pub fn de_null_seq<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// A captured response reduced to what the oracles need.
pub struct Resp {
    pub status: u16,
    pub body: String,
    pub elapsed_ms: u128,
    /// The `Location` header value, if any (open-redirect / CRLF oracle).
    pub location: Option<String>,
    /// All response headers (lowercased name, value) - the CORS and CRLF/header-injection oracles read
    /// arbitrary headers off this. Bounded (responses have few headers), so cheap to keep.
    pub headers: Vec<(String, String)>,
}

impl Resp {
    /// First value of a response header, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.as_str())
    }
}

/// Build an evasion-aware scan client. `min_timeout_ms` is the floor the operation needs (e.g. an
/// injection SLEEP probe needs the timeout above the sleep); pass 0 when there is no such floor.
pub fn build_client(
    evasive: bool,
    identify: Option<String>,
    auth: Option<&AuthSpec>,
    target: &str,
    timeout_ms: u64,
    min_timeout_ms: u64,
) -> Option<Client> {
    let mode = adaptive::identity::Mode::from_flags(evasive, identify);
    let seed = (!target.is_empty()).then_some(target);
    let browser = adaptive::identity::resolve(&mode, seed);
    transport::build_scan_client(transport::ScanClient {
        identity_headers: &browser.headers,
        user_agent: &browser.user_agent,
        auth,
        attribution_token: None,
        emulate: !matches!(mode, adaptive::identity::Mode::Fast),
        timeout: Some(Duration::from_millis(
            timeout_ms.clamp(1000, 120_000).max(min_timeout_ms),
        )),
        redirect: transport::Redirect::Limited(3),
        accept_invalid_certs: true,
        cookie_store: true,
        resolve: Vec::new(),
        ..Default::default()
    })
    .ok()
}

/// Same as [`build_client`] but with redirects DISABLED, so the caller sees the raw 3xx + `Location`
/// instead of the followed destination. The open-redirect / header-injection oracles need that.
pub fn build_client_no_redirect(
    evasive: bool,
    identify: Option<String>,
    auth: Option<&AuthSpec>,
    target: &str,
    timeout_ms: u64,
) -> Option<Client> {
    let mode = adaptive::identity::Mode::from_flags(evasive, identify);
    let seed = (!target.is_empty()).then_some(target);
    let browser = adaptive::identity::resolve(&mode, seed);
    transport::build_scan_client(transport::ScanClient {
        identity_headers: &browser.headers,
        user_agent: &browser.user_agent,
        auth,
        attribution_token: None,
        emulate: !matches!(mode, adaptive::identity::Mode::Fast),
        timeout: Some(Duration::from_millis(timeout_ms.clamp(1000, 120_000))),
        redirect: transport::Redirect::None,
        accept_invalid_certs: true,
        cookie_store: true,
        resolve: Vec::new(),
        ..Default::default()
    })
    .ok()
}

/// Send one request with an optional `(body, content-type)` and read the capped response.
/// Per-host pacing, so the scanner does not knock over what it is measuring.
///
/// This exists because of a measured failure, not a theory. Batching the
/// out-of-band callbacks removed the only thing that had been spacing our
/// requests out: the blocking polls between injection points were accidental
/// rate limiting. With them gone, an injection point fires ten payloads back to
/// back, six points run at once, and a small PHP application ran out of worker
/// processes. The pass that followed skipped almost every site with "the
/// endpoint did not answer", and reported seven findings where it had reported
/// fifteen. Nothing was wrong with the target: it answers in 8ms when asked
/// alone.
///
/// Accidental throttling is not a design. This is the deliberate version:
/// additive-increase on success, multiplicative-decrease on transport failure,
/// per host, with a floor of one in-flight request and a delay that decays as
/// the target recovers.
/// How many requests this process has sent, and how long it spent waiting on
/// them. Reported at the end of a pass.
///
/// Added because "the scan took 69 minutes" is not actionable and "the scan
/// sent 41,000 requests and spent 55 minutes in transport" is. Guessing at
/// where a scan's time goes cost several hours today; this is the cheap way to
/// stop guessing.
pub mod meter {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{LazyLock, Mutex};

    pub static REQUESTS: AtomicU64 = AtomicU64::new(0);
    pub static WAIT_MS: AtomicU64 = AtomicU64::new(0);
    pub static PACE_MS: AtomicU64 = AtomicU64::new(0);
    pub static FAILURES: AtomicU64 = AtomicU64::new(0);

    pub fn snapshot() -> (u64, u64, u64, u64) {
        (
            REQUESTS.load(Ordering::Relaxed),
            WAIT_MS.load(Ordering::Relaxed),
            PACE_MS.load(Ordering::Relaxed),
            FAILURES.load(Ordering::Relaxed),
        )
    }

    pub fn reset() {
        REQUESTS.store(0, Ordering::Relaxed);
        WAIT_MS.store(0, Ordering::Relaxed);
        PACE_MS.store(0, Ordering::Relaxed);
        FAILURES.store(0, Ordering::Relaxed);
        CLASSES.lock().unwrap().clear();
    }

    /// Engine-time per detection class, and how many times each one ran.
    ///
    /// "The scan sent 41,000 requests" says the pass was expensive. It does not
    /// say which check was expensive, and the difference decides whether the
    /// answer is a faster oracle, a cheaper one, or not running it at all. The
    /// first attempt at this problem was three hours of guessing.
    ///
    /// These are engine-seconds, not wall-clock: classes run concurrently
    /// across workers, so the column sums to more than the pass took. The
    /// ratios are the point.
    static CLASSES: LazyLock<Mutex<BTreeMap<&'static str, (u64, u64)>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    pub fn charge(class: &'static str, d: std::time::Duration) {
        let mut g = CLASSES.lock().unwrap();
        let e = g.entry(class).or_insert((0, 0));
        e.0 += d.as_millis() as u64;
        e.1 += 1;
    }

    /// (class, milliseconds, calls), most expensive first.
    pub fn by_class() -> Vec<(&'static str, u64, u64)> {
        let mut v: Vec<_> = CLASSES
            .lock()
            .unwrap()
            .iter()
            .map(|(k, (ms, n))| (*k, *ms, *n))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

/// Run one class's probe and charge the meter for what it took.
pub async fn spent<T>(class: &'static str, fut: impl std::future::Future<Output = T>) -> T {
    let t0 = Instant::now();
    let out = fut.await;
    meter::charge(class, t0.elapsed());
    out
}

pub mod pace {
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::Semaphore;

    /// Ceiling on concurrent requests to one host. FIXED, deliberately.
    ///
    /// The first version of this adapted the ceiling by permanently forgetting
    /// semaphore permits on failure. It stalled a scan dead: permits consumed,
    /// growth gated behind successes that could no longer happen, and the
    /// engine sat on idle connections issuing nothing at 0.2% CPU. Capacity
    /// that can only shrink is a deadlock waiting for the right sequence of
    /// failures.
    ///
    /// Rate is controlled by delay instead. Delay cannot strand anything: the
    /// worst case is slow, and slow recovers on its own.
    const MAX_INFLIGHT: usize = 8;
    /// Consecutive transport failures before we brake.
    const SHRINK_AFTER: u64 = 2;
    /// Consecutive successes before we ease off.
    const GROW_AFTER: u64 = 20;
    const MAX_DELAY_MS: u64 = 1500;

    /// Consecutive failures before we stop overlapping requests entirely.
    const SERIALISE_AFTER: u64 = 4;
    /// Successes before we allow overlap again.
    const UNSERIALISE_AFTER: u64 = 40;

    /// How many recent unpayloaded responses the latency window keeps.
    ///
    /// Enough that one slow answer does not move the picture, few enough that
    /// the picture is of NOW: a target that has been under a scan for twenty
    /// minutes is not the target that was idle when the pass started, and the
    /// number the time-based oracles need is what normal costs under the load
    /// we are ourselves applying.
    const LATENCY_WINDOW: usize = 64;

    pub struct HostPace {
        sem: Arc<Semaphore>,
        /// Held for the whole request when the host is judged to be serialising
        /// us anyway. Reversible, unlike consuming capacity.
        gate: tokio::sync::Mutex<()>,
        serial: std::sync::atomic::AtomicBool,
        fails: AtomicU64,
        oks: AtomicU64,
        delay_ms: AtomicU64,
        /// Round-trip times for requests that carried no payload, in ms.
        latency: Mutex<VecDeque<u128>>,
    }

    impl HostPace {
        fn new() -> Self {
            Self {
                sem: Arc::new(Semaphore::new(MAX_INFLIGHT)),
                gate: tokio::sync::Mutex::new(()),
                serial: std::sync::atomic::AtomicBool::new(false),
                fails: AtomicU64::new(0),
                oks: AtomicU64::new(0),
                delay_ms: AtomicU64::new(0),
                latency: Mutex::new(VecDeque::new()),
            }
        }

        /// Record what an ordinary request to this host cost.
        ///
        /// Only baseline sends feed this. A payload request is the thing being
        /// measured against the window, so letting it into the window would let
        /// a real five-second sleep raise the bar it has to clear.
        pub fn observe(&self, ms: u128) {
            let mut w = self.latency.lock().unwrap_or_else(|e| e.into_inner());
            if w.len() == LATENCY_WINDOW {
                w.pop_front();
            }
            w.push_back(ms);
        }

        /// What a slow-but-ordinary response costs here: the 90th percentile of
        /// the window, or `None` until there is enough of a window to mean
        /// anything.
        pub fn slow_normal_ms(&self) -> Option<u128> {
            let w = self.latency.lock().unwrap_or_else(|e| e.into_inner());
            if w.len() < 8 {
                return None;
            }
            let mut v: Vec<u128> = w.iter().copied().collect();
            v.sort_unstable();
            Some(v[(v.len() * 9) / 10])
        }

        pub fn delay(&self) -> u64 {
            self.delay_ms.load(Ordering::Relaxed)
        }

        pub fn sem(&self) -> Arc<Semaphore> {
            Arc::clone(&self.sem)
        }

        pub fn serialising(&self) -> bool {
            self.serial.load(Ordering::Relaxed)
        }

        pub fn gate(&self) -> &tokio::sync::Mutex<()> {
            &self.gate
        }

        /// A request came back. Ease off the brake, slowly.
        pub fn ok(&self) {
            self.fails.store(0, Ordering::Relaxed);
            let n = self.oks.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= GROW_AFTER {
                let d = self.delay_ms.load(Ordering::Relaxed);
                self.delay_ms
                    .store(d.saturating_sub(d / 4), Ordering::Relaxed);
            }
            if n >= UNSERIALISE_AFTER {
                self.oks.store(0, Ordering::Relaxed);
                self.serial.store(false, Ordering::Relaxed);
            } else if n >= GROW_AFTER {
                self.oks.store(0, Ordering::Relaxed);
            }
        }

        /// A request did not come back at all. Brake, hard.
        pub fn failed(&self) {
            self.oks.store(0, Ordering::Relaxed);
            let n = self.fails.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= SHRINK_AFTER {
                let d = self.delay_ms.load(Ordering::Relaxed);
                self.delay_ms
                    .store(((d * 2) + 100).min(MAX_DELAY_MS), Ordering::Relaxed);
            }
            // Requests that never come back, repeatedly, mean overlapping is
            // not working here. The usual cause is not the target being small:
            // it is that WE hold a session the target locks per request, and a
            // time-based payload parks that lock for five or ten seconds while
            // everything else queues behind it and times out. Measured on
            // Mutillidae: eight concurrent requests on one session serialise
            // into a perfect staircase, while eight without a session run flat.
            //
            // So stop overlapping. The target was serialising us anyway; all
            // the parallelism bought was timeouts, and a timeout is read as
            // "the endpoint did not answer", which silently skips real work.
            if n >= SERIALISE_AFTER {
                self.fails.store(0, Ordering::Relaxed);
                self.serial.store(true, Ordering::Relaxed);
            }
        }
    }

    static HOSTS: OnceLock<Mutex<HashMap<String, Arc<HostPace>>>> = OnceLock::new();

    pub fn for_url(url: &str) -> Arc<HostPace> {
        let host = url
            .split("://")
            .nth(1)
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        let map = HOSTS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(m.entry(host).or_insert_with(|| Arc::new(HostPace::new())))
    }
}

/// What a time-based oracle is allowed to treat as a delay on this host, and
/// whether it can conclude anything here at all.
pub enum Timing {
    /// A response slower than this many milliseconds is a candidate. Everything
    /// below is the application being itself.
    Above(u128),
    /// The target's own ordinary responses already run at or past the sleep we
    /// would inject, so no delay measured here could distinguish a sleeping
    /// database from a busy one. `slow_normal_ms` is what normal costs.
    Hopeless { slow_normal_ms: u128 },
}

/// Decide the bar from what this host is actually doing right now.
///
/// A fixed threshold is what turned a 45-endpoint application into a 69-minute
/// scan. It is correct in isolation - a five-second sleep does cross 3.8
/// seconds - but it says nothing about whether crossing 3.8 seconds MEANS
/// anything on a target whose own pages take four. Every response that drifted
/// over the line entered the confirmation sequence: control, retry, and a
/// doubled sleep, ten-odd seconds each, five separators deep, on parameters
/// with no shell behind them.
///
/// The bar is now the host's own slow-normal plus half the sleep we injected,
/// never below the fixed floor. A target answering in 8ms keeps the old
/// behaviour exactly; a target answering in four seconds stops volunteering
/// every page for a confirmation it was never going to pass.
///
/// This does NOT relax any confirmation. The control, the reproduction and the
/// scaling check all still have to pass; the change is which responses are
/// worth spending them on. Weakening the scaling check was the tempting fix and
/// it is the wrong one: that check exists because the oracle was reading load
/// the scanner itself created as proof of a shell.
pub fn timing(url: &str, sleep_secs: u64, floor_ms: u128) -> Timing {
    let sleep_ms = sleep_secs as u128 * 1000;
    let Some(slow) = pace::for_url(url).slow_normal_ms() else {
        // Nothing measured yet: the floor is the only honest answer.
        return Timing::Above(floor_ms);
    };
    if slow >= sleep_ms {
        return Timing::Hopeless {
            slow_normal_ms: slow,
        };
    }
    Timing::Above(floor_ms.max(slow + sleep_ms / 2))
}

/// Record what an ordinary, unpayloaded request to this URL's host cost.
pub fn observe_latency(url: &str, ms: u128) {
    pace::for_url(url).observe(ms);
}

pub async fn send(
    client: &Client,
    method: &str,
    url: &str,
    body: Option<(&str, &str)>,
) -> Option<Resp> {
    send_with(client, method, url, body, &[]).await
}

/// Like [`send`], but sets `extra_headers` on the request too. This is how injection sites that live
/// in a request header or cookie (User-Agent, Referer, X-Forwarded-For, Cookie) carry their payload.
pub async fn send_with(
    client: &Client,
    method: &str,
    url: &str,
    body: Option<(&str, &str)>,
    extra_headers: &[(String, String)],
) -> Option<Resp> {
    // Pace against this host: hold a permit for the request, and wait out any
    // backoff the host has earned. See `pace`.
    let pacer = pace::for_url(url);
    let sem = pacer.sem();
    let _permit = sem.acquire().await.ok()?;
    // When the host has shown it cannot overlap, take the gate so this request
    // has it to itself. Reversible: sustained success releases the mode.
    let _gate = if pacer.serialising() {
        Some(pacer.gate().lock().await)
    } else {
        None
    };
    let d = pacer.delay();
    if d > 0 {
        meter::PACE_MS.fetch_add(d, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_millis(d)).await;
    }

    // A connection-level failure is not an answer about the endpoint, so it is
    // retried once on a fresh connection before it counts as one.
    //
    // This is the keep-alive race, and it is not rare: Apache's default
    // MaxKeepAliveRequests is 100, so a pooled connection is closed by the
    // server exactly when a scanner is most likely to be reusing it. Measured
    // against Mutillidae, it arrived in bursts - 59 failures inside one second
    // - and every one of them was reported as "the endpoint did not answer a
    // baseline request", which skipped the site and read as a detection
    // failure. Hand-testing never reproduced it, because a hand test opens a
    // fresh connection every time.
    let t0 = Instant::now();
    let mut attempt = 0;
    let outcome = loop {
        let mut rb = match method {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            "PATCH" => client.patch(url),
            _ => client.get(url),
        };
        for (k, v) in extra_headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if let Some((b, ctype)) = body {
            rb = rb.header("content-type", ctype).body(b.to_string());
        }
        let r = rb.send().await;
        let retryable = r
            .as_ref()
            .err()
            .map(|e| e.is_connect() && !e.is_timeout())
            .unwrap_or(false);
        if retryable && attempt == 0 {
            attempt += 1;
            continue;
        }
        break r;
    };
    meter::REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    meter::WAIT_MS.fetch_add(
        t0.elapsed().as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    match outcome {
        Ok(r) => {
            pacer.ok();
            let status = r.status().as_u16();
            let headers: Vec<(String, String)> = r
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (k.as_str().to_ascii_lowercase(), s.to_string()))
                })
                .collect();
            let location = headers
                .iter()
                .find(|(k, _)| k == "location")
                .map(|(_, v)| v.clone());
            let body = read_body_capped(r).await;
            Some(Resp {
                status,
                body,
                elapsed_ms: t0.elapsed().as_millis(),
                location,
                headers,
            })
        }
        Err(e) => {
            // Say WHY. "The endpoint did not answer" has been reported hundreds
            // of times in a single pass while the same URL answered a hand
            // request in 8ms, and without the reason there is nothing to act
            // on: a connect refusal, a read timeout and a body error are three
            // different problems wearing one message.
            if std::env::var("CORTEX_TRACE_FAIL").is_ok() {
                eprintln!(
                    "cortex: request failed {} {} :: timeout={} connect={} request={} :: {e}",
                    method,
                    url,
                    e.is_timeout(),
                    e.is_connect(),
                    e.is_request(),
                );
            }
            meter::FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            pacer.failed();
            None
        }
    }
}

/// A server error for the oracles: an HTTP 5xx, or a 2xx/4xx page that leaks a stack trace.
pub fn is_server_error(status: u16, body: &str) -> bool {
    status >= 500 || STACK_ERR_RE.is_match(body)
}

/// Body carries a database-engine error signature (error-based SQLi oracle). Shared by the REST
/// injection engine and the GraphQL engine.
pub fn is_sql_error(body: &str) -> bool {
    SQL_ERR_RE.is_match(body)
}

/// Body leaks the shape of `/etc/passwd` (LFI oracle).
pub fn is_passwd(body: &str) -> bool {
    PASSWD_RE.is_match(body)
}

pub static SQL_ERR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(SQL syntax.*MySQL|Warning.*\bmysqli?_|MySqlException|check the manual that corresponds to your (MySQL|MariaDB)|Unknown column '[^']+' in|PostgreSQL.*ERROR|pg_query\(\)|PSQLException|unterminated quoted string|Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark after the character string|Incorrect syntax near|SQLServerException|\bORA-\d{5}\b|Oracle error|quoted string not properly terminated|SQLite/JDBCDriver|SQLite3?::|sqlite3?\.?(OperationalError|Exception)|SQLITE_ERROR|SQLite error|near "[^"]*": syntax error|unrecognized token|SQL logic error|java\.sql\.SQLException|syntax error at or near|You have an error in your SQL syntax)"#).unwrap()
});
pub static PASSWD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"root:.*:0:0:").unwrap());

/// A type-appropriate baseline value for a body field we have no example for, so a JSON body with an
/// `integer`/`boolean` field is well-typed rather than a string the server rejects.
pub fn typed_default(ty: Option<&str>) -> &'static str {
    match ty {
        Some("integer") | Some("number") => "1",
        Some("boolean") => "true",
        Some("array") => "[]",
        Some("object") => "{}",
        _ => "test",
    }
}

/// Render a baseline body value as its declared JSON type. Falls back to a JSON string when the
/// value does not parse as the declared type (so a bad example can never produce invalid JSON).
pub fn json_typed(value: &str, ty: Option<&str>) -> Value {
    match ty {
        Some("integer") => value
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::String(value.to_string())),
        Some("number") => value
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(value.to_string())),
        Some("boolean") => value
            .parse::<bool>()
            .map(Value::Bool)
            .unwrap_or_else(|_| Value::String(value.to_string())),
        Some("array") | Some("object") => serde_json::from_str::<Value>(value)
            .unwrap_or_else(|_| Value::String(value.to_string())),
        _ => Value::String(value.to_string()),
    }
}

/// Percent-encode a string for a URL/form context (keeps unreserved chars).
pub fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode a percent/`+`-encoded value.
pub fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// Server-side error / stack-trace signatures across common stacks, so a 200-with-error-page counts
// as a server error for the oracles (not just HTTP 5xx).
static STACK_ERR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(Traceback \(most recent call last\)|Exception in thread|\bat [\w.$]+\([\w.]+\.java:\d+\)|\.java:\d+\)|java\.lang\.[A-Za-z]+Exception|NullPointerException|undefined method `[^']+' for|NoMethodError|ActionController::|TypeError:|ReferenceError:|at Object\.<anonymous>|node:internal|Fatal error: Uncaught|PHP (Warning|Fatal error|Notice)|Stack trace:|System\.[A-Za-z.]+Exception|goroutine \d+ \[|panic: |Whitelabel Error Page|Internal Server Error)"#).unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_error_detects_status_and_stacktrace() {
        assert!(is_server_error(500, ""));
        assert!(is_server_error(
            200,
            "Traceback (most recent call last): ..."
        ));
        assert!(is_server_error(200, "java.lang.NullPointerException"));
        assert!(!is_server_error(200, "ok"));
        assert!(!is_server_error(400, "bad request"));
    }

    #[test]
    fn typed_helpers() {
        assert_eq!(typed_default(Some("integer")), "1");
        assert_eq!(typed_default(Some("boolean")), "true");
        assert_eq!(typed_default(None), "test");
        assert_eq!(
            json_typed("abc", Some("integer")),
            Value::String("abc".into())
        );
        assert_eq!(json_typed("42", Some("integer")), Value::from(42i64));
        assert_eq!(json_typed("true", Some("boolean")), Value::Bool(true));
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    fn feed(url: &str, samples: &[u128]) {
        for ms in samples {
            observe_latency(url, *ms);
        }
    }

    #[test]
    fn a_fast_target_keeps_the_old_bar() {
        let url = "http://timing-fast.test/x";
        feed(url, &[6, 7, 8, 8, 9, 10, 11, 12, 9, 8]);
        match timing(url, 5, 3800) {
            Timing::Above(ms) => assert_eq!(ms, 3800),
            Timing::Hopeless { .. } => panic!("a target answering in 8ms is not hopeless"),
        }
    }

    #[test]
    fn a_slow_target_raises_the_bar_instead_of_confirming_noise() {
        // Pages that take about three seconds. A four-second answer used to be
        // a command-injection candidate here, and cost ten seconds to disprove.
        let url = "http://timing-slow.test/x";
        feed(
            url,
            &[2900, 3000, 3100, 2800, 3200, 3050, 2950, 3300, 3000, 3100],
        );
        match timing(url, 5, 3800) {
            // slow-normal (~3300) plus half the injected sleep.
            Timing::Above(ms) => assert!(ms > 5000, "bar was {ms}, expected above 5000"),
            Timing::Hopeless { .. } => panic!("three seconds is slow, not unmeasurable"),
        }
    }

    #[test]
    fn a_target_slower_than_the_sleep_cannot_be_measured_this_way() {
        let url = "http://timing-hopeless.test/x";
        feed(
            url,
            &[5200, 5400, 6000, 5100, 7000, 5500, 5300, 5900, 6100, 5800],
        );
        match timing(url, 5, 3800) {
            Timing::Hopeless { slow_normal_ms } => assert!(slow_normal_ms >= 5000),
            Timing::Above(ms) => panic!("bar {ms} pretends a 5s sleep is detectable here"),
        }
    }

    #[test]
    fn with_nothing_measured_the_floor_is_the_answer() {
        match timing("http://timing-unknown.test/x", 5, 3800) {
            Timing::Above(ms) => assert_eq!(ms, 3800),
            Timing::Hopeless { .. } => panic!("no samples is not evidence of slowness"),
        }
    }
}
