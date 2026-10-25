//! Web Tracer capture agent - Method 1 (SSLKEYLOGFILE + packet capture).
//!
//! `crossfyre trace` launches a browser with `SSLKEYLOGFILE` pointed at a temp file and runs a
//! packet capture alongside it. TLS is decrypted from the logged session keys (no proxy, no CA
//! install, no browser extension - it works on any TLS the browser negotiates, HTTP/1.1 and
//! HTTP/2), each request/response is reduced to a SHAPE (method + redacted URL + status + tech),
//! and shapes are batched to the control plane where they classify into the asset graph attributed
//! to the `web_trace` session workflow.
//!
//! ## What leaves the machine
//! Only shapes. Before anything is sent, [`redact_url`] strips userinfo, the fragment, and every
//! query VALUE (keys are kept so the server can inventory parameters; values may be secrets).
//! Request/response bodies and headers are never captured beyond the `Server` banner used for tech
//! fingerprinting. This is a hunter capturing their OWN browsing, but we still minimise egress.
//!
//! ## Testability
//! The pure reduction pipeline ([`redact_url`], [`parse_ek_line`], [`shape`], [`Batcher`]) is unit
//! tested below. The capture orchestration in [`run`] shells out to `tshark`/`dumpcap` and a real
//! browser, which cannot run in CI; it is written to be correct against real tooling and is
//! exercised manually. `crossfyre doctor` checks for `tshark` on PATH.

use std::collections::VecDeque;
use std::error::Error;

type BoxErr = Box<dyn Error>;

/// A single captured request/response reduced to its shape. This is the wire format posted to
/// `/api/v1/web-trace/ingest`; it deliberately carries no bodies, headers, or secret values.
// TraceEvent + redact_url live in the shared `cfx_capture` crate (the privacy-safe reduction is used
// by the mobile netstack too). Re-exported so this module and its callers keep referring to them by
// the same names.
pub use cfx_capture::{TraceEvent, redact_url};

/// A raw capture pulled out of one `tshark -T ek` line before shaping.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RawCapture {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub status: Option<i64>,
    pub server: Option<String>,
    /// The request carried an Authorization header or a Cookie. We keep only this boolean - the
    /// header value is deliberately discarded here so a credential never enters a TraceEvent.
    pub authed: bool,
    /// Request body media type, when a body was present (set by the proxy backend, which has the
    /// body; the packet backend leaves this None).
    pub content_type: Option<String>,
    /// Request body field NAMES only (values discarded). Populated by the proxy backend.
    pub body_params: Vec<String>,
}

impl RawCapture {
    fn is_request(&self) -> bool {
        self.method.is_some() && self.uri.is_some()
    }
    fn is_response(&self) -> bool {
        self.status.is_some()
    }
}

/// Parse one line of `tshark -T ek` output into a [`RawCapture`].
///
/// `-T ek` emits newline-delimited JSON; packet lines carry a `layers` object whose keys are the
/// requested `-e` fields (dots replaced by underscores) with ARRAY values. We match by key SUFFIX
/// rather than exact name so the parser survives tshark's prefix/version differences (e.g.
/// `http.request.method` vs `http_http_request_method`). Non-packet lines (the `index` control
/// lines) and lines with none of our fields return `None`.
pub fn parse_ek_line(line: &str) -> Option<RawCapture> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let layers = v.get("layers").or_else(|| v.pointer("/layers"))?;
    let obj = layers.as_object()?;

    let first = |suffix: &str| -> Option<String> {
        for (k, val) in obj {
            if k.ends_with(suffix) {
                // Field values are arrays in `-ek`; accept a bare scalar too.
                let s = match val {
                    serde_json::Value::Array(a) => {
                        a.first().and_then(|x| x.as_str().map(str::to_string))
                    }
                    serde_json::Value::String(s) => Some(s.clone()),
                    other => other.as_str().map(str::to_string),
                };
                if let Some(s) = s {
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }
        None
    };

    let raw = RawCapture {
        method: first("request.method"),
        uri: first("request.full_uri").or_else(|| first("request_full_uri")),
        status: first("response.code")
            .or_else(|| first("response_code"))
            .and_then(|s| s.parse::<i64>().ok()),
        server: first("http.server")
            .or_else(|| first("_server"))
            .or_else(|| first("server")),
        // Presence of either header marks the request authenticated; the value is never retained.
        authed: first("authorization").is_some() || first("cookie").is_some(),
        // The packet backend does not reassemble request bodies; body shape comes from the proxy.
        content_type: None,
        body_params: Vec::new(),
    };
    if raw.is_request() || raw.is_response() {
        Some(raw)
    } else {
        None
    }
}

/// Turn a raw capture into a wire [`TraceEvent`], applying redaction. Returns `None` for a capture
/// that is neither a usable request (needs a method+uri) nor carries a status we can attach.
pub fn shape(raw: &RawCapture, host_filter: Option<&str>) -> Option<TraceEvent> {
    if !raw.is_request() {
        return None;
    }
    let uri = raw.uri.as_deref()?;
    if let Some(f) = host_filter {
        if !uri.contains(f) {
            return None;
        }
    }
    Some(TraceEvent {
        method: raw
            .method
            .clone()
            .unwrap_or_else(|| "GET".into())
            .to_uppercase(),
        url: redact_url(uri),
        status: raw.status,
        tech: raw.server.clone(),
        authed: raw.authed,
        content_type: raw.content_type.clone(),
        body_params: raw.body_params.clone(),
        ..Default::default()
    })
}

/// Extract the request body's field NAMES (never values) from a captured body, for the two content
/// types an API request almost always uses. This is the body-side analogue of keeping URL query
/// KEYS while blanking their values: the field set is the operation's request contract; the values
/// are user data / secrets and are deliberately discarded.
///
/// - `application/json`: top-level object keys. For a JSON array body we look at the first object
///   element's keys (list endpoints post arrays of uniform objects). Non-object JSON yields nothing.
/// - `application/x-www-form-urlencoded`: the `a=1&b=2` keys.
/// - anything else (multipart, binary, text): no keys (we do not guess).
///
/// Returns a de-duplicated, order-preserving list. Pure and panic-free.
pub fn body_param_keys(content_type: Option<&str>, body: &[u8]) -> Vec<String> {
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    let mut push = |k: String| {
        if !k.is_empty() && !out.contains(&k) {
            out.push(k);
        }
    };
    if ct.contains("application/json") || ct.contains("+json") {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
            let obj = match &v {
                serde_json::Value::Object(_) => Some(&v),
                serde_json::Value::Array(a) => a.iter().find(|x| x.is_object()),
                _ => None,
            };
            if let Some(serde_json::Value::Object(map)) = obj {
                for k in map.keys() {
                    push(k.clone());
                }
            }
        }
    } else if ct.contains("application/x-www-form-urlencoded") {
        // Parse KEYS out of `a=1&b=2`; never decode/keep the values.
        let s = std::str::from_utf8(body).unwrap_or("");
        for pair in s.split('&') {
            let key = pair.split('=').next().unwrap_or("").trim();
            if !key.is_empty() {
                // percent-decode just the key so `user%5Bid%5D` reads as `user[id]`.
                push(percent_decode_key(key));
            }
        }
    }
    out
}

/// Minimal percent-decode for form KEYS (we never decode values). `+` -> space, `%XX` -> byte.
fn percent_decode_key(k: &str) -> String {
    let bytes = k.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Size/flush-time batcher. Requests and their responses arrive as separate packets; correlating
/// them into one shape is out of scope for v1, so we send request shapes as they arrive and let the
/// server dedupe by normalized endpoint. This just bounds how often we POST.
pub struct Batcher {
    queue: VecDeque<TraceEvent>,
    max: usize,
}

impl Batcher {
    pub fn new(max: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max: max.max(1),
        }
    }
    /// Push an event; returns a full batch to flush if the buffer reached `max`.
    pub fn push(&mut self, ev: TraceEvent) -> Option<Vec<TraceEvent>> {
        self.queue.push_back(ev);
        if self.queue.len() >= self.max {
            Some(self.drain())
        } else {
            None
        }
    }
    /// Take everything currently buffered (used on the timer tick and at shutdown).
    pub fn drain(&mut self) -> Vec<TraceEvent> {
        self.queue.drain(..).collect()
    }
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Which capture backend a trace run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaptureMethod {
    /// Method 1: SSLKEYLOGFILE + packet capture (needs Wireshark/tshark + capture privileges).
    Keylog,
    /// Method 2: local intercepting proxy (Burp-style), needs only a browser.
    #[default]
    Proxy,
}

/// Configuration for a capture run, assembled from the `crossfyre trace` flags (which the
/// Setup/Deploy tab pre-fills).
#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub api_url: String,
    pub workflow_id: String,
    pub token: String,
    /// Capture backend (proxy by default; keylog for passive packet capture).
    pub method: CaptureMethod,
    /// Local port for the intercepting proxy (Method 2). 0 = OS-assigned ephemeral port.
    pub proxy_port: u16,
    /// Network interface for packet capture (`any` on Linux, else the default route iface).
    pub interface: String,
    /// Browser to launch (`chrome`/`chromium`/`firefox`), or None to let the user drive their own.
    pub browser: Option<String>,
    /// Only send shapes whose URL contains this substring (keeps out-of-scope hosts out).
    pub host_filter: Option<String>,
    pub batch_size: usize,
    pub flush_secs: u64,
    /// Opt-in: capture the session auth (cookie/bearer/API-key header) the browse presents and seed
    /// it into the Credentials arsenal as an encrypted, host-scoped credential. Off by default; the
    /// normal capture pipeline never touches secret values.
    pub seed_credentials: bool,
}

/// POST one batch to the nodeless ingest endpoint. `ended=true` on the final flush closes the
/// session server-side. Returns the accepted count.
pub async fn post_batch(
    client: &reqwest::Client,
    cfg: &TraceConfig,
    events: &[TraceEvent],
    ended: bool,
) -> Result<usize, BoxErr> {
    let res = client
        .post(format!(
            "{}/api/v1/web-trace/ingest",
            cfg.api_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "workflow_id": cfg.workflow_id,
            "token": cfg.token,
            "events": events,
            "ended": ended,
        }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        let msg = body["message"]
            .as_str()
            .unwrap_or("ingest rejected")
            .to_string();
        return Err(msg.into());
    }
    Ok(body["data"]["accepted"].as_u64().unwrap_or(0) as usize)
}

/// POST the session credentials the proxy observed to the token-gated seed endpoint. Each entry is
/// `{host, auth_type, config?, secret}`; the server encrypts the secret and stores a host-scoped
/// credential. Returns the number seeded. Only ever called when `--seed-credentials` is set.
pub async fn post_seed_credentials(
    client: &reqwest::Client,
    cfg: &TraceConfig,
    credentials: &[serde_json::Value],
) -> Result<usize, BoxErr> {
    let res = client
        .post(format!(
            "{}/api/v1/web-trace/seed-credential",
            cfg.api_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "workflow_id": cfg.workflow_id,
            "token": cfg.token,
            "credentials": credentials,
        }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        let msg = body["message"]
            .as_str()
            .unwrap_or("seed rejected")
            .to_string();
        return Err(msg.into());
    }
    Ok(body["data"]["seeded"].as_u64().unwrap_or(0) as usize)
}

/// The `tshark` argv for a decrypted-HTTP capture over the given keylog file. Split out so the
/// exact invocation is reviewable in one place (and so a future dumpcap/tcpdump backend can slot
/// in). Uses `-T ek` with explicit fields; `-l` line-buffers so we stream shapes live.
pub fn tshark_args(interface: &str, keylog_path: &str) -> Vec<String> {
    vec![
        "-i".into(),
        interface.into(),
        "-l".into(),
        "-o".into(),
        format!("tls.keylog_file:{keylog_path}"),
        "-Y".into(),
        "http.request || http.response".into(),
        "-T".into(),
        "ek".into(),
        "-e".into(),
        "http.request.method".into(),
        "-e".into(),
        "http.request.full_uri".into(),
        "-e".into(),
        "http.response.code".into(),
        "-e".into(),
        "http.server".into(),
        // Presence-only auth detection: these are read to set a boolean and then discarded; the
        // header VALUES never leave the machine (see shape()).
        "-e".into(),
        "http.authorization".into(),
        "-e".into(),
        "http.cookie".into(),
    ]
}

/// Run a capture session end to end. UNTESTABLE in CI (needs `tshark` + a browser); the reducer it
/// drives is unit tested. Streams `tshark -T ek`, shapes each packet, batches, and POSTs; flushes
/// on a timer and on shutdown (Ctrl-C or browser exit) with `ended=true`.
pub async fn run(cfg: TraceConfig) -> Result<(), BoxErr> {
    // Method 2 (local proxy) is the default, minimal-prerequisite path.
    if cfg.method == CaptureMethod::Proxy {
        return super::trace_proxy::run_proxy(cfg)
            .await
            .map_err(|e| -> BoxErr { e });
    }

    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    // Keylog file the browser writes TLS secrets to and tshark reads to decrypt.
    let keylog = std::env::temp_dir().join(format!("cfx-trace-{}.keys", std::process::id()));
    std::fs::write(&keylog, b"").map_err(|e| format!("cannot create keylog file: {e}"))?;
    let keylog_path = keylog.to_string_lossy().to_string();

    println!(
        "Web Tracer: starting capture on {} (session {})",
        cfg.interface, cfg.workflow_id
    );
    println!("  keylog: {keylog_path}");

    // Optionally launch the browser with SSLKEYLOGFILE set. If not, the user points their own
    // already-configured browser (doctor prints the env line).
    let mut browser_child = None;
    if let Some(browser) = &cfg.browser {
        let bin = browser_binary(browser);
        match Command::new(&bin)
            .env("SSLKEYLOGFILE", &keylog_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => {
                println!("  launched {bin} with SSLKEYLOGFILE set");
                browser_child = Some(c);
            }
            Err(e) => {
                eprintln!(
                    "  could not launch {bin} ({e}); set SSLKEYLOGFILE={keylog_path} in your own browser"
                );
            }
        }
    } else {
        println!("  set SSLKEYLOGFILE={keylog_path} in your browser, then browse your target");
    }

    let mut tshark = Command::new("tshark")
        .args(tshark_args(&cfg.interface, &keylog_path))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start tshark (is Wireshark installed?): {e}"))?;

    let stdout = tshark.stdout.take().ok_or("tshark produced no stdout")?;
    let mut lines = BufReader::new(stdout).lines();

    let client = reqwest::Client::new();
    let mut batcher = Batcher::new(cfg.batch_size);
    let mut total = 0usize;
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(cfg.flush_secs.max(1)));

    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        if let Some(raw) = parse_ek_line(&l) {
                            if let Some(ev) = shape(&raw, cfg.host_filter.as_deref()) {
                                if let Some(batch) = batcher.push(ev) {
                                    match post_batch(&client, &cfg, &batch, false).await {
                                        Ok(n) => { total += n; print!("\r  captured {total} endpoints"); let _ = std::io::Write::flush(&mut std::io::stdout()); }
                                        Err(e) => eprintln!("\n  ingest error: {e}"),
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => break, // tshark exited
                    Err(e) => { eprintln!("\n  capture read error: {e}"); break; }
                }
            }
            _ = ticker.tick() => {
                if !batcher.is_empty() {
                    let batch = batcher.drain();
                    if let Ok(n) = post_batch(&client, &cfg, &batch, false).await { total += n; }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n  stopping…");
                break;
            }
        }
    }

    // Final flush closes the session.
    let tail = batcher.drain();
    if let Err(e) = post_batch(&client, &cfg, &tail, true).await {
        eprintln!("  final flush error: {e}");
    }
    let _ = tshark.start_kill();
    if let Some(mut b) = browser_child {
        let _ = b.start_kill();
    }
    let _ = std::fs::remove_file(&keylog);
    println!("\nWeb Tracer: session ended, {total} endpoints captured.");
    Ok(())
}

/// The program to launch for `--browser <name>`. On Linux the browsers are on PATH under
/// these names; macOS and Windows keep them where their installers put them, so there the
/// name is looked up and the path found is what is launched.
pub fn browser_binary(name: &str) -> String {
    let bin: String = match name.to_lowercase().as_str() {
        "chrome" | "google-chrome" => "google-chrome".into(),
        "chromium" => "chromium".into(),
        "firefox" => "firefox".into(),
        "edge" | "msedge" => "microsoft-edge".into(),
        other => other.into(),
    };
    if cfg!(target_os = "linux") {
        return bin;
    }
    super::capture::browser::locate(&bin)
        .map(|p| p.display().to_string())
        .unwrap_or(bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_blanks_query_values_keeps_keys() {
        assert_eq!(
            redact_url("https://api.example.com/v1/users/42?token=secret&page=2"),
            "https://api.example.com/v1/users/42?token=&page="
        );
        // key with no value is preserved as-is
        assert_eq!(
            redact_url("https://h.com/x?flag&a=1"),
            "https://h.com/x?flag&a="
        );
        // no query, no change
        assert_eq!(redact_url("https://h.com/a/b"), "https://h.com/a/b");
        // trailing '?' collapses away
        assert_eq!(redact_url("https://h.com/a?"), "https://h.com/a");
    }

    #[test]
    fn redact_strips_userinfo_and_fragment() {
        assert_eq!(
            redact_url("https://user:pass@h.com/a?x=1#frag"),
            "https://h.com/a?x="
        );
        assert_eq!(redact_url("https://h.com/a#section"), "https://h.com/a");
        // userinfo with '@' but no password
        assert_eq!(redact_url("http://token@h.com/p"), "http://h.com/p");
    }

    #[test]
    fn ek_line_parses_request_and_response() {
        let req = r#"{"timestamp":"1","layers":{"http.request.method":["POST"],"http.request.full_uri":["https://api.example.com/v1/login?next=/home"]}}"#;
        let raw = parse_ek_line(req).expect("request parsed");
        assert_eq!(raw.method.as_deref(), Some("POST"));
        assert!(raw.uri.as_deref().unwrap().contains("/v1/login"));

        let resp = r#"{"layers":{"http.response.code":["200"],"http.server":["nginx/1.25"]}}"#;
        let raw = parse_ek_line(resp).expect("response parsed");
        assert_eq!(raw.status, Some(200));
        assert_eq!(raw.server.as_deref(), Some("nginx/1.25"));

        // presence of an Authorization header sets authed (the value is not retained on RawCapture)
        let authed = r#"{"layers":{"http.request.method":["GET"],"http.request.full_uri":["https://h.com/me"],"http.authorization":["Bearer eyJ..."]}}"#;
        assert!(
            parse_ek_line(authed).expect("parsed").authed,
            "auth header detected"
        );

        // control/index lines and irrelevant packets yield nothing
        assert!(parse_ek_line(r#"{"index":{"_type":"doc"}}"#).is_none());
        assert!(parse_ek_line("not json").is_none());
    }

    #[test]
    fn shape_applies_filter_and_redaction() {
        let raw = RawCapture {
            method: Some("get".into()),
            uri: Some("https://user:pw@api.example.com/v1/users/9?secret=abc".into()),
            status: None,
            server: Some("caddy".into()),
            authed: true,
            content_type: None,
            body_params: Vec::new(),
        };
        let ev = shape(&raw, Some("example.com")).expect("in scope");
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.url, "https://api.example.com/v1/users/9?secret=");
        assert_eq!(ev.tech.as_deref(), Some("caddy"));
        assert!(ev.authed, "auth flag carried through");
        // filtered out when the host does not match scope
        assert!(shape(&raw, Some("other.com")).is_none());
        // a bare response (no method/uri) is not a shapeable request
        assert!(
            shape(
                &RawCapture {
                    status: Some(200),
                    ..Default::default()
                },
                None
            )
            .is_none()
        );
    }

    #[test]
    fn body_param_keys_extracts_names_never_values() {
        // JSON object: keys only, values discarded.
        // serde_json's default object map is sorted, so the field SET comes back alphabetical
        // (order is not meaningful for a request-shape field set).
        let keys = body_param_keys(
            Some("application/json"),
            br#"{"email":"a@b.com","role":"admin","nested":{"x":1}}"#,
        );
        assert_eq!(keys, vec!["email", "nested", "role"]);
        // JSON array of objects: shape from the first element.
        let keys = body_param_keys(
            Some("application/json; charset=utf-8"),
            br#"[{"id":1,"name":"x"}]"#,
        );
        assert_eq!(keys, vec!["id", "name"]);
        // form-urlencoded: keys only, bracket keys percent-decoded.
        let keys = body_param_keys(
            Some("application/x-www-form-urlencoded"),
            b"user%5Bid%5D=7&token=SECRET&user%5Bid%5D=9",
        );
        assert_eq!(keys, vec!["user[id]", "token"]);
        // no body / unknown type -> nothing.
        assert!(body_param_keys(Some("text/plain"), b"hello").is_empty());
        assert!(body_param_keys(None, b"").is_empty());
        // malformed JSON -> nothing, never panics.
        assert!(body_param_keys(Some("application/json"), b"{not json").is_empty());
    }

    #[test]
    fn batcher_flushes_at_capacity_and_drains() {
        let mut b = Batcher::new(2);
        let ev = TraceEvent {
            method: "GET".into(),
            url: "https://h/x".into(),
            status: None,
            tech: None,
            authed: false,
            content_type: None,
            body_params: Vec::new(),
            ..Default::default()
        };
        assert!(b.push(ev.clone()).is_none());
        let flushed = b.push(ev.clone()).expect("flush at capacity");
        assert_eq!(flushed.len(), 2);
        assert!(b.is_empty());
        assert!(b.push(ev).is_none()); // one below capacity, no flush
        assert_eq!(b.drain().len(), 1);
    }
}
