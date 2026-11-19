//! The Toolmark fingerprint engine (S1): fetch a target service, collect signals,
//! run the signature engine, hash the favicon, detect WAF/CDN, and stream
//! findings. Each finding is a serde value the node relays verbatim into the
//! shared asset graph.

use crate::signatures::{self, Signatures};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::LazyLock;
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct FpParams {
    /// Target URL or host[:port].
    pub target: String,
    /// Evasiveness posture (set by the node's Evasiveness switch): blend in as a
    /// browser (true, default) vs a neutral honest client (false).
    #[serde(default = "d_true")]
    pub evasive: bool,
    /// Attribution token: when set, advertise it so an authorized program can
    /// allow-list the traffic.
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "d_true")]
    pub follow_redirects: bool,
    #[serde(default = "d_true")]
    pub favicon: bool,
    /// OPSEC depth tier: 0 passive, 1 quiet (favicon), 2 standard, 3 aggressive.
    #[serde(default = "d_tier")]
    pub depth_tier: u8,
    /// Optional request auth (headers + cookie) resolved from a credential by the
    /// node, so fingerprinting sees the authenticated surface.
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// Names pinned to addresses, `[["app.example.com", "203.0.113.7:443"], ...]`. A
    /// caller that has already decided which addresses of a name may be dialled sends
    /// them, so the name is not looked up again here and answered with somewhere else.
    #[serde(default)]
    pub resolve: Vec<(String, std::net::SocketAddr)>,
    /// Refuse private and reserved addresses for any name that is not pinned. See
    /// `transport::ClientConfig::block_internal`.
    #[serde(default)]
    pub block_internal: bool,
    /// Where the op's connections go. Never read from the request's own fields: the
    /// daemon sets it from the egress wrapper, and a request without one gets
    /// `Inherit`.
    #[serde(skip)]
    pub egress: transport::Egress,
}
fn d_timeout() -> u64 {
    8000
}
fn d_true() -> bool {
    true
}
fn d_tier() -> u8 {
    2
}

/// Request auth resolved from a credential. Shared across all engines via
/// `transport`; re-exported so existing `AuthSpec` references in this module keep
/// resolving.
pub use transport::AuthSpec;

pub async fn run<O: crate::observe::Observer>(
    params: FpParams,
    tx: mpsc::UnboundedSender<Value>,
    observer: std::sync::Arc<O>,
) {
    scan(Signatures::shipped(), params, tx, observer).await
}

/// [`run`] with `signatures` in place of the shipped ones.
async fn scan<O: crate::observe::Observer>(
    signatures: &Signatures,
    params: FpParams,
    tx: mpsc::UnboundedSender<Value>,
    observer: std::sync::Arc<O>,
) {
    let (scheme, host, port, url) = match normalize_target(&params.target) {
        Some(t) => t,
        None => {
            let _ = tx.send(
                json!({"type":"error","message":format!("invalid target: {}", params.target)}),
            );
            return;
        }
    };

    // Present a coherent browser via the transport layer: the reqwest backend
    // sends UA + hint headers; the impersonate (wreq) backend presents a real
    // browser TLS/HTTP2 fingerprint (the profile owns the fingerprint headers).
    // Fast posture skips emulation. Profile choice = the private `adaptive` drop-in.
    let mode = adaptive::identity::Mode::from_flags(params.evasive, params.identify.clone());
    let ident = adaptive::identity::resolve(&mode, Some(params.target.as_str()));
    let token = if let adaptive::identity::Mode::Identify(t) = &mode {
        Some(t.as_str())
    } else {
        None
    };
    let client = match transport::build_scan_client(
        transport::ScanClient {
            identity_headers: &ident.headers,
            user_agent: &ident.user_agent,
            auth: params.auth.as_ref(),
            attribution_token: token,
            emulate: !matches!(mode, adaptive::identity::Mode::Fast),
            timeout: Some(std::time::Duration::from_millis(
                params.timeout_ms.clamp(1000, 120_000),
            )),
            redirect: if params.follow_redirects {
                transport::Redirect::Limited(5)
            } else {
                transport::Redirect::None
            },
            accept_invalid_certs: true,
            cookie_store: true,
            resolve: params.resolve.clone(),
            block_internal: params.block_internal,
        },
        &params.egress,
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(json!({"type":"error","message":format!("client build failed: {e}")}));
            return;
        }
    };

    let _ = tx.send(json!({"type":"ack","target": url}));

    // Fetch the landing page.
    let (status, headers, body, cookies) = match client.get(&url).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let mut hdrs: Vec<(String, String)> = Vec::new();
            let mut cookies: Vec<String> = Vec::new();
            for (k, v) in r.headers().iter() {
                let name = k.as_str().to_lowercase();
                let val = v.to_str().unwrap_or("").to_string();
                if name == "set-cookie" {
                    cookies.push(val.clone());
                }
                hdrs.push((name, val));
            }
            let body =
                String::from_utf8_lossy(&read_bytes_capped(r, MAX_BODY_BYTES).await).into_owned();
            (status, hdrs, body, cookies)
        }
        Err(e) => {
            let _ = tx.send(json!({"type":"error","message":format!("fetch failed: {e}")}));
            let _ = tx.send(json!({"type":"done"}));
            return;
        }
    };

    observer
        .observed(crate::observe::Observation {
            url: &url,
            host: &host,
            port,
            scheme: &scheme,
            status,
            headers: &headers,
            body: body.as_bytes(),
        })
        .await;

    let title = extract_title(&body);
    let server = signatures::header_val(&headers, "server");
    // A 3xx here is a redirect that was not followed: the client follows one
    // only on the target's own origin, or none at all with follow_redirects
    // off. Where it pointed is reported, so the finding says what the target
    // does rather than reading as a site with nothing on it.
    let redirect_location = (300..400)
        .contains(&status)
        .then(|| signatures::header_val(&headers, "location"))
        .flatten();
    let (waf, cdn) = signatures::waf_cdn(&headers, &cookies);

    let favicon = if params.favicon && params.depth_tier >= 1 {
        fetch_favicon(&client, &scheme, &host, port).await
    } else {
        Value::Null
    };

    // What the landing page leaves undecided, from the paths worth asking. Each one asked
    // is kept as what the scan saw, as the landing page is.
    let mut found = signatures::Host::new(
        signatures,
        &url,
        &headers,
        &cookies,
        &body,
        params.depth_tier,
    );
    let base = transport::Url::parse(&url).ok();
    signatures::ask(&mut found, |path| {
        let target = base.as_ref().and_then(|b| b.join(&path).ok());
        let (client, observer) = (client.clone(), observer.clone());
        let (host, scheme) = (host.clone(), scheme.clone());
        async move {
            let Some(target) = target else {
                return signatures::Answered::none();
            };
            let Ok(r) = client.get(target.as_str()).send().await else {
                return signatures::Answered::none();
            };
            let status = r.status().as_u16();
            let moved = r.url().as_str() != target.as_str();
            let headers: Vec<(String, String)> = r
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_lowercase(),
                        v.to_str().unwrap_or("").to_string(),
                    )
                })
                .collect();
            let body = read_bytes_capped(r, MAX_PATH_BYTES).await;
            observer
                .observed(crate::observe::Observation {
                    url: target.as_str(),
                    host: &host,
                    port,
                    scheme: &scheme,
                    status,
                    headers: &headers,
                    body: &body,
                })
                .await;
            signatures::Answered {
                status: Some(status),
                moved,
                body: String::from_utf8_lossy(&body).into_owned(),
            }
        }
    })
    .await;
    let detections = found.detections();

    // One finding per detected technology.
    let mut cpes: Vec<String> = Vec::new();
    for d in &detections {
        if !d.cpe.is_empty() {
            cpes.push(d.cpe.clone());
        }
        let _ = tx.send(json!({
            "type": "finding",
            "data": {
                "target": url,
                "host": host, "port": port, "scheme": scheme,
                "type": "technology",
                "source": "toolmark",
                "severity": "info",
                "name": d.name,
                "category": d.category,
                "version": d.version,
                "cpe": d.cpe,
                "confidence": d.confidence,
                "evidence": d.evidence,
                "candidates": d.candidates,
            }
        }));

        // Version-based CVE matches for this technology. Emitted as
        // "version-inferred" (a backported fix could make it a false positive).
        if let Some(ver) = d.version.as_deref().filter(|v| !v.is_empty()) {
            for rule in crate::cve::match_cves(&d.name, ver) {
                let headline = if rule.title.is_empty() {
                    rule.cve.clone()
                } else {
                    rule.title.clone()
                };
                let _ = tx.send(json!({
                    "type": "finding",
                    "data": {
                        "target": url,
                        "host": host, "port": port, "scheme": scheme,
                        "type": "vulnerability",
                        "source": "toolmark-cve",
                        "severity": rule.severity,
                        "name": format!("{} {}: {}", d.name, ver, rule.cve),
                        "cve": rule.cve,
                        "cvss": rule.cvss,
                        "product": d.name,
                        "version": ver,
                        "confidence": "version-inferred",
                        "reference": rule.reference,
                        "description": format!(
                            "{}. Version-based match ({} {}); a backported patch could make this a false positive, so verify the exact build.",
                            headline, d.name, ver
                        ),
                    }
                }));
            }
        }
    }

    // Service summary finding.
    let _ = tx.send(json!({
        "type": "finding",
        "data": {
            "target": url,
            "host": host, "port": port, "scheme": scheme,
            "type": "service",
            "source": "toolmark",
            "severity": "info",
            "status_code": status,
            "redirect_location": redirect_location,
            "title": title,
            "server": server,
            "favicon": favicon,
            "waf": waf,
            "cdn": cdn,
            "tech": detections.iter().map(|d| json!({
                "name": d.name, "version": d.version, "cpe": d.cpe, "confidence": d.confidence
            })).collect::<Vec<_>>(),
            "tech_count": detections.len(),
        }
    }));

    // Run-level environment record (the Plessor control plane).
    let waf_present = !waf.is_null();
    let _ = tx.send(json!({
        "type": "finding",
        "data": {
            "target": url,
            "host": host, "port": port,
            "type": "environment",
            "source": "toolmark",
            "severity": "info",
            "waf_vendor": waf,
            "cdn": cdn,
            "expect_block_codes": if waf_present { json!([403, 406, 429, 999]) } else { json!([]) },
            "recommended_rate": if waf_present { "low" } else { "normal" },
            "cpes": cpes,
        }
    }));

    let _ = tx.send(json!({"type":"done"}));
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static TITLE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());

fn extract_title(body: &str) -> Option<String> {
    TITLE_RE
        .captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Cap on how much of a decoded response we buffer. reqwest's gzip feature
/// auto-decompresses, so without a ceiling a scanned target could serve a small
/// gzip "bomb" that inflates to gigabytes and OOMs the engine. 8 MiB is plenty
/// for fingerprinting a page or hashing a favicon.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The same cap for a path a signature asks for, which is held until the scan ends.
const MAX_PATH_BYTES: usize = 1024 * 1024;

async fn read_bytes_capped(mut resp: transport::Response, cap: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < cap {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = cap - buf.len();
                let take = chunk.len().min(room);
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break;
                }
            }
            _ => break,
        }
    }
    buf
}

fn normalize_target(t: &str) -> Option<(String, String, u16, String)> {
    transport::url::normalize_target(t).map(|tgt| (tgt.scheme, tgt.host, tgt.port, tgt.url))
}

// ---------------------------------------------------------------------------
// Favicon hashing (Shodan-compatible signed mmh3 + md5)
// ---------------------------------------------------------------------------

async fn fetch_favicon(client: &Client, scheme: &str, host: &str, port: u16) -> Value {
    let url = format!("{scheme}://{host}:{port}/favicon.ico");
    match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => {
            let b = read_bytes_capped(r, MAX_BODY_BYTES).await;
            if !b.is_empty() {
                json!({ "mmh3": favicon_mmh3(&b), "md5": format!("{:x}", md5::compute(&b)) })
            } else {
                Value::Null
            }
        }
        _ => Value::Null,
    }
}

/// Shodan `http.favicon.hash`: base64 (MIME, 76-char lines) then MurmurHash3
/// x86_32 seed 0, returned as a signed 32-bit int.
fn favicon_mmh3(bytes: &[u8]) -> i32 {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut wrapped = String::with_capacity(b64.len() + b64.len() / 76 + 2);
    for chunk in b64.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        wrapped.push('\n');
    }
    murmur3_x86_32(wrapped.as_bytes(), 0) as i32
}

fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h1 = seed;
    let nblocks = data.len() / 4;
    for i in 0..nblocks {
        let mut k1 = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;
    h1
}

#[cfg(test)]
mod normalize_target_tests {
    use super::normalize_target;

    #[test]
    fn infers_scheme_and_port() {
        let (s, h, p, _) = normalize_target("example.com").unwrap();
        assert_eq!((s.as_str(), h.as_str(), p), ("http", "example.com", 80));
        let (s, _, p, _) = normalize_target("example.com:443").unwrap();
        assert_eq!((s.as_str(), p), ("https", 443));
        let (s, _, p, _) = normalize_target("example.com:8080").unwrap();
        assert_eq!((s.as_str(), p), ("http", 8080));
        let (s, _, p, _) = normalize_target("https://x.com/a").unwrap();
        assert_eq!((s.as_str(), p), ("https", 443));
    }

    #[test]
    fn empty_is_none() {
        assert!(normalize_target("").is_none());
        assert!(normalize_target("   ").is_none());
    }
}

#[cfg(test)]
mod redirect_tests {
    //! A redirect off the target's origin is not followed, so the service
    //! finding describes the redirect itself. It says where the redirect
    //! pointed, so a 301 on an apex reads as "this sends you to www" rather
    //! than as an empty site.
    use super::*;
    use crate::observe::{Observation, Observer};
    use std::io::{Read, Write};

    /// What a fingerprint handed on: each page's status, Location header and body length.
    #[derive(Default)]
    struct Seen(std::sync::Mutex<Vec<(u16, Option<String>, usize)>>);

    impl Observer for Seen {
        async fn observed(&self, o: Observation<'_>) {
            let location = o
                .headers
                .iter()
                .find(|(name, _)| name == "location")
                .map(|(_, value)| value.clone());
            self.0
                .lock()
                .unwrap()
                .push((o.status, location, o.body.len()));
        }
    }

    #[tokio::test]
    async fn the_service_finding_names_a_redirect_it_did_not_follow() {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { return };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.test/\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let params: FpParams = serde_json::from_value(json!({
            "target": format!("http://127.0.0.1:{port}/"),
            "evasive": false,
            "favicon": false,
            "timeout_ms": 3000,
        }))
        .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let seen = std::sync::Arc::new(Seen::default());
        run(params, tx, seen.clone()).await;
        assert_eq!(
            *seen.0.lock().unwrap(),
            [(301, Some("https://www.example.test/".to_string()), 0)],
            "the page it saw is handed on to be kept"
        );
        let mut service = None;
        while let Ok(ev) = rx.try_recv() {
            if ev.pointer("/data/type") == Some(&json!("service")) {
                service = Some(ev["data"].clone());
            }
        }
        let service = service.expect("no service finding");
        assert_eq!(service["status_code"], 301);
        assert_eq!(
            service["redirect_location"], "https://www.example.test/",
            "{service}"
        );
    }
}

#[cfg(test)]
mod path_tests {
    //! The paths a signature asks for, against servers on 127.0.0.1: what is told apart,
    //! what is left a candidate, and how many requests one host is sent.
    use super::*;
    use crate::observe::{Observation, Observer};
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    /// Keeps nothing.
    struct Nowhere;

    impl Observer for Nowhere {
        async fn observed(&self, _: Observation<'_>) {}
    }

    /// A server answering each request with `route(path, n)`, n counting from 1, and the
    /// paths it was asked for, in order.
    fn serve(
        route: impl Fn(&str, usize) -> (u16, String) + Send + 'static,
    ) -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = asked.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&request);
                let path = line.split(' ').nth(1).unwrap_or("/").to_string();
                let n = {
                    let mut seen = seen.lock().unwrap();
                    seen.push(path.clone());
                    seen.len()
                };
                let (status, body) = route(&path, n);
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        (port, asked)
    }

    /// Framework A is three files. Framework B refines it: the same three and a fourth.
    fn frameworks() -> Signatures {
        let a = "{ path: { path: /a/one.js, regex: 'framework-a' } }, \
                 { path: { path: /a/two.js, regex: 'framework-a' } }, \
                 { path: { path: /a/three.css, regex: 'framework-a' } }";
        let files = [
            (
                "framework-a.yaml",
                format!(
                    "id: framework-a\ninfo: {{ name: Framework A, category: Test }}\n\
                     detect: {{ all: [ {a} ] }}\n"
                ),
            ),
            (
                "framework-b.yaml",
                format!(
                    "id: framework-b\ninfo: {{ name: Framework B, category: Test }}\n\
                     refines: framework-a\n\
                     detect: {{ all: [ {a}, {{ path: {{ path: /b/four.js, regex: 'framework-b' }} }} ] }}\n"
                ),
            ),
        ];
        let files: Vec<(&str, &str)> = files.iter().map(|(f, t)| (*f, t.as_str())).collect();
        let (signatures, skipped) = signatures::load_for_tests(&files);
        assert!(skipped.is_empty(), "{skipped:?}");
        signatures
    }

    /// What A's three files and, when `with_b`, B's fourth answer; anything else gets
    /// `otherwise(n)`.
    fn site(
        with_b: bool,
        otherwise: fn(usize) -> (u16, String),
    ) -> impl Fn(&str, usize) -> (u16, String) {
        move |path, n| match path {
            "/a/one.js" | "/a/two.js" | "/a/three.css" => (200, "/* framework-a */".into()),
            "/b/four.js" if with_b => (200, "/* framework-b */".into()),
            "/" => (200, "<html>home</html>".into()),
            _ => otherwise(n),
        }
    }

    /// Each technology found, with its candidates, and the paths the server was asked.
    async fn fingerprint(
        signatures: &Signatures,
        port: u16,
        tier: u8,
        asked: &Mutex<Vec<String>>,
    ) -> (Vec<(String, Vec<String>)>, Vec<String>) {
        let params: FpParams = serde_json::from_value(json!({
            "target": format!("http://127.0.0.1:{port}/"),
            "evasive": false,
            "timeout_ms": 3000,
            "depth_tier": tier,
        }))
        .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        scan(signatures, params, tx, Arc::new(Nowhere)).await;
        let mut found = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if event.pointer("/data/type") == Some(&json!("technology")) {
                let candidates = event["data"]["candidates"]
                    .as_array()
                    .expect("candidates")
                    .iter()
                    .map(|c| c.as_str().unwrap().to_string())
                    .collect();
                found.push((
                    event["data"]["name"].as_str().unwrap().to_string(),
                    candidates,
                ));
            }
        }
        (found, asked.lock().unwrap().clone())
    }

    fn named(name: &str, candidates: &[&str]) -> (String, Vec<String>) {
        (
            name.into(),
            candidates.iter().map(|c| c.to_string()).collect(),
        )
    }

    fn not_found(_: usize) -> (u16, String) {
        (404, "not found".into())
    }

    #[tokio::test]
    async fn framework_a_and_framework_b_are_told_apart() {
        let signatures = frameworks();

        let (port, asked) = serve(site(false, not_found));
        let (found, paths) = fingerprint(&signatures, port, STANDARD_TIER, &asked).await;
        assert_eq!(found, [named("Framework A", &[])]);
        assert_eq!(paths.len(), 2 + 2 + 4, "{paths:?}");

        let (port, asked) = serve(site(true, not_found));
        let (found, _) = fingerprint(&signatures, port, STANDARD_TIER, &asked).await;
        assert_eq!(found, [named("Framework B", &[])]);
    }

    /// On a server that answers 200 to every path, with a page that changes each time, B's
    /// fourth file cannot be told from what the server says for anything: "A, possibly B".
    /// When it says the same page for everything, the fourth path is that page, and the
    /// answer is A.
    #[tokio::test]
    async fn a_server_that_answers_every_path_leaves_b_a_candidate() {
        let signatures = frameworks();

        let (port, asked) = serve(site(false, |n| (200, format!("<html>request {n}</html>"))));
        let (found, _) = fingerprint(&signatures, port, STANDARD_TIER, &asked).await;
        assert_eq!(found, [named("Framework A", &["Framework B"])]);

        let (port, asked) = serve(site(false, |_| (200, "<html>welcome</html>".into())));
        let (found, _) = fingerprint(&signatures, port, STANDARD_TIER, &asked).await;
        assert_eq!(found, [named("Framework A", &[])]);
    }

    /// A passive scan sends nothing beyond the landing page, and a quiet one adds only the
    /// favicon, whatever the signatures would ask.
    #[tokio::test]
    async fn a_passive_scan_asks_for_the_landing_page_alone() {
        let signatures = frameworks();
        let (port, asked) = serve(site(true, not_found));
        let (found, paths) = fingerprint(&signatures, port, 0, &asked).await;
        assert_eq!(paths, ["/"]);
        assert!(found.is_empty(), "{found:?}");

        let (port, asked) = serve(site(true, not_found));
        let (_, paths) = fingerprint(&signatures, port, 1, &asked).await;
        assert_eq!(paths, ["/", "/favicon.ico"]);
    }

    /// One host is sent at most the landing page, the favicon and [`signatures::MAX_PATHS`]
    /// more, with every shipped signature loaded and with more path signatures than that,
    /// on a server whose every answer leaves them undecided.
    #[tokio::test]
    async fn one_host_is_asked_no_more_than_the_cap() {
        let cap = 2 + signatures::MAX_PATHS;
        let changing = |_: &str, n: usize| (200, format!("<html>request {n}</html>"));

        let (port, asked) = serve(changing);
        let (_, paths) = fingerprint(Signatures::shipped(), port, 3, &asked).await;
        assert!(paths.len() <= cap, "{} requests: {paths:?}", paths.len());

        let many: Vec<(String, String)> = (0..60)
            .map(|n| {
                (
                    format!("p{n}.yaml"),
                    format!(
                        "id: p{n}\ninfo: {{ name: P{n}, category: Test }}\n\
                         detect: {{ path: {{ path: /p{n}, regex: 'p{n}-marker' }} }}\n"
                    ),
                )
            })
            .collect();
        let files: Vec<(&str, &str)> = many.iter().map(|(f, t)| (f.as_str(), t.as_str())).collect();
        let (signatures, skipped) = signatures::load_for_tests(&files);
        assert!(skipped.is_empty(), "{skipped:?}");
        let (port, asked) = serve(changing);
        let (_, paths) = fingerprint(&signatures, port, 3, &asked).await;
        assert_eq!(paths.len(), cap, "{paths:?}");
        let unique: std::collections::BTreeSet<&String> = paths.iter().collect();
        assert_eq!(unique.len(), paths.len(), "a path asked twice: {paths:?}");
    }

    const STANDARD_TIER: u8 = signatures::STANDARD;
}
