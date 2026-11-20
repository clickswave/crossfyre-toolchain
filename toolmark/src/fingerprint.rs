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
    /// OPSEC depth tier: 0 passive, 1 quiet (favicon), 2 standard, 3 aggressive, 4
    /// rendered (the landing page built in a browser).
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

/// Why the rendered tier cannot run for an op with this egress, when it cannot. The
/// browser starts with no proxy of its own and cannot authenticate to the node's
/// SOCKS gateway, so through one it would load the page from this machine's address.
fn rendering_refused(egress: &transport::Egress) -> Option<&'static str> {
    egress.is_proxied().then_some(
        "the rendered tier did not run: the browser cannot go through the op's proxy, so it \
         would have loaded the page from this machine's own address",
    )
}

/// The documents the browser may load while rendering `target`: those of its origin,
/// and none at an internal address when `block_internal` is set.
fn rendering_gate(target: &transport::Url, block_internal: bool) -> cfx_browser::Gate {
    let origin = target.origin();
    std::sync::Arc::new(move |u: &str| {
        transport::Url::parse(u).is_ok_and(|u| {
            u.origin() == origin
                && !(block_internal
                    && u.host_str()
                        .is_some_and(transport::guard::is_internal_literal))
        })
    })
}

/// The landing page at `url` as a browser builds it, or why it was not built.
async fn render(params: &FpParams, url: &str) -> Result<String, String> {
    if let Some(why) = rendering_refused(&params.egress) {
        return Err(why.to_string());
    }
    let Some(exe) = cfx_browser::find_browser() else {
        return Err(
            "the rendered tier did not run: no browser was found. Set CFX_BROWSER to \
                    a Chrome or Chromium binary."
                .to_string(),
        );
    };
    let target = transport::Url::parse(url).map_err(|e| format!("the rendered tier: {e}"))?;
    let (browser, mut cdp) = cfx_browser::Browser::launch(&exe, cfx_browser::no_sandbox())
        .await
        .map_err(|e| format!("the rendered tier could not start a browser ({e})"))?;
    let gate = rendering_gate(&target, params.block_internal);
    let visit = cfx_browser::visit(&mut cdp, url, gate, params.block_internal).await;
    browser.shutdown().await;
    match visit {
        Ok(v) if v.final_url.is_some() => Ok(v.dom),
        Ok(_) => Err("the rendered tier could not load the page in the browser".to_string()),
        Err(e) => Err(format!("the rendered tier could not render the page ({e})")),
    }
}

/// Request auth resolved from a credential. Shared across all engines via
/// `transport`; re-exported so existing `AuthSpec` references in this module keep
/// resolving.
pub use transport::AuthSpec;

/// Fingerprint the target, sending what is found on `tx`, the pages seen to `observer`,
/// and the CVE leads of each technology from `cves`.
pub async fn run<O: crate::observe::Observer>(
    params: FpParams,
    tx: mpsc::UnboundedSender<Value>,
    observer: std::sync::Arc<O>,
    cves: std::sync::Arc<crate::cve::Cves>,
) {
    scan(Signatures::shipped(), params, tx, observer, &cves).await
}

/// [`run`] with `signatures` in place of the shipped ones.
async fn scan<O: crate::observe::Observer>(
    signatures: &Signatures,
    params: FpParams,
    tx: mpsc::UnboundedSender<Value>,
    observer: std::sync::Arc<O>,
    cves: &crate::cve::Cves,
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
    let (status, headers, body, cookies, tls) = match client.get(&url).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            // The certificate its server presented, or none when it came over plain HTTP.
            let tls = (r.url().scheme() == "https")
                .then(|| transport::peer_certificate(&r).map(<[u8]>::to_vec));
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
            (status, hdrs, body, cookies, tls)
        }
        Err(e) => {
            let _ = tx.send(json!({"type":"error","message":format!("fetch failed: {e}")}));
            let _ = tx.send(json!({"type":"done"}));
            return;
        }
    };

    observer
        .observed(crate::observe::Observation {
            asked: crate::observe::Asked::Landing,
            url: &url,
            host: &host,
            port,
            scheme: &scheme,
            status,
            headers: &headers,
            body: body.as_bytes(),
            moved: false,
            certificate: tls.as_ref().and_then(|c| c.as_deref()),
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
    match &tls {
        None => found.no_tls(),
        Some(Some(der)) => found.certificate(der),
        Some(None) => {}
    }
    let base = transport::Url::parse(&url).ok();
    signatures::ask(&mut found, |path, asked| {
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
                    asked,
                    url: target.as_str(),
                    host: &host,
                    port,
                    scheme: &scheme,
                    status,
                    headers: &headers,
                    body: &body,
                    moved,
                    certificate: None,
                })
                .await;
            signatures::Answered::new(status, moved, &body)
        }
    })
    .await;
    // At the rendered tier, the landing page as a browser builds it.
    if params.depth_tier >= signatures::RENDERED {
        match render(&params, &url).await {
            Ok(dom) => {
                // Read, and kept for rematch, no longer than a fetched page's body.
                let dom = capped(dom, MAX_BODY_BYTES);
                observer
                    .observed(crate::observe::Observation {
                        asked: crate::observe::Asked::Rendered,
                        url: &url,
                        host: &host,
                        port,
                        scheme: &scheme,
                        status,
                        headers: &[],
                        body: dom.as_bytes(),
                        moved: false,
                        certificate: None,
                    })
                    .await;
                found.rendered(dom);
            }
            Err(why) => {
                let _ = tx.send(json!({"type": "log", "message": why}));
            }
        }
    }
    let detections = found.detections();

    // One finding per detected technology.
    let mut cpes: Vec<String> = Vec::new();
    for d in &detections {
        if !d.cpe.is_empty() {
            cpes.push(d.cpe.clone());
        }
        let _ = tx.send(technology(d, &url, &host, port, &scheme));

        send_leads(&tx, cves, d, &url, &host, port, &scheme);
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

/// The finding for technology `d`, found at `url` on `host`:`port`.
pub fn technology(
    d: &signatures::Detection,
    url: &str,
    host: &str,
    port: u16,
    scheme: &str,
) -> Value {
    json!({
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
            "version_range": d.version_range.as_ref().map(|r| json!({
                "since": r.since.as_ref().map(ToString::to_string),
                "until": r.until.as_ref().map(ToString::to_string),
            })),
            "distro": d.distro,
        }
    })
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

/// Send the CVE leads for `d` at its version from `cves`, each saying which data it came
/// from. A lead is a version match, never confirmed.
pub(crate) fn send_leads(
    tx: &mpsc::UnboundedSender<Value>,
    cves: &crate::cve::Cves,
    d: &signatures::Detection,
    url: &str,
    host: &str,
    port: u16,
    scheme: &str,
) {
    let (Some(version), Some(name)) = (d.version.as_deref().filter(|v| !v.is_empty()), &d.cpe_name)
    else {
        return;
    };
    let (leads, from) = cves.leads(name, version, d.distro.as_deref());
    for lead in &leads {
        let _ = tx.send(cve_lead(lead, &from, d, url, host, port, scheme));
    }
}

/// One CVE lead as a finding: `d`, at its version, is in a range `lead` affects, by the
/// data `from` names.
fn cve_lead(
    lead: &cfx_cve::Lead,
    from: &str,
    d: &signatures::Detection,
    url: &str,
    host: &str,
    port: u16,
    scheme: &str,
) -> Value {
    let version = d.version.as_deref().unwrap_or_default();
    let reference = if lead.cve.starts_with("GHSA-") {
        format!("https://github.com/advisories/{}", lead.cve)
    } else {
        format!("https://nvd.nist.gov/vuln/detail/{}", lead.cve)
    };
    let exploited = if lead.known.kev {
        ", and it is on CISA's known-exploited list"
    } else {
        ""
    };
    let backport = if lead.backport {
        " The distribution that built it may have backported the fix."
    } else {
        ""
    };
    json!({
        "type": "finding",
        "data": {
            "target": url,
            "host": host, "port": port, "scheme": scheme,
            "type": "vulnerability",
            "source": "toolmark-cve",
            "severity": lead.known.severity.as_deref().unwrap_or("medium"),
            "name": format!("{} {version}: {}", d.name, lead.cve),
            "cve": lead.cve,
            "cvss": lead.known.score,
            "kev": lead.known.kev,
            "epss": lead.known.epss,
            "product": d.name,
            "version": version,
            "cpe": d.cpe_name.as_ref().map(ToString::to_string),
            "confidence": "version-inferred",
            "possible": lead.possible,
            "backport": lead.backport,
            "cve_data": from,
            "reference": reference,
            "description": format!(
                "{} {version} is in a version range {} affects{exploited}. A version match, not \
                 a confirmed finding: check the exact build.{backport}",
                d.name, lead.cve
            ),
        }
    })
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

/// `text` cut to at most `cap` bytes, where a character ends.
fn capped(mut text: String, cap: usize) -> String {
    let mut end = text.len().min(cap);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
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
        // A quiet scan, so the landing page is the only page asked for.
        let params: FpParams = serde_json::from_value(json!({
            "target": format!("http://127.0.0.1:{port}/"),
            "evasive": false,
            "favicon": false,
            "timeout_ms": 3000,
            "depth_tier": 1,
        }))
        .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let seen = std::sync::Arc::new(Seen::default());
        run(params, tx, seen.clone(), crate::cve::snapshot_for_tests()).await;
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

    /// The certificate the landing page's server presented reaches the signatures: a
    /// Traefik with no certificate for the name it was asked for shows its own.
    #[tokio::test]
    async fn the_landing_pages_certificate_is_read() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "TRAEFIK DEFAULT CERT");
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(der)],
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap(),
        );
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { return };
                let mut conn = rustls::ServerConnection::new(Arc::clone(&cfg)).unwrap();
                let mut tls = rustls::Stream::new(&mut conn, &mut s);
                let mut buf = [0u8; 4096];
                if matches!(tls.read(&mut buf), Ok(n) if n > 0) {
                    let _ = tls.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 18\r\n\
                          Connection: close\r\n\r\n404 page not found",
                    );
                    let _ = tls.flush();
                }
            }
        });
        let params: FpParams = serde_json::from_value(json!({
            "target": format!("https://127.0.0.1:{port}/"),
            "evasive": false,
            "timeout_ms": 3000,
            "depth_tier": 0,
            "favicon": false,
        }))
        .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        scan(
            Signatures::shipped(),
            params,
            tx,
            Arc::new(Nowhere),
            &crate::cve::snapshot_for_tests(),
        )
        .await;
        let mut named = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if event.pointer("/data/type") == Some(&json!("technology")) {
                named.push((
                    event["data"]["name"].clone(),
                    event["data"]["evidence"].clone(),
                ));
            }
        }
        assert_eq!(
            named,
            [(
                json!("Traefik"),
                json!(["certificate subject: CN=TRAEFIK DEFAULT CERT"])
            )]
        );
    }

    /// At the rendered tier a browser builds the landing page, and a `rendered` leaf
    /// reads what its script made; below the tier nothing is rendered. Skipped where no
    /// browser is found.
    #[tokio::test]
    async fn the_rendered_tier_reads_what_the_pages_script_built() {
        if cfx_browser::find_browser().is_none() {
            eprintln!("no browser on PATH; skipped");
            return;
        }
        let page = "<html><body><div id=\"app\"></div><script>document.getElementById('app')\
                    .innerHTML = '<p id=\"made-by-script\">hi</p>';</script></body></html>";
        let (port, asked) = serve(move |_, _| (200, page.to_string()));
        let (signatures, skipped) = signatures::load_for_tests(&[(
            "spa.yaml",
            "id: spa\ninfo: { name: Spa, category: Test }\n\
             detect: { rendered: { regex: 'id=\"made-by-script\"' } }\n",
        )]);
        assert!(skipped.is_empty(), "{skipped:?}");
        let (rendered, _) = fingerprint(&signatures, port, signatures::RENDERED, &asked).await;
        let (aggressive, _) = fingerprint(&signatures, port, 3, &asked).await;
        assert_eq!(rendered, [("Spa".to_string(), vec![])]);
        assert_eq!(aggressive, []);
    }

    /// What a scan handed on to be kept: what each page was asked for, and its body.
    #[derive(Default)]
    struct Kept(Mutex<Vec<(crate::observe::Asked, String)>>);

    impl Observer for Kept {
        async fn observed(&self, o: Observation<'_>) {
            let body = String::from_utf8_lossy(o.body).into_owned();
            self.0.lock().unwrap().push((o.asked, body));
        }
    }

    /// The page the browser built is handed on with the pages fetched, for rematch to
    /// read again. Skipped where no browser is found.
    #[tokio::test]
    async fn the_rendered_page_is_handed_on_to_be_kept() {
        if cfx_browser::find_browser().is_none() {
            eprintln!("no browser on PATH; skipped");
            return;
        }
        let page = "<html><body><div id=\"app\"></div><script>document.getElementById('app')\
                    .innerHTML = '<p id=\"made-by-script\">hi</p>';</script></body></html>";
        let (port, _) = serve(move |_, _| (200, page.to_string()));
        let (signatures, _) = signatures::load_for_tests(&[]);
        let params: FpParams = serde_json::from_value(json!({
            "target": format!("http://127.0.0.1:{port}/"),
            "evasive": false,
            "timeout_ms": 3000,
            "depth_tier": signatures::RENDERED,
        }))
        .unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        let kept = Arc::new(Kept::default());
        scan(
            &signatures,
            params,
            tx,
            kept.clone(),
            &crate::cve::snapshot_for_tests(),
        )
        .await;
        let rendered: Vec<String> = kept
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(asked, _)| *asked == crate::observe::Asked::Rendered)
            .map(|(_, body)| body.clone())
            .collect();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert!(
            rendered[0].contains("id=\"made-by-script\""),
            "{}",
            rendered[0]
        );
    }

    /// A rendered page is read and kept no longer than a fetched body, cut where a
    /// character ends.
    #[test]
    fn a_rendered_page_is_cut_at_the_cap_where_a_character_ends() {
        assert_eq!(capped("abcdef".into(), 4), "abcd");
        assert_eq!(capped("ab\u{e9}".into(), 3), "ab");
        assert_eq!(capped("abc".into(), 8), "abc");
    }

    /// The browser loads documents only from the target's origin, and no internal
    /// address when the op refuses them.
    #[test]
    fn the_browser_renders_only_the_targets_origin() {
        let target = transport::Url::parse("http://app.example.test:8080/").unwrap();
        let gate = rendering_gate(&target, false);
        assert!(gate("http://app.example.test:8080/dashboard"));
        assert!(!gate("http://app.example.test/"));
        assert!(!gate("https://app.example.test:8080/"));
        assert!(!gate("http://elsewhere.test:8080/"));
        let inside = transport::Url::parse("http://10.0.0.5/").unwrap();
        assert!(rendering_gate(&inside, false)("http://10.0.0.5/login"));
        assert!(!rendering_gate(&inside, true)("http://10.0.0.5/login"));
    }

    /// Through a proxy the browser would load the page from this machine's own
    /// address, so the rendered tier does not run, and says why.
    #[test]
    fn a_proxied_op_renders_nothing() {
        assert!(rendering_refused(&transport::Egress::Direct).is_none());
        let proxied = transport::Egress::Proxy("socks5h://127.0.0.1:1080".into());
        assert!(rendering_refused(&proxied).is_some_and(|why| why.contains("proxy")));
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
        scan(
            signatures,
            params,
            tx,
            Arc::new(Nowhere),
            &crate::cve::snapshot_for_tests(),
        )
        .await;
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

#[cfg(test)]
mod cve_lead_tests {
    //! The CVE leads a fingerprint sends for what it found, from the snapshot or from a
    //! dataset in the data folder.
    use super::*;
    use crate::observe::{Observation, Observer};
    use std::io::{Read, Write};

    struct Nowhere;

    impl Observer for Nowhere {
        async fn observed(&self, _: Observation<'_>) {}
    }

    /// A server whose every answer says it is `server`.
    fn server(server: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                    )
                    .as_bytes(),
                );
            }
        });
        port
    }

    /// The leads a quiet fingerprint of the server on `port` sends, with `cves`.
    async fn leads(port: u16, cves: &crate::cve::Cves) -> Vec<Value> {
        let params: FpParams = serde_json::from_value(json!({
            "target": format!("http://127.0.0.1:{port}/"),
            "evasive": false,
            "favicon": false,
            "timeout_ms": 3000,
            "depth_tier": 1,
        }))
        .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        scan(
            Signatures::shipped(),
            params,
            tx,
            std::sync::Arc::new(Nowhere),
            cves,
        )
        .await;
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if event.pointer("/data/type") == Some(&json!("vulnerability")) {
                out.push(event["data"].clone());
            }
        }
        out
    }

    fn named(leads: &[Value], cve: &str) -> bool {
        leads.iter().any(|l| l["cve"] == cve)
    }

    /// With no dataset, Apache 2.4.49 gives both of its path traversals from the
    /// snapshot, each a lead that says where it came from, and 2.4.51 gives neither.
    #[tokio::test]
    async fn apache_2_4_49_gives_its_path_traversals_from_the_snapshot() {
        let cves = crate::cve::snapshot_for_tests();
        let found = leads(server("Apache/2.4.49 (Unix)"), &cves).await;
        assert!(
            named(&found, "CVE-2021-41773") && named(&found, "CVE-2021-42013"),
            "{found:?}"
        );
        let lead = found.iter().find(|l| l["cve"] == "CVE-2021-41773").unwrap();
        assert_eq!(lead["cve_data"], crate::cve::SNAPSHOT_LABEL);
        assert_eq!(lead["confidence"], "version-inferred");
        assert_eq!(lead["cpe"], "a:apache:http_server");
        assert_eq!(lead["version"], "2.4.49");
        assert_eq!(
            (lead["kev"].as_bool(), lead["backport"].as_bool()),
            (Some(true), Some(false))
        );
        let later = leads(server("Apache/2.4.51 (Unix)"), &cves).await;
        assert!(!named(&later, "CVE-2021-41773") && !named(&later, "CVE-2021-42013"));
    }

    /// A dataset in the data folder answers in place of the snapshot, and its leads name
    /// it.
    #[tokio::test]
    async fn a_dataset_in_the_data_folder_gives_the_leads_and_is_named() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(
            folder.path().join(crate::cve::DATASET_FILE),
            r#"{"format": 1, "sequence": 4, "made": "2026-11-22T15:00:00Z",
                "products": [{"part": "a", "vendor": "apache", "product": "http_server",
                  "affected": [{"cve": "CVE-2099-0049", "ranges": [{"eq": "2.4.49"}]}]}],
                "cves": {"CVE-2099-0049": {"severity": "high", "score": 7.5}}}"#,
        )
        .unwrap();
        let cves = crate::cve::Cves::load(Some(folder.path()), &Signatures::shipped().cpes());
        let found = leads(server("Apache/2.4.49 (Unix)"), &cves).await;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0]["cve"], "CVE-2099-0049");
        assert_eq!(found[0]["cve_data"], "CVE dataset 4 of 2026-11-22");
        assert_eq!(
            (found[0]["severity"].as_str(), found[0]["cvss"].as_f64()),
            (Some("high"), Some(7.5))
        );
    }
}
