//! The Scout fingerprint engine (S1): fetch a target service, collect signals,
//! run the signature engine, hash the favicon, detect WAF/CDN, and stream
//! findings. Each finding is a serde value the node relays verbatim into the
//! shared asset graph.

use crate::signatures;
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

pub async fn run(params: FpParams, tx: mpsc::UnboundedSender<Value>) {
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
    let client = match transport::build_scan_client(transport::ScanClient {
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
        resolve: Vec::new(),
        ..Default::default()
    }) {
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
            let body = read_body_capped(r).await;
            (status, hdrs, body, cookies)
        }
        Err(e) => {
            let _ = tx.send(json!({"type":"error","message":format!("fetch failed: {e}")}));
            let _ = tx.send(json!({"type":"done"}));
            return;
        }
    };

    let title = extract_title(&body);
    let server = signatures::header_val(&headers, "server");
    let detections = signatures::detect(&headers, &cookies, &body);
    let (waf, cdn) = signatures::waf_cdn(&headers, &cookies);

    let favicon = if params.favicon && params.depth_tier >= 1 {
        fetch_favicon(&client, &scheme, &host, port).await
    } else {
        Value::Null
    };

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
                "source": "scout",
                "severity": "info",
                "name": d.name,
                "category": d.category,
                "version": d.version,
                "cpe": d.cpe,
                "confidence": d.confidence,
                "evidence": d.evidence,
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
                        "source": "scout-cve",
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
            "source": "scout",
            "severity": "info",
            "status_code": status,
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

    // Run-level environment record (the Cortex control plane).
    let waf_present = !waf.is_null();
    let _ = tx.send(json!({
        "type": "finding",
        "data": {
            "target": url,
            "host": host, "port": port,
            "type": "environment",
            "source": "scout",
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

async fn read_body_capped(resp: transport::Response) -> String {
    String::from_utf8_lossy(&read_bytes_capped(resp).await).into_owned()
}

async fn read_bytes_capped(mut resp: transport::Response) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < MAX_BODY_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = MAX_BODY_BYTES - buf.len();
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
            let b = read_bytes_capped(r).await;
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
