//! Web Tracer capture agent - Method 2 (local intercepting proxy, Burp-style).
//!
//! Instead of sniffing packets (Method 1 needs Wireshark + capture privileges), this runs an
//! in-process MITM proxy on `127.0.0.1`: the browser is pointed at it, HTTPS is terminated with a
//! per-host leaf cert minted on the fly from a session CA, and every request/response is reduced to
//! the same redacted [`TraceEvent`] shape and streamed to the control plane. The only prerequisite
//! is a browser - no external tools.
//!
//! The reduction + streaming pipeline (`redact_url` / `shape` / `Batcher` / `post_batch`) is shared
//! verbatim with Method 1; only the capture front-end differs. Forwarding to the origin uses the
//! crate's existing `reqwest` (redirects disabled so the browser still sees them; no body rewriting).

use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use super::trace::{Batcher, RawCapture, TraceConfig, TraceEvent, post_batch, shape};

type BoxErr = Box<dyn Error + Send + Sync>;
type Body = BoxBody<Bytes, Infallible>;

fn full(b: Bytes) -> Body {
    Full::new(b).boxed()
}
fn empty() -> Body {
    Empty::<Bytes>::new().boxed()
}

/// Chromium flags that suppress Google/Chrome background traffic so the capture is the operator's
/// browsing, not the browser phoning home (safebrowsing, optimization hints, account sync, component
/// and spellcheck-dictionary downloads, metrics, GCM, hyperlink auditing). Mirrors the quiet profile
/// Burp's embedded browser launches with.
const CHROMIUM_QUIET_FLAGS: &[&str] = &[
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--safebrowsing-disable-auto-update",
    "--disable-default-apps",
    "--disable-breakpad",
    "--metrics-recording-only",
    "--no-pings",
    "--no-service-autorun",
    "--password-store=basic",
    "--use-mock-keychain",
    "--disable-component-extensions-with-background-pages",
    "--disable-search-engine-choice-screen",
    "--disable-features=OptimizationHints,OptimizationGuideModelDownloading,Translate,MediaRouter,\
DialMediaRouteProvider,InterestFeedContentSuggestions,CalculateNativeWinOcclusion,\
AutofillServerCommunication,CertificateTransparencyComponentUpdater",
];

// ---------------------------------------------------------------------------
// Session CA + on-the-fly per-host leaf certs
// ---------------------------------------------------------------------------

/// The session CA machinery (mint, reload, per-SNI leaves, MITM acceptor) lives in the shared
/// [`capture`] module so the desktop proxy and the mobile netstack behave identically. This file
/// keeps only the DESKTOP-specific persistence + browser-trust plumbing around it.
use super::capture::{self, SessionCa};

/// On-disk home for the persistent CA: `~/.config/crossfyre/web-tracer/` (honors SUDO_USER, same
/// base as the node configs). Returns (cert path, key path).
fn ca_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = crate::toolchain::config::get_toolchain_dir().join("web-tracer");
    (dir.join("ca-cert.pem"), dir.join("ca-key.pem"))
}

/// Load the persisted CA if present, otherwise mint one and persist it. The key is the half that
/// matters for trust: as long as it is stable, every leaf the proxy mints verifies against the CA
/// the user already installed, so they install it exactly once.
fn load_or_generate_ca() -> Result<SessionCa, BoxErr> {
    let (cert_path, key_path) = ca_paths();
    if cert_path.exists() && key_path.exists() {
        match (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            (Ok(cert_pem), Ok(key_pem)) => match capture::load_ca(&cert_pem, &key_pem) {
                Ok(ca) => return Ok(ca),
                // A corrupt or partial file must not wedge tracing: regenerate and let the user
                // re-install the new CA once.
                Err(e) => eprintln!("web tracer: saved CA unreadable ({e}); regenerating"),
            },
            _ => eprintln!("web tracer: saved CA unreadable; regenerating"),
        }
    }
    let ca = capture::generate_ca()?;
    if let Some(parent) = cert_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&cert_path, ca.pem.as_bytes());
    if std::fs::write(&key_path, ca.key.serialize_pem().as_bytes()).is_ok() {
        // The CA private key can mint a trusted cert for ANY site: keep it owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(ca)
}

/// Pre-trust the session CA in a Firefox profile's NSS store via `certutil`, so the operator never
/// has to import it by hand. Each launch uses a throwaway profile that would otherwise start with an
/// empty trust store (which is why a persistent CA alone was not enough: the profile, not the CA, was
/// the thing being thrown away). Best-effort: returns false when `certutil` (from nss) is absent, and
/// the caller falls back to printing the manual-install steps.
fn firefox_trust_ca(profile: &std::path::Path, ca_pem: &std::path::Path) -> bool {
    use std::process::Command;
    let db = format!("sql:{}", profile.display());
    // A fresh profile has no NSS db yet; create one with an empty password (a no-op if it exists).
    let _ = Command::new("certutil")
        .args(["-N", "-d", &db, "--empty-password"])
        .output();
    Command::new("certutil")
        .args(["-A", "-n", "Crossfyre Web Tracer CA", "-t", "C,,", "-i"])
        .arg(ca_pem)
        .args(["-d", &db])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// The per-SNI resolver + leaf minting now live in `capture` (shared with the mobile netstack); the
// proxy builds its acceptor via `capture::mitm_acceptor` below.

// ---------------------------------------------------------------------------
// proxy
// ---------------------------------------------------------------------------

/// Headers that must not be forwarded across a proxy hop.
fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "host"
    )
}

/// Shared bits every connection/request handler needs.
#[derive(Clone)]
struct Ctx {
    client: reqwest::Client,
    acceptor: TlsAcceptor,
    tx: mpsc::Sender<TraceEvent>,
    scope: Option<String>,
    /// The session CA in PEM, served by the built-in cert portal (http://cfx).
    ca_pem: Arc<String>,
    /// Present only under `--seed-credentials`: the per-host auth material observed so far. When
    /// absent (the default) no secret value is ever read or retained.
    seed: Option<SeedStore>,
    /// The session's capture settings, fetched once at start from the control plane
    /// via the shared `cfx_capture::CaptureConfig`. When `full_capture` is on this
    /// proxy attaches the real bytes to each event, which is what the Requests tab
    /// and the Bench Repeater read.
    ///
    /// This used to be absent entirely: the desktop never asked for the config and
    /// never attached the bytes, so PC captures produced a populated Assets tab and
    /// a permanently empty Requests tab with no error anywhere.
    capture: Arc<cfx_capture::CaptureConfig>,
}

// ---------------------------------------------------------------------------
// Opt-in session-credential capture
// ---------------------------------------------------------------------------

/// The latest auth material seen for one host. Values refresh in place (sessions rotate); only the
/// most recent is kept. Populated exclusively when the operator passed `--seed-credentials`.
#[derive(Default, Clone)]
struct HostAuth {
    cookie: Option<String>,
    authorization: Option<String>,
    /// Original-cased custom auth-header name -> value.
    custom: HashMap<String, String>,
}

type SeedStore = Arc<Mutex<HashMap<String, HostAuth>>>;

/// Request headers (besides Cookie/Authorization) that carry an API credential. Deliberately a small
/// allowlist so ordinary headers (Content-Type, Accept, CSRF tokens, ...) are never captured.
const AUTH_HEADERS: &[&str] = &[
    "x-api-key",
    "apikey",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
];

/// The host[:port] a request targets, keeping a non-default port so it matches the asset graph's
/// host convention (and so two apps on the same host but different ports do not share a credential).
fn target_authority(base: &str, uri: &hyper::Uri) -> String {
    if base.is_empty() {
        let host = uri.host().unwrap_or("");
        match uri.port_u16() {
            Some(p)
                if !matches!(
                    (uri.scheme_str(), p),
                    (Some("http"), 80) | (Some("https"), 443) | (None, 80)
                ) =>
            {
                format!("{host}:{p}")
            }
            _ => host.to_string(),
        }
    } else {
        // MITM https: base is already "https://host" (default :443 elided upstream).
        base.trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    }
}

/// Record the auth material on one request against its host. No-op when nothing auth-bearing is present.
fn capture_auth(store: &SeedStore, host: &str, headers: &hyper::HeaderMap) {
    let cookie = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let authz = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut custom: Vec<(String, String)> = Vec::new();
    for (name, value) in headers.iter() {
        if AUTH_HEADERS.contains(&name.as_str().to_ascii_lowercase().as_str()) {
            if let Ok(v) = value.to_str() {
                custom.push((name.as_str().to_string(), v.to_string()));
            }
        }
    }
    if cookie.is_none() && authz.is_none() && custom.is_empty() {
        return;
    }
    let mut map = store.lock().unwrap();
    let e = map.entry(host.to_string()).or_default();
    if cookie.is_some() {
        e.cookie = cookie;
    }
    if authz.is_some() {
        e.authorization = authz;
    }
    for (k, v) in custom {
        e.custom.insert(k, v);
    }
}

/// Turn the captured material into the `{host, auth_type, config?, secret}` entries the seed endpoint
/// expects: Cookie -> cookie cred, `Authorization: Bearer x` -> bearer cred, any other Authorization
/// or allowlisted header -> header cred.
fn build_seed_creds(store: &SeedStore) -> Vec<serde_json::Value> {
    use serde_json::json;
    let map = store.lock().unwrap();
    let mut out = Vec::new();
    for (host, auth) in map.iter() {
        if let Some(cookie) = &auth.cookie {
            out.push(
                json!({ "host": host, "auth_type": "cookie", "secret": { "cookie": cookie } }),
            );
        }
        if let Some(a) = &auth.authorization {
            if a.to_ascii_lowercase().starts_with("bearer ") {
                let token = a[7..].trim().to_string();
                out.push(
                    json!({ "host": host, "auth_type": "bearer", "secret": { "token": token } }),
                );
            } else {
                out.push(json!({ "host": host, "auth_type": "header",
                    "config": { "header_name": "Authorization" }, "secret": { "header_value": a } }));
            }
        }
        for (name, val) in auth.custom.iter() {
            out.push(json!({ "host": host, "auth_type": "header",
                "config": { "header_name": name }, "secret": { "header_value": val } }));
        }
    }
    out
}

/// Magic hostnames the proxy answers itself (Burp-style) to hand out the CA,
/// instead of forwarding upstream. Reached because the browser sends proxied
/// requests by name without resolving DNS.
fn is_portal_host(host: &str) -> bool {
    matches!(
        host.trim().to_ascii_lowercase().as_str(),
        "cfx" | "crossfyre" | "cfx.trace" | "crossfyre.trace"
    )
}

/// The cert portal: a download endpoint for the CA (any `*ca.pem` / `*ca.crt` /
/// `/ca` / `/cert` path) and, for anything else, the install-instructions page.
fn portal_response(path: &str, ca_pem: &str) -> Response<Body> {
    let p = path.trim_end_matches('/').to_ascii_lowercase();
    let wants_cert = p == "/ca"
        || p == "/cert"
        || p == "/download"
        || p.ends_with("ca.pem")
        || p.ends_with("ca.crt");
    if wants_cert {
        return Response::builder()
            .status(200)
            .header("content-type", "application/x-x509-ca-cert")
            .header(
                "content-disposition",
                "attachment; filename=\"crossfyre-ca.pem\"",
            )
            .header("cache-control", "no-store")
            .body(full(Bytes::from(ca_pem.to_string())))
            .unwrap_or_else(|_| Response::new(empty()));
    }
    Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(full(Bytes::from(PORTAL_HTML)))
        .unwrap_or_else(|_| Response::new(empty()))
}

/// Forward one request to its origin, relay the response back, and emit a shape. `base` is empty for
/// a plain-HTTP request (the URI is already absolute) or `https://host` for a request read off a
/// MITM-terminated CONNECT tunnel (the URI is origin-form).
async fn forward(req: Request<Incoming>, base: &str, ctx: &Ctx) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Built-in cert portal (Burp-style). A request whose host is one of the magic
    // names is answered here - the CA download + install page - and never
    // forwarded upstream or recorded as a captured endpoint.
    let portal_host = if base.is_empty() {
        uri.host().unwrap_or("").to_string()
    } else {
        base.trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    };
    if is_portal_host(&portal_host) {
        return portal_response(uri.path(), &ctx.ca_pem);
    }

    let url = if base.is_empty() {
        uri.to_string()
    } else {
        format!("{base}{uri}")
    };
    let authed = req.headers().contains_key(hyper::header::AUTHORIZATION)
        || req.headers().contains_key(hyper::header::COOKIE);

    let (parts, body) = req.into_parts();

    // Opt-in credential capture (never runs unless --seed-credentials armed the store).
    if let Some(store) = &ctx.seed {
        capture_auth(store, &target_authority(base, &uri), &parts.headers);
    }

    // Content-Type is a structural, non-secret header describing the request contract; keep it.
    let content_type = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body_bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();

    // Body-side of the capture: field NAMES only (values discarded), mirroring the query-key rule.
    let body_params =
        crate::toolchain::trace::body_param_keys(content_type.as_deref(), &body_bytes);

    // Kept for full capture, which needs the real request bytes and headers. Cloned
    // before the body is moved into the upstream request. Skipped entirely when the
    // session is in shape-only mode, so the default path allocates nothing extra.
    let full_capture = ctx.capture.full_capture;
    let cap_req_headers = if full_capture {
        header_pairs(parts.headers.iter().map(|(n, v)| (n.as_str(), v)))
    } else {
        Vec::new()
    };
    // Raw bytes, not a String: attach_full decodes by content-encoding, and the
    // lossy conversion has to happen after that or a gzip body is destroyed.
    let cap_req_body: Vec<u8> = if full_capture {
        body_bytes.to_vec()
    } else {
        Vec::new()
    };
    let started = std::time::Instant::now();

    let mut rb = ctx.client.request(method.clone(), url.as_str());
    for (name, value) in parts.headers.iter() {
        if !is_hop_header(name.as_str()) {
            rb = rb.header(name.clone(), value.clone());
        }
    }
    rb = rb.body(body_bytes);

    match rb.send().await {
        Ok(resp) => {
            let status = resp.status();
            let server = resp
                .headers()
                .get(reqwest::header::SERVER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let raw = RawCapture {
                method: Some(method.as_str().to_string()),
                uri: Some(url.clone()),
                status: Some(status.as_u16() as i64),
                server,
                authed,
                content_type: content_type.clone(),
                body_params: body_params.clone(),
            };

            let mut builder = Response::builder().status(status);
            for (name, value) in resp.headers().iter() {
                if !is_hop_header(name.as_str()) {
                    builder = builder.header(name, value);
                }
            }
            let cap_resp_headers = if full_capture {
                header_pairs(resp.headers().iter().map(|(n, v)| (n.as_str(), v)))
            } else {
                Vec::new()
            };

            // The response body has to be read before the event can carry it, so the
            // event is emitted here rather than above. Ordering matters: the browser
            // still gets the identical bytes, we just also keep a copy.
            let bytes = resp.bytes().await.unwrap_or_default();

            // Emit the shape (scope-filtered). Response status + tech are known here, so unlike the
            // packet path this is one correlated event per request.
            if let Some(mut ev) = shape(&raw, ctx.scope.as_deref()) {
                if full_capture {
                    // One shared call rather than six hand-set fields. A half-filled
                    // full-capture event is stored without complaint and surfaces as
                    // an empty Requests tab rather than an error, which is exactly
                    // how this went unnoticed on the desktop path.
                    ev.attach_full(cfx_capture::FullExchange {
                        url: url.clone(),
                        req_headers: cap_req_headers,
                        req_body: cap_req_body,
                        resp_headers: cap_resp_headers,
                        resp_body: bytes.to_vec(),
                        duration_ms: Some(started.elapsed().as_millis() as u64),
                    });
                }
                let _ = ctx.tx.send(ev).await;
            }

            builder
                .body(full(bytes))
                .unwrap_or_else(|_| Response::new(empty()))
        }
        Err(e) => {
            let detail = upstream_error_detail(&e);
            eprintln!("[trace] upstream {method} {url} failed: {detail}");
            let msg = format!("crossfyre trace proxy: upstream error ({detail})");
            Response::builder()
                .status(502)
                .body(full(Bytes::from(msg)))
                .unwrap()
        }
    }
}

/// Fetch this session's capture settings from the control plane.
///
/// Transport only: the endpoint, the request shape, the parsing and the fallback
/// all live in `cfx_capture::CaptureConfig`, shared with the mobile client. That
/// split is deliberate. When the two clients each owned their own copy of "what
/// full capture means", one of them silently stopped implementing it.
async fn fetch_capture_config(
    client: &reqwest::Client,
    api_url: &str,
    workflow_id: &str,
    token: &str,
) -> cfx_capture::CaptureConfig {
    let url = format!(
        "{}{}",
        api_url.trim_end_matches('/'),
        cfx_capture::config::CONFIG_PATH
    );
    let body = cfx_capture::CaptureConfig::request_body(workflow_id, token);
    match client.post(&url).json(&body).send().await {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => cfx_capture::CaptureConfig::parse(&v),
            Err(e) => {
                eprintln!("[trace] capture config unreadable ({e}); using defaults");
                cfx_capture::CaptureConfig::default()
            }
        },
        Err(e) => {
            eprintln!("[trace] capture config fetch failed ({e}); using defaults");
            cfx_capture::CaptureConfig::default()
        }
    }
}

/// Flatten a header map into the ordered `[name, value]` pairs the captured-requests
/// store expects. Generic over the iterator so the same helper serves hyper's request
/// headers and reqwest's response headers; two near-identical copies is how the two
/// sides drift apart.
///
/// Non-UTF-8 header values are lossily decoded rather than dropped: a header that
/// exists is worth showing even if one byte is unprintable, and silently omitting it
/// would misrepresent the request that was actually sent.
fn header_pairs<'a, I>(iter: I) -> Vec<[String; 2]>
where
    I: Iterator<Item = (&'a str, &'a hyper::header::HeaderValue)>,
{
    iter.map(|(n, v)| {
        [
            n.to_string(),
            String::from_utf8_lossy(v.as_bytes()).to_string(),
        ]
    })
    .collect()
}

/// reqwest's `Display` collapses to "error sending request for url (...)" and hides WHY. Walk the
/// source chain (the TLS handshake failure, connection refused, timeout, DNS error, ...) and label
/// the kind, so the operator sees the real cause instead of a dead-end. A common one against old
/// government / enterprise sites is a TLS handshake failure: the server only offers a legacy cipher
/// (RSA key exchange / CBC, e.g. TLS_RSA_WITH_AES_128_CBC_SHA256) that the proxy's rustls stack does
/// not implement - that surfaces here as "connect: ... handshake ...".
fn upstream_error_detail(e: &reqwest::Error) -> String {
    let kind = if e.is_connect() {
        "connect"
    } else if e.is_timeout() {
        "timeout"
    } else if e.is_redirect() {
        "redirect"
    } else if e.is_body() {
        "body"
    } else {
        "request"
    };
    let mut chain: Vec<String> = Vec::new();
    let mut src: Option<&(dyn Error + 'static)> = e.source();
    while let Some(s) = src {
        let m = s.to_string();
        if chain.last().map(|p| p != &m).unwrap_or(true) {
            chain.push(m);
        }
        src = s.source();
    }
    if chain.is_empty() {
        format!("{kind}: {e}")
    } else {
        format!("{kind}: {}", chain.join(": "))
    }
}

/// The service for one browser connection: CONNECT is MITM'd (TLS-terminated, then re-served), any
/// other method is a plain-HTTP proxy request.
async fn handle(req: Request<Incoming>, ctx: Ctx) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::CONNECT {
        let Some(authority) = req.uri().authority().cloned() else {
            return Ok(Response::builder().status(400).body(empty()).unwrap());
        };
        let host = authority.host().to_string();
        let ctx2 = ctx.clone();
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(req).await {
                let tls = match ctx2.acceptor.accept(TokioIo::new(upgraded)).await {
                    Ok(t) => t,
                    Err(_) => return, // browser rejected the cert (CA not trusted) or handshake failed
                };
                let base = format!("https://{host}");
                let inner = ctx2.clone();
                let svc = service_fn(move |r| {
                    let inner = inner.clone();
                    let base = base.clone();
                    async move { Ok::<_, Infallible>(forward(r, &base, &inner).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            }
        });
        // 200 lets the browser proceed to the TLS handshake we then intercept.
        Ok(Response::new(empty()))
    } else {
        Ok(forward(req, "", &ctx).await)
    }
}

/// Accept loop: one task per browser connection.
async fn serve(listener: TcpListener, ctx: Ctx) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(req, ctx.clone()));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades()
                .await;
        });
    }
}

/// Run a capture session using the local proxy. Mirrors `trace::run`'s batching/flush loop but the
/// events come from the proxy (via a channel) instead of tshark lines.
pub async fn run_proxy(cfg: TraceConfig) -> Result<(), BoxErr> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = Arc::new(load_or_generate_ca()?);
    let acceptor = capture::mitm_acceptor(ca.clone());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(false)
        // OpenSSL, not rustls, for the upstream leg: a MITM proxy must reach whatever TLS the origin
        // offers, including legacy RSA-kx / CBC ciphers that rustls refuses (e.g. many old gov and
        // enterprise sites). OpenSSL still negotiates those, so browsing through the proxy works
        // wherever the browser itself would. Scoped here only; other clients keep rustls.
        .use_native_tls()
        // Bound the connect/handshake so an unreachable or stalled origin returns a clear 502 to the
        // browser instead of hanging the tab. No overall timeout: large downloads/streams must survive.
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()?;

    let addr = format!("127.0.0.1:{}", cfg.proxy_port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("cannot bind proxy on {addr}: {e}"))?;
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or(addr.clone());

    // Write the CA so a bring-your-own browser can trust it.
    let ca_path = std::env::temp_dir().join(format!("cfx-trace-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_path, ca.pem.as_bytes()).ok();

    println!(
        "Web Tracer: local proxy on {bound} (session {})",
        cfg.workflow_id
    );
    println!(
        "  CA cert: {} (install it to trace with your own browser)",
        ca_path.display()
    );
    println!("  or browse to http://cfx through the proxy to download + install it");

    // Armed only under --seed-credentials; otherwise no secret is ever read.
    let seed_store: Option<SeedStore> = if cfg.seed_credentials {
        println!(
            "  --seed-credentials: session auth for the hosts you browse will be saved to the arsenal"
        );
        Some(Arc::new(Mutex::new(HashMap::new())))
    } else {
        None
    };

    // Ask the control plane what this session wants captured. The desktop never
    // used to do this, which is the entire reason PC traces produced an empty
    // Requests tab: the server was gating on `full_capture` while the client had
    // no idea the setting existed and never sent the bytes it gates.
    //
    // A failed fetch falls back to CaptureConfig::default() (full capture ON), the
    // same default the shared crate documents, so a control plane blip degrades to
    // capturing more rather than to silently capturing nothing useful.
    let capture = fetch_capture_config(&client, &cfg.api_url, &cfg.workflow_id, &cfg.token).await;
    println!(
        "  capture mode: {}",
        if capture.full_capture {
            "full (headers + bodies -> Requests tab)"
        } else {
            "shape only (Assets tab; Requests tab will stay empty)"
        }
    );

    let (tx, mut rx) = mpsc::channel::<TraceEvent>(1024);
    let ctx = Ctx {
        client,
        acceptor,
        tx,
        scope: cfg.host_filter.clone(),
        ca_pem: Arc::new(ca.pem.clone()),
        seed: seed_store.clone(),
        capture: Arc::new(capture),
    };
    tokio::spawn(serve(listener, ctx));

    // Launch a browser pointed at the proxy, isolated so it can't clobber the user's real profile.
    // --ignore-certificate-errors means the launched browser trusts our MITM cert without installing
    // the CA (it's an ephemeral, operator-controlled profile).
    let mut browser_child = None;
    if let Some(browser) = &cfg.browser {
        let bin = super::trace::browser_binary(browser);
        // Firefox and Chromium point at a proxy in completely different ways:
        // Chromium takes CLI flags, Firefox takes profile prefs and ignores the
        // Chromium flags entirely (which is why `--browser firefox*` captured
        // nothing before). Branch on the family.
        let is_firefox = bin.contains("firefox");
        let profile =
            std::env::temp_dir().join(format!("cfx-trace-profile-{}", std::process::id()));
        let mut cmd = tokio::process::Command::new(&bin);
        let mut ca_trusted = false;
        if is_firefox {
            // Firefox: an isolated profile whose prefs route through the proxy.
            // `allow_hijacking_localhost` is the key one - Firefox, like Chromium,
            // bypasses loopback by default, so without it a http://localhost
            // target never reaches the proxy. HTTPS needs the CA trusted; Firefox has
            // its own trust store with no --ignore-certificate-errors equivalent, so
            // we pre-install the CA into this profile via certutil below.
            let _ = std::fs::create_dir_all(&profile);
            ca_trusted = firefox_trust_ca(&profile, &ca_path);
            // `bound` is "127.0.0.1:<port>"; pull the port for the profile prefs.
            let port = bound
                .rsplit(':')
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or_default();
            // Proxy prefs, then the Firefox equivalent of CHROMIUM_QUIET_FLAGS:
            // silence captive-portal detection (detectportal success.txt), the
            // connectivity checks (success.txt?ipv4/ipv6, generate_204), Remote
            // Settings, safebrowsing updates, telemetry, update pings, region +
            // discovery services and Activity Stream feeds - so the capture is the
            // operator's browsing, not Firefox phoning home.
            let prefs = format!(
                "user_pref(\"network.proxy.type\", 1);\n\
                 user_pref(\"network.proxy.http\", \"127.0.0.1\");\n\
                 user_pref(\"network.proxy.http_port\", {port});\n\
                 user_pref(\"network.proxy.ssl\", \"127.0.0.1\");\n\
                 user_pref(\"network.proxy.ssl_port\", {port});\n\
                 user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n\
                 user_pref(\"network.proxy.no_proxies_on\", \"\");\n\
                 user_pref(\"security.enterprise_roots.enabled\", true);\n\
                 user_pref(\"browser.shell.checkDefaultBrowser\", false);\n\
                 user_pref(\"network.captive-portal-service.enabled\", false);\n\
                 user_pref(\"network.connectivity-service.enabled\", false);\n\
                 user_pref(\"captivedetect.canonicalURL\", \"\");\n\
                 user_pref(\"services.settings.server\", \"\");\n\
                 user_pref(\"browser.safebrowsing.malware.enabled\", false);\n\
                 user_pref(\"browser.safebrowsing.phishing.enabled\", false);\n\
                 user_pref(\"browser.safebrowsing.downloads.enabled\", false);\n\
                 user_pref(\"browser.safebrowsing.provider.google4.updateURL\", \"\");\n\
                 user_pref(\"browser.safebrowsing.provider.mozilla.updateURL\", \"\");\n\
                 user_pref(\"extensions.blocklist.enabled\", false);\n\
                 user_pref(\"app.update.enabled\", false);\n\
                 user_pref(\"app.update.auto\", false);\n\
                 user_pref(\"browser.region.network.url\", \"\");\n\
                 user_pref(\"browser.region.update.enabled\", false);\n\
                 user_pref(\"browser.discovery.enabled\", false);\n\
                 user_pref(\"browser.ping-centre.telemetry\", false);\n\
                 user_pref(\"browser.newtabpage.activity-stream.feeds.telemetry\", false);\n\
                 user_pref(\"browser.newtabpage.activity-stream.telemetry\", false);\n\
                 user_pref(\"browser.newtabpage.activity-stream.feeds.snippets\", false);\n\
                 user_pref(\"browser.newtabpage.activity-stream.feeds.section.topstories\", false);\n\
                 user_pref(\"browser.newtabpage.activity-stream.default.sites\", \"\");\n\
                 user_pref(\"dom.push.enabled\", false);\n\
                 user_pref(\"extensions.getAddons.cache.enabled\", false);\n\
                 user_pref(\"extensions.systemAddon.update.enabled\", false);\n\
                 user_pref(\"network.prefetch-next\", false);\n\
                 user_pref(\"datareporting.healthreport.uploadEnabled\", false);\n\
                 user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);\n\
                 user_pref(\"toolkit.telemetry.enabled\", false);\n\
                 user_pref(\"toolkit.telemetry.unified\", false);\n\
                 user_pref(\"toolkit.telemetry.archive.enabled\", false);\n\
                 user_pref(\"toolkit.telemetry.server\", \"\");\n\
                 user_pref(\"app.normandy.enabled\", false);\n\
                 user_pref(\"app.normandy.first_run\", false);\n\
                 user_pref(\"app.shield.optoutstudies.enabled\", false);\n\
                 user_pref(\"browser.aboutwelcome.enabled\", false);\n\
                 user_pref(\"browser.startup.homepage_override.mstone\", \"ignore\");\n"
            );
            let _ = std::fs::write(profile.join("user.js"), &prefs);
            cmd.arg("--no-remote")
                .arg("--profile")
                .arg(&profile)
                .arg("about:blank");
        } else {
            // Chromium family: --proxy-server routes both HTTP and HTTPS (via
            // CONNECT). --proxy-bypass-list=<-loopback> is essential for testing a
            // local app - Chromium bypasses loopback by default, so without it a
            // http://localhost target never hits the proxy. --ignore-certificate
            // -errors lets the ephemeral profile trust our MITM cert without
            // installing the CA.
            cmd.arg(format!("--proxy-server={bound}"))
                .arg("--proxy-bypass-list=<-loopback>")
                .arg(format!("--user-data-dir={}", profile.display()))
                .arg("--ignore-certificate-errors");
            // Silence background/telemetry traffic (safebrowsing, optimization
            // hints, account sync, component/dictionary downloads, the New Tab
            // Page's promos/doodles, GCM, metrics) so the capture is the operator's
            // browsing, not Google phoning home - the same reason Burp's embedded
            // browser is quiet.
            for flag in CHROMIUM_QUIET_FLAGS {
                cmd.arg(flag);
            }
            cmd.arg("about:blank");
        }
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        match cmd.spawn() {
            Ok(c) => {
                println!("  launched {bin} through the proxy (isolated profile)");
                if is_firefox {
                    if ca_trusted {
                        println!(
                            "  firefox: CA auto-trusted in this profile - HTTPS captures immediately, nothing to import"
                        );
                    } else {
                        println!(
                            "  firefox: HTTP captures now; for HTTPS import the CA above (Settings -> Privacy -> Certificates), or install `certutil` (nss) so it auto-trusts next time"
                        );
                    }
                }
                browser_child = Some(c);
            }
            Err(e) => eprintln!(
                "  could not launch {bin} ({e}); point your browser at http://{bound} and trust the CA above"
            ),
        }
    } else {
        println!(
            "  point your browser's HTTP/HTTPS proxy at {bound}, trust the CA, then browse your target"
        );
    }
    println!("  browsing captures into the session; Ctrl-C (or close the browser) to end.");

    // Batch + flush loop.
    let post_client = reqwest::Client::new();
    let mut batcher = Batcher::new(cfg.batch_size);
    let mut total = 0usize;
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(cfg.flush_secs.max(1)));
    // Signature of the last-seeded credential set, so periodic seeding re-posts only when the
    // observed session auth actually changed (a new host, or a rotated secret).
    let mut last_seed_sig: Option<String> = None;

    loop {
        tokio::select! {
            ev = rx.recv() => {
                match ev {
                    Some(ev) => {
                        if let Some(batch) = batcher.push(ev) {
                            match post_batch(&post_client, &cfg, &batch, false).await {
                                Ok(n) => { total += n; print!("\r  captured {total} endpoints"); let _ = std::io::Write::flush(&mut std::io::stdout()); }
                                Err(e) => eprintln!("\n  ingest error: {e}"),
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                if !batcher.is_empty() {
                    let batch = batcher.drain();
                    if let Ok(n) = post_batch(&post_client, &cfg, &batch, false).await { total += n; }
                }
                // Seed observed session credentials live, so they land in the arsenal while the
                // operator is still browsing instead of only at Ctrl-C. Idempotent upsert on the
                // server; skip the round-trip when nothing changed since the last seed.
                if let Some(store) = &seed_store {
                    let creds = build_seed_creds(store);
                    if !creds.is_empty() {
                        let sig = serde_json::to_string(&creds).unwrap_or_default();
                        if last_seed_sig.as_deref() != Some(sig.as_str()) {
                            match super::trace::post_seed_credentials(&post_client, &cfg, &creds).await {
                                Ok(_) => last_seed_sig = Some(sig),
                                Err(e) => eprintln!("\n  credential seed error: {e}"),
                            }
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => { println!("\n  stopping…"); break; }
        }
    }

    // Seed captured credentials while the session is still live (before the final `ended` flush).
    if let Some(store) = &seed_store {
        let creds = build_seed_creds(store);
        if !creds.is_empty() {
            match super::trace::post_seed_credentials(&post_client, &cfg, &creds).await {
                Ok(n) => println!("\n  seeded {n} session credential(s) to the arsenal"),
                Err(e) => eprintln!("\n  credential seed error: {e}"),
            }
        }
    }

    let tail = batcher.drain();
    if let Err(e) = post_batch(&post_client, &cfg, &tail, true).await {
        eprintln!("  final flush error: {e}");
    }
    if let Some(mut b) = browser_child {
        let _ = b.start_kill();
    }
    let _ = std::fs::remove_file(&ca_path);
    println!("\nWeb Tracer: session ended, {total} endpoints captured.");
    Ok(())
}

/// The cert-install portal served at http://cfx (Burp-style). Self-contained
/// (inline CSS, no external assets) so it renders with the browser offline from
/// everything but this proxy. The download button hits `/crossfyre-ca.pem`,
/// which `portal_response` serves as the CA.
const PORTAL_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Crossfyre Web Tracer - Install CA</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0b0b0e; color: #e4e4e7; font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: 720px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
  .brand { display: flex; align-items: center; gap: .6rem; font-weight: 800; letter-spacing: .01em; font-size: 1.05rem; }
  .brand .dot { width: 11px; height: 11px; border-radius: 50%; background: #ff6b35; box-shadow: 0 0 14px rgba(255,107,53,.7); }
  .brand .sub { color: #71717a; font-weight: 600; }
  h1 { font-size: 1.7rem; margin: 1.4rem 0 .4rem; font-weight: 800; }
  .lede { color: #a1a1aa; margin: 0 0 1.6rem; }
  .card { background: rgba(255,255,255,.03); border: 1px solid rgba(255,255,255,.09); border-radius: 14px; padding: 1.25rem 1.35rem; margin: 1rem 0; }
  .dl { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; background: linear-gradient(90deg, rgba(255,107,53,.12), rgba(255,107,53,.03)); border-color: rgba(255,107,53,.3); }
  .dl .txt { flex: 1; min-width: 220px; }
  .dl .txt b { display: block; font-size: 1.05rem; }
  .dl .txt span { color: #a1a1aa; font-size: .85rem; }
  a.btn { display: inline-flex; align-items: center; gap: .5rem; background: #ff6b35; color: #12100e; font-weight: 700; text-decoration: none; padding: .7rem 1.15rem; border-radius: 10px; border: 1px solid #ff6b35; white-space: nowrap; transition: filter .15s; }
  a.btn:hover { filter: brightness(1.08); }
  h2 { font-size: 1.02rem; margin: 1.6rem 0 .6rem; }
  details { border: 1px solid rgba(255,255,255,.09); border-radius: 10px; margin: .5rem 0; background: rgba(255,255,255,.02); }
  summary { cursor: pointer; padding: .7rem .95rem; font-weight: 650; list-style: none; display: flex; align-items: center; gap: .5rem; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: "+"; color: #ff8c5a; font-weight: 800; }
  details[open] summary::before { content: "-"; }
  .body { padding: 0 .95rem 1rem 2rem; color: #c9c9d1; font-size: .9rem; }
  ol { margin: .3rem 0; padding-left: 1.1rem; }
  li { margin: .3rem 0; }
  code { background: #16161a; border: 1px solid rgba(255,255,255,.1); border-radius: 5px; padding: .05rem .4rem; font-family: ui-monospace, "JetBrains Mono", monospace; font-size: .85em; color: #ffd3bf; }
  pre { background: #16161a; border: 1px solid rgba(255,255,255,.1); border-radius: 8px; padding: .7rem .85rem; overflow-x: auto; font-family: ui-monospace, monospace; font-size: .82rem; color: #d6f9e4; }
  .note { color: #71717a; font-size: .82rem; margin-top: 1.4rem; }
  .kbd { color: #ff8c5a; font-weight: 600; }
</style>
</head>
<body>
<div class="wrap">
  <div class="brand"><span class="dot"></span> Crossfyre <span class="sub">/ Web Tracer</span></div>
  <h1>Install the trace CA</h1>
  <p class="lede">You're browsing through the Crossfyre trace proxy. To read <b>HTTPS</b> traffic, your browser needs to trust this session's certificate authority. It's ephemeral - minted for this capture only.</p>

  <div class="card dl">
    <div class="txt">
      <b>CA certificate</b>
      <span>crossfyre-ca.pem - trust it as a website-identifying authority.</span>
    </div>
    <a class="btn" href="/crossfyre-ca.pem" download>Download CA certificate</a>
  </div>

  <h2>Install it</h2>

  <details open>
    <summary>Chrome / Edge / Brave / Chromium</summary>
    <div class="body">
      <ol>
        <li>Open <span class="kbd">Settings -> Privacy and security -> Security -> Manage certificates</span> (or visit <code>chrome://certificate-manager</code>).</li>
        <li>Go to the <b>Authorities</b> tab and click <b>Import</b>.</li>
        <li>Select the downloaded <code>crossfyre-ca.pem</code>.</li>
        <li>Tick <b>Trust this certificate for identifying websites</b>, then OK.</li>
        <li>Reload your target and keep browsing - HTTPS now captures.</li>
      </ol>
      <p>On macOS/Windows, Chrome and Edge use the OS trust store instead - see those tabs below.</p>
    </div>
  </details>

  <details>
    <summary>Firefox</summary>
    <div class="body">
      <ol>
        <li>Open <span class="kbd">Settings -> Privacy &amp; Security -> Certificates -> View Certificates</span>.</li>
        <li>On the <b>Authorities</b> tab, click <b>Import</b> and pick <code>crossfyre-ca.pem</code>.</li>
        <li>Tick <b>Trust this CA to identify websites</b>, then OK.</li>
      </ol>
      <p>Firefox has its own trust store, so this is needed even if the OS already trusts the CA. The browser Crossfyre launches for you sets the proxy automatically; you still import the CA here for HTTPS.</p>
    </div>
  </details>

  <details>
    <summary>macOS (system trust - Safari, Chrome, Edge)</summary>
    <div class="body">
      <ol>
        <li>Double-click <code>crossfyre-ca.pem</code> to open it in <b>Keychain Access</b> (add to the <b>login</b> or <b>System</b> keychain).</li>
        <li>Find <b>Crossfyre</b> under Certificates, double-click it.</li>
        <li>Expand <b>Trust</b>, set <b>When using this certificate</b> to <b>Always Trust</b>, close, and authenticate.</li>
      </ol>
      <p>Or via terminal:</p>
      <pre>sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain crossfyre-ca.pem</pre>
    </div>
  </details>

  <details>
    <summary>Windows (system trust - Chrome, Edge)</summary>
    <div class="body">
      <ol>
        <li>Rename the file to <code>crossfyre-ca.crt</code> and double-click it.</li>
        <li>Click <b>Install Certificate</b> -> <b>Current User</b> (or Local Machine).</li>
        <li>Choose <b>Place all certificates in the following store</b> -> <b>Trusted Root Certification Authorities</b>.</li>
        <li>Finish and accept the security prompt.</li>
      </ol>
    </div>
  </details>

  <details>
    <summary>Linux (system trust)</summary>
    <div class="body">
      <p>Debian / Ubuntu:</p>
      <pre>sudo cp crossfyre-ca.pem /usr/local/share/ca-certificates/crossfyre-ca.crt
sudo update-ca-certificates</pre>
      <p>Fedora / RHEL:</p>
      <pre>sudo cp crossfyre-ca.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust</pre>
      <p>Chrome/Chromium on Linux keep their own NSS store; the Authorities-tab import above is the reliable path there.</p>
    </div>
  </details>

  <p class="note">Plain <b>HTTP</b> targets capture without any of this - the CA is only for decrypting HTTPS. When the capture ends, the CA is gone; remove it from your trust store afterwards if you like.</p>
</div>
</body>
</html>"#;
