//! Per-flow MITM inspect + forward: the shared heart of the tracer. Given one client TCP flow whose
//! intended destination is known (`target_host:target_port`), terminate its TLS as that host (session
//! CA leaf), read each HTTP/1 request, reduce it to a privacy-safe [`TraceEvent`], forward it to the
//! origin through the chosen [`Egress`], stream the response back, and emit the event.
//!
//! The desktop proxy hands this an accepted CONNECT socket; the mobile netstack hands it a TCP flow
//! reassembled off the TUN fd. Same code either way.

use std::error::Error;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, SERVER};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;
use tokio_rustls::TlsConnector;

use crate::reduce::{TraceEvent, body_field_names, redact_url};
use crate::{CaptureCfg, EditedRequest, Egress, InterceptDecision, SessionCa, mitm_acceptor};

type BoxErr = Box<dyn Error + Send + Sync>;

/// A rustls client config trusting the Mozilla webpki roots, for the UPSTREAM (origin) leg. Built
/// once. Cross-compiles to Android (pure-Rust roots), unlike a native-tls upstream.
static UPSTREAM_TLS: LazyLock<TlsConnector> = LazyLock::new(|| {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
});

/// The same leg, accepting whatever certificate the origin presents.
///
/// For targets behind a corporate CA or a self-signed certificate, which is a large share
/// of the internal applications this tool exists to test. Until this existed the webpki
/// roots were the only trust anchor, so such a target could not be forwarded to at all:
/// the client leg succeeded, the forward leg refused, and the operator saw a 502 with no
/// explanation. Meanwhile `cortex`, `scout` and `voyage` have always accepted invalid
/// certificates, so the product disagreed with itself.
///
/// Reached only when a flow's [`CaptureCfg::trust_any_upstream_cert`] is set, which is
/// off by default and a per-project decision the operator makes deliberately. It is a real
/// loss of protection and not a convenience: with it on, a machine-in-the-middle between
/// the proxy and the origin is indistinguishable from the origin. That is the same trade
/// Burp makes, and the reason it belongs to a project rather than to a build.
static UPSTREAM_TLS_TRUST_ANY: LazyLock<TlsConnector> = LazyLock::new(|| {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnyServerCert(Arc::new(provider))))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
});

/// Accepts any server certificate. Signature checking is still real: only the question of
/// WHO the certificate belongs to is skipped, because that is the question a private CA
/// cannot answer to a public root store.
#[derive(Debug)]
struct TrustAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for TrustAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Serve one captured client flow: MITM-terminate it, then inspect + forward every request on it.
/// Generic over the client stream so both a tokio `TcpStream` (desktop CONNECT proxy) and a userspace
/// netstack flow (mobile TUN) work. `target_host`/`target_port` is the flow's original destination and
/// is used as the forwarding fallback when a request carries no Host header. Returns when the client
/// closes the connection.
/// What a finished flow turned out to be.
///
/// `tls` with zero `requests` is the signature of certificate pinning done in
/// application code: the TLS handshake completes (the app trusts our CA at the
/// platform level, which is what patching arranges), and then the pinner rejects
/// the certificate and closes before sending a byte. Without this distinction
/// that flow is indistinguishable from an idle connection, so a pinned API looks
/// like "nothing happened" rather than "we were refused".
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowOutcome {
    pub tls: bool,
    pub requests: usize,
    /// Carried through without interception, by operator choice.
    pub bypassed: bool,
}

pub async fn serve_mitm_flow<C>(
    client: C,
    target_host: String,
    target_port: u16,
    ca: Arc<SessionCa>,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
    cfg: CaptureCfg,
) -> Result<FlowOutcome, BoxErr>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Peek the first byte to tell TLS from plaintext HTTP without relying on the port (HTTPS runs on
    // many ports). A TLS record starts with 0x16 (handshake); anything else we treat as plaintext.
    let mut client = client;
    let mut first = [0u8; 1];
    let n = client.read(&mut first).await?;
    if n == 0 {
        return Ok(FlowOutcome::default());
    }
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    if first[0] == 0x16 {
        // Read the ClientHello before deciding. The server name is in it, in the
        // clear, and it is the only thing that can distinguish two hosts sharing
        // one CDN address. Whatever is read here is replayed verbatim, so the
        // decision costs the connection nothing either way.
        let mut head = first[..n].to_vec();
        let mut probe = [0u8; 2048];
        // One read is enough in practice (a ClientHello arrives in one segment)
        // and a second could block a connection that has nothing more to send.
        if let Ok(m) = client.read(&mut probe).await {
            head.extend_from_slice(&probe[..m]);
        }
        let sni = crate::sni::server_name(&head);

        // Name every TLS flow, decryptable or not. Until now a host we could not
        // intercept appeared only as an IP in a error line, so "which host is
        // refusing us?" had no answer at all: behind a CDN one address serves
        // thousands of names. The ClientHello says it in the clear.
        match sni.as_deref() {
            Some(h) => log::info!("tls flow -> {h} ({target_host}:{target_port})"),
            None => log::info!("tls flow -> {target_host}:{target_port} (no SNI)"),
        }

        if let Some(host) = sni.as_deref() {
            if crate::sni::is_bypassed(host, &cfg.bypass_hosts) {
                log::info!("bypass {host}: relaying untouched, not intercepting");
                let mut upstream = egress.connect(target_host.as_str(), target_port).await?;
                upstream.write_all(&head).await?;
                let mut client = PrefixedIo::new(Vec::new(), client);
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                return Ok(FlowOutcome {
                    tls: true,
                    requests: 0,
                    bypassed: true,
                });
            }
        }

        let stream = PrefixedIo::new(head, client);
        log::debug!("flow {target_host}:{target_port}: TLS detected, accepting (MITM handshake)");
        let tls = mitm_acceptor(ca).accept(stream).await?;
        log::debug!("flow {target_host}:{target_port}: TLS handshake done, serving HTTP");
        let ctx = ServeCtx {
            egress,
            tx,
            cfg,
            served: served.clone(),
        };
        serve_http(tls, "https", target_host, target_port, ctx).await?;
        Ok(FlowOutcome {
            tls: true,
            requests: served.load(std::sync::atomic::Ordering::Relaxed),
            bypassed: false,
        })
    } else {
        let stream = PrefixedIo::new(first[..n].to_vec(), client);
        let ctx = ServeCtx {
            egress,
            tx,
            cfg,
            served: served.clone(),
        };
        serve_http(stream, "http", target_host, target_port, ctx).await?;
        Ok(FlowOutcome {
            tls: false,
            requests: served.load(std::sync::atomic::Ordering::Relaxed),
            bypassed: false,
        })
    }
}

/// What every request on one connection needs, so the count stays a property of
/// the connection rather than another positional argument.
struct ServeCtx {
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
    cfg: CaptureCfg,
    /// Requests actually served. Zero on a TLS connection means the client
    /// refused our certificate rather than that it had nothing to say.
    served: Arc<std::sync::atomic::AtomicUsize>,
}

/// Serve HTTP/1 over an (already TLS-terminated or plaintext) client stream, forwarding each request.
async fn serve_http<S>(
    io: S,
    scheme: &'static str,
    target_host: String,
    target_port: u16,
    ctx: ServeCtx,
) -> Result<(), BoxErr>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = Arc::new(target_host);
    let ServeCtx {
        egress,
        tx,
        cfg,
        served,
    } = ctx;
    let svc = service_fn(move |req: Request<Incoming>| {
        let egress = egress.clone();
        let tx = tx.clone();
        let host = host.clone();
        let cfg = cfg.clone();
        served.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        async move { handle_request(req, scheme, host, target_port, egress, tx, cfg).await }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), svc)
        .await?;
    Ok(())
}

/// An `AsyncRead`/`AsyncWrite` that replays a captured prefix (the peeked bytes) before delegating to
/// the inner stream, so peeking the first byte does not consume it.
struct PrefixedIo<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}
impl<S> PrefixedIo<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = self.prefix.len() - self.pos;
            let n = remaining.min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn handle_request(
    req: Request<Incoming>,
    scheme: &'static str,
    target_host: Arc<String>,
    target_port: u16,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
    cfg: CaptureCfg,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match forward(req, scheme, &target_host, target_port, egress, tx, &cfg).await {
        Ok(resp) => Ok(resp),
        // A dead/unreachable origin must not kill the client connection: answer 502 like a proxy.
        Err(_) => Ok(Response::builder()
            .status(502)
            .body(Full::new(Bytes::from_static(b"upstream error")))
            .unwrap()),
    }
}

async fn forward(
    req: Request<Incoming>,
    scheme: &'static str,
    target_host: &str,
    target_port: u16,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
    cfg: &CaptureCfg,
) -> Result<Response<Full<Bytes>>, BoxErr> {
    let method = req.method().to_string();
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let headers = req.headers().clone();
    let authed = headers.contains_key(AUTHORIZATION) || headers.contains_key(COOKIE);
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let host_hdr = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(target_host)
        .to_string();

    // Buffer the request body so we can read its field names AND replay it upstream.
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let body_params = body_field_names(content_type.as_deref(), &body_bytes);
    let full_url = format!("{scheme}://{host_hdr}{pq}");

    // Ordered [name, value] header pairs, captured once (used for the gate + full capture).
    let req_header_pairs: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // MANUAL INTERCEPTION: hold the request for human approval (and optional edit) before it leaves.
    let mut edited: Option<EditedRequest> = None;
    if let Some(gate) = &cfg.gate {
        match gate
            .decide(&method, &full_url, &req_header_pairs, &body_bytes)
            .await
        {
            InterceptDecision::Drop => {
                log::debug!(
                    "intercept: dropped {method} {}",
                    full_url.split('?').next().unwrap_or("")
                );
                return Ok(Response::builder()
                    .status(403)
                    .body(Full::new(Bytes::from_static(b"dropped by interceptor")))?);
            }
            InterceptDecision::Forward => {}
            InterceptDecision::ForwardModified(ed) => edited = Some(ed),
        }
    }

    // Rebuild the request for the origin: the operator-edited version when present, otherwise the
    // original (same method/uri/headers, buffered body). Host/port stay the flow's destination.
    let up_req = if let Some(ed) = &edited {
        let mut b = Request::builder()
            .method(ed.method.as_str())
            .uri(ed.path.as_str());
        for (k, v) in &ed.headers {
            // The operator's framing headers are dropped and recomputed below, because
            // an intercept pane is exactly where a body changes and its length does not.
            // Both directions were measured, and neither reports anything: a 25-byte edit
            // behind a stale `content-length: 5` reached the origin as five bytes, hyper
            // having truncated it to the length it was given, and a 4-byte edit behind a
            // stale 4096 went out declaring 4096, leaving the origin waiting for the rest.
            //
            // Reachable, not hypothetical. `mobile/rust/src/intercept.rs` builds the
            // edited request's headers from the captured request's own `req_headers`,
            // which carry its original Content-Length, and pairs them with the body the
            // operator retyped. So every length-changing edit was silently wrong, and the
            // first case is the worse one: the request is well formed, the origin answers
            // it, and that answer gets read as evidence about a body nobody sent.
            if k.eq_ignore_ascii_case("content-length")
                || k.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            b = b.header(k.as_str(), v.as_str());
        }
        // The one length that is true by construction.
        b = b.header(CONTENT_LENGTH, ed.body.len());
        b.body(Full::new(Bytes::from(ed.body.clone())))?
    } else {
        let mut b = Request::builder()
            .method(parts.method.clone())
            .uri(pq.clone());
        for (k, v) in parts.headers.iter() {
            b = b.header(k, v);
        }
        b.body(Full::new(body_bytes.clone()))?
    };

    // Dial the flow's ACTUAL destination through the routing egress. For upstream TLS SNI, use the
    // request Host so the origin serves the right certificate; fall back to the dial target.
    let sni_host = sni_name(if host_hdr.is_empty() {
        target_host
    } else {
        host_hdr.as_str()
    });
    // Path only, never the query: `pq` carries `?access_token=...` and friends,
    // and this line runs for every forwarded request.
    let path_only = pq.split('?').next().unwrap_or("");
    log::debug!(
        "forward {method} {scheme}://{host_hdr}{path_only} -> dial {target_host}:{target_port}"
    );
    let tcp = egress.connect(target_host, target_port).await?;
    log::debug!("dialed {target_host}:{target_port}");
    let started = std::time::Instant::now();
    let (status, tech, resp_headers, resp_bytes) = if scheme == "https" {
        let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())?;
        let connector = if cfg.trust_any_upstream_cert {
            &*UPSTREAM_TLS_TRUST_ANY
        } else {
            &*UPSTREAM_TLS
        };
        let stream = connector.connect(server_name, tcp).await?;
        send_upstream(stream, up_req).await?
    } else {
        send_upstream(tcp, up_req).await?
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    log::debug!("upstream {target_host}:{target_port} -> {status}");

    // Record the exchange to a local store, if one is attached, while the bodies are still
    // bytes. This deliberately does not go through the event: `TraceEvent` carries
    // full-capture bodies as lossily-converted `String`, which cannot be replayed. See
    // `RawExchange`.
    // What actually went upstream. Where the gate modified the request, that is the
    // operator's version, because the exchange worth keeping is the one that happened.
    //
    // ALL of it, not just the body. An earlier version recorded the edited body and
    // headers next to the original method and URL, so a request retargeted from
    // `/original` to `/edited` was stored as having gone to `/original`. Evidence that
    // disagrees with what left the machine is worse than none.
    //
    // Worked out here rather than inside the sink block, because the TRACE EVENT had the
    // same problem and for the same reason: it was built from the request as it arrived.
    // That event feeds the asset graph, so an edited request was being filed against the
    // operation it was retargeted away from.
    let (sent_method, sent_path, sent_headers, sent_body) = match &edited {
        Some(ed) => (
            ed.method.clone(),
            ed.path.clone(),
            ed.headers.clone(),
            ed.body.clone(),
        ),
        None => (
            method.clone(),
            pq.clone(),
            req_header_pairs.clone(),
            body_bytes.to_vec(),
        ),
    };
    // The destination is fixed by the already-open flow, so an edited Host is what the
    // origin was told rather than where the bytes went. Recorded as sent either way.
    let sent_host = sent_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| host_hdr.clone());
    let sent_full_url = format!("{scheme}://{sent_host}{sent_path}");

    if let Some(sink) = &cfg.sink {
        let raw = crate::RawExchange {
            at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            method: sent_method.clone(),
            url: sent_full_url.clone(),
            host: sent_host.clone(),
            req_headers: sent_headers.clone(),
            status,
            duration_ms,
            resp_headers: resp_headers
                .iter()
                .map(|[k, v]| (k.clone(), v.clone()))
                .collect(),
            req_body: sent_body.clone(),
            resp_body: resp_bytes.to_vec(),
        };
        sink.record(&raw).await;
    }

    // Base privacy-safe event; enriched with full bytes only when full capture is on.
    let mut event = TraceEvent {
        method: sent_method,
        url: redact_url(&sent_full_url),
        status: Some(status),
        tech,
        authed,
        content_type,
        body_params,
        full_url: None,
        req_headers: None,
        req_body: None,
        resp_headers: None,
        resp_body: None,
        duration_ms: None,
    };
    if cfg.full {
        // The headers that went, matching the url and method above. Taking these from the
        // request as it arrived while the url described the request as it left is exactly
        // the half-and-half record this test exists to stop.
        let req_hdr_arr: Vec<[String; 2]> = sent_headers
            .iter()
            .map(|(k, v)| [k.clone(), v.clone()])
            .collect();
        // Hand over the RAW bytes and let attach_full decode them. Doing the
        // lossy conversion here is what turned every gzip response into
        // mojibake, and it is unrecoverable once done.
        event.attach_full(crate::FullExchange {
            // The request that went, like everything else on this event.
            url: sent_full_url,
            req_headers: req_hdr_arr,
            req_body: sent_body,
            resp_headers,
            resp_body: resp_bytes.to_vec(),
            duration_ms: Some(duration_ms),
        });
        // Full capture is the mode where "nothing showed up" is indistinguishable from
        // "nothing was captured", so say what actually got attached per flow. Without
        // this the only observable is a Requests tab that stays empty.
        log::info!(
            "full capture: {} {} req_headers={} req_body={}B resp_headers={} resp_body={}B",
            event.method,
            event.url,
            event.req_headers.as_ref().map_or(0, |h| h.len()),
            event.req_body.as_ref().map_or(0, |b| b.len()),
            event.resp_headers.as_ref().map_or(0, |h| h.len()),
            event.resp_body.as_ref().map_or(0, |b| b.len()),
        );
    }
    let _ = tx.send(event);

    Ok(Response::builder()
        .status(status as u16)
        .body(Full::new(resp_bytes))?)
}

/// The server name to offer upstream, taken from a `Host` header.
///
/// A `Host` carries a port whenever it is not the scheme's default; a TLS server name
/// never does. This was passing the header through unchanged, and rustls rejects
/// `example.com:8443` outright, so EVERY https target on a non-standard port failed to
/// forward and the operator saw a 502. Staging and internal services on `:8443` are
/// exactly where that lands, and the symptom reads as the target refusing the connection.
///
/// Found while building the first end-to-end capture test, which necessarily used an
/// origin on an ephemeral port and so was the first thing here ever to try one.
fn sni_name(host: &str) -> &str {
    let h = host.trim();
    // `[::1]` or `[::1]:8443`: the brackets exist precisely because the colons are not a
    // port separator, and a server name wants the address without them.
    if let Some(rest) = h.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) => &rest[..end],
            None => h,
        };
    }
    match h.rsplit_once(':') {
        // A trailing all-digit segment is a port. The `!head.contains(':')` guard keeps a
        // bare IPv6 address, which is malformed in a Host header but should not be
        // truncated into something different if one arrives.
        Some((head, tail))
            if !head.is_empty()
                && !tail.is_empty()
                && tail.bytes().all(|b| b.is_ascii_digit())
                && !head.contains(':') =>
        {
            head
        }
        _ => h,
    }
}

/// HTTP/1 client handshake over an already-connected (optionally TLS) stream: send `req`, return
/// (status, Server banner, response headers as [name,value] pairs, response body bytes).
async fn send_upstream<S>(
    stream: S,
    req: Request<Full<Bytes>>,
) -> Result<(i64, Option<String>, Vec<[String; 2]>, Bytes), BoxErr>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await?;
    let status = resp.status().as_u16() as i64;
    let tech = resp
        .headers()
        .get(SERVER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let resp_headers: Vec<[String; 2]> = resp
        .headers()
        .iter()
        .map(|(k, v)| [k.to_string(), v.to_str().unwrap_or("").to_string()])
        .collect();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, tech, resp_headers, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // Bring up a bare HTTP origin that echoes a fixed body, drive a TLS client THROUGH serve_mitm_flow
    // at it, and assert (a) the client gets the origin's response and (b) a correctly-reduced
    // TraceEvent is emitted. This exercises TLS termination + reduction + forward + event end to end
    // on loopback, with no device or TUN.
    #[test]
    fn a_host_header_with_a_port_is_not_a_server_name() {
        // Every one of these used to reach rustls verbatim, and rustls rejects anything
        // carrying a port, so the forward leg failed and the client got a 502.
        assert_eq!(sni_name("example.com"), "example.com");
        assert_eq!(sni_name("example.com:8443"), "example.com");
        assert_eq!(sni_name("localhost:38231"), "localhost");
        assert_eq!(sni_name("127.0.0.1:8443"), "127.0.0.1");
        assert_eq!(sni_name("127.0.0.1"), "127.0.0.1");
        assert_eq!(sni_name("[::1]:8443"), "::1");
        assert_eq!(sni_name("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(sni_name("  example.com:443  "), "example.com");

        // Not a port, so not truncated. A bare IPv6 is malformed in a Host header, and
        // turning `::1` into `::` would offer a different address entirely.
        assert_eq!(sni_name("::1"), "::1");
        // A trailing colon is not a port either.
        assert_eq!(sni_name("example.com:"), "example.com:");
        // And what comes out is something rustls will actually take.
        for h in [
            "example.com:8443",
            "localhost:38231",
            "127.0.0.1:8443",
            "[::1]:8443",
        ] {
            let name = sni_name(h);
            assert!(
                rustls::pki_types::ServerName::try_from(name.to_string()).is_ok(),
                "{h} reduced to {name}, which rustls still refuses"
            );
        }
    }

    #[tokio::test]
    async fn mitm_flow_reduces_and_forwards() {
        // 1. HTTP origin.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await.unwrap();
            let body = "hello-origin";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nServer: test-origin\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.flush().await;
        });

        // 2. The MITM flow in front of it.
        let ca = Arc::new(crate::generate_ca().unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
        let mitm = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mitm_port = mitm.local_addr().unwrap().port();
        let ca2 = ca.clone();
        tokio::spawn(async move {
            let (client, _) = mitm.accept().await.unwrap();
            // Routing target is the loopback origin; the logical host ("origin.test") is carried by
            // the client's SNI + Host header and is what shows up (redacted) in the event URL.
            let _ = serve_mitm_flow(
                client,
                "127.0.0.1".into(),
                origin_port,
                ca2,
                Egress::Direct,
                tx,
                crate::CaptureCfg::default(),
            )
            .await;
        });

        // 3. A plaintext HTTP/1 client pointed at the MITM. Real traffic is the same scheme on both
        //    legs; the peek routes this to the plaintext path. The TLS-termination path is the same
        //    code wrapped in a rustls accept and is exercised on-device.
        let tcp = TcpStream::connect(("127.0.0.1", mitm_port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/login?token=secret&next=2")
            .header(HOST, "origin.test")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer xyz")
            .body(Full::new(Bytes::from_static(
                br#"{"email":"a@b","pw":"p"}"#,
            )))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let got = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&got[..], b"hello-origin");

        // 4. The emitted event is correctly reduced: keys kept, values + secrets gone.
        let ev = rx.recv().await.expect("a trace event");
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.url, "http://origin.test/api/login?token=&next=");
        assert_eq!(ev.status, Some(200));
        assert_eq!(ev.tech.as_deref(), Some("test-origin"));
        assert!(ev.authed);
        assert_eq!(ev.content_type.as_deref(), Some("application/json"));
        assert!(ev.body_params.contains(&"email".to_string()));
        assert!(ev.body_params.contains(&"pw".to_string()));
        // The secret VALUES never appear anywhere in the event.
        let blob = format!("{ev:?}");
        assert!(!blob.contains("secret") && !blob.contains("Bearer") && !blob.contains("a@b"));
    }

    // Same flow with `full` on, asserted against the SERIALIZED event rather than the struct.
    // The wire is where this can go wrong silently: the ingest endpoint decides whether a batch
    // is worth storing by looking for the keys `req_headers` / `resp_headers` / `resp_body` in
    // the JSON, so a field that is populated but named differently (or skipped when empty)
    // produces exactly the failure we saw in the field, which is assets arriving normally and
    // the Requests tab staying empty with nothing logged anywhere.
    // A gzip response through the real flow, asserted on the serialized event.
    // This is the exact path mobile capture takes, and it is where the bodies
    // were arriving as mojibake: the proxy sees the compressed bytes, and
    // from_utf8_lossy on a deflate stream is not reversible, so the decode has
    // to happen before the event is built.
    #[tokio::test]
    async fn a_gzip_response_is_captured_as_readable_text() {
        use std::io::Write as _;
        let payload = r#"{"name":"projects/aculogic-405f8/installations/abc"}"#;
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(payload.as_bytes()).unwrap();
            e.finish().unwrap()
        };

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let gz2 = gz.clone();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await.unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                gz2.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&gz2).await;
            let _ = s.flush().await;
        });

        let ca = Arc::new(crate::generate_ca().unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
        let mitm = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mitm_port = mitm.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (client, _) = mitm.accept().await.unwrap();
            let _ = serve_mitm_flow(
                client,
                "127.0.0.1".into(),
                origin_port,
                ca,
                Egress::Direct,
                tx,
                crate::CaptureCfg {
                    full: true,
                    ..Default::default()
                },
            )
            .await;
        });

        let tcp = TcpStream::connect(("127.0.0.1", mitm_port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/projects/aculogic-405f8/installations")
            .header(HOST, "firebaseinstallations.googleapis.test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        // The CLIENT still receives the original compressed bytes: capture
        // observes, it does not rewrite the traffic it is proxying.
        let got = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&got[..], &gz[..], "the proxied response must be untouched");

        let ev = rx.recv().await.expect("a trace event");
        let wire = serde_json::to_value(&ev).unwrap();
        let body = wire.get("resp_body").and_then(|v| v.as_str()).unwrap();
        assert_eq!(body, payload, "captured body should be readable JSON");

        // And the stored headers no longer claim an encoding the body has lost,
        // which is what lets the Repeater replay the request as stored.
        let hdrs = format!("{:?}", wire.get("resp_headers").unwrap()).to_lowercase();
        assert!(
            !hdrs.contains("content-encoding"),
            "content-encoding should be dropped once decoded: {hdrs}"
        );
    }

    #[tokio::test]
    async fn full_capture_puts_headers_and_bodies_on_the_wire() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await.unwrap();
            let body = r#"{"ok":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nServer: test-origin\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.flush().await;
        });

        let ca = Arc::new(crate::generate_ca().unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
        let mitm = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mitm_port = mitm.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (client, _) = mitm.accept().await.unwrap();
            let _ = serve_mitm_flow(
                client,
                "127.0.0.1".into(),
                origin_port,
                ca,
                Egress::Direct,
                tx,
                crate::CaptureCfg {
                    full: true,
                    ..Default::default()
                },
            )
            .await;
        });

        let tcp = TcpStream::connect(("127.0.0.1", mitm_port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/login?token=secret")
            .header(HOST, "origin.test")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer xyz")
            .body(Full::new(Bytes::from_static(br#"{"email":"a@b"}"#)))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let _ = resp.into_body().collect().await.unwrap();

        let ev = rx.recv().await.expect("a trace event");
        let wire = serde_json::to_value(&ev).unwrap();

        // Exactly the three keys the ingest gate tests for, by their wire names.
        assert!(
            wire.get("req_headers").is_some(),
            "req_headers missing from the wire event: {wire}"
        );
        assert!(
            wire.get("resp_headers").is_some(),
            "resp_headers missing from the wire event: {wire}"
        );
        assert!(
            wire.get("resp_body").is_some(),
            "resp_body missing from the wire event: {wire}"
        );
        // And a host to attribute the row to, without which the server skips it.
        assert!(
            wire.get("full_url").and_then(|v| v.as_str()).is_some(),
            "full_url missing from the wire event: {wire}"
        );

        // Full capture means UNREDACTED: this is the whole point of the mode, and it is
        // what separates a Requests row from the shape-only event beside it.
        let body = wire.get("resp_body").and_then(|v| v.as_str()).unwrap();
        assert!(body.contains("ok"), "response body not captured: {body:?}");
        let req_hdrs = format!("{:?}", wire.get("req_headers").unwrap());
        assert!(
            req_hdrs.contains("authorization"),
            "request headers did not survive: {req_hdrs}"
        );
    }
}
