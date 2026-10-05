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
// Unsync, because hyper does not require a response body to be Sync and the sink's
// write future does not promise it. Demanding Sync here would mean widening a trait
// signature across the crate to satisfy a bound nothing needs.
use http_body_util::combinators::UnsyncBoxBody;
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
    /// Out of scope. Nothing was dialled, no certificate was minted, and the guard has
    /// already written it down. Named separately from a flow that simply carried no
    /// requests, because a caller that cannot tell them apart reports a refusal as
    /// certificate pinning.
    pub refused: bool,
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

        // Scope BEFORE bypass, and both before the handshake.
        //
        // `bypass_hosts` answers "do not intercept this". Scope answers "do not reach
        // this". They are allowed to disagree and scope wins, because the bypass branch
        // below relays the flow with copy_bidirectional and returns: there is no
        // per-request gate behind it, nothing is parsed and nothing is recorded. A bypass
        // entry that outranked scope would be the one path in the product that carries
        // invisible traffic to a destination the operator never authorised.
        if !admit_flow(&cfg, sni.as_deref(), &target_host, target_port) {
            return Ok(FlowOutcome {
                tls: true,
                refused: true,
                ..Default::default()
            });
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
                    refused: false,
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
            refused: false,
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
        // No scope check here. The plaintext branch carries absolute-form requests that
        // can each name a different host, so the only honest gate is per request, and it
        // is in handle_request. Checking the connection's destination as well would refuse
        // on the proxy's own address.
        Ok(FlowOutcome {
            tls: false,
            requests: served.load(std::sync::atomic::Ordering::Relaxed),
            bypassed: false,
            refused: false,
        })
    }
}

/// Every destination this TLS flow will use, as one decision.
///
/// The name the client asked for is what is judged: the SNI, or the flow's destination
/// when there is none. When the destination is a different NAME from the SNI, both are
/// judged, because both are destinations.
///
/// When the destination is a bare ADDRESS it is not judged separately. It is the
/// resolver's answer for a name that was already admitted, and requiring it to match a
/// rule of its own would refuse every flow on the mobile front end, where the client
/// names a host and the device supplies the address. What that leaves is a client that
/// lies in SNI reaching an address the operator did not list; the client here is the
/// operator's own browser, and an address can always be listed explicitly.
fn admit_flow(cfg: &CaptureCfg, sni: Option<&str>, target_host: &str, target_port: u16) -> bool {
    let asked = sni.unwrap_or(target_host);
    if !cfg.admit(asked, target_port, cfx_scope::Point::Connect, None) {
        log::warn!("out of scope: refused tls flow to {asked}:{target_port}");
        return false;
    }
    let dest_is_name = target_host.parse::<std::net::IpAddr>().is_err();
    if dest_is_name && !target_host.eq_ignore_ascii_case(asked) {
        let why = format!("asked for {asked}");
        if !cfg.admit(
            target_host,
            target_port,
            cfx_scope::Point::Connect,
            Some(&why),
        ) {
            log::warn!("out of scope: refused tls flow to {target_host}:{target_port} ({why})");
            return false;
        }
    }
    true
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
        // A proxy that normalises header names cannot be used to find the bugs that live
        // in how servers disagree about parsing them. Smuggling, header injection and a
        // good deal of WAF evasion all turn on exactly which bytes arrive, and real
        // stacks do treat `Content-Length` and `content-length` differently despite the
        // specification. hyper keeps the original casing in an extension when asked, and
        // the client leg below re-emits it, so what the operator wrote is what the origin
        // reads.
        .preserve_header_case(true)
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

/// Unix milliseconds. Both the recorded exchange and the recorded failure want it, and
/// one of them having a different idea of the clock than the other would put rows out of
/// order in the history for no visible reason.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Carry one absolute-form proxy request, capturing it like any other.
///
/// `GET http://example.test/a HTTP/1.1` sent straight to the proxy port, which is how
/// every plaintext target reaches a proxy. A CONNECT tunnel does not happen for these and
/// there is nothing to MITM, because there is no TLS: the request arrives already parsed
/// and only needs forwarding and recording.
///
/// The capture core could always do this, and the session in front of it answered 501
/// instead, so every `http://` target on an internal network was simply not carried. The
/// path was there; nothing called it.
pub async fn serve_plain_request(
    req: Request<Incoming>,
    target_host: String,
    target_port: u16,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
    cfg: CaptureCfg,
) -> Response<UnsyncBoxBody<Bytes, BoxErr>> {
    match handle_request(
        req,
        "http",
        Arc::new(target_host),
        target_port,
        egress,
        tx,
        cfg,
    )
    .await
    {
        Ok(r) => r,
        // handle_request is infallible by construction; this arm exists so the signature
        // does not export an error nobody can produce.
        Err(e) => match e {},
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
) -> Result<Response<UnsyncBoxBody<Bytes, BoxErr>>, std::convert::Infallible> {
    // Read what identifies the request before forwarding consumes it, so a failure still
    // has something to record. Without this a request that never reached the target left
    // no row at all: the operator browsed, got a bare 502 in the browser, and found an
    // empty history with nothing anywhere saying a request had been made. An untrusted
    // target certificate behaves exactly like a proxy that is not listening.
    let started = std::time::Instant::now();
    let failed_method = req.method().to_string();
    let failed_pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let failed_host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&target_host)
        .to_string();
    let failed_req_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // The destination, which is where the bytes go: the flow's for a tunnel, and the
    // request's own authority for absolute-form plaintext, which the session resolved
    // before calling here. Not the Host header: that is text inside the request and does
    // not route. Refusing on it would make virtual-host routing and cache-poisoning tests
    // impossible, which is the same separation the Repeater makes between a destination
    // and the bytes sent to it.
    //
    // Not a repeat of the CONNECT check. Successive absolute-form requests on one proxy
    // connection can each name a different host, so this is the only gate an http://
    // target ever passes, and it is per request for that reason.
    //
    // Before forward, so a refused request never parks at the intercept gate: an operator
    // must not be shown a Forward button for something out of scope.
    //
    // Nothing is recorded as an exchange. The 502 arm below writes a synthetic one, and
    // copying that here would put requests that were never sent into the table the
    // operation model and coverage are derived from. A refusal gets its own row.
    let what = format!("{failed_method} {failed_pq}");
    if !cfg.admit(
        &target_host,
        target_port,
        cfx_scope::Point::Request,
        Some(&what),
    ) {
        log::warn!("out of scope: refused {what} to {target_host}:{target_port}");
        return Ok(Response::builder()
            .status(403)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("x-crossfyre-scope", "refused")
            .body(fixed_body(cfx_scope::refusal_text(
                &target_host,
                target_port,
            )))
            .unwrap());
    }

    match forward(req, scheme, &target_host, target_port, egress, tx, &cfg).await {
        Ok(resp) => Ok(resp),
        // A dead/unreachable origin must not kill the client connection: answer 502 like a proxy.
        Err(e) => {
            // The body says whose answer this is. "upstream error" in a browser tab tells
            // the operator nothing, and the common cause here is one they can fix from the
            // window: a target behind its own CA needs the trust toggle.
            let detail = e.to_string();
            let body = format!(
                "crossfyre could not reach the target. This page came from the proxy; \
                 nothing was received from the target.\n\n{}\n\nThe error was:\n{detail}\n",
                why_it_failed(&detail),
            );
            if let Some(sink) = &cfg.sink {
                let ex = crate::RawExchange {
                    at_ms: now_ms(),
                    method: failed_method,
                    url: format!("{scheme}://{failed_host}{failed_pq}"),
                    host: failed_host,
                    status: 502,
                    duration_ms: started.elapsed().as_millis() as u64,
                    req_headers: failed_req_headers,
                    // Our own, and labelled as ours. Nothing came back to report.
                    resp_headers: vec![
                        ("content-type".into(), "text/plain".into()),
                        ("x-crossfyre-proxy-error".into(), e.to_string()),
                    ],
                    req_body: Vec::new(),
                    resp_body: body.clone().into_bytes(),
                    resp_len: None,
                };
                sink.record(ex);
            }
            Ok(Response::builder()
                .status(502)
                .header(CONTENT_TYPE, "text/plain")
                .body(fixed_body(body))
                .unwrap())
        }
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
) -> Result<Response<UnsyncBoxBody<Bytes, BoxErr>>, BoxErr> {
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
                    .body(fixed_body(Bytes::from_static(b"dropped by interceptor")))?);
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
        let mut req = b.body(Full::new(body_bytes.clone()))?;
        // The original header casing lives in an extension that hyper owns and does not
        // export, so it cannot be read or rebuilt here. Carrying the extensions across is
        // the only way the client leg can re-emit what arrived.
        *req.extensions_mut() = parts.extensions.clone();
        req
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
    let (status, tech, resp_headers, upstream_body) = if scheme == "https" {
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

    // An upgrade the connection cannot carry.
    //
    // A WebSocket handshake is an ordinary GET with `Upgrade: websocket`, and every
    // request header is forwarded verbatim, so an origin that speaks WebSockets answers
    // 101 and means it. This connection is served without hyper's upgrade support, so
    // nothing would ever be relayed: passing the 101 back opens a socket in the
    // application whose first frame goes nowhere, and it hangs.
    //
    // The record was the worse half. An exchange stored with status 101 reads like a
    // successful handshake, so the one place an operator would look to find out why their
    // socket is dead said the opposite of what happened.
    //
    // Refusing is worse product and better behaviour. A WebSocket that fails at once
    // sends somebody to read this message; one that hangs sends them to debug the target.
    // When upgrades are carried for real this branch goes away, and the exchange it
    // records is the row that will say when that happened.
    if status == 101 {
        let body = format!(
            "crossfyre did not carry this upgrade.\n\nThe target accepted a protocol \
             upgrade ({}), and this capture session does not relay the connection that \
             follows one yet. Passing the acceptance back would open a socket that never \
             carries anything, which fails later and somewhere else.\n\nThe request and \
             the target's response headers are recorded. The frames after them are not.\n",
            resp_headers
                .iter()
                .find(|[k, _]| k.eq_ignore_ascii_case("upgrade"))
                .map(|[_, v]| v.as_str())
                .unwrap_or("unnamed protocol"),
        );
        let mut ev = TraceEvent {
            method: sent_method.clone(),
            url: redact_url(&sent_full_url),
            status: Some(501),
            tech,
            authed,
            content_type,
            body_params,
            full_url: None,
            req_headers: None,
            req_body: None,
            resp_headers: None,
            resp_body: None,
            duration_ms: Some(duration_ms),
        };
        if cfg.full {
            ev.attach_full(crate::FullExchange {
                url: sent_full_url.clone(),
                req_headers: sent_headers
                    .iter()
                    .map(|(k, v)| [k.clone(), v.clone()])
                    .collect(),
                req_body: sent_body.clone(),
                // The target's own headers, kept, because what it offered is evidence
                // even though the tunnel was refused.
                resp_headers: resp_headers.clone(),
                resp_body: body.clone().into_bytes(),
                duration_ms: Some(duration_ms),
            });
        }
        if let Some(sink) = &cfg.sink {
            let raw = crate::RawExchange {
                at_ms: now_ms(),
                method: sent_method,
                url: sent_full_url,
                host: sent_host,
                req_headers: sent_headers,
                status: 501,
                duration_ms,
                resp_headers: resp_headers
                    .iter()
                    .map(|[k, v]| (k.clone(), v.clone()))
                    .collect(),
                req_body: sent_body,
                resp_body: body.clone().into_bytes(),
                resp_len: None,
            };
            sink.record(raw);
        }
        let _ = tx.send(ev);
        return Ok(Response::builder()
            .status(501)
            .header(CONTENT_TYPE, "text/plain")
            .header("x-crossfyre-proxy-error", "upgrade not carried")
            .body(fixed_body(body))?);
    }

    // What goes back to the client.
    //
    // This used to be a status and a body and nothing else. Every response through the
    // proxy therefore arrived with no Content-Type, no Set-Cookie, no Location and no
    // Cache-Control, so a browser could not complete a login and could not follow a
    // redirect. Worse for a tool whose output is evidence: the exchange was stored WITH
    // its headers, so the record and the thing the client actually received disagreed,
    // and nothing in the conformance suite noticed because its client helper threw the
    // headers away.
    //
    // `append` rather than `insert`, because `Set-Cookie` legitimately repeats and
    // inserting would keep only the last one, which silently loses sessions.
    let mut reply = Response::builder().status(status as u16);
    if let Some(out) = reply.headers_mut() {
        for [k, v] in &resp_headers {
            // Hop-by-hop headers describe the connection they were read on. Relaying them
            // onto a different connection is a framing bug waiting to happen, and
            // `content-length` in particular would describe the origin's framing rather
            // than the body we reassembled. hyper sets the real one.
            if is_hop_header(k) {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                hyper::header::HeaderValue::from_str(v),
            ) {
                out.append(name, val);
            }
        }
    }

    // Base privacy-safe event; enriched with full bytes only when full capture is on.
    let event = TraceEvent {
        method: sent_method.clone(),
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
    // The event and the record are finished by the BODY, when the body ends, because
    // until then there is nothing to say about it. Everything they need is taken here,
    // where it is still in scope.
    Ok(reply.body(
        RecordingBody::new(
            upstream_body,
            Finish {
                cfg: cfg.clone(),
                tx,
                event,
                full_url: sent_full_url,
                method: sent_method,
                host: sent_host,
                req_headers: sent_headers,
                req_body: sent_body,
                resp_headers,
                status,
                duration_ms,
            },
        )
        .boxed_unsync(),
    )?)
}

// ---------------------------------------------------------------------------
// Recording the response without holding it
// ---------------------------------------------------------------------------

/// A reply this proxy wrote itself, in the same shape as a streamed one.
///
/// `Full`'s error type is `Infallible` and a streamed upstream body's is not, so the two
/// need reconciling before they can share a return type. The match on an empty enum is
/// how you promise a compiler that a value cannot exist.
fn fixed_body(bytes: impl Into<Bytes>) -> UnsyncBoxBody<Bytes, BoxErr> {
    Full::new(bytes.into())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

/// How much of a response body is kept for the record.
///
/// Everything above this is carried to the client and not stored. The number is a
/// judgement about what an operator reads versus what they merely download: a page, an
/// API response or a script is far under it, and a disk image, a video or an APK is far
/// over. Sixteen megabytes is generous for the first and useless for the second, which is
/// the right shape, because keeping the second has never helped anybody find a bug.
pub const RECORDED_BODY_MAX: usize = 16 * 1024 * 1024;

/// A response body on its way to the client, keeping a bounded prefix for the record.
///
/// This replaced collecting the whole body before answering. That was simple and it meant
/// the proxy held every byte a target chose to send, twice: once as the collected body
/// and again as the copy the record owned. Measured, a sixty-four megabyte response cost
/// a hundred and thirty megabytes of resident memory, so a gigabyte download needed two
/// gigabytes and a disk image took the machine with it.
///
/// Worse than the size, nothing bounded it. The number of bytes came from the target,
/// which in this product is by definition hostile, so a response that never ended was a
/// denial of service against the operator's own tool.
///
/// The record fires once, when the body ends or when it is dropped. Dropped matters for
/// two reasons. A client that disconnects halfway through a download still made a
/// request, and an exchange missing from the history because somebody pressed stop is a
/// history that cannot be trusted to be complete. And it is the ordinary path rather than
/// the exceptional one: hyper does not reliably poll a body whose length it already knows
/// to its final frame, it writes the bytes and drops it.
///
/// So the contract is that an exchange is recorded SHORTLY AFTER its response completes,
/// not before. Measured, the write is about a sixth of a millisecond. The collecting
/// version this replaced had the stronger property for free, and losing it is the price
/// of not holding a four-gigabyte download in memory.
///
/// The remaining gap, written down rather than discovered: a process that exits inside
/// that window loses the last exchange. The fix is a write queue in the sink that
/// `Project::close` drains, so closing a project means every capture is on disk. That is
/// worth doing before anybody relies on a project file as evidence.
struct RecordingBody {
    inner: Incoming,
    kept: Vec<u8>,
    /// Everything that arrived, whether it was kept or not.
    total: usize,
    /// Taken on the first emit, so a body that ends and is then dropped records once.
    finish: Option<Box<Finish>>,
}

/// What the record needs, captured before the body starts flowing.
struct Finish {
    cfg: CaptureCfg,
    tx: UnboundedSender<TraceEvent>,
    event: TraceEvent,
    full_url: String,
    method: String,
    host: String,
    req_headers: Vec<(String, String)>,
    req_body: Vec<u8>,
    resp_headers: Vec<[String; 2]>,
    status: i64,
    duration_ms: u64,
}

impl RecordingBody {
    fn new(inner: Incoming, finish: Finish) -> Self {
        Self {
            inner,
            kept: Vec::new(),
            total: 0,
            finish: Some(Box::new(finish)),
        }
    }

    /// Emit the event, and hand back the record write if there is a sink.
    ///
    /// Once, because a body that ends and is then dropped must not record twice.
    fn emit(&mut self) {
        let Some(f) = self.finish.take() else {
            return;
        };
        let kept = std::mem::take(&mut self.kept);
        let total = self.total;
        let truncated = total > kept.len();

        let mut event = f.event;
        if f.cfg.full {
            event.attach_full(crate::FullExchange {
                url: f.full_url.clone(),
                req_headers: f
                    .req_headers
                    .iter()
                    .map(|(k, v)| [k.clone(), v.clone()])
                    .collect(),
                req_body: f.req_body.clone(),
                resp_headers: f.resp_headers.clone(),
                resp_body: kept.clone(),
                duration_ms: Some(f.duration_ms),
            });
            log::info!(
                "full capture: {} {} req_headers={} req_body={}B resp_headers={} resp_body={}B{}",
                event.method,
                event.url,
                f.req_headers.len(),
                f.req_body.len(),
                f.resp_headers.len(),
                total,
                if truncated {
                    format!(" (kept {})", kept.len())
                } else {
                    String::new()
                },
            );
        }
        let _ = f.tx.send(event);

        let Some(sink) = f.cfg.sink.as_ref() else {
            return;
        };
        sink.record(crate::RawExchange {
            at_ms: now_ms(),
            method: f.method,
            url: f.full_url,
            host: f.host,
            req_headers: f.req_headers,
            status: f.status,
            duration_ms: f.duration_ms,
            resp_headers: f
                .resp_headers
                .iter()
                .map(|[k, v]| (k.clone(), v.clone()))
                .collect(),
            req_body: f.req_body,
            resp_body: kept,
            resp_len: truncated.then_some(total),
        });
    }
}

impl hyper::body::Body for RecordingBody {
    type Data = Bytes;
    type Error = BoxErr;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let me = &mut *self;
        match std::pin::Pin::new(&mut me.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    me.total += data.len();
                    let room = RECORDED_BODY_MAX.saturating_sub(me.kept.len());
                    if room > 0 {
                        me.kept.extend_from_slice(&data[..room.min(data.len())]);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                // The transfer failed partway. What arrived is still evidence about the
                // target, and silence is not, so it is handed over before the error goes
                // on to the client.
                me.emit();
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Ready(None) => {
                me.emit();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for RecordingBody {
    fn drop(&mut self) {
        // A client that went away mid-download still made the request, and an exchange
        // missing from the history because somebody pressed stop is a history that cannot
        // be trusted to be complete.
        //
        // This is also the ORDINARY path rather than the exceptional one: hyper does not
        // reliably poll a body whose length it already knows to its final frame, it writes
        // the bytes and drops it. Handing over is synchronous, so a destructor can do it,
        // which is the whole reason the sink takes exchanges rather than futures.
        self.emit();
    }
}

/// Say what a forward-leg failure actually means, in a sentence that names the fix.
///
/// The raw error is kept either way, because the exact text matters to whoever has to
/// debug an unusual case. What it is not is readable: an operator meeting
/// `InvalidCertificate(Other(OtherError(CaUsedAsEndEntity)))` for the first time learns
/// that something is wrong with a certificate, and nothing about which certificate,
/// whose, or what to do. That sends them to look at the target, which is the wrong place
/// for most of these.
fn why_it_failed(detail: &str) -> &'static str {
    let e = detail.to_ascii_lowercase();
    if e.contains("certificaterequired") || e.contains("certificate required") {
        return "The target asked for a client certificate and this proxy has none to offer. \
                Mutual TLS is not configured here yet, so this target cannot be reached \
                through it at all.";
    }
    if e.contains("notvalidforname") {
        return "The target's certificate does not cover the name it was asked for. That is \
                usually a service served under a different hostname, or an address used \
                where a name was expected.";
    }
    if e.contains("expired") {
        return "The target's certificate has expired. If that is expected on this target, \
                \"trust any target cert\" in the window carries it anyway.";
    }
    if e.contains("unknownissuer")
        || e.contains("invalid peer certificate")
        || e.contains("self-signed")
        || e.contains("selfsigned")
    {
        return "The target's certificate was not signed by any public authority, which is \
                what an internal service behind a corporate or self-signed CA looks like. \
                Switch on \"trust any target cert\" in the window to carry it.";
    }
    if e.contains("connection refused") {
        return "Nothing is listening on that port. The target is down, or the port is wrong.";
    }
    if e.contains("failed to lookup") || e.contains("name or service not known") {
        return "That hostname does not resolve from this machine. A name that only exists \
                inside a VPN needs the VPN up.";
    }
    if e.contains("timed out") || e.contains("timeout") {
        return "The target accepted nothing within the timeout. A firewall dropping the \
                connection looks exactly like this.";
    }
    "A target behind its own certificate authority needs \"trust any target cert\" \
     switched on in the window. A target that is simply down needs nothing from you here."
}

/// Headers that belong to one connection and must not be relayed onto another.
///
/// `content-length` and `host` are in here for a reason beyond the RFC's list: the body
/// is reassembled on the way through, so the origin's length describes a framing that no
/// longer applies, and the host belongs to the hop being made rather than the one that
/// was read.
pub fn is_hop_header(name: &str) -> bool {
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
) -> Result<(i64, Option<String>, Vec<[String; 2]>, Incoming), BoxErr>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake(TokioIo::new(stream))
        .await?;
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
    Ok((status, tech, resp_headers, resp.into_body()))
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
    fn a_forward_failure_is_explained_in_terms_of_what_to_do() {
        // Each of these is a real rustls or io error string, and each one used to reach
        // the operator exactly as written. The raw text is still shown below the
        // explanation; this is what goes above it.
        let cases = [
            (
                "received fatal alert: CertificateRequired",
                "client certificate",
            ),
            (
                "invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))",
                "not signed by any public authority",
            ),
            (
                "invalid peer certificate: NotValidForName",
                "does not cover the name",
            ),
            ("invalid peer certificate: Expired", "has expired"),
            ("Connection refused (os error 111)", "Nothing is listening"),
            (
                "failed to lookup address information: Name or service not known",
                "does not resolve",
            ),
            ("operation timed out", "within the timeout"),
        ];
        for (raw, expected) in cases {
            let said = why_it_failed(raw);
            assert!(
                said.contains(expected),
                "{raw:?} should be explained with {expected:?}, got: {said}"
            );
        }

        // Anything unrecognised still gets a sentence, because the raw error on its own
        // is the thing this exists to stop.
        let unknown = why_it_failed("something nobody has seen before");
        assert!(
            unknown.contains("trust any target cert"),
            "the fallback names the control by its label in the window, so it can be \
             found rather than searched for: {unknown}"
        );
    }

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
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(tcp))
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
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(tcp))
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
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(tcp))
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
