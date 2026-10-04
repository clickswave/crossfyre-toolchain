//! A runnable local capture session.
//!
//! This is the layer a desktop workbench drives: bind a proxy port, point a browser at it,
//! and every flow goes through the capture core into a local project, optionally parking
//! at an in-process gate on the way. Nothing here talks to a control plane, which is the
//! whole point. A pentester on a client site with no outbound route, or under an NDA that
//! forbids sending a client's traffic to a vendor, is the case this exists for.
//!
//! # Why this is not `trace_proxy.rs`
//!
//! `core/src/toolchain/trace_proxy.rs` is the existing local proxy and it does not use
//! [`cfx_capture::serve_mitm_flow`]. It shares the CA and the event shape and then
//! forwards with a reqwest client of its own, so the two paths have diverged while the
//! documentation says they are identical. The tested path is `serve_mitm_flow`, which is
//! what the conformance suite drives, so that is the one a new front end should feed.
//!
//! # Scope of this first version
//!
//! CONNECT only. A browser sends CONNECT for every https destination, which is nearly all
//! real traffic, and the upgraded socket is exactly what `serve_mitm_flow` wants: it does
//! its own first-byte peek, SNI read, bypass decision and MITM handshake.
//!
//! An absolute-form plaintext request (`GET http://host/path`) arrives on the proxy
//! connection instead of on a per-destination stream, and successive ones can name
//! different hosts, so it cannot simply be handed over the same way. It answers 501 with a
//! message saying so rather than failing in a way that looks like the target's fault. That
//! is a gap and it is written down here rather than discovered.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// Launching a browser at the proxy.
///
/// It lives in `cfx_capture` and is re-exported here, because the CLI's web tracer wants
/// exactly the same thing and depends on `capture` but not on this crate. Two copies of
/// the quiet-profile settings is how one of them ends up years out of date, which is
/// what had already happened.
pub use cfx_capture::browser;

#[cfg(feature = "testing")]
pub mod testing;

use cfx_capture::{CaptureCfg, Egress, LocalGate, SessionCa, TraceEvent, serve_mitm_flow};
use cfx_project::{Project, ProjectSink};

/// How a session should behave.
pub struct SessionConfig {
    /// Where to listen. Use port 0 to let the OS pick, then read [`Session::port`].
    ///
    /// Defaults to loopback. A capture proxy listening on every interface is one anybody
    /// on the network can route their traffic through, using the operator's machine and
    /// their trusted CA, so binding wider is a decision rather than a default.
    pub bind: SocketAddr,
    pub project: Arc<Project>,
    /// The CA whose leaves the browser must trust. Persisted by the host, because a fresh
    /// CA per session is what makes an already-installed certificate fail.
    pub ca: Arc<SessionCa>,
    /// Park each request for a human before it leaves.
    pub intercept: bool,
    /// Hosts carried through without interception, for certificate pinning that would
    /// otherwise break the application under test.
    pub bypass_hosts: Vec<String>,
    /// Forward to origins whose certificate no public CA signed. A per-project decision;
    /// see `CaptureCfg::trust_any_upstream_cert` for what it costs.
    pub trust_any_upstream_cert: bool,
}

impl SessionConfig {
    pub fn new(project: Arc<Project>, ca: Arc<SessionCa>) -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            project,
            ca,
            intercept: false,
            bypass_hosts: Vec::new(),
            trust_any_upstream_cert: false,
        }
    }
}

/// A listening capture session. Dropping it stops accepting; [`Session::stop`] also waits.
pub struct Session {
    port: u16,
    gate: Arc<LocalGate>,
    project: Arc<Project>,
    stop: tokio::sync::watch::Sender<bool>,
    accepting: tokio::task::JoinHandle<()>,
}

impl Session {
    pub async fn start(cfg: SessionConfig) -> std::io::Result<Self> {
        install_crypto();

        let listener = TcpListener::bind(cfg.bind).await?;
        let port = listener.local_addr()?.port();

        // Always built, switched rather than conditional. A gate that only exists when
        // interception was on at start is why the UI's toggle could not work without
        // stopping the proxy.
        let gate = Arc::new(LocalGate::new());
        gate.set_enabled(cfg.intercept);
        let sink = Arc::new(ProjectSink::new(cfg.project.clone()));
        let capture = CaptureCfg {
            // The local store is the full-capture surface by definition: a workbench
            // exists to show the operator the bytes.
            full: true,
            gate: Some(gate.clone() as Arc<dyn cfx_capture::InterceptGate>),
            bypass_hosts: cfg.bypass_hosts.clone(),
            sink: Some(sink),
            trust_any_upstream_cert: cfg.trust_any_upstream_cert,
        };

        // The capture core also emits privacy-safe events on a channel, which a session
        // with no control plane has nobody to send to. Drained and dropped rather than
        // left unread, because an unbounded channel nobody reads is a slow leak for the
        // life of the session.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let (stop, mut stop_rx) = tokio::sync::watch::channel(false);
        let ca = cfg.ca.clone();
        let accepting = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    r = listener.accept() => r,
                    _ = stop_rx.changed() => return,
                };
                let Ok((stream, _)) = accepted else { continue };
                let ctx = FlowCtx {
                    ca: ca.clone(),
                    tx: tx.clone(),
                    capture: capture.clone(),
                };
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let ctx = ctx.clone();
                        async move { Ok::<_, std::convert::Infallible>(proxy(req, ctx).await) }
                    });
                    // `with_upgrades`, or CONNECT cannot hand the socket over and every
                    // https destination silently fails.
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .with_upgrades()
                        .await;
                });
            }
        });

        Ok(Self {
            port,
            gate,
            project: cfg.project,
            stop,
            accepting,
        })
    }

    /// The port actually bound, which is what a browser is pointed at.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The intercept queue. Always present; ask it whether it is holding.
    pub fn gate(&self) -> &Arc<LocalGate> {
        &self.gate
    }

    /// Whether requests are being held right now.
    pub fn intercepting(&self) -> bool {
        self.gate.is_enabled()
    }

    /// Turn interception on or off without stopping the proxy. Returns how many held
    /// requests were released, which is non-zero only when switching off.
    pub fn set_intercept(&self, on: bool) -> usize {
        self.gate.set_enabled(on)
    }

    pub fn project(&self) -> &Arc<Project> {
        &self.project
    }

    /// Stop accepting and release anything held at the gate.
    ///
    /// The gate is shut down first. A held request is one the operator was still looking
    /// at, and releasing it to the target after they closed the session is the one outcome
    /// nobody asked for.
    pub async fn stop(self) {
        let dropped = self.gate.shutdown();
        if dropped > 0 {
            log::info!("session stopping: dropped {dropped} request(s) still held");
        }
        let _ = self.stop.send(true);
        self.accepting.abort();
        let _ = self.accepting.await;
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("port", &self.port)
            .field("intercepting", &self.gate.is_enabled())
            .field("project", &self.project.path())
            .finish()
    }
}

#[derive(Clone)]
struct FlowCtx {
    ca: Arc<SessionCa>,
    tx: tokio::sync::mpsc::UnboundedSender<TraceEvent>,
    capture: CaptureCfg,
}

fn text(status: u16, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

/// One request on the proxy connection.
async fn proxy(req: Request<hyper::body::Incoming>, ctx: FlowCtx) -> Response<Full<Bytes>> {
    if req.method() != Method::CONNECT {
        // See the module note. Saying what is wrong matters: a bare failure here reads as
        // the target being unreachable, which sends the operator to look at the target.
        log::warn!(
            "proxy: {} {} is a plaintext proxy request, which this session does not carry yet",
            req.method(),
            req.uri()
        );
        return text(
            501,
            "This capture session carries CONNECT (https) only. A plaintext \
             http:// request through the proxy is not forwarded yet.",
        );
    }

    let Some(authority) = req.uri().authority().cloned() else {
        return text(400, "CONNECT needs an authority");
    };
    let host = authority.host().to_string();
    // The browser omits the port for 443. Guessing 80 here would send every https flow to
    // a plaintext port and look like the target refusing TLS.
    let port = authority.port_u16().unwrap_or(443);

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                log::debug!("proxy: CONNECT {host}:{port} never upgraded: {e}");
                return;
            }
        };
        // Straight to the capture core, which does its own peek, SNI read, bypass check
        // and MITM handshake. Nothing is parsed here.
        match serve_mitm_flow(
            TokioIo::new(upgraded),
            host.clone(),
            port,
            ctx.ca,
            Egress::Direct,
            ctx.tx,
            ctx.capture,
        )
        .await
        {
            Ok(outcome) => {
                // A TLS flow that served no request is the signature of certificate
                // pinning in application code, and is worth distinguishing from an idle
                // connection or the operator never visiting the site.
                if outcome.tls && outcome.requests == 0 && !outcome.bypassed {
                    log::info!(
                        "{host}:{port} completed a TLS handshake and then sent nothing, which \
                         is what pinning looks like"
                    );
                }
            }
            Err(e) => log::debug!("flow {host}:{port} ended: {e}"),
        }
    });

    // 200 lets the browser go ahead with the handshake this session then intercepts.
    Response::new(Full::new(Bytes::new()))
}

/// Install the rustls crypto provider. Idempotent, and in one place so the session and the
/// test helper cannot install different ones.
pub(crate) fn install_crypto() {
    cfx_capture::install_default_crypto_provider();
}
