//! Proxy conformance, headless.
//!
//! The capture core is a library, so the behaviour a user calls "the proxy works" can be
//! asserted with no window, no device and no TUN. That matters more here than usual: a
//! proxy that silently stops intercepting looks exactly like a proxy that is working
//! until somebody notices an empty history, and the unit tests next to each module check
//! the pieces rather than the path through them.
//!
//! This drives the public API only (`serve_mitm_flow`, `CaptureCfg`, `Egress`,
//! `InterceptGate`), which is also the claim being tested: that a front-end needs nothing
//! private to run a flow.
//!
//! Two things it deliberately does not cover, so the gap is written down rather than
//! implied:
//!
//! - The UPSTREAM TLS leg. When the client leg is TLS the forward leg is too, and it
//!   validates against the webpki roots, which no loopback origin can satisfy. So the TLS
//!   case here asserts everything up to the origin dial (peek, leaf, handshake, request
//!   parse) and then that the failure is a 502 rather than a dropped connection. The
//!   origin-side half is exercised against real hosts on device.
//! - The out-of-line blob threshold named in the test plan. That belongs to the project
//!   store, which does not exist yet. What is testable today is that a body far larger
//!   than any internal buffer survives the round trip byte for byte, which is below.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use cfx_capture::{
    CaptureCfg, EditedRequest, Egress, InterceptDecision, InterceptGate, SessionCa, TraceEvent,
    generate_ca, serve_mitm_flow,
};

/// Every assertion that could hang instead of failing gets this. A proxy bug whose symptom
/// is "the request never comes back" is the one this suite exists to catch, and a hung test
/// reports as a timed-out CI job rather than as a red assertion.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long a test origin waits for a request to stop arriving before it answers.
const ORIGIN_IDLE: Duration = Duration::from_millis(100);

/// How long a client waits for more of a reply after the first byte. Deliberately far
/// larger than [`ORIGIN_IDLE`]: with both at one value, a pipelined second response that
/// was simply behind the first read as a second response that never came, which is a
/// race dressed up as a proxy defect.
const CLIENT_IDLE: Duration = Duration::from_millis(1500);

async fn within<F: Future>(what: &str, f: F) -> F::Output {
    match tokio::time::timeout(PATIENCE, f).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {PATIENCE:?}, which counts as a failure"),
    }
}

// ---------------------------------------------------------------------------
// Origins
// ---------------------------------------------------------------------------

/// What a test origin saw and how often it was reached.
#[derive(Default)]
struct OriginLog {
    received: Mutex<Vec<Vec<u8>>>,
    connections: AtomicUsize,
}

impl OriginLog {
    fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
    fn first(&self) -> Vec<u8> {
        self.received
            .lock()
            .unwrap()
            .first()
            .cloned()
            .unwrap_or_default()
    }
}

/// An origin that writes `reply` verbatim to every connection and records what it read
/// first. Writing bytes rather than building a response is the point: several cases below
/// need a reply that no HTTP library would produce, such as a body that stops early or an
/// HTTP/2 preface.
fn origin(reply: Vec<u8>) -> (u16, Arc<OriginLog>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = TcpListener::from_std(listener).unwrap();
    let log = Arc::new(OriginLog::default());
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let reply = reply.clone();
            let log = log2.clone();
            log.connections.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let got = read_until_quiet(&mut s, ORIGIN_IDLE).await;
                log.received.lock().unwrap().push(got);
                let _ = s.write_all(&reply).await;
                let _ = s.flush().await;
                // Dropping here closes the connection, which is what makes a reply with a
                // short body read as "the origin went away mid-body".
            });
        }
    });
    (port, log)
}

/// Read until the peer has been quiet for a moment. Used instead of parsing a request
/// because some cases send bytes that are not a request at all, such as a ClientHello.
async fn read_until_quiet<S: AsyncReadExt + Unpin>(s: &mut S, idle: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match tokio::time::timeout(idle, s.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => return out,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => return out,
        }
    }
}

/// Read a reply: wait up to `PATIENCE` for the first byte, then until the peer has gone
/// quiet. The two timeouts have to differ. The origins here answer only after their own
/// idle period, so one short timeout reads an empty reply and reports it as the proxy
/// having sent nothing, which is a test bug that looks exactly like the bug being hunted.
async fn read_reply<S: AsyncReadExt + Unpin>(s: &mut S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    match tokio::time::timeout(PATIENCE, s.read(&mut buf)).await {
        Ok(Ok(0)) | Err(_) => return out,
        Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
        Ok(Err(_)) => return out,
    }
    out.extend_from_slice(&read_until_quiet(s, CLIENT_IDLE).await);
    out
}

/// The single `Content-Length` the origin was given, as a number.
///
/// Parsed rather than matched as a substring, because a substring is how this check first
/// went vacuous: `"content-length: 4096"` contains `"content-length: 4"`, so a test that
/// asserted a four-byte body had a four-byte length passed while the wire said 4096.
/// Panics on anything other than exactly one header, since two is itself the framing bug.
fn declared_length(raw: &str) -> usize {
    let values: Vec<&str> = raw
        .lines()
        .filter_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .collect();
    assert_eq!(
        values.len(),
        1,
        "expected exactly one content-length, saw {values:?} in:\n{raw}"
    );
    values[0]
        .parse()
        .unwrap_or_else(|_| panic!("content-length {:?} is not a number", values[0]))
}

fn ok_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nServer: conformance-origin\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// The capture front end under test
// ---------------------------------------------------------------------------

/// A listener with `serve_mitm_flow` behind it, pointed at `origin_port`. Returns the port
/// to connect to, the flow's eventual outcome, and the events it emitted.
struct Front {
    port: u16,
    outcome: tokio::task::JoinHandle<Vec<Result<cfx_capture::FlowOutcome, String>>>,
    events: tokio::sync::mpsc::UnboundedReceiver<TraceEvent>,
    ca: Arc<SessionCa>,
}

/// Accept `flows` connections, run each through the capture core, and collect what each
/// one turned out to be.
async fn front(origin_port: u16, cfg: CaptureCfg, flows: usize) -> Front {
    cfx_capture::install_default_crypto_provider();
    let ca = Arc::new(generate_ca().unwrap());
    let (tx, events) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ca2 = ca.clone();
    // Each accepted flow is SPAWNED, not awaited in turn. A front end that served one
    // flow to completion before accepting the next would pass every single-flow test in
    // this file while being useless, and would hide the one property a GUI depends on:
    // that a flow parked on a human does not stop the others.
    let outcome = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..flows {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let (ca, tx, cfg) = (ca2.clone(), tx.clone(), cfg.clone());
            tasks.push(tokio::spawn(async move {
                serve_mitm_flow(
                    client,
                    "127.0.0.1".into(),
                    origin_port,
                    ca,
                    Egress::Direct,
                    tx,
                    cfg,
                )
                .await
                .map_err(|e| e.to_string())
            }));
        }
        let mut out = Vec::new();
        for t in tasks {
            out.push(t.await.expect("the flow task did not panic"));
        }
        out
    });
    Front {
        port,
        outcome,
        events,
        ca,
    }
}

/// One plaintext HTTP/1 request through `port`, returning (status, body).
async fn plain_request(port: u16, req: Request<Full<Bytes>>) -> (u16, Bytes) {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = within("the request", sender.send_request(req))
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

fn get(path: &str, host: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// 1. TLS and plaintext on the same entry point
// ---------------------------------------------------------------------------

/// A minimal TLS 1.2-shaped ClientHello carrying `host` as SNI. Enough for the first-byte
/// peek and the SNI read, which is all the bypass decision looks at. Not a handshake a
/// real server would complete, which is exactly what makes it a clean probe: if the flow
/// intercepts instead of bypassing, the handshake fails and no bytes reach the origin.
fn client_hello(host: &str) -> Vec<u8> {
    let mut sni = vec![0x00];
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    let mut sni_list = (sni.len() as u16).to_be_bytes().to_vec();
    sni_list.extend_from_slice(&sni);
    let mut ext = vec![0x00, 0x00];
    ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_list);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[tokio::test]
async fn a_plaintext_client_is_forwarded_and_reported_as_plaintext() {
    let (op, olog) = origin(ok_response("plain-ok"));
    let mut f = front(op, CaptureCfg::default(), 1).await;

    let (status, body) = plain_request(f.port, get("/hello", "origin.test")).await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"plain-ok");
    assert_eq!(olog.connections(), 1, "the origin was dialled exactly once");

    let ev = within("the event", f.events.recv())
        .await
        .expect("an event");
    assert_eq!(ev.url, "http://origin.test/hello");

    let outcomes = within("the flow", f.outcome).await.unwrap();
    let o = outcomes[0].as_ref().expect("the flow completed");
    assert!(!o.tls, "a plaintext flow must not report itself as TLS");
    assert_eq!(o.requests, 1);
    assert!(!o.bypassed);
}

#[tokio::test]
async fn a_tls_client_on_the_same_entry_point_gets_our_leaf() {
    // No origin reply matters here: the forward leg cannot complete against a loopback
    // origin (see the module note), and what is being asserted is everything before it.
    let (op, _olog) = origin(ok_response("unreachable-over-tls"));
    let mut f = front(op, CaptureCfg::default(), 1).await;

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut f.ca.pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));

    let tcp = TcpStream::connect(("127.0.0.1", f.port)).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("origin.test").unwrap();
    // The handshake is the assertion. It succeeds only if the peek routed 0x16 to the TLS
    // path and the resolver minted a leaf for this SNI that chains to the session CA.
    let tls = within("the TLS handshake", connector.connect(name, tcp))
        .await
        .expect("a client trusting the session CA completes the MITM handshake");

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = within(
        "the request",
        sender.send_request(get("/over-tls", "origin.test")),
    )
    .await
    .unwrap();
    // 502 and not a closed connection: an upstream that cannot be reached must not take
    // the client's connection with it.
    assert_eq!(
        resp.status(),
        502,
        "an unreachable upstream answers 502 through the open client connection"
    );
    // Hyper keeps the connection alive, so the flow is still serving until the client
    // hangs up. Dropping the sender is the client hanging up.
    drop(sender);

    let outcomes = within("the flow", f.outcome).await.unwrap();
    let o = outcomes[0].as_ref().expect("the flow completed");
    assert!(o.tls, "a TLS flow must report itself as TLS");
    assert_eq!(o.requests, 1, "the request parsed over TLS");
    assert!(!o.bypassed);
    // No event: the exchange never completed, and a half-measured request is worse than
    // none in a history a human reads as evidence.
    assert!(f.events.try_recv().is_err());
}

// ---------------------------------------------------------------------------
// 2. Bypass
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_bypassed_host_is_relayed_untouched() {
    let (op, olog) = origin(Vec::new());
    let cfg = CaptureCfg {
        bypass_hosts: vec!["pinned.test".to_string()],
        ..Default::default()
    };
    let mut f = front(op, cfg, 1).await;

    let hello = client_hello("pinned.test");
    let mut tcp = TcpStream::connect(("127.0.0.1", f.port)).await.unwrap();
    tcp.write_all(&hello).await.unwrap();
    tcp.flush().await.unwrap();
    // The relay is a `copy_bidirectional`, which finishes only once both directions have
    // closed. Without this the flow is still correctly relaying when the test gives up.
    tcp.shutdown().await.unwrap();

    let outcomes = within("the flow", f.outcome).await.unwrap();
    let o = outcomes[0].as_ref().expect("the flow completed");
    assert!(o.bypassed, "a host on the bypass list is carried through");
    assert!(o.tls);
    assert_eq!(o.requests, 0, "a bypassed flow is never parsed");

    // Untouched means byte for byte, including the ClientHello that was already read in
    // order to make the decision. Replaying it is what keeps the handshake valid.
    let seen = olog.first();
    assert_eq!(
        seen, hello,
        "the origin received the ClientHello exactly as the client sent it"
    );
    assert!(
        f.events.try_recv().is_err(),
        "a bypassed flow emits no event, because nothing was inspected"
    );
}

#[tokio::test]
async fn a_host_not_on_the_bypass_list_is_intercepted_instead() {
    // The control for the test above. Without it, a bypass that fired for every host
    // would pass just as well, and "bypass works" would mean "interception is off".
    let (op, olog) = origin(Vec::new());
    let cfg = CaptureCfg {
        bypass_hosts: vec!["other.test".to_string()],
        ..Default::default()
    };
    let f = front(op, cfg, 1).await;

    let mut tcp = TcpStream::connect(("127.0.0.1", f.port)).await.unwrap();
    tcp.write_all(&client_hello("pinned.test")).await.unwrap();
    tcp.flush().await.unwrap();

    let outcomes = within("the flow", f.outcome).await.unwrap();
    match outcomes[0].as_ref() {
        // The synthetic hello cannot finish a real handshake, so interception fails here.
        // That it failed at the TLS acceptor rather than being relayed is the point.
        Err(_) => {}
        Ok(o) => assert!(
            !o.bypassed,
            "this host is not on the list and must be intercepted"
        ),
    }
    assert_eq!(
        olog.connections(),
        0,
        "an intercepted flow does not relay the ClientHello to the origin"
    );
}

// ---------------------------------------------------------------------------
// 3. Chunked bodies, both directions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_chunked_response_is_reassembled_for_the_client_and_the_event() {
    let reply = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n\
                 5\r\nhello\r\n1\r\n-\r\n5\r\nworld\r\n0\r\n\r\n";
    let (op, _olog) = origin(reply.as_bytes().to_vec());
    let cfg = CaptureCfg {
        full: true,
        ..Default::default()
    };
    let mut f = front(op, cfg, 1).await;

    let (status, body) = plain_request(f.port, get("/chunked", "origin.test")).await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"hello-world", "the chunks arrive reassembled");

    let ev = within("the event", f.events.recv())
        .await
        .expect("an event");
    assert_eq!(
        ev.resp_body.as_deref(),
        Some("hello-world"),
        "full capture records the reassembled body, not the chunk framing"
    );
}

#[tokio::test]
async fn a_chunked_request_body_reaches_the_origin_whole() {
    let (op, olog) = origin(ok_response("got-it"));
    let cfg = CaptureCfg {
        full: true,
        ..Default::default()
    };
    let mut f = front(op, cfg, 1).await;

    // Written as raw bytes rather than handed to a client library, so the chunk framing
    // under test is the framing on the wire. `c` and `9` are the two pieces, 21 bytes in
    // total, split so the field names straddle the boundary: a proxy that reads only the
    // first chunk sees `{"user":"a",` and would find one field name instead of two.
    let wire = "POST /submit HTTP/1.1\r\nHost: origin.test\r\n\
                Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n\
                c\r\n{\"user\":\"a\",\r\n9\r\n\"pw\":\"b\"}\r\n0\r\n\r\n";
    let mut tcp = TcpStream::connect(("127.0.0.1", f.port)).await.unwrap();
    tcp.write_all(wire.as_bytes()).await.unwrap();
    tcp.flush().await.unwrap();
    let raw = read_reply(&mut tcp).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200 OK"),
        "the chunked request was accepted, got:\n{text}"
    );

    let seen = String::from_utf8_lossy(&olog.first()).to_string();
    assert!(
        seen.contains(r#"{"user":"a","pw":"b"}"#),
        "the origin received the whole body in one piece, got:\n{seen}"
    );
    // One chunk of 0x15, where the client sent two. The body is buffered before it is
    // forwarded, so the origin sees the proxy's framing rather than a relay of the
    // client's. The `Transfer-Encoding` header is carried over and the re-framing agrees
    // with it, which is what makes this consistent rather than merely working.
    assert!(
        seen.contains("15\r\n{\"user\":\"a\",\"pw\":\"b\"}\r\n0\r\n\r\n"),
        "the two client chunks were coalesced into one, got:\n{seen}"
    );

    let ev = within("the event", f.events.recv())
        .await
        .expect("an event");
    assert!(
        ev.body_params.contains(&"user".to_string()) && ev.body_params.contains(&"pw".to_string()),
        "field names are read off the reassembled body"
    );
}

// ---------------------------------------------------------------------------
// 4. The three intercept decisions
// ---------------------------------------------------------------------------

struct FixedGate {
    decision: InterceptDecision,
    seen: Arc<Mutex<Vec<String>>>,
}

impl InterceptGate for FixedGate {
    fn decide<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        _headers: &'a [(String, String)],
        _body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = InterceptDecision> + Send + 'a>> {
        self.seen.lock().unwrap().push(format!("{method} {url}"));
        let d = self.decision.clone();
        Box::pin(async move { d })
    }
}

fn gated(decision: InterceptDecision) -> (CaptureCfg, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let cfg = CaptureCfg {
        full: true,
        gate: Some(Arc::new(FixedGate {
            decision,
            seen: seen.clone(),
        })),
        bypass_hosts: Vec::new(),
    };
    (cfg, seen)
}

#[tokio::test]
async fn a_gate_that_forwards_changes_nothing() {
    let (op, olog) = origin(ok_response("forwarded"));
    let (cfg, seen) = gated(InterceptDecision::Forward);
    let f = front(op, cfg, 1).await;

    let (status, body) = plain_request(f.port, get("/gated", "origin.test")).await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"forwarded");
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["GET http://origin.test/gated"],
        "the gate saw the request, with the full URL and not the redacted one"
    );
    let got = String::from_utf8_lossy(&olog.first()).to_string();
    assert!(got.starts_with("GET /gated "), "got:\n{got}");
}

#[tokio::test]
async fn a_gate_that_modifies_replaces_what_the_origin_sees() {
    let (op, olog) = origin(ok_response("edited"));
    let (cfg, _seen) = gated(InterceptDecision::ForwardModified(EditedRequest {
        method: "PUT".into(),
        path: "/edited?by=operator".into(),
        headers: vec![
            ("host".into(), "origin.test".into()),
            ("x-added-by".into(), "interceptor".into()),
        ],
        body: b"operator-chose-this".to_vec(),
    }));
    let f = front(op, cfg, 1).await;

    let (status, _body) = plain_request(
        f.port,
        Request::builder()
            .method("GET")
            .uri("/original")
            .header("host", "origin.test")
            .body(Full::new(Bytes::from_static(b"client-sent-this")))
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200);

    let got = String::from_utf8_lossy(&olog.first()).to_string();
    assert!(
        got.starts_with("PUT /edited?by=operator "),
        "the edited request line is what left, got:\n{got}"
    );
    assert!(got.to_ascii_lowercase().contains("x-added-by: interceptor"));
    assert!(got.ends_with("operator-chose-this"), "got:\n{got}");
    assert!(
        !got.contains("client-sent-this") && !got.contains("/original"),
        "nothing of the original request reached the origin, got:\n{got}"
    );
}

#[tokio::test]
async fn a_gate_that_drops_answers_403_and_never_dials_the_origin() {
    let (op, olog) = origin(ok_response("should-never-be-sent"));
    let (cfg, seen) = gated(InterceptDecision::Drop);
    let mut f = front(op, cfg, 1).await;

    let (status, body) = plain_request(f.port, get("/dropped", "origin.test")).await;
    assert_eq!(status, 403);
    assert_eq!(&body[..], b"dropped by interceptor");
    assert_eq!(seen.lock().unwrap().len(), 1, "the gate was consulted");
    assert_eq!(
        olog.connections(),
        0,
        "a dropped request must not reach the origin at all, which is the whole promise"
    );
    assert!(
        f.events.try_recv().is_err(),
        "a dropped request is not an exchange and emits no event"
    );
}

// ---------------------------------------------------------------------------
// 5. A body larger than any internal buffer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_three_megabyte_response_survives_byte_for_byte() {
    // Not random: a repeating pattern makes a truncation or a doubled buffer visible in
    // the failure message rather than as "3145728 != 3145727".
    let body: Vec<u8> = (0..3 * 1024 * 1024)
        .map(|i| b'a' + (i % 26) as u8)
        .collect();
    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    reply.extend_from_slice(&body);

    let (op, _olog) = origin(reply);
    let cfg = CaptureCfg {
        full: true,
        ..Default::default()
    };
    let mut f = front(op, cfg, 1).await;

    let (status, got) = plain_request(f.port, get("/big", "origin.test")).await;
    assert_eq!(status, 200);
    assert_eq!(got.len(), body.len(), "length survived");
    assert_eq!(&got[..], &body[..], "contents survived");

    let ev = within("the event", f.events.recv())
        .await
        .expect("an event");
    assert_eq!(
        ev.resp_body.as_ref().map(|b| b.len()),
        Some(body.len()),
        "full capture recorded the whole body rather than a prefix"
    );
}

// ---------------------------------------------------------------------------
// 6. An origin that goes away mid-body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_origin_that_closes_mid_body_answers_502_rather_than_hanging() {
    // Declares 4096 bytes, sends 16, closes. The failure this guards against is the proxy
    // waiting for the rest forever, which on a desktop looks like a frozen tab.
    let mut reply = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n".to_vec();
    reply.extend_from_slice(b"only-sixteen-byt");
    let (op, olog) = origin(reply);
    let mut f = front(op, CaptureCfg::default(), 1).await;

    let (status, _body) = plain_request(f.port, get("/truncated", "origin.test")).await;
    assert_eq!(
        status, 502,
        "a body that stops early is an upstream error, not a 200 with a short body"
    );
    assert_eq!(olog.connections(), 1);
    assert!(
        f.events.try_recv().is_err(),
        "no event for an exchange that never completed"
    );
}

// ---------------------------------------------------------------------------
// 7. Pipelining
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_pipelined_requests_are_both_served_in_order() {
    let (op, olog) = origin(ok_response("pipelined"));
    let mut f = front(op, CaptureCfg::default(), 1).await;

    // Both requests in one write, before either response is read. A proxy that reads one
    // request and discards the rest of the buffer answers the first and stalls the second.
    let mut tcp = TcpStream::connect(("127.0.0.1", f.port)).await.unwrap();
    let both = "GET /first HTTP/1.1\r\nHost: origin.test\r\n\r\n\
                GET /second HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n";
    tcp.write_all(both.as_bytes()).await.unwrap();
    tcp.flush().await.unwrap();

    let raw = read_reply(&mut tcp).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    assert_eq!(
        text.matches("HTTP/1.1 200 OK").count(),
        2,
        "both pipelined requests were answered, got:\n{text}"
    );
    assert_eq!(
        olog.connections(),
        2,
        "each forwarded request dials its own upstream connection"
    );

    let a = within("the first event", f.events.recv())
        .await
        .expect("event 1");
    let b = within("the second event", f.events.recv())
        .await
        .expect("event 2");
    assert_eq!(
        [a.url.as_str(), b.url.as_str()],
        ["http://origin.test/first", "http://origin.test/second"],
        "events are emitted in the order the requests arrived"
    );
}

// ---------------------------------------------------------------------------
// 8. An upstream that answers with HTTP/2
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_upstream_that_answers_with_http2_is_reported_not_hung() {
    // We offer HTTP/1.1 and never negotiate h2, so an origin that replies with an h2
    // preface is misconfigured or doing prior-knowledge h2. Either way the only two
    // acceptable outcomes are a quick error to the client or nothing at all; what must not
    // happen is the client waiting on a response that will never parse.
    let mut reply = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // An empty SETTINGS frame: length 0, type 0x04, no flags, stream 0.
    reply.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let (op, olog) = origin(reply);
    let mut f = front(op, CaptureCfg::default(), 1).await;

    let (status, _body) = plain_request(f.port, get("/h2-upstream", "origin.test")).await;
    assert_eq!(
        status, 502,
        "an unparseable upstream reply becomes a 502 rather than a stalled request"
    );
    assert_eq!(olog.connections(), 1);
    assert!(f.events.try_recv().is_err());
}

/// An operator who edits a body by hand and leaves the original `Content-Length` behind.
/// This is not a hypothetical: it is what happens every time someone changes a value in an
/// intercept pane, and the header is the one field nobody remembers to recount.
///
/// The edited path forwards `ed.headers` verbatim, so whatever is asserted here is the
/// contract the intercept UI has to meet. Measured before the fix: hyper honours an
/// explicit `Content-Length` by truncating the body to it, so a 25-byte edit behind a
/// stale `content-length: 5` left as five bytes. Not a smuggling primitive, since the
/// remainder is dropped rather than sent, and the connection is new per request. Worse in
/// one way: the request is well formed, the origin answers it, and the operator reads that
/// answer as evidence about the body they typed.
#[tokio::test]
async fn an_edited_body_is_forwarded_with_a_length_that_matches_it() {
    let (op, olog) = origin(ok_response("edited"));
    let body = b"operator-made-this-longer".to_vec();
    let (cfg, _seen) = gated(InterceptDecision::ForwardModified(EditedRequest {
        method: "POST".into(),
        path: "/edited".into(),
        headers: vec![
            ("host".into(), "origin.test".into()),
            // Stale on purpose: the original body was 5 bytes, the new one is 25.
            ("content-length".into(), "5".into()),
        ],
        body: body.clone(),
    }));
    let f = front(op, cfg, 1).await;

    let (status, _) = plain_request(
        f.port,
        Request::builder()
            .method("POST")
            .uri("/original")
            .header("host", "origin.test")
            .body(Full::new(Bytes::from_static(b"short")))
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200);

    let seen = String::from_utf8_lossy(&olog.first()).to_string();
    assert_eq!(
        declared_length(&seen),
        body.len(),
        "the forwarded length describes the forwarded body, got:\n{seen}"
    );
    assert!(
        seen.ends_with(&String::from_utf8_lossy(&body).to_string()),
        "the whole edited body arrived, got:\n{seen}"
    );
}

/// The other direction of the same mistake: a stale length LARGER than the edited body.
/// On the wire that is `content-length: 4096` followed by four bytes, which leaves a real
/// origin waiting for 4092 more until its own read timeout.
///
/// The origin in this file is deliberately lenient and answers once the request stops
/// arriving, so what this asserts is the wire and not how any particular server reacts to
/// it. The assertion is the declared length, for that reason.
#[tokio::test]
async fn an_edited_body_shorter_than_the_stale_length_still_arrives() {
    let (op, olog) = origin(ok_response("edited"));
    let body = b"tiny".to_vec();
    let (cfg, _seen) = gated(InterceptDecision::ForwardModified(EditedRequest {
        method: "POST".into(),
        path: "/edited".into(),
        headers: vec![
            ("host".into(), "origin.test".into()),
            ("content-length".into(), "4096".into()),
        ],
        body: body.clone(),
    }));
    let f = front(op, cfg, 1).await;

    let (status, _) = plain_request(
        f.port,
        Request::builder()
            .method("POST")
            .uri("/original")
            .header("host", "origin.test")
            .body(Full::new(Bytes::from_static(b"x")))
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200, "the exchange completed rather than stalling");

    let seen = String::from_utf8_lossy(&olog.first()).to_string();
    assert_eq!(
        declared_length(&seen),
        body.len(),
        "the forwarded length is the body's, not the operator's leftover, got:\n{seen}"
    );
    assert!(seen.ends_with("tiny"), "got:\n{seen}");
}

/// A gate that parks for `delay` before answering, which is what a GUI gate does: it waits
/// for a human. Appendix B of the desktop plan lists "can `serve_mitm_flow` be driven with
/// a gate that resolves from a GUI without deadlocking the flow" as a claim read off the
/// code once and never run. This is that claim, run.
struct SlowGate {
    delay: Duration,
}

impl InterceptGate for SlowGate {
    fn decide<'a>(
        &'a self,
        _method: &'a str,
        _url: &'a str,
        _headers: &'a [(String, String)],
        _body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = InterceptDecision> + Send + 'a>> {
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            InterceptDecision::Forward
        })
    }
}

#[tokio::test]
async fn a_flow_parked_on_the_gate_does_not_hold_up_another_flow() {
    // The desktop case this stands in for: two tabs load at once, the operator is staring
    // at the first request in an intercept pane, and the second request must still be
    // able to reach its own pane rather than queueing behind a decision nobody has made.
    const PARK: Duration = Duration::from_millis(600);
    let (op, olog) = origin(ok_response("concurrent"));
    let cfg = CaptureCfg {
        full: false,
        gate: Some(Arc::new(SlowGate { delay: PARK })),
        bypass_hosts: Vec::new(),
    };
    let f = front(op, cfg, 2).await;

    let started = std::time::Instant::now();
    let (a, b) = tokio::join!(
        plain_request(f.port, get("/tab-one", "origin.test")),
        plain_request(f.port, get("/tab-two", "origin.test")),
    );
    let elapsed = started.elapsed();

    assert_eq!((a.0, b.0), (200, 200), "both flows completed");
    assert_eq!(olog.connections(), 2);
    // Serialised, this is two parks back to back. The threshold sits between one and two
    // so it fails on serialisation rather than on a slow machine.
    assert!(
        elapsed < PARK * 2,
        "the two flows overlapped: {elapsed:?} against a {PARK:?} park each, so a flow \
         waiting on the gate blocked the other one"
    );
}
