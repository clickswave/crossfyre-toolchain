//! A browser-shaped capture, start to finish, with no control plane.
//!
//! This is Phase 1's exit criterion reduced to a test: point something at the proxy port,
//! let it CONNECT and do TLS, and find the exchange in a local project file afterwards.
//! The client is written over a raw socket so the test has no HTTP client of its own to be
//! wrong about, and it speaks the sequence a browser speaks: CONNECT, read 200, then
//! handshake inside the tunnel.
//!
//! `localhost` is the target name throughout for a boring reason: the proxy dials the
//! CONNECT authority, so the name has to resolve, and the client verifies the MITM leaf
//! against the same name. A made-up hostname would fail DNS inside the proxy and look
//! like the target being down.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cfx_capture::{EditedRequest, InterceptDecision, generate_ca};
use cfx_project::{Cap, Project};
use cfx_session::{Session, SessionConfig};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "cfx-session-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&p);
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A TLS origin with its own self-signed leaf for `localhost`, the way an internal service
/// looks. Returns its port and a count of handshakes it completed.
async fn tls_origin(reply: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
    cfx_capture::install_default_crypto_provider();
    let key = rcgen::KeyPair::generate().expect("key");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf = params.self_signed(&key).expect("leaf");
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(leaf.der().to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let seen = seen2.clone();
            let reply = reply.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(sock).await {
                    seen.fetch_add(1, Ordering::Relaxed);
                    let mut buf = vec![0u8; 16 * 1024];
                    // One read is enough: these requests are small and the reply does not
                    // depend on what they said.
                    let _ =
                        tokio::time::timeout(Duration::from_millis(300), tls.read(&mut buf)).await;
                    let _ = tls.write_all(&reply).await;
                    let _ = tls.flush().await;
                }
            });
        }
    });
    (port, seen)
}

fn ok_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nServer: e2e-origin\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// Do what a browser does: CONNECT through `proxy_port` to `target`, then TLS inside the
/// tunnel trusting `ca_pem`, then one request. Returns (status, body).
async fn through_proxy(
    proxy_port: u16,
    target_port: u16,
    ca_pem: &str,
    method: &str,
    path: &str,
    body: &'static [u8],
) -> (u16, bytes::Bytes) {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect = format!(
        "CONNECT localhost:{target_port} HTTP/1.1\r\nHost: localhost:{target_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    tcp.flush().await.unwrap();

    // Read exactly the CONNECT response head and no more, or the TLS bytes that follow
    // would be swallowed with it.
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tcp.read(&mut one).await.unwrap();
        assert!(n > 0, "the proxy closed during CONNECT");
        head.push(one[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the tunnel was refused: {head}"
    );

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = connector
        .connect(name, tcp)
        .await
        .expect("the MITM leaf verified against the session CA");

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("localhost:{target_port}"))
        .header("content-type", "application/octet-stream")
        .body(Full::new(bytes::Bytes::from_static(body)))
        .unwrap();
    let resp = sender
        .send_request(req)
        .await
        .expect("the request completed");
    let status = resp.status().as_u16();
    let got = resp.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    (status, got)
}

#[tokio::test]
async fn a_browse_through_the_session_lands_in_the_project() {
    let s = Scratch::new("e2e");
    let (origin_port, handshakes) = tls_origin(ok_response("hello-from-origin")).await;

    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project.clone(), ca);
    // The origin is self-signed, which is the internal-application case.
    cfg.trust_any_upstream_cert = true;
    let session = Session::start(cfg).await.expect("session starts");
    assert!(session.port() > 0, "a port was bound");
    assert!(session.gate().is_none(), "not intercepting unless asked");

    // Bytes no UTF-8 decoder round trips, so the project's copy is provably the real one.
    const BINARY: &[u8] = &[0x89, b'P', b'N', b'G', 0x00, 0xff, 0xfe, 0x80];
    let (status, body) = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "POST",
        "/upload?x=1",
        BINARY,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"hello-from-origin");
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        1,
        "the proxy really did reach the origin over TLS"
    );

    // Give the sink its moment: it records on the request's own task, which finishes just
    // after the client has its response.
    for _ in 0..200 {
        if project.count().await.expect("count") > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(project.count().await.expect("count"), 1);
    let stored = project.get(1).await.expect("get").expect("the exchange");
    assert_eq!(stored.exchange.method, "POST");
    assert_eq!(
        stored.exchange.url,
        format!("https://localhost:{origin_port}/upload?x=1"),
        "https, because the flow was MITM-terminated, and the query value is kept"
    );
    assert_eq!(stored.exchange.status, Some(200));
    assert_eq!(
        stored.exchange.req_body, BINARY,
        "the request body survived the whole path byte for byte"
    );
    assert_eq!(stored.exchange.resp_body, b"hello-from-origin");

    // And it is searchable, which is what a history pane needs.
    let hits = project.search("upload", 10).await.expect("search");
    assert_eq!(hits.len(), 1, "the URL is indexed");

    session.stop().await;
}

#[tokio::test]
async fn an_intercepting_session_holds_a_request_until_the_operator_decides() {
    let s = Scratch::new("intercept");
    let (origin_port, _) = tls_origin(ok_response("released")).await;

    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project.clone(), ca);
    cfg.intercept = true;
    cfg.trust_any_upstream_cert = true;
    let session = Session::start(cfg).await.expect("session starts");
    let gate = session.gate().expect("intercepting").clone();
    let port = session.port();

    let browse = tokio::spawn(async move {
        through_proxy(port, origin_port, &ca_pem, "GET", "/original", b"").await
    });

    // What a UI awaits instead of polling.
    tokio::time::timeout(Duration::from_secs(10), gate.arrival())
        .await
        .expect("a request arrived at the gate");
    let waiting = gate.pending();
    assert_eq!(waiting.len(), 1);
    assert_eq!(
        waiting[0].url,
        format!("https://localhost:{origin_port}/original")
    );
    assert_eq!(
        project.count().await.expect("count"),
        0,
        "nothing is recorded while the request is still held, because no exchange happened"
    );

    assert!(gate.resolve(
        waiting[0].id,
        InterceptDecision::ForwardModified(EditedRequest {
            method: "GET".into(),
            path: "/edited".into(),
            headers: vec![("host".into(), format!("localhost:{origin_port}"))],
            body: Vec::new(),
        })
    ));

    let (status, body) = tokio::time::timeout(Duration::from_secs(10), browse)
        .await
        .expect("the browse finished")
        .expect("no panic");
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"released");

    for _ in 0..200 {
        if project.count().await.expect("count") > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stored = project.get(1).await.expect("get").expect("the exchange");
    assert_eq!(
        stored.exchange.url,
        format!("https://localhost:{origin_port}/edited"),
        "the project records what was actually sent, which is the operator's version"
    );

    session.stop().await;
}

#[tokio::test]
async fn stopping_a_session_drops_what_the_operator_was_still_looking_at() {
    let s = Scratch::new("stop");
    let (origin_port, handshakes) = tls_origin(ok_response("never")).await;

    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project.clone(), ca);
    cfg.intercept = true;
    cfg.trust_any_upstream_cert = true;
    let session = Session::start(cfg).await.expect("session starts");
    let gate = session.gate().expect("intercepting").clone();
    let port = session.port();

    let browse = tokio::spawn(async move {
        through_proxy(port, origin_port, &ca_pem, "GET", "/held", b"").await
    });
    tokio::time::timeout(Duration::from_secs(10), gate.arrival())
        .await
        .expect("a request arrived");

    // The operator closes the session with a request still on screen.
    session.stop().await;

    let (status, _) = tokio::time::timeout(Duration::from_secs(10), browse)
        .await
        .expect("the browse finished")
        .expect("no panic");
    assert_eq!(
        status, 403,
        "a request nobody approved is refused rather than forwarded on the way out"
    );
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        0,
        "and the origin was never reached"
    );
    assert_eq!(project.count().await.expect("count"), 0);
}
