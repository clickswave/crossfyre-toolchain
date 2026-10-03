//! Test support: an origin to capture and a client that behaves like a browser.
//!
//! Behind the `testing` feature. It exists because three separate test suites needed the
//! same client and the third one would have been the third slightly different
//! implementation of "send CONNECT, read the 200 without eating the TLS bytes that follow,
//! then handshake inside the tunnel". That read is the fiddly part: a buffered read of the
//! CONNECT response swallows the start of the client hello, and the symptom is a handshake
//! failure that looks like the proxy's fault.
//!
//! `localhost` is the name throughout, for a dull but load-bearing reason: the proxy dials
//! the CONNECT authority, so it has to resolve, and the client verifies the MITM leaf
//! against the same name. A made-up hostname fails DNS inside the proxy and presents as
//! the target being down.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A TLS origin with its own self-signed leaf for `localhost`, which is what an internal
/// service behind a corporate CA looks like from here.
///
/// Returns the port and a count of handshakes it COMPLETED. That count is the oracle worth
/// having: a status code cannot tell "the proxy refused the certificate" from "the proxy
/// could not connect", and a handshake either happened or it did not.
pub async fn tls_origin(reply: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
    crate::install_crypto();
    let key = rcgen::KeyPair::generate().expect("keypair");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf = params.self_signed(&key).expect("self-signed leaf");
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(leaf.der().to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let counter = handshakes.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let counter = counter.clone();
            let reply = reply.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(sock).await {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let mut buf = vec![0u8; 16 * 1024];
                    // One read is enough: these requests are small, and the reply does not
                    // depend on what they said.
                    let _ =
                        tokio::time::timeout(Duration::from_millis(300), tls.read(&mut buf)).await;
                    let _ = tls.write_all(&reply).await;
                    let _ = tls.flush().await;
                }
            });
        }
    });
    (port, handshakes)
}

/// A complete HTTP/1 response with `body`.
pub fn ok_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nServer: cfx-test-origin\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// One request through a capture session, the way a browser makes it.
///
/// CONNECT to `localhost:target_port` through `proxy_port`, TLS inside the tunnel trusting
/// `ca_pem`, then the request. Returns (status, body).
pub async fn through_proxy(
    proxy_port: u16,
    target_port: u16,
    ca_pem: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> (u16, Bytes) {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to the proxy");
    let connect = format!(
        "CONNECT localhost:{target_port} HTTP/1.1\r\nHost: localhost:{target_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes())
        .await
        .expect("send CONNECT");
    tcp.flush().await.expect("flush");

    // A byte at a time, stopping exactly at the end of the head. A buffered read here
    // takes the beginning of the TLS client hello with it and the handshake then fails for
    // a reason that has nothing to do with TLS.
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tcp.read(&mut one).await.expect("read CONNECT response");
        assert!(n > 0, "the proxy closed the connection during CONNECT");
        head.push(one[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the tunnel was refused:\n{head}"
    );

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots
            .add(c.expect("a certificate in the CA pem"))
            .expect("add root");
    }
    let mut ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let tls = connector
        .connect(name, tcp)
        .await
        .expect("the MITM leaf verifies against the session CA");

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("http/1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("localhost:{target_port}"))
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::from(body)))
        .expect("build request");
    let resp = sender
        .send_request(req)
        .await
        .expect("the request completed");
    let status = resp.status().as_u16();
    let got = resp
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    // Hyper keeps the connection alive, so the flow serves until the client hangs up.
    drop(sender);
    (status, got)
}

/// Bytes no UTF-8 decoder round trips, for proving a stored body is the real one.
pub fn binary_payload(tag: u8) -> Vec<u8> {
    vec![0x89, b'P', b'N', b'G', 0x00, 0xff, 0xfe, 0x80, tag]
}

/// Poll until `f` is true, or fail. For the gap between a client having its response and
/// the sink having finished recording, which happens on the request's own task.
pub async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..500 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what} never became true");
}
