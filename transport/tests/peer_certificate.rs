//! A scan client hands over the certificate the server presented, with the response it
//! came with, so an engine can read whom the certificate names. Over plain HTTP there
//! is none.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use transport::{Egress, ScanClient, build_scan_client, peer_certificate};

/// A self-signed certificate, and the server configuration that presents it.
fn certificate() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec!["app.example.test".into()]).unwrap();
    let der = cert.cert.der().to_vec();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(der.clone())],
        key,
    )
    .unwrap();
    (der, Arc::new(cfg))
}

/// Answer each connection to a new listener with "ok", over TLS with `tls`, or in the
/// clear without it. Returns the listener's port.
fn serve(tls: Option<Arc<rustls::ServerConfig>>) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { break };
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let mut buf = vec![0u8; 8192];
            match &tls {
                Some(cfg) => {
                    let mut conn = rustls::ServerConnection::new(Arc::clone(cfg)).unwrap();
                    let mut t = rustls::Stream::new(&mut conn, &mut s);
                    if matches!(t.read(&mut buf), Ok(n) if n > 0) {
                        let _ = t.write_all(reply);
                        let _ = t.flush();
                    }
                }
                None => {
                    if matches!(s.read(&mut buf), Ok(n) if n > 0) {
                        let _ = s.write_all(reply);
                    }
                }
            }
        }
    });
    port
}

fn client() -> transport::Client {
    build_scan_client(
        ScanClient {
            accept_invalid_certs: true,
            ..ScanClient::default()
        },
        &Egress::Direct,
    )
    .unwrap()
}

#[tokio::test]
async fn the_certificate_the_server_presented_comes_with_the_response() {
    let (der, cfg) = certificate();
    let port = serve(Some(cfg));
    let r = client()
        .get(format!("https://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(peer_certificate(&r), Some(der.as_slice()));
}

#[tokio::test]
async fn plain_http_has_no_certificate() {
    let port = serve(None);
    let r = client()
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(peer_certificate(&r), None);
}
