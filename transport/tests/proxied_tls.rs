//! Through a proxy the node was given, a scan client checks the destination's
//! certificate even when it was asked to accept any.
//!
//! The proxy carries the bytes of the TLS connection. One that answers CONNECT and
//! then presents a certificate of its own would otherwise read every header, cookie
//! and token the scan sends, and write the responses its findings are made from.
//! Directly, a scanner still reaches a target with a self-signed certificate.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use transport::{AuthSpec, Egress, Redirect, ScanClient, build_scan_client};

const NAME: &str = "app.example.test";
const SECRET: &str = "SESSION-OF-THE-TEST-ACCOUNT";

/// What a server presenting a self-signed certificate for [`NAME`] read: each request
/// head it decrypted, or that the client walked away from the handshake.
type Seen = Arc<Mutex<Vec<String>>>;

fn server_config() -> Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .unwrap();
    Arc::new(cfg)
}

/// Play the destination's TLS server on `s`, with a certificate nothing trusts.
fn present_own_certificate(s: std::net::TcpStream, cfg: Arc<rustls::ServerConfig>, seen: &Seen) {
    let mut s = s;
    let _ = s.set_nonblocking(false);
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut conn = rustls::ServerConnection::new(cfg).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut s);
    let mut buf = vec![0u8; 8192];
    match tls.read(&mut buf) {
        Ok(n) if n > 0 => {
            seen.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = tls.flush();
        }
        _ => seen
            .lock()
            .unwrap()
            .push("the client refused the handshake".into()),
    }
}

/// A SOCKS5 proxy that answers CONNECT for any destination and then plays that
/// destination itself.
async fn hostile_proxy(seen: Seen) -> u16 {
    let cfg = server_config();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (cfg, seen) = (Arc::clone(&cfg), Arc::clone(&seen));
            tokio::spawn(async move {
                let got =
                    cfx_tunnel::socks5_server::accept(&mut s, Duration::from_secs(5), |_, _| {
                        Some(())
                    })
                    .await;
                if got.is_err() || cfx_tunnel::socks5_server::reply(&mut s, 0).await.is_err() {
                    return;
                }
                let s = s.into_std().unwrap();
                let _ = tokio::task::spawn_blocking(move || present_own_certificate(s, cfg, &seen))
                    .await;
            });
        }
    });
    port
}

/// A target with a self-signed certificate, reached directly.
async fn self_signed_target(seen: Seen) -> u16 {
    let cfg = server_config();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (cfg, seen) = (Arc::clone(&cfg), Arc::clone(&seen));
            let s = s.into_std().unwrap();
            tokio::task::spawn_blocking(move || present_own_certificate(s, cfg, &seen));
        }
    });
    port
}

/// A client built as the engines build theirs for an authenticated scan: the session's
/// header and cookie, and invalid certificates accepted.
fn scan_client(egress: &Egress) -> transport::Client {
    let auth: AuthSpec = serde_json::from_value(serde_json::json!({
        "headers": {"Authorization": format!("Bearer {SECRET}")},
        "cookies": "sid=SECRET-COOKIE",
    }))
    .unwrap();
    build_scan_client(
        ScanClient {
            user_agent: "Mozilla/5.0",
            auth: Some(&auth),
            timeout: Some(Duration::from_secs(5)),
            redirect: Redirect::Limited(3),
            accept_invalid_certs: true,
            cookie_store: true,
            ..Default::default()
        },
        egress,
    )
    .expect("builds")
}

#[tokio::test]
async fn through_a_proxy_a_certificate_nothing_trusts_is_refused() {
    let seen: Seen = Arc::default();
    let port = hostile_proxy(Arc::clone(&seen)).await;
    // The shape of the URL the node hands an engine for its gateway.
    let egress = Egress::Proxy(format!(
        "socks5h://3f9c0a7b1e2d4c56:{}@127.0.0.1:{port}",
        "ab".repeat(32)
    ));
    let r = scan_client(&egress)
        .get(format!("https://{NAME}/api/me"))
        .send()
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = seen.lock().unwrap().clone();
    assert!(
        !seen
            .iter()
            .any(|s| s.contains(SECRET) || s.contains("SECRET-COOKIE")),
        "the proxy read the session: {seen:#?}"
    );
    assert!(
        r.is_err(),
        "a response came back: {:?}",
        r.map(|r| r.status())
    );
}

#[tokio::test]
async fn directly_a_self_signed_target_is_still_reached() {
    let seen: Seen = Arc::default();
    let port = self_signed_target(Arc::clone(&seen)).await;
    let r = scan_client(&Egress::Direct)
        .get(format!("https://127.0.0.1:{port}/api/me"))
        .send()
        .await
        .map(|r| r.status().as_u16());
    assert_eq!(r.ok(), Some(200));
    assert!(seen.lock().unwrap()[0].contains(SECRET));
}
