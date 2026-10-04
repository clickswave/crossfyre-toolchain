//! The raw sender honours the caller's certificate policy.
//!
//! It used to have one setting welded in, [`Verify::Any`], which is right for the
//! scanners and was silently also what the Workbench's Repeater and replay got. A replay
//! is several sends of a stored credential for somebody else's account, so "accept
//! whatever certificate answers on that host" is a machine-in-the-middle's work done for
//! it, and the capture proxy had been offering exactly this choice per project the whole
//! time.
//!
//! Driven against a real self-signed TLS server rather than by inspecting a config,
//! because the config being built is not the question. The question is whether a
//! handshake that should be refused is refused.

use std::sync::Arc;
use std::time::Duration;

use cortex::rawhttp::{ReadUntil, SendFail, Verify, send_until};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A TLS server with a certificate no public authority has ever heard of, which is what
/// an internal application behind a company CA looks like from out here.
async fn self_signed_server() -> u16 {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("mint");
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("key");

    // The provider named rather than inferred: cortex pulls in more than one rustls
    // backend through its dependency tree, so the process-level default is ambiguous and
    // rustls refuses to guess. The same provider the sender under test uses.
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("tls protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    tokio::spawn(async move {
        // One connection per policy under test, and a third so a run that reconnects
        // does not hang on an accept that is not coming.
        for _ in 0..3 {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    // A client that walked away mid-handshake is the expected shape of
                    // the refusing case, not a failure of this server.
                    return;
                };
                let mut scratch = [0u8; 1024];
                let _ = tls.read(&mut scratch).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    .await;
                let _ = tls.flush().await;
            });
        }
    });

    port
}

#[tokio::test]
async fn trusting_any_certificate_reaches_a_self_signed_origin() {
    let port = self_signed_server().await;
    let (out, _) = send_until(
        "localhost",
        port,
        true,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        Duration::from_secs(5),
        ReadUntil::Framed,
        Verify::Any,
    )
    .await;

    let body = out.expect("a self-signed origin is reachable when any certificate is accepted");
    assert!(
        String::from_utf8_lossy(&body).contains("200 OK"),
        "expected the origin's response, got {:?}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn checking_certificates_refuses_the_same_origin() {
    let port = self_signed_server().await;
    let (out, _) = send_until(
        "localhost",
        port,
        true,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        Duration::from_secs(5),
        ReadUntil::Framed,
        Verify::WebPki,
    )
    .await;

    // The failure has to be the certificate specifically. A timeout or a connection
    // error would also be "not Ok" and would mean this test was passing for a reason
    // that has nothing to do with the policy, which is how a guard like this rots.
    match out {
        Err(SendFail::Tls(why)) => {
            assert!(
                !why.is_empty(),
                "the reason is what the window puts in front of somebody, so it cannot be empty"
            );
        }
        Err(other) => panic!("refused, but not for the certificate: {other}"),
        Ok(body) => panic!(
            "a certificate no public authority vouches for was accepted: {:?}",
            String::from_utf8_lossy(&body)
        ),
    }
}

/// The two policies disagree about the same origin, which is the whole point of there
/// being two. Asserted together because each test above passes on its own if the
/// parameter is ignored and the hardcoded behaviour happens to match it.
#[tokio::test]
async fn the_policy_is_what_decides() {
    let port = self_signed_server().await;
    let req = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let (lax, _) = send_until(
        "localhost",
        port,
        true,
        req,
        Duration::from_secs(5),
        ReadUntil::Framed,
        Verify::Any,
    )
    .await;
    let (strict, _) = send_until(
        "localhost",
        port,
        true,
        req,
        Duration::from_secs(5),
        ReadUntil::Framed,
        Verify::WebPki,
    )
    .await;

    assert!(lax.is_ok(), "Verify::Any should reach it");
    assert!(strict.is_err(), "Verify::WebPki should not");
}
