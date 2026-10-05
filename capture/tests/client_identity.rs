//! Presenting a certificate when a target asks for one.
//!
//! An API that requires a client certificate refuses the handshake without one. The
//! browser holds the operator's certificate, but with this proxy in the middle the browser
//! is no longer the client the target sees, so the certificate has to live here.
//!
//! The end-to-end case runs against a server that really demands client auth, because
//! everything else about this feature can look correct while the certificate is never
//! sent.

use std::sync::Arc;

use cfx_capture::ClientIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
    pem: String,
}

fn a_ca() -> Ca {
    let key = rcgen::KeyPair::generate().expect("ca key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test ca");
    let cert = params.self_signed(&key).expect("self signed");
    let pem = cert.pem();
    Ca { cert, key, pem }
}

/// A certificate and key signed by `ca`, as PEM.
fn issue(cn: &str, ca: &Ca) -> (String, String) {
    let key = rcgen::KeyPair::generate().expect("key");
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("signed by the ca");
    (cert.pem(), key.serialize_pem())
}

#[test]
fn a_certificate_and_its_key_build_an_identity() {
    let ca = a_ca();
    let (cert, key) = issue("ops.example", &ca);
    ClientIdentity::from_pem(&cert, &key).expect("a matched pair builds");
}

#[test]
fn each_half_of_a_bad_paste_is_named_rather_than_lumped_together() {
    let ca = a_ca();
    let (cert, key) = issue("ops.example", &ca);

    // The two arrive in the same paste, so "invalid certificate" sends somebody to look at
    // the wrong one.
    let e = ClientIdentity::from_pem("not a certificate", &key).expect_err("no certificate");
    assert!(e.contains("no certificate was found"), "{e}");
    assert!(
        e.contains("BEGIN CERTIFICATE"),
        "it says what one looks like: {e}"
    );

    let e = ClientIdentity::from_pem(&cert, "not a key").expect_err("no key");
    assert!(e.contains("no private key was found"), "{e}");

    // And the failure that is about neither half on its own.
    let (other_cert, _) = issue("someone.else", &ca);
    let e = ClientIdentity::from_pem(&other_cert, &key).expect_err("mismatched");
    assert!(
        e.contains("does not go with"),
        "a key that is not this certificate's is its own mistake: {e}"
    );
}

#[tokio::test]
async fn the_certificate_is_presented_to_a_server_that_demands_one() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = a_ca();
    let ca_pem = ca.pem.clone();
    let (server_cert, server_key) = issue("localhost", &ca);
    let (client_cert, client_key) = issue("ops.example", &ca);

    // A server that will not talk to anybody without a certificate signed by this CA.
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(c.expect("ca der")).expect("add");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("verifier");
    let chain: Vec<_> = rustls_pemfile::certs(&mut server_cert.as_bytes())
        .collect::<Result<_, _>>()
        .expect("server chain");
    let key = rustls_pemfile::private_key(&mut server_key.as_bytes())
        .expect("read")
        .expect("server key");
    let server_cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let l = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<String>>();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.expect("accept");
        match acceptor.accept(tcp).await {
            Ok(mut s) => {
                // The chain the server received from the client, if it received one.
                let (_, conn) = s.get_ref();
                let who = conn.peer_certificates().map(|c| c.len().to_string());
                let _ = tx.send(who);
                let _ = s.write_all(b"ok").await;
            }
            Err(e) => {
                let _ = tx.send(Some(format!("refused: {e}")));
            }
        }
    });

    let identity = ClientIdentity::from_pem(&client_cert, &client_key).expect("identity");
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    // `trust_any` because the server's certificate is signed by a CA no public root knows,
    // which is the same situation every internal target is in.
    let mut s = identity
        .connector(true)
        .connect(name, tcp)
        .await
        .expect("the handshake completed, so a certificate was accepted");

    let mut back = [0u8; 2];
    s.read_exact(&mut back).await.expect("read");
    assert_eq!(&back, b"ok");

    let seen = rx.await.expect("the server reported");
    assert_eq!(
        seen,
        Some("1".to_string()),
        "the server saw no client certificate, so the identity was configured and not sent"
    );
}

#[tokio::test]
async fn without_an_identity_that_same_server_refuses() {
    // The other half of the claim. Without this, a handshake that succeeded for some
    // unrelated reason would read as the certificate having been presented.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = a_ca();
    let ca_pem = ca.pem.clone();
    let (server_cert, server_key) = issue("localhost", &ca);

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(c.expect("ca der")).expect("add");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("verifier");
    let chain: Vec<_> = rustls_pemfile::certs(&mut server_cert.as_bytes())
        .collect::<Result<_, _>>()
        .expect("chain");
    let key = rustls_pemfile::private_key(&mut server_key.as_bytes())
        .expect("read")
        .expect("key");
    let server_cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let l = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.expect("accept");
        let _ = acceptor.accept(tcp).await;
    });

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer(Arc::new(provider))))
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("the handshake itself completes");
    // rustls reports the refusal on the first read rather than at accept.
    let mut back = [0u8; 2];
    assert!(
        s.read_exact(&mut back).await.is_err(),
        "a server demanding a certificate served somebody who presented none"
    );
}

#[derive(Debug)]
struct AnyServer(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
