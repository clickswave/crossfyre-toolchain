//! A send pinned to an address dials that address, and nothing else.
//!
//! The raw sender used to resolve the host itself at connect, so a caller that had
//! already looked the name up and checked where it points had no way to make the send
//! go there. A second lookup can answer differently from the first, and the check then
//! describes a connection that never happened.
//!
//! The name here is under `.invalid`, which never resolves. A send that reaches the
//! listener can only have dialled the pin.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plessor::rawhttp::{ReadUntil, Route, SendFail, Verify, send_until_via};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NAME: &str = "pinned.invalid";
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: pinned.invalid\r\nConnection: close\r\n\r\n";
const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// What a listener saw: how many connections, and per connection the request text, or
/// for TLS the server name the client asked for.
#[derive(Default)]
struct Seen {
    connections: AtomicUsize,
    notes: Mutex<Vec<String>>,
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

async fn plain_listener() -> (SocketAddr, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Seen::default());
    let s = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            s.connections.fetch_add(1, Ordering::SeqCst);
            let head = read_head(&mut stream).await;
            s.notes.lock().unwrap().push(head);
            let _ = stream.write_all(ANSWER).await;
            let _ = stream.flush().await;
        }
    });
    (addr, seen)
}

async fn tls_listener() -> (SocketAddr, Arc<Seen>) {
    let cert = rcgen::generate_simple_self_signed(vec![NAME.into()]).expect("mint");
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("key");
    // The provider named, as in certificate_policy.rs: more than one is linked here.
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
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Seen::default());
    let s = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            s.connections.fetch_add(1, Ordering::SeqCst);
            let Ok(mut tls) = acceptor.clone().accept(stream).await else {
                continue;
            };
            let sni = tls.get_ref().1.server_name().unwrap_or("").to_string();
            s.notes.lock().unwrap().push(sni);
            let _ = read_head(&mut tls).await;
            let _ = tls.write_all(ANSWER).await;
            let _ = tls.flush().await;
        }
    });
    (addr, seen)
}

async fn send(
    host: &str,
    port: u16,
    pin: Option<SocketAddr>,
    https: bool,
) -> Result<Vec<u8>, SendFail> {
    send_via(
        &Route {
            egress: transport::Egress::Inherit,
            block_internal: false,
        },
        host,
        port,
        pin,
        https,
    )
    .await
}

async fn send_via(
    route: &Route,
    host: &str,
    port: u16,
    pin: Option<SocketAddr>,
    https: bool,
) -> Result<Vec<u8>, SendFail> {
    send_until_via(
        route,
        host,
        port,
        pin,
        https,
        REQUEST,
        Duration::from_secs(5),
        ReadUntil::Framed,
        Verify::Any,
    )
    .await
    .0
}

#[tokio::test]
async fn a_pinned_send_dials_the_pin_for_a_name_that_resolves_nowhere() {
    let (addr, seen) = plain_listener().await;
    let out = send(NAME, addr.port(), Some(addr), false).await;

    let body = out.expect("the pin is reachable even though the name is not");
    assert!(String::from_utf8_lossy(&body).contains("200 OK"));
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    let notes = seen.notes.lock().unwrap();
    assert!(
        notes[0].contains("Host: pinned.invalid"),
        "the request goes out as written, naming the host: {:?}",
        notes[0]
    );
}

#[tokio::test]
async fn a_pinned_tls_send_dials_the_pin_and_names_the_host() {
    let (addr, seen) = tls_listener().await;
    let out = send(NAME, addr.port(), Some(addr), true).await;

    let body = out.expect("the pin is reachable over TLS");
    assert!(String::from_utf8_lossy(&body).contains("200 OK"));
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        seen.notes.lock().unwrap()[0],
        NAME,
        "the server name is the host, not the address that was dialled"
    );
}

#[tokio::test]
async fn a_pin_on_another_port_is_refused_before_anything_is_dialled() {
    // A pin is an address the caller decided this host and port go to. One whose port
    // differs from the port being sent to is a mistake somewhere upstream, and dialling
    // it would reach a service nobody checked.
    let (addr, seen) = plain_listener().await;
    let other = if addr.port() == 1 { 2 } else { addr.port() - 1 };
    let out = send(NAME, other, Some(addr), false).await;

    match out {
        Err(SendFail::Connect(why)) => assert!(why.contains(&addr.to_string()), "{why}"),
        Err(e) => panic!("refused, but not as a connect failure: {e}"),
        Ok(_) => panic!("a pin on another port was dialled"),
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn without_a_pin_the_host_is_dialled_as_before() {
    let (addr, seen) = plain_listener().await;
    let out = send("127.0.0.1", addr.port(), None, false).await;
    assert!(String::from_utf8_lossy(&out.expect("reachable")).contains("200 OK"));
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);

    let out = send(NAME, addr.port(), None, false).await;
    assert!(
        matches!(out, Err(SendFail::Connect(_))),
        "and a name that resolves nowhere still goes nowhere"
    );
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_pin_is_refused_through_a_proxy_and_nothing_is_dialled() {
    // A proxy looks the name up itself, so the address the caller checked would not
    // be the one used. Refused before the proxy or the pin is dialled.
    let (addr, seen) = plain_listener().await;
    let (proxy, proxied) = plain_listener().await;
    let route = Route {
        egress: transport::Egress::Proxy(format!("socks5h://127.0.0.1:{}", proxy.port())),
        block_internal: false,
    };
    let out = send_via(&route, NAME, addr.port(), Some(addr), false).await;
    match out {
        Err(SendFail::Connect(why)) => assert!(why.contains("pinned"), "{why}"),
        Err(e) => panic!("refused, but not as a connect failure: {e}"),
        Ok(_) => panic!("a pin was sent through a proxy"),
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 0);
    assert_eq!(proxied.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn block_internal_refuses_a_private_pin_before_dialling_it() {
    let (addr, seen) = plain_listener().await;
    let route = Route {
        egress: transport::Egress::Direct,
        block_internal: true,
    };
    let out = send_via(&route, NAME, addr.port(), Some(addr), false).await;
    assert!(matches!(out, Err(SendFail::Connect(_))), "{out:?}");
    assert_eq!(seen.connections.load(Ordering::SeqCst), 0);
}
