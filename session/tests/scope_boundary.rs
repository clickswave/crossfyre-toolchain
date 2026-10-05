//! The scope boundary, asserted at the wire.
//!
//! `cfx_scope`'s own tests prove the rules parse and that the guard records what it
//! refuses. These prove the thing that actually matters: a destination the operator did
//! not write down is never reached.
//!
//! Every one of them asserts at the ORIGIN, by counting the connections it accepted.
//! A gate that answers the client and still dials the target has failed at the only job
//! it has, and from the client's side the two are indistinguishable.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use cfx_capture::cfx_scope::{Guard, Point, Policy};
use cfx_capture::generate_ca;
use cfx_project::{Cap, Project};
use cfx_session::testing::{ok_response, plain_origin, through_proxy, tls_origin};
use cfx_session::{Session, SessionConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "cfx-scope-{tag}-{}-{}",
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

/// A session whose scope is exactly these entries. The test's own list is checked for
/// typos, so a test that silently fenced nothing cannot pass by accident.
async fn session_scoped(s: &Scratch, entries: &[&str]) -> (Session, Arc<Guard>, String) {
    let (policy, rejected) =
        Policy::from_entries(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>());
    assert!(
        rejected.is_empty(),
        "the test's own scope parsed: {rejected:?}"
    );
    let guard = Guard::new(policy);

    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project, ca);
    cfg.trust_any_upstream_cert = true;
    cfg.scope = guard.clone();
    let session = Session::start(cfg).await.expect("session starts");
    (session, guard, ca_pem)
}

/// The raw head of a CONNECT, without the TLS that would follow a 200.
async fn connect_only(proxy_port: u16, authority: &str) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to the proxy");
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    tcp.flush().await.expect("flush");
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        match tokio::time::timeout(Duration::from_millis(600), tcp.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// One absolute-form request, which is how a plaintext target reaches a proxy. No CONNECT.
async fn absolute_form(proxy_port: u16, url: &str, host: &str) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to the proxy");
    tcp.write_all(
        format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("send request");
    tcp.flush().await.expect("flush");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_millis(900), tcp.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[tokio::test]
async fn an_out_of_scope_connect_is_refused_before_anything_is_dialled() {
    let s = Scratch::new("connect");
    let (origin_port, handshakes) = tls_origin(ok_response("should-never-be-read")).await;
    let (session, guard, _ca) = session_scoped(&s, &["in.example"]).await;

    let head = connect_only(session.port(), &format!("localhost:{origin_port}")).await;

    assert!(head.starts_with("HTTP/1.1 403"), "refused: {head}");
    assert!(head.contains("Out of scope"), "and it says why: {head}");
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        0,
        "no handshake happened. Past the 200 the browser begins one against our leaf, and \
         a refusal then reaches the operator as a certificate warning about a site they \
         were never allowed to test"
    );
    assert_eq!(guard.refused_total(), 1);
    assert_eq!(guard.recent(1)[0].point, Point::Connect);
    assert_eq!(guard.recent(1)[0].port, origin_port);
}

#[tokio::test]
async fn an_in_scope_connect_is_carried_as_before() {
    let s = Scratch::new("connect-ok");
    let (origin_port, handshakes) = tls_origin(ok_response("hello")).await;
    let (session, guard, ca_pem) = session_scoped(&s, &["localhost"]).await;

    let (status, body) = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "GET",
        "/x",
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"hello");
    assert_eq!(handshakes.load(Ordering::Relaxed), 1);
    assert_eq!(guard.refused_total(), 0);
}

#[tokio::test]
async fn an_out_of_scope_plaintext_request_is_refused_and_the_origin_sees_nothing() {
    // The plaintext path has no CONNECT, so without a per-request gate it is carried with
    // nothing watching it at all.
    let s = Scratch::new("plain");
    let (origin_port, served) = plain_origin("should-never-be-read").await;
    let (session, guard, _ca) = session_scoped(&s, &["in.example"]).await;

    let resp = absolute_form(
        session.port(),
        &format!("http://127.0.0.1:{origin_port}/admin"),
        &format!("127.0.0.1:{origin_port}"),
    )
    .await;

    assert!(resp.starts_with("HTTP/1.1 403"), "refused: {resp}");
    assert!(
        resp.contains("x-crossfyre-scope: refused"),
        "marked: {resp}"
    );
    assert_eq!(served.load(Ordering::Relaxed), 0, "the origin saw nothing");
    assert_eq!(guard.refused_total(), 1);
    let r = guard.recent(1).remove(0);
    assert_eq!(r.point, Point::Request);
    assert_eq!(
        r.detail.as_deref(),
        Some("GET /admin"),
        "the record says what was asked for, not only where"
    );
}

#[tokio::test]
async fn one_admitted_request_does_not_authorise_the_next_on_the_same_connection() {
    // Absolute-form requests on one proxy connection can each name a different host. A
    // decision made per connection would let one admitted request authorise every later
    // one on the same socket.
    let s = Scratch::new("per-request");
    let (origin_port, served) = plain_origin("ok").await;
    let (session, guard, _ca) = session_scoped(&s, &["127.0.0.1"]).await;

    let mut tcp = TcpStream::connect(("127.0.0.1", session.port()))
        .await
        .expect("connect");
    // First: in scope.
    tcp.write_all(
        format!(
            "GET http://127.0.0.1:{origin_port}/one HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("write one");
    // Second: a different host, out of scope, on the same socket.
    tcp.write_all(
        format!(
            "GET http://out.example:{origin_port}/two HTTP/1.1\r\nHost: out.example:{origin_port}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("write two");
    tcp.flush().await.expect("flush");

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_millis(1200), tcp.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.contains("HTTP/1.1 200"),
        "the first was carried: {text}"
    );
    assert!(
        text.contains("HTTP/1.1 403"),
        "the second was refused: {text}"
    );
    assert_eq!(served.load(Ordering::Relaxed), 1, "one connection, not two");
    assert_eq!(guard.refused_total(), 1);
}

#[tokio::test]
async fn a_bypassed_host_that_is_out_of_scope_is_still_refused() {
    // Bypass says "do not intercept this". Scope says "do not reach this". They are
    // allowed to disagree and scope has to win: the bypass path relays with
    // copy_bidirectional and returns, so there is no per-request gate behind it and
    // nothing is recorded. Bypass winning would be the one path in the product that
    // carries invisible traffic to a destination nobody authorised.
    let s = Scratch::new("bypass");
    let (origin_port, handshakes) = tls_origin(ok_response("nope")).await;
    let (policy, _) = Policy::from_entries(&["in.example".to_string()]);
    let guard = Guard::new(policy);
    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let mut cfg = SessionConfig::new(project, ca);
    cfg.trust_any_upstream_cert = true;
    cfg.bypass_hosts = vec!["localhost".to_string()];
    cfg.scope = guard.clone();
    let session = Session::start(cfg).await.expect("session starts");

    let head = connect_only(session.port(), &format!("localhost:{origin_port}")).await;
    assert!(head.starts_with("HTTP/1.1 403"), "refused: {head}");
    assert_eq!(handshakes.load(Ordering::Relaxed), 0);
    assert_eq!(guard.refused_total(), 1);
}

#[tokio::test]
async fn narrowing_the_scope_takes_effect_without_stopping_the_proxy() {
    // An operator narrows a scope the moment they notice traffic they should not be
    // seeing. Needing a restart to do it means it keeps flowing while they work out how.
    let s = Scratch::new("live");
    let (origin_port, handshakes) = tls_origin(ok_response("hello")).await;
    let (session, _guard, ca_pem) = session_scoped(&s, &["localhost"]).await;

    let (status, _) = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "GET",
        "/before",
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(handshakes.load(Ordering::Relaxed), 1);

    session
        .scope()
        .set_policy(Policy::from_entries(&["somewhere.else".to_string()]).0);

    let head = connect_only(session.port(), &format!("localhost:{origin_port}")).await;
    assert!(head.starts_with("HTTP/1.1 403"), "now refused: {head}");
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        1,
        "and the second never reached the origin"
    );
}

#[tokio::test]
async fn an_unset_scope_carries_everything() {
    // Every project that exists today has no scope. Turning this on must not change any
    // of them: a default that refused would look like a broken proxy rather than a fence.
    let s = Scratch::new("unset");
    let (origin_port, handshakes) = tls_origin(ok_response("hello")).await;
    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project, ca);
    cfg.trust_any_upstream_cert = true;
    let session = Session::start(cfg).await.expect("session starts");

    let (status, body) = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "GET",
        "/x",
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"hello");
    assert_eq!(handshakes.load(Ordering::Relaxed), 1);
}
