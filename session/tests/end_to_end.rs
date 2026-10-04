//! A browser-shaped capture, start to finish, with no control plane.
//!
//! Phase 1's exit criterion reduced to a test: point something at the proxy port, let it
//! CONNECT and do TLS, and find the exchange in a local project file afterwards. The
//! client lives in `cfx_session::testing` so that this suite, the workbench's and anything
//! later all speak the same sequence rather than three near-identical hand-rolled ones.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use cfx_capture::{EditedRequest, InterceptDecision, generate_ca};
use cfx_project::{Cap, Project};
use cfx_session::testing::{binary_payload, eventually, ok_response, through_proxy, tls_origin};
use cfx_session::{Session, SessionConfig};

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

/// A session over a fresh project and a fresh CA, with the self-signed origin trusted
/// because every origin in these tests is one.
async fn session_over(s: &Scratch, intercept: bool) -> (Session, Arc<Project>, String) {
    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project.clone(), ca);
    cfg.intercept = intercept;
    cfg.trust_any_upstream_cert = true;
    let session = Session::start(cfg).await.expect("session starts");
    (session, project, ca_pem)
}

#[tokio::test]
async fn a_browse_through_the_session_lands_in_the_project() {
    let s = Scratch::new("e2e");
    let (origin_port, handshakes) = tls_origin(ok_response("hello-from-origin")).await;
    let (session, project, ca_pem) = session_over(&s, false).await;

    assert!(session.port() > 0, "a port was bound");
    assert!(!session.intercepting(), "not intercepting unless asked");

    let payload = binary_payload(0x11);
    let (status, body) = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "POST",
        "/upload?x=1",
        payload.clone(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"hello-from-origin");
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        1,
        "the proxy really did reach the origin over TLS"
    );

    // The sink records on the request's own task, which finishes just after the client has
    // its response.
    let p = project.clone();
    eventually("the exchange was recorded", || {
        let p = p.clone();
        async move { p.count().await.unwrap_or(0) > 0 }
    })
    .await;

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
        stored.exchange.req_body, payload,
        "the request body survived CONNECT, TLS, the MITM and the store byte for byte"
    );
    assert_eq!(stored.exchange.resp_body, b"hello-from-origin");

    let hits = project.search("upload", 10).await.expect("search");
    assert_eq!(hits.len(), 1, "and a history pane can find it");

    session.stop().await;
}

#[tokio::test]
async fn an_intercepting_session_holds_a_request_until_the_operator_decides() {
    let s = Scratch::new("intercept");
    let (origin_port, _) = tls_origin(ok_response("released")).await;
    let (session, project, ca_pem) = session_over(&s, true).await;
    let gate = session.gate().clone();
    let port = session.port();

    let browse = tokio::spawn(async move {
        through_proxy(port, origin_port, &ca_pem, "GET", "/original", Vec::new()).await
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
        "nothing is recorded while the request is held, because no exchange has happened"
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

    let p = project.clone();
    eventually("the exchange was recorded", || {
        let p = p.clone();
        async move { p.count().await.unwrap_or(0) > 0 }
    })
    .await;
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
    let (session, project, ca_pem) = session_over(&s, true).await;
    let gate = session.gate().clone();
    let port = session.port();

    let browse = tokio::spawn(async move {
        through_proxy(port, origin_port, &ca_pem, "GET", "/held", Vec::new()).await
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

#[tokio::test]
async fn a_plaintext_proxy_request_says_what_is_wrong_rather_than_failing_vaguely() {
    // The known gap. It matters that the message names it: a bare failure here reads as
    // the target being unreachable and sends the operator to look at the target.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let s = Scratch::new("plaintext");
    let (session, _project, _ca) = session_over(&s, false).await;

    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", session.port()))
        .await
        .expect("connect");
    tcp.write_all(b"GET http://example.test/x HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .expect("send");
    tcp.flush().await.expect("flush");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf)).await;
    let got = String::from_utf8_lossy(&buf).to_string();

    assert!(got.starts_with("HTTP/1.1 501"), "got:\n{got}");
    assert!(
        got.contains("CONNECT") && got.contains("not forwarded yet"),
        "the reply has to say it is us and not the target, got:\n{got}"
    );
    session.stop().await;
}

#[tokio::test]
async fn a_request_that_never_reached_the_target_is_still_in_the_history() {
    // The silent failure. The proxy answers 502 and the browser shows an error, but with
    // nothing recorded the window stayed empty, so the operator had a target that looked
    // broken, a proxy that looked dead, and no way from the window to tell which. An
    // untrusted target certificate is the common way in: it behaves exactly like a proxy
    // that is not listening.
    let s = Scratch::new("upstream-fail");
    let (origin_port, _) = tls_origin(ok_response("never seen")).await;

    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let ca = Arc::new(generate_ca().expect("ca"));
    let ca_pem = ca.pem.clone();
    let mut cfg = SessionConfig::new(project.clone(), ca);
    // The one difference from every other test here: the self-signed origin is NOT
    // trusted, which is what an internal service behind a corporate CA looks like.
    cfg.trust_any_upstream_cert = false;
    let session = Session::start(cfg).await.expect("session starts");

    let (status, body) = through_proxy(
        session.port(),
        origin_port,
        &ca_pem,
        "GET",
        "/internal/admin",
        Vec::new(),
    )
    .await;
    assert_eq!(status, 502, "the client is told, as a proxy should");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("could not reach the target"),
        "and told whose answer it is rather than given a bare two words, got: {text}"
    );
    assert!(
        text.contains("trust any target cert"),
        "including the fix, which is a switch in the same window, got: {text}"
    );

    let p = project.clone();
    eventually("the failure was recorded", || {
        let p = p.clone();
        async move { p.count().await.unwrap_or(0) > 0 }
    })
    .await;

    let stored = project.get(1).await.expect("get").expect("the row");
    assert_eq!(stored.exchange.method, "GET");
    assert_eq!(
        stored.exchange.url,
        format!("https://localhost:{origin_port}/internal/admin"),
        "the row says what was asked for, which is the point of having it"
    );
    assert_eq!(stored.exchange.status, Some(502));
    assert!(
        stored
            .exchange
            .resp_headers
            .iter()
            .any(|[k, _]| k == "x-crossfyre-proxy-error"),
        "and the response is labelled as the proxy's own, because nothing came back"
    );

    session.stop().await;
}

#[tokio::test]
async fn interception_can_be_switched_without_stopping_the_proxy() {
    // The toggle in the window. Before this the gate only existed if interception was on
    // when the proxy started, so ticking the box mid-session did nothing at all and said
    // nothing about it.
    let s = Scratch::new("toggle");
    let (origin_port, _) = tls_origin(ok_response("through")).await;
    let (session, project, ca_pem) = session_over(&s, false).await;
    assert!(
        !session.intercepting(),
        "starts off because that is what was asked"
    );

    // Off: a request goes straight through and nothing queues.
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
    assert_eq!(session.gate().pending_count(), 0);

    // On, without restarting anything.
    session.set_intercept(true);
    assert!(session.intercepting());
    let port = session.port();
    let pem = ca_pem.clone();
    let browse = tokio::spawn(async move {
        through_proxy(port, origin_port, &pem, "GET", "/after", Vec::new()).await
    });
    tokio::time::timeout(Duration::from_secs(10), session.gate().arrival())
        .await
        .expect("the request is held now");
    assert_eq!(session.gate().pending_count(), 1);

    // And off again releases it rather than dropping it: the operator asked for traffic
    // to flow, not for their queue to be thrown away.
    assert_eq!(
        session.set_intercept(false),
        1,
        "the held request was forwarded"
    );
    let (status, body) = tokio::time::timeout(Duration::from_secs(10), browse)
        .await
        .expect("it completed")
        .expect("no panic");
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"through");

    let p = project.clone();
    eventually("both exchanges recorded", || {
        let p = p.clone();
        async move { p.count().await.unwrap_or(0) >= 2 }
    })
    .await;
    session.stop().await;
}
