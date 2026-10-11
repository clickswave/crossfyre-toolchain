//! Going out through another proxy.
//!
//! On a corporate network the only route out is the company proxy, and without this the
//! capture cannot reach any target. What is pinned here is the handshake, the two refusals
//! an operator will actually meet, and the one detail that corrupts every flow if it is
//! wrong.

use std::io;

use cfx_capture::{Egress, UpstreamProxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A proxy that answers `answer` to a CONNECT and then relays to `relay_to`, if given.
///
/// Returns its address and the first CONNECT line it was sent, so a test can assert on
/// what went up rather than only on what came back.
async fn proxy(
    answer: &'static str,
    relay_to: Option<String>,
    extra_after_head: &'static str,
) -> (String, tokio::sync::oneshot::Receiver<String>) {
    let l = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = l.local_addr().expect("addr").to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while s.read_exact(&mut b).await.is_ok() {
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&head).to_string());
        let _ = s.write_all(answer.as_bytes()).await;
        // Whatever a careless proxy might send straight after its blank line. The tunnel's
        // first bytes belong to the origin, so anything over-read here is lost from the
        // target's first response.
        if !extra_after_head.is_empty() {
            let _ = s.write_all(extra_after_head.as_bytes()).await;
        }
        if let Some(to) = relay_to {
            let mut up = TcpStream::connect(to).await.expect("relay");
            let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
        }
    });
    (addr, rx)
}

fn up(addr: &str, auth: Option<(&str, &str)>) -> UpstreamProxy {
    let (h, p) = addr.rsplit_once(':').expect("host:port");
    UpstreamProxy {
        host: h.to_string(),
        port: p.parse().expect("port"),
        auth: auth.map(|(u, p)| (u.to_string(), p.to_string())),
    }
}

#[tokio::test]
async fn a_tunnel_is_opened_and_the_bytes_go_through() {
    // Something to reach, so the tunnel can be shown to carry rather than only to open.
    let origin = TcpListener::bind(("127.0.0.1", 0)).await.expect("origin");
    let origin_addr = origin.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.expect("accept");
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hello");
        s.write_all(b"world").await.expect("write");
    });

    let (addr, asked) = proxy(
        "HTTP/1.1 200 Connection established\r\n\r\n",
        Some(origin_addr.clone()),
        "",
    )
    .await;
    let (host, port) = origin_addr.rsplit_once(':').expect("split");
    let mut s = Egress::Upstream(up(&addr, None))
        .connect(host, port.parse().expect("port"))
        .await
        .expect("tunnel");

    let sent = asked.await.expect("the proxy read a request");
    assert!(
        sent.starts_with(&format!("CONNECT {origin_addr} HTTP/1.1\r\n")),
        "the CONNECT line names the ORIGIN and not the proxy: {sent:?}"
    );
    assert!(
        sent.to_lowercase()
            .contains(&format!("host: {origin_addr}")),
        "a CONNECT carries a Host: {sent:?}"
    );
    assert!(
        !sent.to_lowercase().contains("proxy-authorization"),
        "no credentials were set, so none may be sent: {sent:?}"
    );

    s.write_all(b"hello").await.expect("write through");
    let mut back = [0u8; 5];
    s.read_exact(&mut back).await.expect("read through");
    assert_eq!(&back, b"world", "the tunnel carries in both directions");
}

#[tokio::test]
async fn credentials_go_up_as_basic_when_they_are_set() {
    let (addr, asked) = proxy("HTTP/1.1 200 OK\r\n\r\n", None, "").await;
    let _ = Egress::Upstream(up(&addr, Some(("ops", "s3cret"))))
        .connect("example.test", 443)
        .await;
    let sent = asked.await.expect("read");
    // base64("ops:s3cret")
    assert!(
        sent.contains("Proxy-Authorization: Basic b3BzOnMzY3JldA=="),
        "the credentials did not go up as Basic: {sent:?}"
    );
}

#[tokio::test]
async fn the_bytes_after_the_blank_line_are_the_tunnel_and_are_not_eaten() {
    // The detail that is invisible when it is wrong and corrupts the first response of
    // every flow: a buffered read of the proxy's answer swallows whatever follows it, and
    // after a 200 those bytes belong to the origin.
    let (addr, _asked) = proxy(
        "HTTP/1.1 200 Connection established\r\n\r\n",
        None,
        "THE-ORIGINS-FIRST-BYTES",
    )
    .await;
    let mut s = Egress::Upstream(up(&addr, None))
        .connect("example.test", 443)
        .await
        .expect("tunnel");
    let mut got = [0u8; 23];
    s.read_exact(&mut got).await.expect("read");
    assert_eq!(
        &got, b"THE-ORIGINS-FIRST-BYTES",
        "the answer's reader ate into the tunnel"
    );
}

#[tokio::test]
async fn a_proxy_that_wants_credentials_says_so_in_words_about_credentials() {
    let (addr, _) = proxy(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
        None,
        "",
    )
    .await;
    let e = Egress::Upstream(up(&addr, None))
        .connect("example.test", 443)
        .await
        .expect_err("407 is not a tunnel");
    let said = e.to_string();
    assert!(
        said.contains("wants credentials") && said.contains("none were set"),
        "a 407 with nothing configured has one obvious cause and the message should name \
         it: {said}"
    );

    // And with credentials set, the same status means something else entirely.
    let (addr2, _) = proxy("HTTP/1.1 407 Nope\r\n\r\n", None, "").await;
    let e2 = Egress::Upstream(up(&addr2, Some(("ops", "wrong"))))
        .connect("example.test", 443)
        .await
        .expect_err("407 is not a tunnel");
    assert!(
        e2.to_string().contains("refused the ones given"),
        "the same status with credentials set means they were wrong: {e2}"
    );
}

#[tokio::test]
async fn a_refusal_and_a_silence_are_both_reported_against_the_proxy() {
    let (addr, _) = proxy("HTTP/1.1 403 Forbidden\r\n\r\n", None, "").await;
    let e = Egress::Upstream(up(&addr, None))
        .connect("blocked.test", 443)
        .await
        .expect_err("403 is not a tunnel");
    assert!(
        e.to_string().contains("refused to carry blocked.test:443"),
        "a refusal names what was refused: {e}"
    );

    // Nothing listening at all. The message has to name the PROXY, because "connection
    // refused" with no subject reads as the target refusing and sends somebody to look at
    // the wrong machine.
    let dead = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let dead_addr = dead.local_addr().expect("addr").to_string();
    drop(dead);
    let e = Egress::Upstream(up(&dead_addr, None))
        .connect("example.test", 443)
        .await
        .expect_err("nothing is listening");
    assert!(
        e.to_string().contains("upstream proxy") && e.to_string().contains("could not be reached"),
        "the message does not name the proxy: {e}"
    );
}

#[tokio::test]
async fn a_proxy_that_answers_nothing_gives_up_rather_than_holding_the_flow() {
    // Accepts and says nothing. Without a deadline this holds the flow for as long as the
    // window is open and the operator sees a page that never loads with nothing saying why.
    let l = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = l.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let (s, _) = l.accept().await.expect("accept");
        // Held, not dropped: a closed socket is a different path.
        std::future::pending::<()>().await;
        drop(s);
    });

    let e = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Egress::Upstream(up(&addr, None)).connect("example.test", 443),
    )
    .await
    .expect("the deadline fired before the test's own")
    .expect_err("silence is not a tunnel");
    assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
}

#[tokio::test]
async fn the_password_is_not_in_the_debug_output() {
    // A derived Debug on a struct holding a credential is that credential printed by every
    // `{:?}` anybody adds later, including the one in a log line written in a hurry.
    let e = Egress::Upstream(up("127.0.0.1:8080", Some(("ops", "s3cret"))));
    let shown = format!("{e:?}");
    assert!(
        !shown.contains("s3cret"),
        "the password is in Debug: {shown}"
    );
    assert!(shown.contains("ops"), "the user is worth seeing: {shown}");
}
