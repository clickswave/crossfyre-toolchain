//! The client against local proxies written here, which record what they are sent
//! and answer from a script. Nothing leaves loopback, and no destination name is
//! ever resolved: the names end in `.invalid`, so a client that resolved one itself
//! would fail rather than reach anything.

use std::future::Future;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use cfx_tunnel::{Host, Kind, Target, Timeouts, TunnelError, Upstream, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const NAME: &str = "only-the-proxy-knows.invalid";

fn quick() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_millis(400),
    }
}

fn up(url: &str) -> Upstream {
    Upstream::parse(url).unwrap()
}

/// A proxy that takes one connection on `bind` and runs `script` on it.
async fn proxy_on<F, Fut, T>(bind: &str, script: F) -> (u16, JoinHandle<T>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let l = TcpListener::bind(bind).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        script(s).await
    });
    (port, h)
}

async fn proxy<F, Fut, T>(script: F) -> (u16, JoinHandle<T>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    proxy_on("127.0.0.1:0", script).await
}

async fn take(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await.unwrap();
    b
}

/// The rest of a SOCKS5 request after its first four bytes, read by its address type.
async fn take_socks5_request(s: &mut TcpStream) -> Vec<u8> {
    let mut req = take(s, 4).await;
    let rest = match req[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let len = take(s, 1).await;
            req.extend_from_slice(&len);
            len[0] as usize + 2
        }
        a => panic!("address type {a}"),
    };
    req.extend(take(s, rest).await);
    req
}

/// Reads a ping, writes a pong: the tunnel carries bytes both ways.
async fn ping_pong(s: &mut TcpStream) {
    assert_eq!(take(s, 4).await, b"ping");
    s.write_all(b"pong").await.unwrap();
}

async fn assert_ping_pong(t: &mut cfx_tunnel::Tunnel) {
    t.write_all(b"ping").await.unwrap();
    assert_eq!(read_tunnel(t, 4).await, b"pong");
}

/// Reads `n` bytes from a tunnel, failing rather than waiting for ever.
async fn read_tunnel(t: &mut cfx_tunnel::Tunnel, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), t.read_exact(&mut b))
        .await
        .expect("nothing to read from the tunnel after 5 s")
        .unwrap();
    b
}

/// Holds a connection open until the client closes it, so a client that misread
/// the last answer waits for more and times out instead of hearing the close.
async fn hold(s: &mut TcpStream) {
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink).await;
}

/// A listener that must never be connected to.
async fn untouched() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

async fn assert_untouched(l: &TcpListener) {
    // `connect` has returned, so a connection it made is already queued.
    let got = tokio::time::timeout(Duration::from_millis(100), l.accept()).await;
    assert!(got.is_err(), "the proxy was dialled");
}

const SOCKS5_OK: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

// ── SOCKS5 ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn socks5_sends_the_name_unresolved_after_the_credentials() {
    let (port, seen) = proxy(|mut s| async move {
        let greeting = take(&mut s, 4).await;
        s.write_all(&[5, 2]).await.unwrap();
        let auth = take(&mut s, 1 + 1 + 13 + 1 + 7).await;
        s.write_all(&[1, 0]).await.unwrap();
        let req = take_socks5_request(&mut s).await;
        s.write_all(&SOCKS5_OK).await.unwrap();
        ping_pong(&mut s).await;
        (greeting, auth, req)
    })
    .await;
    let u = up(&format!("socks5://customer-7781:hunter2@127.0.0.1:{port}"));
    let mut t = connect(&u, &Target::new(NAME, 443), quick()).await.unwrap();
    assert_ping_pong(&mut t).await;

    let (greeting, auth, req) = seen.await.unwrap();
    assert_eq!(greeting, [5, 2, 0, 2], "offers no-auth and user/pass");
    let mut want_auth = vec![1, 13];
    want_auth.extend_from_slice(b"customer-7781");
    want_auth.push(7);
    want_auth.extend_from_slice(b"hunter2");
    assert_eq!(auth, want_auth);
    let mut want_req = vec![5, 1, 0, 3, NAME.len() as u8];
    want_req.extend_from_slice(NAME.as_bytes());
    want_req.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(req, want_req, "the name went as address type 3, unresolved");
}

#[tokio::test]
async fn socks5_without_credentials_offers_no_auth_only() {
    let (port, seen) = proxy(|mut s| async move {
        let greeting = take(&mut s, 3).await;
        s.write_all(&[5, 0]).await.unwrap();
        let req = take_socks5_request(&mut s).await;
        s.write_all(&SOCKS5_OK).await.unwrap();
        ping_pong(&mut s).await;
        (greeting, req)
    })
    .await;
    let mut t = connect(
        &up(&format!("socks5://127.0.0.1:{port}")),
        &Target::new("192.0.2.10", 8080),
        quick(),
    )
    .await
    .unwrap();
    assert_ping_pong(&mut t).await;
    let (greeting, req) = seen.await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    assert_eq!(
        req,
        [5, 1, 0, 1, 192, 0, 2, 10, 0x1f, 0x90],
        "an IPv4 target goes as address type 1"
    );
}

#[tokio::test]
async fn socks5_ipv6_target_goes_as_an_address() {
    let (port, seen) = proxy(|mut s| async move {
        take(&mut s, 3).await;
        s.write_all(&[5, 0]).await.unwrap();
        let req = take_socks5_request(&mut s).await;
        s.write_all(&SOCKS5_OK).await.unwrap();
        req
    })
    .await;
    let target = Target::new("[2001:db8::5]", 443);
    connect(
        &up(&format!("socks5h://127.0.0.1:{port}")),
        &target,
        quick(),
    )
    .await
    .unwrap();
    let mut want = vec![5, 1, 0, 4];
    want.extend_from_slice(&"2001:db8::5".parse::<Ipv6Addr>().unwrap().octets());
    want.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(seen.await.unwrap(), want);
}

#[tokio::test]
async fn socks5_proxy_on_ipv6_loopback() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("SKIPPED: this machine has no IPv6 loopback");
        return;
    }
    let (port, seen) = proxy_on("[::1]:0", |mut s| async move {
        take(&mut s, 3).await;
        s.write_all(&[5, 0]).await.unwrap();
        let req = take_socks5_request(&mut s).await;
        s.write_all(&SOCKS5_OK).await.unwrap();
        ping_pong(&mut s).await;
        req
    })
    .await;
    let u = up(&format!("socks5://[::1]:{port}"));
    assert_eq!(u.label(), format!("socks5://[::1]:{port}"));
    let mut t = connect(&u, &Target::new(NAME, 80), quick()).await.unwrap();
    assert_ping_pong(&mut t).await;
    assert_eq!(seen.await.unwrap()[3], 3);
}

#[tokio::test]
async fn socks5_reply_is_read_to_its_end_and_no_further() {
    // The bound address is a name, and the destination's first bytes arrive in the
    // same segment as the reply. They belong to the tunnel.
    let (port, _) = proxy(|mut s| async move {
        take(&mut s, 3).await;
        s.write_all(&[5, 0]).await.unwrap();
        take_socks5_request(&mut s).await;
        let mut reply = vec![5, 0, 0, 3, 13];
        reply.extend_from_slice(b"bound.example");
        reply.extend_from_slice(&[0x04, 0x38]);
        reply.extend_from_slice(b"220 banner\r\n");
        s.write_all(&reply).await.unwrap();
        // Hold the connection open until the client is done.
        let _ = s.read(&mut [0u8; 1]).await;
    })
    .await;
    let mut t = connect(
        &up(&format!("socks5://127.0.0.1:{port}")),
        &Target::new(NAME, 25),
        quick(),
    )
    .await
    .unwrap();
    assert_eq!(read_tunnel(&mut t, 12).await, b"220 banner\r\n");
}

#[tokio::test]
async fn socks5_wrong_credentials_are_an_auth_error() {
    let (port, _) = proxy(|mut s| async move {
        take(&mut s, 4).await;
        s.write_all(&[5, 2]).await.unwrap();
        take(&mut s, 1 + 1 + 1 + 1 + 5).await;
        s.write_all(&[1, 1]).await.unwrap();
    })
    .await;
    let err = connect(
        &up(&format!("socks5://u:wrong@127.0.0.1:{port}")),
        &Target::new(NAME, 443),
        quick(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err, TunnelError::Auth);
}

#[tokio::test]
async fn socks5_proxy_that_wants_credentials_we_lack_is_an_auth_error() {
    let (port, _) = proxy(|mut s| async move {
        take(&mut s, 3).await;
        s.write_all(&[5, 0xFF]).await.unwrap();
    })
    .await;
    let err = connect(
        &up(&format!("socks5://127.0.0.1:{port}")),
        &Target::new(NAME, 443),
        quick(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err, TunnelError::Auth);
}

#[tokio::test]
async fn socks5_refusals_carry_the_reply_code() {
    for code in [1u8, 2, 4, 5, 8, 0x42] {
        let (port, _) = proxy(move |mut s| async move {
            take(&mut s, 3).await;
            s.write_all(&[5, 0]).await.unwrap();
            take_socks5_request(&mut s).await;
            // A refusal cut short after its code: the code is all that matters.
            s.write_all(&[5, code]).await.unwrap();
        })
        .await;
        let err = connect(
            &up(&format!("socks5://127.0.0.1:{port}")),
            &Target::new(NAME, 443),
            quick(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err, TunnelError::Refused(code));
    }
}

#[tokio::test]
async fn socks5_malformed_answers_are_protocol_errors() {
    // Each script answers the greeting and, where it gets that far, the request.
    // The last field holds the connection open after a complete answer, so only
    // reading the answer itself can produce the error.
    type Script = (&'static str, Vec<u8>, Option<Vec<u8>>, bool);
    let scripts: Vec<Script> = vec![
        ("greeting answered with version 4", vec![4, 0], None, true),
        (
            "an HTTP server",
            b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec(),
            None,
            true,
        ),
        ("a method that was not offered", vec![5, 2], None, true),
        ("GSSAPI chosen", vec![5, 1], None, true),
        (
            "reply with version 4",
            vec![5, 0],
            Some(vec![4, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            true,
        ),
        (
            "reply with address type 9",
            vec![5, 0],
            Some(vec![5, 0, 0, 9, 0, 0, 0, 0, 0, 0]),
            true,
        ),
        (
            "reply cut off in its address",
            vec![5, 0],
            Some(vec![5, 0, 0, 1, 127, 0]),
            false,
        ),
        ("greeting answer cut off", vec![5], None, false),
        ("no answer at all, then closed", vec![], None, false),
    ];
    for (what, greeting_reply, request_reply, keep_open) in scripts {
        let (port, _) = proxy(move |mut s| async move {
            take(&mut s, 3).await;
            s.write_all(&greeting_reply).await.unwrap();
            if let Some(r) = request_reply {
                take_socks5_request(&mut s).await;
                s.write_all(&r).await.unwrap();
            }
            if keep_open {
                hold(&mut s).await;
            }
        })
        .await;
        let err = connect(
            &up(&format!("socks5://127.0.0.1:{port}")),
            &Target::new(NAME, 443),
            quick(),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("{what}: a tunnel was opened"));
        assert!(matches!(err, TunnelError::Protocol(_)), "{what}: {err:?}");
    }
}

#[tokio::test]
async fn socks5_name_of_255_bytes_is_sent_and_256_is_refused_before_dialling() {
    let max = format!("{}.invalid", "a".repeat(255 - ".invalid".len()));
    let (port, seen) = proxy(|mut s| async move {
        take(&mut s, 3).await;
        s.write_all(&[5, 0]).await.unwrap();
        let req = take_socks5_request(&mut s).await;
        s.write_all(&SOCKS5_OK).await.unwrap();
        req
    })
    .await;
    connect(
        &up(&format!("socks5://127.0.0.1:{port}")),
        &Target::new(&max, 443),
        quick(),
    )
    .await
    .unwrap();
    let req = seen.await.unwrap();
    assert_eq!(req[4], 255);
    assert_eq!(&req[5..260], max.as_bytes());

    let (l, port) = untouched().await;
    let over = format!("a{max}");
    let err = connect(
        &up(&format!("socks5://127.0.0.1:{port}")),
        &Target::new(&over, 443),
        quick(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, TunnelError::Invalid(_)), "{err:?}");
    assert_untouched(&l).await;
}

#[tokio::test]
async fn oversize_credentials_are_refused_before_dialling() {
    let (l, port) = untouched().await;
    for (user, pass) in [
        ("a".repeat(256), "p".to_string()),
        ("u".to_string(), "p".repeat(256)),
    ] {
        // Built field by field, as the node does from the platform's answer, so only
        // connect's own check stands between it and the wire.
        let u = Upstream {
            kind: Kind::Socks5,
            host: "127.0.0.1".into(),
            port,
            auth: Some((user, pass)),
        };
        let err = connect(&u, &Target::new(NAME, 443), quick())
            .await
            .err()
            .unwrap();
        assert!(matches!(err, TunnelError::Invalid(_)), "{err:?}");
    }
    assert_untouched(&l).await;
}

#[tokio::test]
async fn a_name_that_would_rewrite_the_request_is_refused_before_dialling() {
    let (l, port) = untouched().await;
    let names = [
        "app.example.com:443 HTTP/1.1\r\nHost: internal\r\n\r\nGET / HTTP/1.1\r\nX: y",
        "a\0b",
        "a b",
        "",
    ];
    for kind in ["http", "https", "socks4", "socks5"] {
        for name in names {
            let target = Target {
                host: Host::Name(name.into()),
                port: 443,
            };
            let err = connect(&up(&format!("{kind}://127.0.0.1:{port}")), &target, quick())
                .await
                .err()
                .unwrap();
            assert!(
                matches!(err, TunnelError::Invalid(_)),
                "{kind} {name:?}: {err:?}"
            );
        }
    }
    assert_untouched(&l).await;
}

#[tokio::test]
async fn a_silent_proxy_times_out() {
    for kind in ["http", "socks4", "socks5"] {
        let (port, _) = proxy(|mut s| async move {
            // Read whatever comes and never answer.
            let mut sink = Vec::new();
            let _ = s.read_to_end(&mut sink).await;
        })
        .await;
        let started = Instant::now();
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            connect(
                &up(&format!("{kind}://u@127.0.0.1:{port}")),
                &Target::new(NAME, 443),
                quick(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{kind}: still waiting after 5 s"));
        assert_eq!(res.err(), Some(TunnelError::Timeout), "{kind}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{kind}: {:?}",
            started.elapsed()
        );
    }
}

#[tokio::test]
async fn a_proxy_that_answers_a_byte_at_a_time_runs_out_one_deadline() {
    // Each byte arrives well inside the deadline, and the whole answer does not.
    // A timeout per read would wait for all of it.
    let (port, _) = proxy(|mut s| async move {
        take(&mut s, 3).await;
        for b in [5u8, 0] {
            tokio::time::sleep(Duration::from_millis(150)).await;
            s.write_all(&[b]).await.unwrap();
        }
        take_socks5_request(&mut s).await;
        for b in SOCKS5_OK {
            tokio::time::sleep(Duration::from_millis(150)).await;
            if s.write_all(&[b]).await.is_err() {
                return;
            }
        }
    })
    .await;
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        connect(
            &up(&format!("socks5://127.0.0.1:{port}")),
            &Target::new(NAME, 443),
            quick(),
        ),
    )
    .await
    .expect("still waiting after 5 s");
    assert_eq!(res.err(), Some(TunnelError::Timeout));
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_closed_proxy_port_is_a_connect_error() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = connect(
        &up(&format!("socks5://127.0.0.1:{port}")),
        &Target::new(NAME, 443),
        quick(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, TunnelError::Connect(_)), "{err:?}");
}

/// The proxy's accept queue is full and it accepts nothing, so the kernel drops the
/// next SYN and the connection attempt never completes. Linux only: other systems
/// refuse or queue it instead.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_proxy_that_never_completes_the_tcp_connection_hits_the_connect_timeout() {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let l = sock.listen(0).unwrap();
    let addr = l.local_addr().unwrap();
    // Fill the queue. Each of these completes in the kernel and is never accepted.
    let mut held = Vec::new();
    for _ in 0..4 {
        match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => held.push(s),
            _ => break,
        }
    }
    let t = Timeouts {
        connect: Duration::from_millis(300),
        handshake: Duration::from_secs(5),
    };
    let started = Instant::now();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        connect(&up(&format!("socks5://{addr}")), &Target::new(NAME, 443), t),
    )
    .await
    .expect("still connecting after 5 s")
    .err()
    .unwrap();
    assert!(
        matches!(&err, TunnelError::Connect(m) if m.contains("no connection within")),
        "{err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    drop((held, l));
}

// ── SOCKS4 ─────────────────────────────────────────────────────────────

async fn take_until_nul(s: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = take(s, 1).await[0];
        if b == 0 {
            return out;
        }
        out.push(b);
    }
}

#[tokio::test]
async fn socks4a_sends_the_name_after_the_user_id() {
    let (port, seen) = proxy(|mut s| async move {
        let head = take(&mut s, 8).await;
        let user = take_until_nul(&mut s).await;
        let name = take_until_nul(&mut s).await;
        s.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
        ping_pong(&mut s).await;
        (head, user, name)
    })
    .await;
    let mut t = connect(
        &up(&format!("socks4a://ident@127.0.0.1:{port}")),
        &Target::new(NAME, 443),
        quick(),
    )
    .await
    .unwrap();
    assert_ping_pong(&mut t).await;
    let (head, user, name) = seen.await.unwrap();
    assert_eq!(head, [4, 1, 0x01, 0xBB, 0, 0, 0, 1]);
    assert_eq!(user, b"ident");
    assert_eq!(name, NAME.as_bytes());
}

#[tokio::test]
async fn socks4_sends_an_ipv4_address_as_one() {
    let (port, seen) = proxy(|mut s| async move {
        let head = take(&mut s, 8).await;
        let user = take_until_nul(&mut s).await;
        s.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
        (head, user)
    })
    .await;
    connect(
        &up(&format!("socks4://127.0.0.1:{port}")),
        &Target::new("198.51.100.7", 80),
        quick(),
    )
    .await
    .unwrap();
    let (head, user) = seen.await.unwrap();
    assert_eq!(head, [4, 1, 0, 80, 198, 51, 100, 7]);
    assert!(user.is_empty());
}

#[tokio::test]
async fn socks4_refusal_and_malformed_reply() {
    for (reply, want) in [
        (
            [0u8, 0x5B, 0, 0, 0, 0, 0, 0],
            Some(TunnelError::Refused(0x5B)),
        ),
        (
            [0, 0x5D, 0, 0, 0, 0, 0, 0],
            Some(TunnelError::Refused(0x5D)),
        ),
        ([4, 0x5A, 0, 0, 0, 0, 0, 0], None),
        ([0, 0x00, 0, 0, 0, 0, 0, 0], None),
    ] {
        let (port, _) = proxy(move |mut s| async move {
            take(&mut s, 8).await;
            take_until_nul(&mut s).await;
            take_until_nul(&mut s).await;
            s.write_all(&reply).await.unwrap();
        })
        .await;
        let err = connect(
            &up(&format!("socks4://127.0.0.1:{port}")),
            &Target::new(NAME, 443),
            quick(),
        )
        .await
        .err()
        .unwrap();
        match want {
            Some(w) => assert_eq!(err, w),
            None => assert!(
                matches!(err, TunnelError::Protocol(_)),
                "{reply:?}: {err:?}"
            ),
        }
    }
}

#[tokio::test]
async fn socks4_cannot_carry_ipv6_and_says_so_before_dialling() {
    let (l, port) = untouched().await;
    let target = Target {
        host: Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        port: 443,
    };
    let err = connect(&up(&format!("socks4://127.0.0.1:{port}")), &target, quick())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&err, TunnelError::Invalid(m) if m.contains("IPv6")),
        "{err:?}"
    );
    assert_untouched(&l).await;
}

// ── HTTP CONNECT ───────────────────────────────────────────────────────

async fn take_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(take(s, 1).await[0]);
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn http_connect_with_credentials_and_early_destination_bytes() {
    let (port, seen) = proxy(|mut s| async move {
        let head = take_head(&mut s).await;
        // The destination speaks first, in the same segment as the 200.
        s.write_all(b"HTTP/1.1 200 Connection established\r\nVia: 1.1 test\r\n\r\n220 banner\r\n")
            .await
            .unwrap();
        ping_pong(&mut s).await;
        head
    })
    .await;
    let u = up(&format!("http://Aladdin:open%20sesame@127.0.0.1:{port}"));
    let mut t = connect(&u, &Target::new(NAME, 25), quick()).await.unwrap();
    assert_eq!(read_tunnel(&mut t, 12).await, b"220 banner\r\n");
    assert_ping_pong(&mut t).await;
    assert_eq!(
        seen.await.unwrap(),
        format!(
            "CONNECT {NAME}:25 HTTP/1.1\r\nHost: {NAME}:25\r\n\
             Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n\r\n"
        )
    );
}

#[tokio::test]
async fn http_connect_brackets_an_ipv6_target_and_sends_no_credentials_without_them() {
    let (port, seen) = proxy(|mut s| async move {
        let head = take_head(&mut s).await;
        s.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await.unwrap();
        head
    })
    .await;
    connect(
        &up(&format!("http://127.0.0.1:{port}")),
        &Target::new("2001:db8::5", 8443),
        quick(),
    )
    .await
    .unwrap();
    assert_eq!(
        seen.await.unwrap(),
        "CONNECT [2001:db8::5]:8443 HTTP/1.1\r\nHost: [2001:db8::5]:8443\r\n\r\n"
    );
}

#[tokio::test]
async fn http_status_codes_map_to_errors() {
    for (answer, want) in [
        (
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
            TunnelError::Auth,
        ),
        ("HTTP/1.1 403 Forbidden\r\n\r\n", TunnelError::Http(403)),
        (
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            TunnelError::Http(502),
        ),
        ("HTTP/1.1 301\r\n\r\n", TunnelError::Http(301)),
    ] {
        let (port, _) = proxy(move |mut s| async move {
            take_head(&mut s).await;
            s.write_all(answer.as_bytes()).await.unwrap();
        })
        .await;
        let err = connect(
            &up(&format!("http://u:p@127.0.0.1:{port}")),
            &Target::new(NAME, 443),
            quick(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err, want, "{answer:?}");
    }
}

#[tokio::test]
async fn http_malformed_answers_are_protocol_errors() {
    // `true` holds the connection open after an answer whose headers ended.
    let answers: [(&[u8], bool); 7] = [
        (b"\x05\x00", false),
        (b"SSH-2.0-OpenSSH_9.6\r\n\r\n", true),
        (b"HTTP/2 200\r\n\r\n", true),
        (b"HTTP/1.1 20 OK\r\n\r\n", true),
        (b"HTTP/1.1 2000 OK\r\n\r\n", true),
        (b"HTTP/1.1 200 OK\r\nVia: cut off", false),
        (b"", false),
    ];
    for (answer, keep_open) in answers {
        let (port, _) = proxy(move |mut s| async move {
            take_head(&mut s).await;
            s.write_all(answer).await.unwrap();
            if keep_open {
                hold(&mut s).await;
            }
        })
        .await;
        let err = connect(
            &up(&format!("http://127.0.0.1:{port}")),
            &Target::new(NAME, 443),
            quick(),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("{answer:?}: a tunnel was opened"));
        assert!(
            matches!(err, TunnelError::Protocol(_)),
            "{answer:?}: {err:?}"
        );
    }
}

/// An answer whose headers end exactly at `len` bytes.
fn head_of(len: usize) -> Vec<u8> {
    let start = b"HTTP/1.1 200 OK\r\nX-Pad: ";
    let end = b"\r\n\r\n";
    let mut h = start.to_vec();
    h.resize(len - end.len(), b'a');
    h.extend_from_slice(end);
    h
}

#[tokio::test]
async fn http_answer_headers_are_capped_at_8_kib() {
    // At the cap: accepted.
    let (port, _) = proxy(|mut s| async move {
        take_head(&mut s).await;
        s.write_all(&head_of(8 * 1024)).await.unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
    })
    .await;
    connect(
        &up(&format!("http://127.0.0.1:{port}")),
        &Target::new(NAME, 443),
        quick(),
    )
    .await
    .unwrap();

    // One byte over: refused at the cap, while the proxy is still sending header.
    // A client without the cap reads on until the proxy gives up and closes, which
    // is a different error.
    let (port, _) = proxy(|mut s| async move {
        take_head(&mut s).await;
        s.write_all(&head_of(8 * 1024 + 1)).await.unwrap();
        for _ in 0..256 {
            if s.write_all(&[b'a'; 1024]).await.is_err() {
                return;
            }
        }
    })
    .await;
    let err = connect(
        &up(&format!("http://127.0.0.1:{port}")),
        &Target::new(NAME, 443),
        quick(),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(&err, TunnelError::Protocol(m) if m.contains("8192")),
        "{err:?}"
    );
}
