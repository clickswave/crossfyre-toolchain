//! The SOCKS5 server against raw client bytes, and against this crate's client.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use cfx_tunnel::socks5_server::{
    self, ADDRESS_TYPE_NOT_SUPPORTED, COMMAND_NOT_SUPPORTED, GENERAL_FAILURE, Refusal, SUCCEEDED,
};
use cfx_tunnel::{Host, Target, Timeouts, TunnelError, Upstream, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const USER: &str = "3f9c0a7b1e2d4c56";
const SECRET: &str = "9e1f0c2b4d6a8e0f1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d";

type Accepted = Result<(&'static str, Target), Refusal>;

/// A server that accepts one client with [`socks5_server::accept`], counting how often
/// it asks for the credentials to be checked. On success it answers `code`.
async fn server(deadline: Duration, code: u8) -> (u16, Arc<AtomicUsize>, JoinHandle<Accepted>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let checks = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&checks);
    let h = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let got = socks5_server::accept(&mut s, deadline, |u, p| {
            counted.fetch_add(1, Ordering::SeqCst);
            (u == USER && socks5_server::secret_eq(p.as_bytes(), SECRET.as_bytes()))
                .then_some("lease-1")
        })
        .await;
        if got.is_ok() {
            socks5_server::reply(&mut s, code).await.unwrap();
        } else {
            // Close with a FIN after the answer and read what the client sent past the
            // point of refusal. Dropping with those bytes unread sends a reset, and
            // Windows discards an answer the reset overtakes.
            tokio::spawn(async move {
                let _ = s.shutdown().await;
                let mut rest = Vec::new();
                let _ =
                    tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut rest)).await;
            });
        }
        got
    });
    (port, checks, h)
}

fn auth(user: &str, pass: &str) -> Vec<u8> {
    let mut a = vec![1, user.len() as u8];
    a.extend_from_slice(user.as_bytes());
    a.push(pass.len() as u8);
    a.extend_from_slice(pass.as_bytes());
    a
}

async fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut b))
        .await
        .expect("no answer from the server after 5 s")
        .unwrap();
    b
}

/// Everything the server sends until it closes.
async fn rest(s: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
    out
}

/// Greeting and credentials, accepted.
async fn logged_in(port: u16) -> TcpStream {
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(read_n(&mut c, 2).await, [5, 2]);
    c.write_all(&auth(USER, SECRET)).await.unwrap();
    assert_eq!(read_n(&mut c, 2).await, [1, 0]);
    c
}

const LONG: Duration = Duration::from_secs(5);

#[tokio::test]
async fn a_name_comes_back_unresolved_and_the_client_hears_the_reply() {
    let (port, checks, h) = server(LONG, SUCCEEDED).await;
    let mut c = logged_in(port).await;
    let mut req = vec![5, 1, 0, 3, 15];
    req.extend_from_slice(b"app.example.com");
    req.extend_from_slice(&443u16.to_be_bytes());
    c.write_all(&req).await.unwrap();
    assert_eq!(read_n(&mut c, 10).await, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let (lease, target) = h.await.unwrap().unwrap();
    assert_eq!(lease, "lease-1");
    assert_eq!(
        target,
        Target {
            host: Host::Name("app.example.com".into()),
            port: 443
        }
    );
    assert_eq!(checks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn addresses_come_back_as_addresses() {
    let v6: Ipv6Addr = "2001:db8::9".parse().unwrap();
    let mut v6_req = vec![5, 1, 0, 4];
    v6_req.extend_from_slice(&v6.octets());
    v6_req.extend_from_slice(&[0, 80]);
    // A name that is an address literal is an address, so an address policy sees it.
    let mut lit_req = vec![5, 1, 0, 3, 9];
    lit_req.extend_from_slice(b"127.0.0.1");
    lit_req.extend_from_slice(&[0, 80]);
    let mut lit6_req = vec![5, 1, 0, 3, 3];
    lit6_req.extend_from_slice(b"::1");
    lit6_req.extend_from_slice(&[0, 80]);
    let cases = [
        (
            vec![5, 1, 0, 1, 169, 254, 169, 254, 0, 80],
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        ),
        (v6_req, IpAddr::V6(v6)),
        (lit_req, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        (lit6_req, IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];
    for (req, ip) in cases {
        let (port, _, h) = server(LONG, SUCCEEDED).await;
        let mut c = logged_in(port).await;
        c.write_all(&req).await.unwrap();
        assert_eq!(read_n(&mut c, 2).await, [5, 0]);
        let (_, target) = h.await.unwrap().unwrap();
        assert_eq!(
            target,
            Target {
                host: Host::Ip(ip),
                port: 80
            }
        );
    }
}

#[tokio::test]
async fn a_client_offering_no_auth_only_is_refused_unchecked() {
    let (port, checks, h) = server(LONG, SUCCEEDED).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(rest(&mut c).await, [5, 0xFF]);
    assert_eq!(h.await.unwrap().err(), Some(Refusal::NoUserPass));
    assert_eq!(checks.load(Ordering::SeqCst), 0);

    // No methods at all is the same.
    let (port, _, h) = server(LONG, SUCCEEDED).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&[5, 0]).await.unwrap();
    assert_eq!(rest(&mut c).await, [5, 0xFF]);
    assert_eq!(h.await.unwrap().err(), Some(Refusal::NoUserPass));
}

#[tokio::test]
async fn wrong_credentials_are_refused_and_the_connection_closes() {
    let wrong_secret = format!("{}0", &SECRET[..SECRET.len() - 1]);
    let cases = [
        auth(USER, &wrong_secret),
        auth(USER, &SECRET[..SECRET.len() - 1]),
        auth("0000000000000000", SECRET),
        auth(USER, ""),
    ];
    for creds in cases {
        let (port, checks, h) = server(LONG, SUCCEEDED).await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(&[5, 2, 0, 2]).await.unwrap();
        assert_eq!(read_n(&mut c, 2).await, [5, 2]);
        c.write_all(&creds).await.unwrap();
        // Status 1, then the connection closes.
        assert_eq!(rest(&mut c).await, [1, 1]);
        assert_eq!(h.await.unwrap().err(), Some(Refusal::Auth));
        assert_eq!(checks.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn credentials_that_cannot_be_checked_are_refused_unchecked() {
    // An empty user name, and a password that is not UTF-8.
    for creds in [
        vec![1, 0, 3, b'a', b'b', b'c'],
        vec![1, 1, b'u', 2, 0xC3, 0x28],
    ] {
        let (port, checks, h) = server(LONG, SUCCEEDED).await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(&[5, 1, 2]).await.unwrap();
        assert_eq!(read_n(&mut c, 2).await, [5, 2]);
        c.write_all(&creds).await.unwrap();
        assert_eq!(rest(&mut c).await, [1, 1]);
        assert_eq!(h.await.unwrap().err(), Some(Refusal::Auth));
        assert_eq!(checks.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bind_and_udp_associate_get_command_not_supported() {
    for cmd in [2u8, 3, 9] {
        let (port, _, h) = server(LONG, SUCCEEDED).await;
        let mut c = logged_in(port).await;
        c.write_all(&[5, cmd, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let got = rest(&mut c).await;
        assert_eq!(got[..2], [5, COMMAND_NOT_SUPPORTED], "cmd {cmd}");
        assert_eq!(h.await.unwrap().err(), Some(Refusal::Command(cmd)));
    }
}

#[tokio::test]
async fn an_unknown_address_type_gets_address_type_not_supported() {
    let (port, _, h) = server(LONG, SUCCEEDED).await;
    let mut c = logged_in(port).await;
    c.write_all(&[5, 1, 0, 2, 0, 0, 0, 0, 0, 80]).await.unwrap();
    assert_eq!(rest(&mut c).await[..2], [5, ADDRESS_TYPE_NOT_SUPPORTED]);
    assert_eq!(h.await.unwrap().err(), Some(Refusal::AddressType(2)));
}

#[tokio::test]
async fn destinations_no_proxy_is_asked_for_get_general_failure() {
    let named = |name: &[u8], port: u16| {
        let mut r = vec![5, 1, 0, 3, name.len() as u8];
        r.extend_from_slice(name);
        r.extend_from_slice(&port.to_be_bytes());
        r
    };
    let cases = [
        named(b"", 80),
        named(b"app.example.com", 0),
        named(b"a\r\nb", 80),
        named(b"a b", 80),
        named(b"a\0b", 80),
        named(&[0xC3, 0x28], 80),
        vec![5, 1, 0, 1, 192, 0, 2, 1, 0, 0],
    ];
    for req in cases {
        let (port, _, h) = server(LONG, SUCCEEDED).await;
        let mut c = logged_in(port).await;
        c.write_all(&req).await.unwrap();
        assert_eq!(rest(&mut c).await[..2], [5, GENERAL_FAILURE], "{req:?}");
        assert!(
            matches!(h.await.unwrap(), Err(Refusal::Target(_))),
            "{req:?}"
        );
    }
}

#[tokio::test]
async fn cut_short_or_foreign_greetings_are_malformed_and_unanswered() {
    let cases: [&[u8]; 6] = [
        &[],
        &[5],
        &[5, 3, 2],
        &[4, 1, 0, 80, 127, 0, 0, 1, 0],
        b"CONNECT a:1 HTTP/1.1\r\n\r\n",
        b"\x16\x03\x01\x02\x00",
    ];
    for greeting in cases {
        let (port, checks, h) = server(LONG, SUCCEEDED).await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(greeting).await.unwrap();
        c.shutdown().await.unwrap();
        assert!(rest(&mut c).await.is_empty(), "{greeting:?}: answered");
        assert!(
            matches!(h.await.unwrap(), Err(Refusal::Malformed(_))),
            "{greeting:?}"
        );
        assert_eq!(checks.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn cut_short_credentials_or_request_are_malformed() {
    // Credentials that stop inside the password, then a request that stops inside
    // its name, then one with the wrong version.
    let (port, checks, h) = server(LONG, SUCCEEDED).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&[5, 1, 2]).await.unwrap();
    read_n(&mut c, 2).await;
    c.write_all(&[1, 3, b'a', b'b', b'c', 10, b'x'])
        .await
        .unwrap();
    c.shutdown().await.unwrap();
    assert!(matches!(h.await.unwrap(), Err(Refusal::Malformed(_))));
    assert_eq!(checks.load(Ordering::SeqCst), 0);

    let (port, _, h) = server(LONG, SUCCEEDED).await;
    let mut c = logged_in(port).await;
    c.write_all(&[5, 1, 0, 3, 20, b'a', b'b']).await.unwrap();
    c.shutdown().await.unwrap();
    assert!(matches!(h.await.unwrap(), Err(Refusal::Malformed(_))));

    let (port, _, h) = server(LONG, SUCCEEDED).await;
    let mut c = logged_in(port).await;
    c.write_all(&[4, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await.unwrap();
    assert!(matches!(h.await.unwrap(), Err(Refusal::Malformed(_))));

    // A credentials message with the wrong version.
    let (port, _, h) = server(LONG, SUCCEEDED).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(&[5, 1, 2]).await.unwrap();
    read_n(&mut c, 2).await;
    c.write_all(&[5, 1, b'a', 1, b'b']).await.unwrap();
    assert!(matches!(h.await.unwrap(), Err(Refusal::Malformed(_))));
}

#[tokio::test]
async fn a_client_that_stalls_runs_out_one_deadline() {
    // Silent after connecting.
    let (port, _, h) = server(Duration::from_millis(300), SUCCEEDED).await;
    let _c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let started = Instant::now();
    let got = tokio::time::timeout(LONG, h)
        .await
        .expect("still waiting after 5 s")
        .unwrap();
    assert_eq!(got.err(), Some(Refusal::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));

    // A byte at a time, each well inside the deadline.
    let (port, _, h) = server(Duration::from_millis(500), SUCCEEDED).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let started = Instant::now();
    let mut bytes = vec![5, 1, 2];
    bytes.extend(auth(USER, SECRET));
    let dripper = tokio::spawn(async move {
        for b in bytes {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if c.write_all(&[b]).await.is_err() {
                return;
            }
        }
    });
    let got = tokio::time::timeout(LONG, h)
        .await
        .expect("still waiting after 5 s")
        .unwrap();
    assert_eq!(got.err(), Some(Refusal::Timeout));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    dripper.abort();
}

#[test]
fn secret_eq_compares_whole_secrets() {
    use socks5_server::secret_eq;
    assert!(secret_eq(b"abc", b"abc"));
    assert!(secret_eq(b"", b""));
    assert!(!secret_eq(b"abc", b"abd"));
    assert!(!secret_eq(b"abc", b"ab"));
    assert!(!secret_eq(b"ab", b"abc"));
    assert!(!secret_eq(b"", b"a"));
}

/// This crate's client through this crate's server to an echo destination: the
/// shape of the node's gateway, minus its policy.
#[tokio::test]
async fn the_client_and_server_speak_to_each_other() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 5];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
    });

    let gw = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_port = gw.local_addr().unwrap().port();
    let seen = tokio::spawn(async move {
        let mut targets = Vec::new();
        for _ in 0..2 {
            let (mut s, _) = gw.accept().await.unwrap();
            let got = socks5_server::accept(&mut s, LONG, |u, p| {
                (u == USER && socks5_server::secret_eq(p.as_bytes(), SECRET.as_bytes()))
                    .then_some(())
            })
            .await;
            let Ok(((), target)) = got else {
                targets.push(None);
                continue;
            };
            targets.push(Some(target.clone()));
            match target.host {
                Host::Ip(ip) => {
                    let mut onward = TcpStream::connect((ip, target.port)).await.unwrap();
                    socks5_server::reply(&mut s, SUCCEEDED).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut onward).await;
                }
                Host::Name(_) => {
                    socks5_server::reply(&mut s, socks5_server::HOST_UNREACHABLE)
                        .await
                        .unwrap();
                }
            }
        }
        targets
    });

    let t = Timeouts::default();
    let good = Upstream::parse(&format!("socks5h://{USER}:{SECRET}@127.0.0.1:{gw_port}")).unwrap();
    let mut tunnel = connect(&good, &Target::new("127.0.0.1", echo_port), t)
        .await
        .unwrap();
    tunnel.write_all(b"hello").await.unwrap();
    let mut back = [0u8; 5];
    tunnel.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"hello");
    drop(tunnel);

    let err = connect(&good, &Target::new("app.example.invalid", 443), t)
        .await
        .err()
        .unwrap();
    assert_eq!(err, TunnelError::Refused(socks5_server::HOST_UNREACHABLE));

    let targets = seen.await.unwrap();
    assert_eq!(targets[0], Some(Target::new("127.0.0.1", echo_port)));
    assert_eq!(
        targets[1],
        Some(Target {
            host: Host::Name("app.example.invalid".into()),
            port: 443
        })
    );
}

#[tokio::test]
async fn the_client_hears_a_wrong_secret_as_an_auth_error() {
    let (port, _, h) = server(LONG, SUCCEEDED).await;
    let wrong = Upstream::parse(&format!(
        "socks5h://{USER}:{}@127.0.0.1:{port}",
        "0".repeat(64)
    ))
    .unwrap();
    let err = connect(
        &wrong,
        &Target::new("app.example.invalid", 443),
        Timeouts::default(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err, TunnelError::Auth);
    assert_eq!(h.await.unwrap().err(), Some(Refusal::Auth));
}
