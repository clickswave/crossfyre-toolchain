//! Local stand-ins for the proxies and destinations the egress tests send to. Each
//! records what it was asked for and answers as its protocol says. A proxy that
//! accepts a destination answers for that destination itself instead of dialling
//! it, so nothing leaves loopback, and a destination listener that counts zero
//! connections shows that nothing went around the proxy.

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A destination name nothing but the proxy can be trusted with: it ends in
/// `.invalid`, so a client that looked it up itself would fail rather than reach
/// anything.
pub const NAME: &str = "only-the-proxy-knows.invalid";

/// The body every stand-in destination answers with.
pub const BODY: &str = "ok";

/// What a proxy was asked for on one connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// `socks5`, `socks4`, `connect`, or `forward` for an HTTP request in absolute
    /// form.
    pub how: &'static str,
    /// The destination as the proxy received it: a name, or an address as text.
    pub host: String,
    pub port: u16,
    /// The destination came as a name, for the proxy to look up.
    pub name: bool,
    /// The SOCKS5 user name, or the SOCKS4 user id.
    pub user: Option<String>,
    /// The SOCKS5 password.
    pub pass: Option<String>,
    /// The `Proxy-Authorization` header an HTTP proxy was sent.
    pub proxy_authorization: Option<String>,
    /// The request line the destination behind the proxy received.
    pub request: String,
}

/// How an HTTP proxy answers `CONNECT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// 200, then it answers for the destination.
    Open,
    /// 407.
    WantsCredentials,
    /// A 200 whose headers run past 8 KiB.
    Oversize,
    /// Nothing, ever.
    Silent,
}

/// A listener on loopback that counts connections and keeps what each asked for.
#[derive(Clone)]
pub struct Recorder {
    pub port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    connections: Arc<AtomicUsize>,
}

impl Recorder {
    /// Every request completed through this proxy, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// TCP connections accepted, whatever came of them.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    fn push(&self, s: Seen) {
        self.seen.lock().unwrap().push(s);
    }
}

async fn listen<F, Fut>(handle: F) -> Recorder
where
    F: Fn(TcpStream, Recorder) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let r = Recorder {
        port: l.local_addr().unwrap().port(),
        seen: Arc::default(),
        connections: Arc::default(),
    };
    let rec = r.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            rec.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(handle(s, rec.clone()));
        }
    });
    r
}

/// A port nothing listens on.
pub fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A destination: answers any request with 200 and [`BODY`], and counts.
pub async fn destination() -> Recorder {
    listen(|mut s, r| async move {
        let line = read_head(&mut s).await.unwrap_or_default();
        let line = line.lines().next().unwrap_or_default().to_string();
        r.push(Seen {
            how: "direct",
            request: line,
            ..Seen::default()
        });
        let _ = answer_ok(&mut s).await;
    })
    .await
}

/// A SOCKS5 proxy. With `auth` it takes only that user name and password.
pub async fn socks5(auth: Option<(&'static str, &'static str)>) -> Recorder {
    listen(move |mut s, r| async move {
        let _ = socks5_session(&mut s, &r, auth).await;
    })
    .await
}

async fn socks5_session(
    s: &mut TcpStream,
    r: &Recorder,
    auth: Option<(&str, &str)>,
) -> std::io::Result<()> {
    let head = take(s, 2).await?;
    assert_eq!(head[0], 5, "not a SOCKS5 greeting");
    let methods = take(s, head[1] as usize).await?;
    let mut seen = Seen {
        how: "socks5",
        ..Seen::default()
    };
    match auth {
        Some((user, pass)) if methods.contains(&2) => {
            s.write_all(&[5, 2]).await?;
            let v = take(s, 2).await?;
            let u = take(s, v[1] as usize).await?;
            let plen = take(s, 1).await?;
            let p = take(s, plen[0] as usize).await?;
            let (u, p) = (String::from_utf8_lossy(&u), String::from_utf8_lossy(&p));
            if u != user || p != pass {
                s.write_all(&[1, 1]).await?;
                return Ok(());
            }
            s.write_all(&[1, 0]).await?;
            seen.user = Some(u.into_owned());
            seen.pass = Some(p.into_owned());
        }
        None if methods.contains(&0) => s.write_all(&[5, 0]).await?,
        _ => {
            s.write_all(&[5, 0xFF]).await?;
            return Ok(());
        }
    }
    let req = take(s, 4).await?;
    assert_eq!(req[1], 1, "not CONNECT");
    match req[3] {
        1 => {
            let a = take(s, 4).await?;
            seen.host = IpAddr::from(<[u8; 4]>::try_from(a).unwrap()).to_string();
        }
        3 => {
            let n = take(s, 1).await?;
            seen.host = String::from_utf8_lossy(&take(s, n[0] as usize).await?).into_owned();
            seen.name = true;
        }
        4 => {
            let a = take(s, 16).await?;
            seen.host = IpAddr::from(<[u8; 16]>::try_from(a).unwrap()).to_string();
        }
        t => panic!("address type {t}"),
    }
    let port = take(s, 2).await?;
    seen.port = u16::from_be_bytes([port[0], port[1]]);
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    stand_in(s, r, seen).await
}

/// A SOCKS4 and SOCKS4a proxy that takes any user id.
pub async fn socks4() -> Recorder {
    listen(|mut s, r| async move {
        let _ = socks4_session(&mut s, &r).await;
    })
    .await
}

async fn socks4_session(s: &mut TcpStream, r: &Recorder) -> std::io::Result<()> {
    let req = take(s, 8).await?;
    assert_eq!((req[0], req[1]), (4, 1), "not a SOCKS4 CONNECT");
    let mut seen = Seen {
        how: "socks4",
        port: u16::from_be_bytes([req[2], req[3]]),
        ..Seen::default()
    };
    let user = take_nul(s).await?;
    seen.user = (!user.is_empty()).then_some(user);
    if req[4..7] == [0, 0, 0] && req[7] != 0 {
        seen.host = take_nul(s).await?;
        seen.name = true;
    } else {
        seen.host = IpAddr::from(<[u8; 4]>::try_from(&req[4..8]).unwrap()).to_string();
    }
    s.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await?;
    stand_in(s, r, seen).await
}

/// An HTTP proxy: `CONNECT` answered as `answer` says, and a request in absolute
/// form answered as its destination would.
pub async fn http(answer: Answer) -> Recorder {
    listen(move |mut s, r| async move {
        let _ = http_session(&mut s, &r, answer).await;
    })
    .await
}

async fn http_session(s: &mut TcpStream, r: &Recorder, answer: Answer) -> std::io::Result<()> {
    let head = read_head(s).await?;
    let line = head.lines().next().unwrap_or_default().to_string();
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let proxy_authorization = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("proxy-authorization")
            .then(|| v.trim().to_string())
    });
    if method != "CONNECT" {
        // Absolute form: http://host:port/path
        let rest = target.strip_prefix("http://").unwrap_or(target);
        let authority = rest.split('/').next().unwrap_or("");
        let (host, port) = split_host_port(authority, 80);
        r.push(Seen {
            how: "forward",
            name: host.parse::<IpAddr>().is_err(),
            host,
            port,
            proxy_authorization,
            request: line,
            ..Seen::default()
        });
        return answer_ok(s).await;
    }
    let (host, port) = split_host_port(target, 0);
    let seen = Seen {
        how: "connect",
        name: host.parse::<IpAddr>().is_err(),
        host,
        port,
        proxy_authorization,
        ..Seen::default()
    };
    match answer {
        Answer::Open => {
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            stand_in(s, r, seen).await
        }
        Answer::WantsCredentials => {
            s.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n",
            )
            .await
        }
        Answer::Oversize => {
            let pad = "a".repeat(9 * 1024);
            s.write_all(format!("HTTP/1.1 200 OK\r\nX-Pad: {pad}\r\n\r\n").as_bytes())
                .await
        }
        Answer::Silent => {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        }
    }
}

/// Answer for the destination behind the proxy: read its request, record it with
/// what the proxy was asked, and send 200.
async fn stand_in<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    r: &Recorder,
    mut seen: Seen,
) -> std::io::Result<()> {
    let head = read_head(s).await?;
    seen.request = head.lines().next().unwrap_or_default().to_string();
    r.push(seen);
    answer_ok(s).await
}

async fn answer_ok<S: AsyncWrite + Unpin>(s: &mut S) -> std::io::Result<()> {
    s.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        )
        .as_bytes(),
    )
    .await?;
    s.shutdown().await
}

fn split_host_port(authority: &str, default: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((h, p)) = rest.split_once(']')
    {
        let port = p.strip_prefix(':').and_then(|p| p.parse().ok());
        return (h.to_string(), port.unwrap_or(default));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default)),
        None => (authority.to_string(), default),
    }
}

async fn take<S: AsyncRead + Unpin>(s: &mut S, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(b)
}

async fn take_nul<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<String> {
    let mut out = Vec::new();
    loop {
        let b = take(s, 1).await?[0];
        if b == 0 {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        out.push(b);
    }
}

/// Read up to the blank line that ends an HTTP head, one byte at a time so nothing
/// after it is consumed.
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 64 * 1024 {
            break;
        }
        head.push(take(s, 1).await?[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Send a minimal request over an open connection and read the whole answer.
pub async fn fetch_over<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(s: &mut S) -> String {
    s.write_all(b"GET /over HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

/// `user:pass` in a Basic `Proxy-Authorization` value.
pub fn basic(user: &str, pass: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{pass}").into_bytes();
    let mut out = String::new();
    for c in raw.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((*c.get(1).unwrap_or(&0) as u32) << 8)
            | (*c.get(2).unwrap_or(&0) as u32);
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    format!("Basic {out}")
}
