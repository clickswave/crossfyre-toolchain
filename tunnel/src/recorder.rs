//! Stand-ins for the engines' egress tests, behind the `recorder` feature, which only
//! test builds turn on.
//!
//! [`Recorder`] is a SOCKS5 proxy with a user name and password, as the node's
//! gateway is. It writes down every destination it is asked for and joins the client
//! to a loopback listener the test chose for it, so an engine gets real answers and
//! nothing goes further than this machine. [`Fixture`] is such a listener, and counts
//! the connections it accepts. A test then compares the two counts: every connection
//! the fixture saw has to be one the proxy opened, and a connection the engine made
//! by itself shows up as the difference.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::socks5_server::{self, CONNECTION_REFUSED, NOT_ALLOWED, SUCCEEDED};
use crate::{Host, Target};

/// The credentials every [`Recorder`] takes. Shaped like the gateway's: a 16-hex
/// handle and a 64-hex secret.
pub const USER: &str = "3f9c0a7b1e2d4c56";
pub const PASS: &str = "5e1d6c0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d";

/// A SOCKS5 proxy on loopback that records its destinations.
#[derive(Clone)]
pub struct Recorder {
    pub port: u16,
    seen: Arc<Mutex<Vec<Target>>>,
    joined: Arc<AtomicUsize>,
    accepted: Arc<AtomicUsize>,
}

impl Recorder {
    /// Start a proxy that joins each client to `route(destination)`. A destination
    /// `route` has no address for is answered "not allowed" and still recorded.
    pub async fn start<F>(route: F) -> Recorder
    where
        F: Fn(&Target) -> Option<SocketAddr> + Send + Sync + 'static,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let r = Recorder {
            port: l.local_addr().expect("addr").port(),
            seen: Arc::default(),
            joined: Arc::default(),
            accepted: Arc::default(),
        };
        let rec = r.clone();
        let route = Arc::new(route);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                rec.accepted.fetch_add(1, Ordering::SeqCst);
                let (rec, route) = (rec.clone(), Arc::clone(&route));
                tokio::spawn(async move {
                    let accepted =
                        socks5_server::accept(&mut s, Duration::from_secs(10), |u, p| {
                            (u == USER && p == PASS).then_some(())
                        })
                        .await;
                    let Ok(((), target)) = accepted else { return };
                    rec.seen.lock().unwrap().push(target.clone());
                    let Some(addr) = route(&target) else {
                        let _ = socks5_server::reply(&mut s, NOT_ALLOWED).await;
                        return;
                    };
                    let Ok(mut onward) = TcpStream::connect(addr).await else {
                        let _ = socks5_server::reply(&mut s, CONNECTION_REFUSED).await;
                        return;
                    };
                    rec.joined.fetch_add(1, Ordering::SeqCst);
                    if socks5_server::reply(&mut s, SUCCEEDED).await.is_ok() {
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut onward).await;
                    }
                });
            }
        });
        r
    }

    /// The URL an engine is handed for this proxy, with its credentials.
    pub fn url(&self) -> String {
        format!("socks5h://{USER}:{PASS}@127.0.0.1:{}", self.port)
    }

    /// The `egress` object of a wrapped request that sends through this proxy.
    pub fn egress_json(&self) -> String {
        format!(r#"{{"v":1,"proxy":"{}"}}"#, self.url())
    }

    /// Every destination asked for, in order.
    pub fn seen(&self) -> Vec<Target> {
        self.seen.lock().unwrap().clone()
    }

    /// Tunnels this proxy opened to a listener.
    pub fn joined(&self) -> usize {
        self.joined.load(Ordering::SeqCst)
    }

    /// TCP connections accepted, whatever came of them.
    pub fn connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Joins a destination to the same port on 127.0.0.1, whether it came as a name or
/// as an address. Tests name their fixtures by port.
pub fn to_loopback(t: &Target) -> Option<SocketAddr> {
    Some(SocketAddr::from(([127, 0, 0, 1], t.port)))
}

/// The destination's name, when it came as one.
pub fn name_of(t: &Target) -> Option<&str> {
    match &t.host {
        Host::Name(n) => Some(n.as_str()),
        Host::Ip(_) => None,
    }
}

/// A listener on loopback that counts the connections it accepts.
#[derive(Clone)]
pub struct Fixture {
    pub port: u16,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    async fn listen<F, Fut>(serve: F) -> Fixture
    where
        F: Fn(TcpStream, Fixture) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let f = Fixture {
            port: l.local_addr().expect("addr").port(),
            accepted: Arc::default(),
            requests: Arc::default(),
        };
        let fx = f.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                fx.accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve(s, fx.clone()));
            }
        });
        f
    }

    /// An HTTP server that answers every request with 200 and `body`, as
    /// `content_type`, on as many requests per connection as the client sends. It
    /// closes after a request that asks it to.
    pub async fn http(content_type: &'static str, body: String) -> Fixture {
        let body = Arc::new(body);
        Fixture::listen(move |mut s, fx| {
            let body = Arc::clone(&body);
            async move {
                loop {
                    let Some((line, close)) = read_request(&mut s).await else {
                        return;
                    };
                    let head_only = line.starts_with("HEAD ");
                    fx.requests.lock().unwrap().push(line);
                    let mut out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\
                         Content-Length: {}\r\n{}\r\n",
                        body.len(),
                        if close { "Connection: close\r\n" } else { "" }
                    )
                    .into_bytes();
                    if !head_only {
                        out.extend_from_slice(body.as_bytes());
                    }
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                    if close {
                        let _ = s.shutdown().await;
                        return;
                    }
                }
            }
        })
        .await
    }

    /// A service that speaks first: `banner` as soon as a connection opens, then it
    /// reads whatever the client sends for a moment and closes.
    pub async fn banner(banner: &'static [u8]) -> Fixture {
        Fixture::listen(move |mut s, _| async move {
            if s.write_all(banner).await.is_err() {
                return;
            }
            let mut buf = [0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await;
            let _ = s.shutdown().await;
        })
        .await
    }

    /// Connections accepted.
    pub fn connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// The request line of every HTTP request answered, in order.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// `http://127.0.0.1:<port>`
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// One request's line, and whether it asked for the connection to close. The body,
/// when `Content-Length` gives one, is read and dropped.
async fn read_request(s: &mut TcpStream) -> Option<(String, bool)> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 64 * 1024 || s.read(&mut b).await.ok()? == 0 {
            return None;
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let lower = head.to_ascii_lowercase();
    let len = lower
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if len > 0 {
        let mut body = vec![0u8; len.min(16 * 1024 * 1024)];
        s.read_exact(&mut body).await.ok()?;
    }
    let close = lower
        .lines()
        .any(|l| l.starts_with("connection:") && l.contains("close"));
    Some((head.lines().next().unwrap_or_default().to_string(), close))
}
