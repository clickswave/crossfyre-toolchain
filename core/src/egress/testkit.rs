//! Stand-ins for the egress tests: a NATS server that records what the node
//! publishes, the platform's node-facing routes, engines, and a resolver with fixed
//! answers. Everything listens on loopback; nothing here reaches past this machine.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cfx_tunnel::recorder::{PASS, Recorder, USER};
use cfx_tunnel::{Kind, Upstream};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::gateway::Resolver;

/// A resolver that knows only `names`, each with its addresses.
pub fn resolver(names: &[(&str, &[&str])]) -> Resolver {
    let map: HashMap<String, Vec<IpAddr>> = names
        .iter()
        .map(|(n, ips)| {
            (
                n.to_string(),
                ips.iter().map(|i| i.parse().unwrap()).collect(),
            )
        })
        .collect();
    let map = Arc::new(map);
    Arc::new(move |name: String| {
        let map = Arc::clone(&map);
        Box::pin(async move {
            map.get(&name).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("no such name {name}"))
            })
        })
    })
}

/// The upstream a test's team proxy is: a recorder on loopback.
pub fn recorder_upstream(r: &Recorder) -> Upstream {
    Upstream {
        kind: Kind::Socks5,
        host: "127.0.0.1".into(),
        port: r.port,
        auth: Some((USER.into(), PASS.into())),
    }
}

/// The platform's `egress` object for a node sending through recorder `r`.
pub fn proxy_settings(rev: i64, id: &str, r: &Recorder) -> Value {
    json!({"v": 1, "rev": rev, "mode": "proxy", "proxy": {
        "id": id, "type": "socks5", "host": "127.0.0.1", "port": r.port,
        "username": USER, "password": PASS,
    }})
}

pub fn direct_settings(rev: i64) -> Value {
    json!({"v": 1, "rev": rev, "mode": "direct", "proxy": null})
}

/// A port that refuses every connection for as long as the socket returned with it is
/// held. It is bound, never listens, and is not shared, so no listener another test
/// starts meanwhile can be given the same port. A port taken from a listener and then
/// freed can be, and that test's "dead" proxy then answers.
pub fn refusing_port() -> (tokio::net::TcpSocket, u16) {
    let s = tokio::net::TcpSocket::new_v4().unwrap();
    s.set_reuseaddr(false).unwrap();
    s.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = s.local_addr().unwrap().port();
    (s, port)
}

/// A client for the fakes that ignores any proxy variable the test runs under.
pub fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// A NATS server that takes the node's publishes and keeps them, in order.
pub struct FakeNats {
    pub url: String,
    published: Arc<Mutex<Vec<(String, Value)>>>,
}

impl FakeNats {
    pub async fn start() -> FakeNats {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("nats://127.0.0.1:{}", l.local_addr().unwrap().port());
        let published: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
        let keep = Arc::clone(&published);
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(serve_nats(s, Arc::clone(&keep)));
            }
        });
        FakeNats { url, published }
    }

    pub async fn client(&self) -> async_nats::Client {
        async_nats::connect(&self.url).await.unwrap()
    }

    pub fn published(&self) -> Vec<(String, Value)> {
        self.published.lock().unwrap().clone()
    }

    /// The `type` of each message published, in order.
    pub fn types(&self) -> Vec<String> {
        self.published()
            .iter()
            .map(|(_, v)| v["type"].as_str().unwrap_or("").to_string())
            .collect()
    }

    /// The first message of this `type`.
    pub fn first(&self, kind: &str) -> Option<Value> {
        self.published()
            .into_iter()
            .map(|(_, v)| v)
            .find(|v| v["type"] == kind)
    }

    /// Waits up to five seconds for a message of this `type`.
    pub async fn wait_for(&self, kind: &str) -> Option<Value> {
        for _ in 0..100 {
            if let Some(v) = self.first(kind) {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }
}

async fn serve_nats(s: TcpStream, keep: Arc<Mutex<Vec<(String, Value)>>>) {
    let (r, mut w) = s.into_split();
    let info = r#"INFO {"server_id":"fake","server_name":"fake","version":"2.10.0","proto":1,"max_payload":1048576,"headers":true}"#;
    if w.write_all(format!("{info}\r\n").as_bytes()).await.is_err() {
        return;
    }
    let mut r = BufReader::new(r);
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(op) = parts.first() else { continue };
        match op.to_ascii_uppercase().as_str() {
            "PING" => {
                if w.write_all(b"PONG\r\n").await.is_err() {
                    return;
                }
            }
            "PUB" | "HPUB" => {
                let hpub = op.eq_ignore_ascii_case("HPUB");
                let total: usize = parts.last().and_then(|n| n.parse().ok()).unwrap_or(0);
                let headers: usize = if hpub {
                    parts
                        .get(parts.len() - 2)
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0)
                } else {
                    0
                };
                let mut buf = vec![0u8; total + 2];
                if r.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let payload = &buf[headers..total];
                let v = serde_json::from_slice(payload).unwrap_or(Value::Null);
                keep.lock().unwrap().push((parts[1].to_string(), v));
            }
            _ => {}
        }
    }
}

/// The platform's node-facing routes. `answer(path, body)` gives the status and the
/// JSON body of each answer.
pub struct FakePlatform {
    pub url: String,
    requests: Arc<Mutex<Vec<(String, Value)>>>,
}

impl FakePlatform {
    pub async fn start<F>(answer: F) -> FakePlatform
    where
        F: Fn(&str, &Value) -> (u16, Value) + Send + Sync + 'static,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let requests: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
        let keep = Arc::clone(&requests);
        let answer = Arc::new(answer);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (keep, answer) = (Arc::clone(&keep), Arc::clone(&answer));
                tokio::spawn(async move {
                    let Some((path, body)) = read_http_request(&mut s).await else {
                        return;
                    };
                    keep.lock().unwrap().push((path.clone(), body.clone()));
                    let (code, reply) = answer(&path, &body);
                    let text = reply.to_string();
                    let _ = s
                        .write_all(
                            format!(
                                "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{text}",
                                text.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = s.shutdown().await;
                });
            }
        });
        FakePlatform { url, requests }
    }

    /// Every request, as path and JSON body.
    pub fn requests(&self) -> Vec<(String, Value)> {
        self.requests.lock().unwrap().clone()
    }

    /// Requests to this path.
    pub fn count(&self, path: &str) -> usize {
        self.requests().iter().filter(|(p, _)| p == path).count()
    }
}

/// One request's path and JSON body.
async fn read_http_request(s: &mut TcpStream) -> Option<(String, Value)> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 64 * 1024 || s.read(&mut b).await.ok()? == 0 {
            return None;
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head.split_whitespace().nth(1)?.to_string();
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.ok()?;
    Some((path, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

/// The platform's envelope around `data`.
pub fn ok(data: Value) -> (u16, Value) {
    (
        200,
        json!({"status": 200, "message": "ok", "errors": [], "data": data}),
    )
}

/// An engine daemon: each connection's first line goes to `answer`, whose lines are
/// written back.
#[derive(Clone)]
pub struct FakeEngine {
    pub port: u16,
    seen: Arc<Mutex<Vec<Value>>>,
    connections: Arc<AtomicUsize>,
}

impl FakeEngine {
    pub async fn start<F, Fut>(answer: F) -> FakeEngine
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Vec<Value>> + Send + 'static,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let e = FakeEngine {
            port: l.local_addr().unwrap().port(),
            seen: Arc::default(),
            connections: Arc::default(),
        };
        let fe = e.clone();
        let answer = Arc::new(answer);
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                fe.connections.fetch_add(1, Ordering::SeqCst);
                let (fe, answer) = (fe.clone(), Arc::clone(&answer));
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut lines = BufReader::new(r).lines();
                    let Ok(Some(line)) = lines.next_line().await else {
                        return;
                    };
                    let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    fe.seen.lock().unwrap().push(req.clone());
                    for out in answer(req).await {
                        if w.write_all(format!("{out}\n").as_bytes()).await.is_err() {
                            return;
                        }
                    }
                    let _ = w.shutdown().await;
                });
            }
        });
        e
    }

    /// An engine from before the egress wrapper. It refuses the wrapper, as every such
    /// engine does, and runs anything else by connecting to the op's target itself.
    pub async fn old() -> FakeEngine {
        FakeEngine::start(|req: Value| async move {
            if req["operation"] == "egress" {
                return vec![json!({"type": "error", "message": "Unknown operation: egress"})];
            }
            let _ = hit(&req["target"]).await;
            vec![json!({"type": "done"})]
        })
        .await
    }

    /// An engine that reads the wrapper and reaches the op's target through the proxy it
    /// names, as the engines from this release do. A request without a wrapper goes
    /// direct.
    pub async fn current() -> FakeEngine {
        FakeEngine::start(|req: Value| async move {
            if req["operation"] == "egress" {
                let proxy = req["egress"]["proxy"].as_str().unwrap_or("").to_string();
                let got = match Upstream::parse(&proxy) {
                    Ok(up) => hit_through(&up, &req["inner"]["target"]).await,
                    Err(e) => Err(e),
                };
                return match got {
                    Ok(()) => vec![json!({"type": "done"})],
                    Err(e) => vec![json!({"type": "error", "message": e})],
                };
            }
            let _ = hit(&req["target"]).await;
            vec![json!({"type": "done"})]
        })
        .await
    }

    /// Every request line it received, in order.
    pub fn seen(&self) -> Vec<Value> {
        self.seen.lock().unwrap().clone()
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// `http://host:port/...` to its host and port.
fn host_port(target: &Value) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(target.as_str()?).ok()?;
    Some((url.host_str()?.to_string(), url.port_or_known_default()?))
}

/// GET the target directly, as an engine without a wrapper does.
async fn hit(target: &Value) -> Result<(), String> {
    let (host, port) = host_port(target).ok_or("no target")?;
    let s = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| e.to_string())?;
    get(s, &host).await
}

async fn hit_through(up: &Upstream, target: &Value) -> Result<(), String> {
    let (host, port) = host_port(target).ok_or("no target")?;
    let t = cfx_tunnel::connect(
        up,
        &cfx_tunnel::Target::new(&host, port),
        cfx_tunnel::Timeouts::default(),
    )
    .await
    .map_err(|e| e.to_string())?;
    get(t, &host).await
}

async fn get<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    host: &str,
) -> Result<(), String> {
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    Ok(())
}
