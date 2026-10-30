//! A Cloud API on 127.0.0.1 for the Cloud rails: it speaks the routes in
//! `cfx_cloud_wire`, records every request it reads, and answers as a test tells it to.

use cfx_cloud_wire as wire;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The key the fake accepts.
pub(crate) const KEY: &str = "cfm_0123456789abcdef0123456789abcdef";
pub(crate) const WORKSPACE: &str = "11111111-2222-4333-8444-555555555555";

/// One request as the fake read it.
#[derive(Clone, Debug)]
pub(crate) struct Req {
    pub method: String,
    pub path: String,
    /// The part after `/api/v1/mcp/`.
    pub route: String,
    /// Names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Value,
    /// The whole request as it arrived, head and body.
    pub raw: String,
}

impl Req {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn authorised(&self) -> bool {
        self.header("authorization") == Some(&format!("Bearer {KEY}"))
    }
}

pub(crate) struct Resp {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    /// Held this long before answering, as a long poll is.
    pub delay: Duration,
}

impl Resp {
    /// The envelope with this status and `data`.
    pub(crate) fn with(status: u16, data: Value) -> Self {
        let body = json!({"status": status, "message": "", "errors": [], "data": data});
        Resp {
            status,
            body: body.to_string(),
            headers: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    pub(crate) fn ok(data: Value) -> Self {
        Resp::with(200, data)
    }

    pub(crate) fn refusal(status: u16, reason: wire::Reason) -> Self {
        Resp::with(status, json!({"reason": reason.as_str()}))
    }

    /// A body that is not the API's JSON, such as a proxy's error page.
    pub(crate) fn raw(status: u16, text: &str) -> Self {
        Resp {
            status,
            body: text.into(),
            headers: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    pub(crate) fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

pub(crate) type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;

pub(crate) struct FakeCloud {
    pub port: u16,
    reqs: Arc<Mutex<Vec<Req>>>,
    conns: Arc<AtomicUsize>,
}

impl FakeCloud {
    pub(crate) fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub(crate) fn requests(&self) -> Vec<Req> {
        self.reqs.lock().unwrap().clone()
    }

    pub(crate) fn routes(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| r.route).collect()
    }

    pub(crate) fn conns(&self) -> usize {
        self.conns.load(Ordering::SeqCst)
    }

    pub(crate) async fn start(h: Handler) -> FakeCloud {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().unwrap().port();
        let reqs = Arc::new(Mutex::new(Vec::new()));
        let conns = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (r, c) = (Arc::clone(&reqs), Arc::clone(&conns));
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = l.accept().await else {
                    return;
                };
                c.fetch_add(1, Ordering::SeqCst);
                let (r, h, calls) = (Arc::clone(&r), Arc::clone(&h), Arc::clone(&calls));
                tokio::spawn(async move {
                    let Some(req) = read_request(&mut sock).await else {
                        return;
                    };
                    r.lock().unwrap().push(req.clone());
                    let resp = h(&req);
                    if !resp.delay.is_zero() {
                        tokio::time::sleep(resp.delay).await;
                    }
                    let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    let mut head = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: \
                         {}\r\nConnection: close\r\nx-crossfyre-call-id: call-{n}\r\n",
                        resp.status,
                        resp.body.len()
                    );
                    for (k, v) in &resp.headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(resp.body.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        FakeCloud { port, reqs, conns }
    }
}

async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next()?.to_string();
    let mut parts = first.split(' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body_bytes = &buf[head_end..buf.len().min(head_end + len)];
    let body = serde_json::from_slice(body_bytes).unwrap_or(Value::Null);
    let route = path.strip_prefix(wire::PATH).unwrap_or(&path).to_string();
    Some(Req {
        method,
        path,
        route,
        headers,
        body,
        raw: String::from_utf8_lossy(&buf).into_owned(),
    })
}

/// A `whoami` answer for the fake's key.
pub(crate) fn whoami(permission: &str) -> Value {
    json!({
        "key": {"id": "k-1", "prefix": "cfm_01234567", "name": "laptop agent",
                "permission": permission, "expires_at": "2027-01-28T09:00:00Z"},
        "user": {"id": "u-1", "username": "dikshant"},
        "workspace": {"id": WORKSPACE, "name": "Acme staging"},
        "plan": "Pro",
        "limits": {"running_workflows": 1, "max_concurrent_workflows": 5, "monthly_used": 3,
                   "monthly_cap": 100, "launches_left_this_hour": 10, "key_concurrent_cap": 5},
        "approval": {"policy": "risky", "fallback": true, "phone_registered": false},
        "scope": {"current": 3, "attested": 2, "effective": 2,
                  "effective_sha256": "9f2c0000000000000000000000000000"},
    })
}

/// Answers `whoami` and `key/revoke` for the fake's key, and refuses any other key as
/// the platform does.
pub(crate) fn account(permission: &'static str) -> Handler {
    Arc::new(move |r: &Req| {
        if !r.authorised() {
            return Resp::refusal(401, wire::Reason::KeyInvalid);
        }
        match r.route.as_str() {
            wire::route::WHOAMI => Resp::ok(whoami(permission)),
            wire::route::KEY_REVOKE => Resp::ok(json!({"revoked": true})),
            _ => Resp::refusal(404, wire::Reason::NotFound),
        }
    })
}
