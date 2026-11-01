//! Fixtures for the rails: listeners that count what reaches them, an engine daemon
//! that records what it was asked, a client that answers on cue, and a resolver that
//! says what a name points at without DNS.

use crate::audit::Audit;
use crate::core::{CallOutput, Mcp, Settings, ToolResult};
use crate::guard::{BoxFut, Resolver};
use crate::jobs::JobStore;
use crate::peer::{Answer, ClientPeer};
use crate::scope_file;
use crate::{EngineInfo, WorkbenchMode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        // Short: a fake Workbench's socket goes in control/ under it, and macOS refuses a
        // socket path over 103 bytes, 49 of which its temp directory already takes.
        let id = uuid::Uuid::new_v4().simple().to_string();
        let p = std::env::temp_dir().join(format!("cfx-mcp-{}", &id[..16]));
        std::fs::create_dir(&p).expect("temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        TempDir(p)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

/// Write a file only its owner can change, whatever the umask, as the server
/// requires of a scope file.
pub(crate) fn write_private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// A target

pub(crate) enum Reply {
    Ok {
        headers: Vec<(String, String)>,
        body: String,
    },
    Redirect(String),
    /// Read the request and never answer.
    Silent,
}

impl Reply {
    pub(crate) fn ok(body: &str) -> Self {
        Reply::Ok {
            headers: Vec::new(),
            body: body.into(),
        }
    }
}

/// A local HTTP listener that counts connections and keeps the last request it read.
pub(crate) struct Listener {
    pub port: u16,
    conns: Arc<AtomicUsize>,
    last: Arc<Mutex<String>>,
}

impl Listener {
    pub(crate) fn conns(&self) -> usize {
        self.conns.load(Ordering::SeqCst)
    }
    pub(crate) fn last_request(&self) -> String {
        self.last.lock().unwrap().clone()
    }
}

pub(crate) async fn listener(reply: Reply) -> Listener {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().unwrap().port();
    let conns = Arc::new(AtomicUsize::new(0));
    let last = Arc::new(Mutex::new(String::new()));
    let response = match reply {
        Reply::Ok { headers, body } => {
            let mut h = String::from("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n");
            for (k, v) in headers {
                h.push_str(&format!("{k}: {v}\r\n"));
            }
            format!("{h}Content-Length: {}\r\n\r\n{body}", body.len())
        }
        Reply::Redirect(loc) => {
            format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\n\r\n")
        }
        Reply::Silent => String::new(),
    };
    let (c, la) = (Arc::clone(&conns), Arc::clone(&last));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                return;
            };
            c.fetch_add(1, Ordering::SeqCst);
            let (la, response) = (Arc::clone(&la), response.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            *la.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
                            if response.is_empty() {
                                continue;
                            }
                            if sock.write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Listener { port, conns, last }
}

// ---------------------------------------------------------------------------
// An engine daemon

#[derive(Default, Clone)]
pub(crate) struct StubOpts {
    /// Sent after the ack.
    pub events: Vec<Value>,
    /// The ack says so, and the cancel line is answered with a cancelled done.
    pub cancellable: bool,
    /// After the events, wait for a cancel line or the connection to close instead
    /// of sending `done`.
    pub hold: bool,
    /// Play the engine: send one GET to the op's `target` and to every
    /// `endpoints[].url`, with names looked up here. Absent means send nothing.
    pub simulate: Option<HashMap<String, IpAddr>>,
    /// Play a daemon from before the `capabilities` operation, which answers it with
    /// `Unknown operation` and ignores the options it does not know.
    pub old: bool,
    /// A pause before each of `events`, so a client sees them arrive one at a time.
    pub delay_ms: u64,
}

pub(crate) struct Stub {
    pub port: u16,
    ops: Arc<Mutex<Vec<Value>>>,
    cancels: Arc<AtomicUsize>,
}

impl Stub {
    pub(crate) fn ops(&self) -> Vec<Value> {
        self.ops.lock().unwrap().clone()
    }
    pub(crate) fn cancels(&self) -> usize {
        self.cancels.load(Ordering::SeqCst)
    }
}

async fn simulated_get(url: &str, map: &HashMap<String, IpAddr>) {
    let Ok(u) = transport::Url::parse(url) else {
        return;
    };
    let Some(host) = u.host_str() else { return };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Some(port) = u.port_or_known_default() else {
        return;
    };
    let ip = match map.get(host) {
        Some(ip) => *ip,
        None => match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return,
        },
    };
    let Ok(Ok(mut s)) =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect((ip, port))).await
    else {
        return;
    };
    let mut target = u.path().to_string();
    if let Some(q) = u.query() {
        target.push('?');
        target.push_str(q);
    }
    let req = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let _ = s.write_all(req.as_bytes()).await;
    let mut buf = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
}

pub(crate) async fn stub_engine(opts: StubOpts) -> Stub {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().unwrap().port();
    let ops = Arc::new(Mutex::new(Vec::new()));
    let cancels = Arc::new(AtomicUsize::new(0));
    let (o, c) = (Arc::clone(&ops), Arc::clone(&cancels));
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = l.accept().await else {
                return;
            };
            let (o, c, opts) = (Arc::clone(&o), Arc::clone(&c), opts.clone());
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                // The capabilities question, any number of times, then the operation.
                let op = loop {
                    let Ok(Some(line)) = lines.next_line().await else {
                        return;
                    };
                    let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    if v["operation"] != "capabilities" {
                        break v;
                    }
                    let answer = if opts.old {
                        json!({"type": "error", "message": "Unknown operation: capabilities"})
                    } else {
                        json!({"type": "capabilities", "cancel": true,
                               "inject": ["follow_redirects", "resolve"],
                               "fingerprint": ["resolve", "block_internal"]})
                    };
                    let mut a = answer.to_string();
                    a.push('\n');
                    if w.write_all(a.as_bytes()).await.is_err() {
                        return;
                    }
                };
                o.lock().unwrap().push(op.clone());
                if let Some(map) = &opts.simulate {
                    if let Some(t) = op.get("target").and_then(|t| t.as_str())
                        && op.get("endpoints").is_none()
                    {
                        simulated_get(t, map).await;
                    }
                    for e in op["endpoints"].as_array().cloned().unwrap_or_default() {
                        if let Some(u) = e.get("url").and_then(|u| u.as_str()) {
                            simulated_get(u, map).await;
                        }
                    }
                }
                let send = |v: Value| {
                    let mut s = v.to_string();
                    s.push('\n');
                    s
                };
                let mut ack = json!({"type": "ack", "target": op.get("target")});
                if opts.cancellable {
                    ack["cancellable"] = json!(true);
                }
                let mut out = send(ack);
                for e in &opts.events {
                    if opts.delay_ms > 0 {
                        if w.write_all(out.as_bytes()).await.is_err() {
                            return;
                        }
                        out.clear();
                        tokio::time::sleep(Duration::from_millis(opts.delay_ms)).await;
                    }
                    out.push_str(&send(e.clone()));
                }
                if w.write_all(out.as_bytes()).await.is_err() {
                    return;
                }
                if !opts.hold {
                    let _ = w.write_all(send(json!({"type": "done"})).as_bytes()).await;
                    return;
                }
                while let Ok(Some(l)) = lines.next_line().await {
                    let v: Value = serde_json::from_str(&l).unwrap_or(Value::Null);
                    if v["operation"] == "cancel" {
                        c.fetch_add(1, Ordering::SeqCst);
                        if opts.cancellable {
                            let _ = w
                                .write_all(
                                    send(json!({"type": "done", "cancelled": true})).as_bytes(),
                                )
                                .await;
                            return;
                        }
                    }
                }
            });
        }
    });
    Stub { port, ops, cancels }
}

/// What toolmark sends for a page it fingerprinted.
pub(crate) fn toolmark_events(title: &str, server: &str) -> Vec<Value> {
    vec![
        json!({"type": "finding", "data": {
            "type": "technology", "source": "scout", "severity": "info",
            "name": "nginx", "category": "web-server", "version": "1.18.0",
            "cpe": "cpe:2.3:a:f5:nginx", "confidence": 90, "evidence": "server header"}}),
        json!({"type": "finding", "data": {
            "type": "vulnerability", "source": "scout-cve", "severity": "HIGH",
            "name": "nginx 1.18.0: CVE-2021-23017", "cve": "CVE-2021-23017", "cvss": 7.7,
            "product": "nginx", "version": "1.18.0", "confidence": "version-inferred",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
            "description": "resolver off-by-one"}}),
        json!({"type": "finding", "data": {
            "type": "service", "source": "scout", "severity": "info", "status_code": 200,
            "title": title, "server": server, "favicon": null, "waf": null, "cdn": null}}),
        json!({"type": "finding", "data": {"type": "environment", "source": "scout"}}),
    ]
}

// ---------------------------------------------------------------------------
// A client

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Elicit {
    /// Cannot show a form.
    None,
    Accept,
    Decline,
    /// Closes the form without answering it.
    Dismiss,
    /// Shows the form and never answers.
    Hang,
}

pub(crate) struct FakePeer {
    pub elicit: Elicit,
    /// The name the client gave in `initialize`.
    pub label: String,
    asked: AtomicUsize,
    pub questions: Mutex<Vec<String>>,
    pub progress: Mutex<Vec<(f64, Option<f64>)>>,
    /// The message of each progress notification.
    pub progress_messages: Mutex<Vec<String>>,
    /// How many times the server said its tool list changed.
    pub list_changed: AtomicUsize,
    /// How the client answers a request to open a URL; `None` cannot be asked.
    pub url: Elicit,
    /// Every URL a person was sent to.
    pub urls: Mutex<Vec<String>>,
}

impl FakePeer {
    pub(crate) fn new(elicit: Elicit) -> Self {
        FakePeer {
            elicit,
            label: "fake-client 1.0".into(),
            asked: AtomicUsize::new(0),
            questions: Mutex::new(Vec::new()),
            progress: Mutex::new(Vec::new()),
            progress_messages: Mutex::new(Vec::new()),
            list_changed: AtomicUsize::new(0),
            url: Elicit::None,
            urls: Mutex::new(Vec::new()),
        }
    }
    pub(crate) fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl ClientPeer for FakePeer {
    fn label(&self) -> String {
        self.label.clone()
    }
    fn can_elicit_form(&self) -> bool {
        self.elicit != Elicit::None
    }
    fn confirm<'a>(
        &'a self,
        message: String,
        _: &'static str,
        _: &'static str,
    ) -> BoxFut<'a, Answer> {
        Box::pin(async move {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.questions.lock().unwrap().push(message);
            if self.elicit == Elicit::Hang {
                std::future::pending::<()>().await;
            }
            match self.elicit {
                Elicit::Accept => Answer::Yes,
                Elicit::Dismiss => Answer::Dismissed,
                _ => Answer::No,
            }
        })
    }
    fn progress<'a>(&'a self, done: f64, total: Option<f64>, m: &'a str) -> BoxFut<'a, ()> {
        Box::pin(async move {
            self.progress.lock().unwrap().push((done, total));
            self.progress_messages.lock().unwrap().push(m.to_string());
        })
    }
    fn tool_list_changed<'a>(&'a self) -> BoxFut<'a, ()> {
        Box::pin(async move {
            self.list_changed.fetch_add(1, Ordering::SeqCst);
        })
    }
    fn can_elicit_url(&self) -> bool {
        self.url != Elicit::None
    }
    fn open_url<'a>(&'a self, _: String, url: String, _: String) -> BoxFut<'a, Answer> {
        Box::pin(async move {
            self.urls.lock().unwrap().push(url);
            match self.url {
                Elicit::Accept => Answer::Yes,
                Elicit::Decline => Answer::No,
                _ => Answer::Dismissed,
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Names

#[derive(Default, Clone)]
pub(crate) struct FakeResolver(pub HashMap<String, Vec<IpAddr>>);

impl FakeResolver {
    pub(crate) fn with(mut self, name: &str, ips: &[&str]) -> Self {
        self.0.insert(
            name.into(),
            ips.iter().map(|i| i.parse().unwrap()).collect(),
        );
        self
    }
}

impl Resolver for FakeResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFut<'a, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            self.0.get(host).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no such test name")
            })
        })
    }
}

// ---------------------------------------------------------------------------
// The server

pub(crate) struct TestMcp {
    pub dir: TempDir,
    pub mcp: Arc<Mcp>,
    /// The closed ports the engines default to, kept closed while the server runs.
    _closed: Vec<ClosedPort>,
}

/// Opens the audit log a test server writes to.
type AuditOpener = Box<dyn FnOnce(&Path) -> Audit>;

pub(crate) struct Build {
    scope: Option<String>,
    toolmark: u16,
    plessor: u16,
    resolver: FakeResolver,
    redact: bool,
    burst: u32,
    per_minute: u32,
    audit: Option<AuditOpener>,
    workbench: WorkbenchMode,
    workbench_dir: Option<PathBuf>,
    closed: Vec<ClosedPort>,
}

/// A scope file with these entries and any extra lines.
pub(crate) fn scope(entries: &[String], extra: &str) -> Build {
    let list: Vec<String> = entries.iter().map(|e| format!("{e:?}")).collect();
    Build::with_file(Some(format!("entries = [{}]\n{extra}\n", list.join(", "))))
}

impl Build {
    pub(crate) fn with_file(text: Option<String>) -> Self {
        let (toolmark, plessor) = (closed_port(), closed_port());
        Build {
            scope: text,
            toolmark: toolmark.port,
            plessor: plessor.port,
            resolver: FakeResolver::default(),
            redact: true,
            burst: 100_000,
            per_minute: 6_000_000,
            audit: None,
            workbench: WorkbenchMode::Auto,
            workbench_dir: None,
            closed: vec![toolmark, plessor],
        }
    }
    pub(crate) fn toolmark(mut self, port: u16) -> Self {
        self.toolmark = port;
        self
    }
    pub(crate) fn plessor(mut self, port: u16) -> Self {
        self.plessor = port;
        self
    }
    pub(crate) fn resolver(mut self, r: FakeResolver) -> Self {
        self.resolver = r;
        self
    }
    pub(crate) fn calls(mut self, burst: u32, per_minute: u32) -> Self {
        self.burst = burst;
        self.per_minute = per_minute;
        self
    }
    pub(crate) fn workbench_mode(mut self, mode: WorkbenchMode) -> Self {
        self.workbench = mode;
        self
    }
    /// As `--no-redact`.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn no_redact(mut self) -> Self {
        self.redact = false;
        self
    }
    /// The Workbench data directory the server looks in, as the CLI would pass it.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn workbench_dir(mut self, dir: &Path) -> Self {
        self.workbench_dir = Some(dir.to_path_buf());
        self
    }
    pub(crate) fn audit(mut self, f: impl FnOnce(&Path) -> Audit + 'static) -> Self {
        self.audit = Some(Box::new(f));
        self
    }
    pub(crate) fn build(self) -> TestMcp {
        let dir = TempDir::new();
        let path = dir.path().join("scope.toml");
        if let Some(text) = &self.scope {
            write_private(&path, text);
        }
        let scope = scope_file::load(&path).expect("scope loads");
        let audit_path = dir.path().join("audit.jsonl");
        let audit = match self.audit {
            Some(f) => f(&audit_path),
            None => Audit::open(&audit_path).unwrap(),
        };
        let store = JobStore::open(&dir.path().join("jobs")).unwrap();
        let settings = Settings {
            version: "0.0.0-test".into(),
            redact: self.redact,
            engines: vec![
                EngineInfo {
                    name: "toolmark".into(),
                    port: self.toolmark,
                    installed: true,
                },
                EngineInfo {
                    name: "plessor".into(),
                    port: self.plessor,
                    installed: true,
                },
            ],
            postgres_port: None,
            workbench: self.workbench,
            workbench_dir: self.workbench_dir,
            call_burst: self.burst,
            calls_per_minute: self.per_minute,
        };
        let mcp = Mcp::new(
            settings,
            dir.path().to_path_buf(),
            scope,
            audit,
            store,
            Arc::new(self.resolver),
        );
        TestMcp {
            dir,
            mcp: Arc::new(mcp),
            _closed: self.closed,
        }
    }
}

/// A port with nothing listening on it, for as long as this lives.
///
/// The port stays bound without listening, so a connection to it is refused and no
/// listener is given it meanwhile, in this process or another. A port freed at once
/// could go to the listener of a test running alongside, which then counted a
/// connection meant for a closed port as one it was sent.
pub(crate) struct ClosedPort {
    pub port: u16,
    _held: tokio::net::TcpSocket,
}

impl std::fmt::Display for ClosedPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.port)
    }
}

pub(crate) fn closed_port() -> ClosedPort {
    let s = tokio::net::TcpSocket::new_v4().unwrap();
    s.bind((std::net::Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let port = s.local_addr().unwrap().port();
    ClosedPort { port, _held: s }
}

impl TestMcp {
    pub(crate) async fn call(&self, peer: &FakePeer, tool: &str, args: Value) -> ToolResult {
        self.call_ct(peer, tool, args, CancellationToken::new())
            .await
    }

    pub(crate) async fn call_ct(
        &self,
        peer: &FakePeer,
        tool: &str,
        args: Value,
        ct: CancellationToken,
    ) -> ToolResult {
        // The list the client called from. A call can change it, as one refused for a
        // key whose owner may no longer launch does, and its result still answers to
        // the definition the client had.
        let listed = self.mcp.backends();
        match self.mcp.call(tool, args, peer, ct).await {
            CallOutput::Result(r) => {
                if let (false, Some(v)) = (r.is_error, &r.structured) {
                    if self.mcp.cloud.on().is_some() {
                        assert_listed_schema(&listed, tool, v);
                    } else {
                        assert_schema(tool, v);
                    }
                }
                r
            }
            CallOutput::InvalidParams(m) => ToolResult {
                structured: None,
                text: format!(
                    "protocol error\n{}",
                    json!({"reason": "unknown_tool", "message": m})
                ),
                is_error: true,
            },
        }
    }

    pub(crate) fn audit_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
            .collect()
    }

    pub(crate) fn audit_text(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap_or_default()
    }
}

/// The refusal code of an error result.
pub(crate) fn reason(r: &ToolResult) -> String {
    assert!(r.is_error, "expected a refusal, got {}", r.text);
    assert!(
        r.structured.is_none(),
        "a refusal carries no structured content"
    );
    let last = r.text.lines().last().unwrap_or("");
    let v: Value = serde_json::from_str(last).expect("refusal ends in JSON");
    v["reason"].as_str().unwrap_or("").to_string()
}

pub(crate) fn refused_list(r: &ToolResult) -> Vec<Value> {
    let last = r.text.lines().last().unwrap_or("");
    let v: Value = serde_json::from_str(last).unwrap_or(Value::Null);
    v["refused"].as_array().cloned().unwrap_or_default()
}

pub(crate) fn ok(r: &ToolResult) -> &Value {
    assert!(!r.is_error, "expected success, got {}", r.text);
    r.structured.as_ref().expect("structured content")
}

pub(crate) fn sock(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}

pub(crate) async fn eventually(what: &str, secs: u64, f: impl Fn() -> bool) {
    for _ in 0..(secs * 20) {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// [`assert_schema`] against the definition the server listed, which for a shared tool
/// with a Cloud key is the Cloud one.
pub(crate) fn assert_listed_schema(listed: &crate::tools::Backends, tool: &str, v: &Value) {
    let def = crate::server::tool_list(listed)
        .into_iter()
        .find(|t| t.name == tool)
        .map(|t| serde_json::to_value(t).unwrap())
        .unwrap_or_else(|| panic!("{tool} answered without being listed"));
    check_schema(tool, &def, v);
}

/// The structured result has every field its outputSchema requires, with the type it
/// says. A client checks this, so a mismatch is a broken tool.
pub(crate) fn assert_schema(tool: &str, v: &Value) {
    let mut tools: Vec<Value> = serde_json::from_str(crate::tools::TOOLS_JSON).unwrap();
    let more: Vec<Value> = serde_json::from_str(crate::tools::TOOLS_WORKBENCH_JSON).unwrap();
    tools.extend(more);
    let def = tools
        .iter()
        .find(|t| t["name"] == tool)
        .unwrap_or_else(|| panic!("no definition for {tool}"));
    check_schema(tool, def, v);
}

fn check_schema(tool: &str, def: &Value, v: &Value) {
    let schema = &def["outputSchema"];
    for req in schema["required"].as_array().cloned().unwrap_or_default() {
        let k = req.as_str().unwrap();
        assert!(v.get(k).is_some(), "{tool} result lacks {k}: {v}");
    }
    let props = schema["properties"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for (k, p) in props {
        let Some(x) = v.get(&k) else { continue };
        let types: Vec<String> = match &p["type"] {
            Value::String(s) => vec![s.clone()],
            Value::Array(a) => a
                .iter()
                .filter_map(|t| t.as_str().map(String::from))
                .collect(),
            _ => continue,
        };
        let actual = match x {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        let fits = types
            .iter()
            .any(|t| t == actual || (t == "number" && actual == "integer"));
        assert!(fits, "{tool}.{k} is {actual}, schema says {types:?}: {x}");
    }
}
