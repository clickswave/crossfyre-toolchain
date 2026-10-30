//! A Workbench stand-in: a Unix socket server speaking the bridge protocol from
//! `cfx_bridge`, which writes an endpoint file the way a Workbench does, records every
//! request it is sent, answers from a script, and can push events.
//!
//! Requests are typed and checked with the same `Call::from_request` a Workbench uses,
//! so a request this server sends that a Workbench would refuse fails here too.

use cfx_bridge::{
    Body, Call, CheckResult, CheckRow, ErrorBody, ErrorCode, ExchangeResult, Handshake,
    HistoryResult, HistoryRow, Method, Origin, ProjectInfo, ProjectRef, ReplayResult, Request,
    Response, ScanSourceResult, ScopeResult, ScopeSummary, SelectionResult, SiteMapResult,
    StatusResult, Welcome,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

pub(crate) const UID_A: &str = "3f9a0c21be7d44c1a0e5b6f1c2d3e4f5";
pub(crate) const UID_B: &str = "b7e1d2c3a4f5061728394a5b6c7d8e9f";

pub(crate) fn project(uid: &str, name: &str) -> ProjectInfo {
    ProjectInfo {
        uid: uid.into(),
        name: name.into(),
        exchanges: 3,
    }
}

/// A pid that is not this process and is always running.
pub(crate) const OTHER_PID: u32 = 1;

/// One method's answer, given the call and the project open now.
pub(crate) type Answer =
    Arc<dyn Fn(&Call, &Option<ProjectInfo>) -> Result<Value, ErrorBody> + Send + Sync>;

pub(crate) struct WbOpts {
    pub pid: u32,
    pub project: Option<ProjectInfo>,
    pub capabilities: Vec<String>,
    pub agent_access: bool,
    /// The token the fake accepts.
    pub token: String,
    /// The token written into the endpoint file, when it differs.
    pub file_token: Option<String>,
    pub file_mode: u32,
    /// Listen here instead of `control/<pid>.sock`.
    pub socket: Option<PathBuf>,
    pub answers: HashMap<Method, Answer>,
    pub delays: HashMap<Method, Duration>,
}

impl Default for WbOpts {
    fn default() -> Self {
        WbOpts {
            pid: std::process::id(),
            project: Some(project(UID_A, "acme-q4")),
            capabilities: Method::ALL.iter().map(|m| m.as_str().to_string()).collect(),
            agent_access: true,
            token: format!("{:064x}", uuid::Uuid::new_v4().as_u128()),
            file_token: None,
            file_mode: 0o600,
            socket: None,
            answers: HashMap::new(),
            delays: HashMap::new(),
        }
    }
}

impl WbOpts {
    pub(crate) fn pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }
    pub(crate) fn project(mut self, p: Option<ProjectInfo>) -> Self {
        self.project = p;
        self
    }
    pub(crate) fn without(mut self, m: Method) -> Self {
        self.capabilities.retain(|c| c != m.as_str());
        self
    }
    /// Answer `m` with this instead of the default.
    pub(crate) fn answer(
        mut self,
        m: Method,
        f: impl Fn(&Call, &Option<ProjectInfo>) -> Result<Value, ErrorBody> + Send + Sync + 'static,
    ) -> Self {
        self.answers.insert(m, Arc::new(f));
        self
    }
}

/// A request as the fake read it.
#[derive(Debug, Clone)]
pub(crate) struct Logged {
    pub method: String,
    pub params: Value,
}

pub(crate) struct FakeWb {
    pub pid: u32,
    endpoint: PathBuf,
    socket: PathBuf,
    log: Arc<Mutex<Vec<Logged>>>,
    hellos: Arc<AtomicUsize>,
    welcomed: Arc<AtomicUsize>,
    project: Arc<Mutex<Option<ProjectInfo>>>,
    lines: broadcast::Sender<String>,
    accept: Option<JoinHandle<()>>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

fn private_dir(p: &Path) {
    std::fs::create_dir_all(p).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Write an endpoint file as a Workbench would, with any mode.
pub(crate) fn write_endpoint(dir: &Path, pid: u32, body: &Value, mode: u32) -> PathBuf {
    let control = dir.join("control");
    private_dir(&control);
    let path = control.join(format!("{pid}.json"));
    std::fs::write(&path, body.to_string()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// A Workbench that is running with Agent access off.
pub(crate) fn access_off(dir: &Path, pid: u32) -> PathBuf {
    write_endpoint(
        dir,
        pid,
        &json!({"v": 1, "app": "crossfyre-workbench", "app_version": "0.1.2", "pid": pid,
                "started_ms": 1, "protocol": 1, "agent_access": false}),
        0o600,
    )
}

impl FakeWb {
    /// Start a fake Workbench whose data directory is `dir`.
    pub(crate) async fn start(dir: &Path, opts: WbOpts) -> FakeWb {
        let control = dir.join("control");
        private_dir(&control);
        let socket = opts
            .socket
            .clone()
            .unwrap_or_else(|| control.join(format!("{}.sock", opts.pid)));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind the fake's socket");
        let endpoint = write_endpoint(
            dir,
            opts.pid,
            &json!({"v": 1, "app": "crossfyre-workbench", "app_version": "0.1.2",
                    "pid": opts.pid, "started_ms": 1_798_619_564_512_i64, "protocol": 1,
                    "agent_access": opts.agent_access,
                    "socket": socket.display().to_string(),
                    "token": opts.file_token.clone().unwrap_or_else(|| opts.token.clone())}),
            opts.file_mode,
        );
        let log = Arc::new(Mutex::new(Vec::new()));
        let hellos = Arc::new(AtomicUsize::new(0));
        let welcomed = Arc::new(AtomicUsize::new(0));
        let project = Arc::new(Mutex::new(opts.project.clone()));
        let (lines, _) = broadcast::channel(64);
        let conns = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared {
            pid: opts.pid,
            token: opts.token,
            capabilities: opts.capabilities,
            answers: opts.answers,
            delays: opts.delays,
            log: Arc::clone(&log),
            hellos: Arc::clone(&hellos),
            welcomed: Arc::clone(&welcomed),
            project: Arc::clone(&project),
            lines: lines.clone(),
        });
        let c = Arc::clone(&conns);
        let accept = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let h = tokio::spawn(serve_conn(Arc::clone(&shared), sock));
                c.lock().unwrap().push(h);
            }
        });
        FakeWb {
            pid: opts.pid,
            endpoint,
            socket,
            log,
            hellos,
            welcomed,
            project,
            lines,
            accept: Some(accept),
            conns,
        }
    }

    pub(crate) fn requests(&self) -> Vec<Logged> {
        self.log.lock().unwrap().clone()
    }

    /// How many requests of this method arrived.
    pub(crate) fn count(&self, m: Method) -> usize {
        self.requests()
            .iter()
            .filter(|l| l.method == m.as_str())
            .count()
    }

    pub(crate) fn hellos(&self) -> usize {
        self.hellos.load(Ordering::SeqCst)
    }

    pub(crate) fn welcomed(&self) -> usize {
        self.welcomed.load(Ordering::SeqCst)
    }

    /// Send an event to every connection.
    pub(crate) fn push(&self, ev: &cfx_bridge::Event) {
        let _ = self.lines.send(cfx_bridge::to_line(ev));
    }

    /// Open another project, or close it, and say so.
    pub(crate) fn switch(&self, p: Option<ProjectInfo>) {
        *self.project.lock().unwrap() = p.clone();
        self.push(&cfx_bridge::Event::Project { project: p });
    }

    /// Stop as a Workbench does on exit: close every connection and remove its files.
    pub(crate) fn exit(&mut self) {
        if let Some(a) = self.accept.take() {
            a.abort();
        }
        for h in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
        let _ = std::fs::remove_file(&self.endpoint);
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for FakeWb {
    fn drop(&mut self) {
        self.exit();
    }
}

struct Shared {
    pid: u32,
    token: String,
    capabilities: Vec<String>,
    answers: HashMap<Method, Answer>,
    delays: HashMap<Method, Duration>,
    log: Arc<Mutex<Vec<Logged>>>,
    hellos: Arc<AtomicUsize>,
    welcomed: Arc<AtomicUsize>,
    project: Arc<Mutex<Option<ProjectInfo>>>,
    lines: broadcast::Sender<String>,
}

async fn serve_conn(s: Arc<Shared>, sock: tokio::net::UnixStream) {
    let (r, mut w) = sock.into_split();
    let mut r = BufReader::new(r).lines();
    let Ok(Ok(Some(first))) = tokio::time::timeout(Duration::from_secs(2), r.next_line()).await
    else {
        return;
    };
    s.hellos.fetch_add(1, Ordering::SeqCst);
    let Ok(Handshake::Hello(hello)) = serde_json::from_str::<Handshake>(&first) else {
        return;
    };
    // A wrong token is closed on with no answer at all.
    if hello.token != s.token {
        return;
    }
    let welcome = Handshake::Welcome(Welcome {
        protocol: cfx_bridge::PROTOCOL,
        app_version: "0.1.2".into(),
        pid: s.pid,
        capabilities: s.capabilities.clone(),
        project: s.project.lock().unwrap().clone(),
    });
    if w.write_all(cfx_bridge::to_line(&welcome).as_bytes())
        .await
        .is_err()
    {
        return;
    }
    s.welcomed.fetch_add(1, Ordering::SeqCst);

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let mut events = s.lines.subscribe();
    let writer = tokio::spawn(async move {
        while let Some(l) = rx.recv().await {
            if w.write_all(l.as_bytes()).await.is_err() {
                return;
            }
        }
    });
    loop {
        tokio::select! {
            line = r.next_line() => {
                let Ok(Some(line)) = line else { break };
                let Ok(req) = Request::parse(&line) else { continue };
                let params = req
                    .params
                    .as_ref()
                    .and_then(|p| serde_json::from_str(p.get()).ok())
                    .unwrap_or(Value::Null);
                s.log.lock().unwrap().push(Logged { method: req.method.clone(), params });
                let (s2, tx2) = (Arc::clone(&s), tx.clone());
                tokio::spawn(async move {
                    let out = answer(&s2, &req).await;
                    let _ = tx2.send(cfx_bridge::to_line(&out));
                });
            }
            ev = events.recv() => {
                if let Ok(l) = ev {
                    let _ = tx.send(l);
                }
            }
        }
    }
    drop(tx);
    let _ = writer.await;
}

async fn answer(s: &Shared, req: &Request) -> Response {
    let call = match Call::from_request(req) {
        Ok(c) => c,
        Err(e) => return Response::err(req.id, e),
    };
    if let Some(d) = s.delays.get(&call.method()) {
        tokio::time::sleep(*d).await;
    }
    let open = s.project.lock().unwrap().clone();
    if let Some(uid) = call.project_uid() {
        match &open {
            None => {
                return Response::err(
                    req.id,
                    ErrorBody::new(ErrorCode::NoProject, "no project is open"),
                );
            }
            Some(p) if p.uid != uid => {
                let mut e = ErrorBody::new(ErrorCode::ProjectChanged, "another project is open");
                e.current = Some(ProjectRef {
                    uid: p.uid.clone(),
                    name: p.name.clone(),
                });
                return Response::err(req.id, e);
            }
            _ => {}
        }
    }
    let out = match s.answers.get(&call.method()) {
        Some(f) => f(&call, &open),
        None => default_answer(&call, &open),
    };
    match out {
        Ok(v) => Response::ok(req.id, v),
        Err(e) => Response::err(req.id, e),
    }
}

fn to_value<T: serde::Serialize>(t: T) -> Result<Value, ErrorBody> {
    Ok(serde_json::to_value(t).unwrap())
}

/// The captured request every default answer is about: an authenticated GET to
/// `http://app.example.test/api/items?id=2`.
pub(crate) fn default_exchange(id: i64) -> ExchangeResult {
    ExchangeResult {
        id,
        at_ms: 1_798_619_564_512,
        method: "GET".into(),
        url: "http://app.example.test/api/items?id=2".into(),
        host: "app.example.test".into(),
        status: Some(200),
        duration_ms: Some(12),
        origin: Origin::Proxy,
        actor: None,
        pinned: false,
        req_headers: Some(vec![
            ("Host".into(), "app.example.test".into()),
            ("Cookie".into(), "sid=S1".into()),
        ]),
        resp_headers: Some(vec![("Content-Type".into(), "application/json".into())]),
        req_body: None,
        resp_body: Some(Body::text("{\"items\":[2]}".into(), 13, false)),
    }
}

pub(crate) fn default_answer(call: &Call, open: &Option<ProjectInfo>) -> Result<Value, ErrorBody> {
    match call {
        Call::Status => to_value(StatusResult {
            project: open.clone(),
            proxy_port: Some(8080),
            intercepting: false,
            scope: ScopeSummary {
                restricted: false,
                rules: 0,
            },
        }),
        Call::History(_) => to_value(HistoryResult {
            rows: vec![HistoryRow {
                id: 1,
                at_ms: 1_798_619_564_512,
                method: "GET".into(),
                url: "http://app.example.test/api/items?id=2".into(),
                host: "app.example.test".into(),
                status: Some(200),
                req_len: 120,
                resp_len: 13,
                pinned: false,
                origin: Origin::Proxy,
                actor: None,
            }],
            next: None,
        }),
        Call::Exchange(p) => {
            let mut x = default_exchange(p.id);
            if !p.parts.contains(&cfx_bridge::Part::Request) {
                x.req_headers = None;
                x.req_body = None;
            }
            if !p.parts.contains(&cfx_bridge::Part::Response) {
                x.resp_headers = None;
                x.resp_body = None;
            }
            to_value(x)
        }
        Call::Selection => match open {
            Some(p) => to_value(SelectionResult {
                project_uid: p.uid.clone(),
                changed_ms: 1_798_619_570_000,
                tool: "history".into(),
                exchange_id: Some(1),
                repeater: None,
            }),
            None => Ok(Value::Null),
        },
        Call::SiteMap(_) => to_value(SiteMapResult {
            endpoints: Vec::new(),
            next: None,
            incomplete: false,
        }),
        Call::Scope(_) => to_value(ScopeResult {
            restricted: false,
            entries: Vec::new(),
            rejected: Vec::new(),
            refused_total: 0,
            refusals_dropped: 0,
            recent: Vec::new(),
        }),
        Call::Check(p) => to_value(CheckResult {
            results: p
                .dests
                .iter()
                .map(|d| CheckRow {
                    host: d.host.clone(),
                    port: d.port,
                    admitted: true,
                })
                .collect(),
        }),
        Call::Replay(p) => to_value(ReplayResult {
            new_id: p.id + 1000,
            status: Some(200),
            duration_ms: 9,
            bytes: 13,
            request_line: "GET /api/items?id=2 HTTP/1.1".into(),
            applied: Vec::new(),
            resp_headers: vec![("Content-Type".into(), "application/json".into())],
            resp_body: Some(Body::text("{\"items\":[2]}".into(), 13, false)),
        }),
        Call::ScanSource(_) => to_value(ScanSourceResult {
            method: "GET".into(),
            url: "http://app.example.test/api/items?id=2".into(),
            req_headers: vec![
                ("Host".into(), "app.example.test".into()),
                ("Cookie".into(), "sid=S1".into()),
            ],
            body: None,
            content_type: None,
        }),
        Call::Cancel(_) => Ok(json!({})),
    }
}
