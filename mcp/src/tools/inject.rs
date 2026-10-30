//! `test_injection`: plessor's `inject` operation, run as a scan with a handle.
//!
//! The call returns as soon as plessor acknowledges, or after `wait_seconds`, and the
//! scan goes on in a task that owns the engine connection and writes the job to disk
//! as events arrive. `get_scan` and `list_findings` read what it wrote.

use super::{in_range, parse_args};
use crate::confirm::WriteAsk;
use crate::core::{
    CallNote, Done, Intent, Mcp, Pending, Reason, Refusal, RunningJob, RunningMap, SCAN_TIME_LIMIT,
    Snap, TrafficRequest,
};
use crate::engine::{self, Line, LineReader, event_type};
use crate::findings::{self, Stamp};
use crate::guard::{self, Dest};
use crate::jobs::{self, FINDINGS_PER_JOB, JobMeta, JobStore, NewJob};
use crate::peer::ClientPeer;
use crate::{redact, untrusted};
use cfx_scope::Point;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// The classes this server lets a model name. plessor's opt-in classes (race,
/// smuggling, prototype pollution, tampering) each need a confirmation of their own
/// and are not offered yet.
pub(crate) const CLASSES: [&str; 15] = [
    "sqli",
    "xss",
    "cmdi",
    "lfi",
    "ssti",
    "ssrf",
    "nosql",
    "xxe",
    "crlf",
    "open_redirect",
    "deserialization",
    "cors",
    "exposure",
    "inventory",
    "ratelimit",
];

const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const ACK_WAIT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    endpoints: Option<Vec<EndpointArg>>,
    #[serde(default)]
    classes: Option<Vec<String>>,
    #[serde(default)]
    test_writes: bool,
    #[serde(default)]
    wait_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointArg {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Vec<String>>,
    #[serde(default)]
    body: Option<Vec<BodyArg>>,
    #[serde(default)]
    body_type: Option<String>,
}

/// Serialised into the operation as plessor reads a body field, where a missing value
/// is an empty string and a null fails the whole operation.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BodyArg {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    ty: Option<String>,
}

struct Endpoint {
    dest: Dest,
    op: Value,
}

fn endpoints(a: &Args) -> Result<Vec<Endpoint>, Refusal> {
    let list: Vec<EndpointArg> = match (&a.url, &a.endpoints) {
        (Some(u), None) => vec![EndpointArg {
            url: u.clone(),
            method: None,
            params: None,
            body: None,
            body_type: None,
        }],
        (None, Some(eps)) => {
            if eps.is_empty() || eps.len() > 100 {
                return Err(Refusal::invalid(
                    "endpoints must hold between 1 and 100 entries",
                ));
            }
            eps.iter()
                .map(|e| EndpointArg {
                    url: e.url.clone(),
                    method: e.method.clone(),
                    params: e.params.clone(),
                    body: e.body.as_ref().map(|b| {
                        b.iter()
                            .map(|f| BodyArg {
                                name: f.name.clone(),
                                value: f.value.clone(),
                                ty: f.ty.clone(),
                            })
                            .collect()
                    }),
                    body_type: e.body_type.clone(),
                })
                .collect()
        }
        _ => {
            return Err(Refusal::invalid(
                "give exactly one of url (one URL with the query parameters to test) or \
                 endpoints",
            ));
        }
    };
    let mut out = Vec::new();
    for e in list {
        let dest = guard::parse_target(&e.url)
            .map_err(|err| Refusal::invalid(format!("endpoint url: {err}")))?;
        let method = e
            .method
            .unwrap_or_else(|| "GET".into())
            .to_ascii_uppercase();
        if !METHODS.contains(&method.as_str()) {
            return Err(Refusal::invalid(
                "method must be one of GET, POST, PUT, PATCH, DELETE",
            ));
        }
        let params = e.params.unwrap_or_default();
        if params.len() > 50 || params.iter().any(|p| p.len() > 200) {
            return Err(Refusal::invalid(
                "params holds at most 50 names of at most 200 characters",
            ));
        }
        let body = e.body.unwrap_or_default();
        if body.len() > 50
            || body
                .iter()
                .any(|f| f.name.len() > 200 || f.value.as_ref().is_some_and(|v| v.len() > 8192))
        {
            return Err(Refusal::invalid(
                "body holds at most 50 fields, each name at most 200 characters and each \
                 value at most 8 KB",
            ));
        }
        let body_type = e.body_type.unwrap_or_else(|| "form".into());
        if body_type != "form" && body_type != "json" {
            return Err(Refusal::invalid("body_type must be form or json"));
        }
        let op = json!({
            "method": method,
            "url": dest.url,
            "params": params,
            "body": body,
            "body_type": body_type,
        });
        out.push(Endpoint { dest, op });
    }
    Ok(out)
}

fn snap_of(m: &JobMeta) -> Snap {
    Snap {
        status: m.status.clone(),
        done: m.progress.done,
        total: m.progress.total,
    }
}

/// The handle and state a scan call returns, and `get_scan` mostly repeats.
pub(crate) fn scan_view(m: &JobMeta, redact: bool) -> Value {
    let shown = |s: &str| {
        let t = untrusted::clean(s, untrusted::NOTE_CAP);
        if redact { redact::redact_text(&t) } else { t }
    };
    json!({
        "scan_id": m.id,
        "status": m.status,
        "progress": {"done": m.progress.done, "total": m.progress.total, "phase": m.progress.phase},
        "counts": {"findings": m.counts.findings, "by_severity": m.counts.by_severity},
        "poll_after_seconds": if jobs::is_terminal(&m.status) { 0 } else { 5 },
        "target_data": {
            "untrusted": true,
            "notes": m.notes.iter().map(|n| shown(n)).collect::<Vec<_>>(),
            "error": m.error.as_deref().map(shown),
        },
    })
}

/// The classes named, checked and without repeats. Empty means all of them.
pub(crate) fn parse_classes(named: Option<Vec<String>>) -> Result<Vec<String>, Refusal> {
    let mut classes: Vec<String> = Vec::new();
    for c in named.unwrap_or_default() {
        let c = c.trim().to_ascii_lowercase();
        if !CLASSES.contains(&c.as_str()) {
            return Err(Refusal::invalid(format!(
                "unknown class {:?}; the classes are {}",
                untrusted::clean(&c, 40),
                CLASSES.join(", ")
            )));
        }
        if !classes.contains(&c) {
            classes.push(c);
        }
    }
    Ok(classes)
}

pub(crate) async fn run(
    mcp: &Mcp,
    args: &Value,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let a: Args = parse_args(args)?;
    let wait = in_range("wait_seconds", a.wait_seconds.unwrap_or(0), 0, 50)?;
    let classes = parse_classes(a.classes.clone())?;
    let eps = endpoints(&a)?;

    let pending = mcp
        .precheck(TrafficRequest {
            tool: "test_injection",
            dests: eps.iter().map(|e| e.dest.clone()).collect(),
            intent: if a.test_writes {
                Intent::Write
            } else {
                Intent::Read
            },
            point: Point::Request,
            pace: false,
            scan_start: true,
        })
        .await?;

    // One scan is one origin on one connection, the way plessor's own CLI batches.
    let origin = eps[0].dest.origin();
    let mut origins: Vec<String> = eps.iter().map(|e| e.dest.origin()).collect();
    origins.sort();
    origins.dedup();
    if origins.len() > 1 {
        return Err(Refusal::invalid(format!(
            "these endpoints span {} origins ({}); make one test_injection call per origin",
            origins.len(),
            origins
                .iter()
                .map(|o| untrusted::clean(o, 200))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let write = a.test_writes.then(|| WriteAsk {
        remember: None,
        message: format!(
            "test_injection with test_writes will send DELETE, PUT and PATCH requests to {} \
             ({} endpoints). These can change or destroy data.",
            untrusted::clean(&origin, 200),
            eps.len()
        ),
    });
    let plan = Plan {
        tool: "test_injection",
        origin,
        endpoints: eps.iter().map(|e| e.op.clone()).collect(),
        shown_endpoints: eps.iter().map(|e| e.dest.url.clone()).collect(),
        classes,
        test_writes: a.test_writes,
        auth: None,
        source: None,
        scope: mcp.scope.entries.clone(),
        wait,
        write,
        on_start: None,
    };
    start_scan(mcp, pending, plan, peer, ct, note).await
}

/// A scan whose destinations passed the checks, ready to be confirmed and started.
pub(crate) struct Plan {
    /// The tool the job is recorded under.
    pub tool: &'static str,
    pub origin: String,
    /// plessor's endpoints, as its operation reads them.
    pub endpoints: Vec<Value>,
    /// What the job file keeps of each endpoint.
    pub shown_endpoints: Vec<String>,
    pub classes: Vec<String>,
    pub test_writes: bool,
    /// Headers and cookies plessor sends with every probe. Handed over on loopback and
    /// never written to a job file, the audit log or a result.
    pub auth: Option<Value>,
    /// Where the request came from, kept in the job.
    pub source: Option<Value>,
    /// The entries plessor may follow up to.
    pub scope: Vec<String>,
    pub wait: u64,
    /// The question for a scan that writes.
    pub write: Option<WriteAsk>,
    /// Called once the scan is running, before the call waits on it.
    pub on_start: Option<Box<dyn FnOnce(Arc<RunningJob>) + Send>>,
}

/// Confirm and start a planned scan, then wait for it as long as it was asked to.
pub(crate) async fn start_scan(
    mcp: &Mcp,
    pending: Pending,
    plan: Plan,
    peer: &dyn ClientPeer,
    ct: &CancellationToken,
    note: &mut CallNote,
) -> Result<Done, Refusal> {
    let port = mcp.engine("plessor")?.port;
    let mut conn = engine::connect(port)
        .await
        .map_err(|_| mcp.engine_down("plessor", port))?;
    mcp.require(
        &mut conn,
        "plessor",
        port,
        "inject",
        &["follow_redirects", "resolve"],
    )
    .await?;
    let clearance = mcp.confirm(pending, peer, plan.write, note, ct).await?;
    if ct.is_cancelled() {
        return Err(Refusal::new(
            Reason::Cancelled,
            "The call was cancelled before anything was sent.",
        ));
    }

    // plessor follows no redirects, since a hop it follows is one this server never
    // sees, and dials a name only at the address the guard cleared for it. Its
    // internal-address filter is on as well, for anything else it connects to.
    let mut op = json!({
        "operation": "inject",
        "response": "stream",
        "target": plan.origin,
        "endpoints": plan.endpoints,
        "classes": plan.classes,
        "test_writes": plan.test_writes,
        "scope": plan.scope,
        "block_internal": clearance.block_internal(mcp.scope.allow_private),
        "follow_redirects": false,
        "resolve": clearance.pins(),
        "timeout_ms": 12_000,
    });
    if let Some(auth) = plan.auth {
        op["auth"] = auth;
    }

    let start_lock = mcp.scan_start.lock().await;
    mcp.check_scan_caps()?;
    let (mut reader, writer) = conn.start(&clearance, &op).await.map_err(|e| {
        Refusal::new(
            Reason::EngineError,
            format!("could not send to plessor: {e}"),
        )
    })?;
    drop(op);
    let ack = tokio::time::timeout(ACK_WAIT, async {
        loop {
            match reader.next().await {
                Ok(Some(Line::Event(v))) => match event_type(&v) {
                    "ack" => return Ok(v),
                    "error" => {
                        let m = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
                        return Err(untrusted::clean(m, untrusted::NOTE_CAP));
                    }
                    _ => continue,
                },
                Ok(Some(_)) => continue,
                _ => return Err("plessor closed the connection".to_string()),
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err("engine did not acknowledge".into()))
    .map_err(|m| Refusal::new(Reason::EngineError, format!("plessor reported: {m}")))?;
    let cancellable = ack.get("cancellable").and_then(|c| c.as_bool()) == Some(true);

    let origin = plan.origin;
    let mut meta = JobMeta::new(
        &mcp.session,
        NewJob {
            tool: plan.tool,
            engine: "plessor",
            target: &origin,
            endpoints: plan.shown_endpoints,
            scope_sha256: mcp.scope.sha256.clone(),
            cancellable,
            test_writes: plan.test_writes,
        },
    );
    meta.source = plan.source;
    meta.progress.total = meta.endpoints.len() as u64;
    meta.progress.phase = "testing endpoints".into();
    if let Err(e) = mcp.jobs.write_meta(&meta) {
        let mut w = writer;
        let _ = w.send_cancel().await;
        return Err(Refusal::new(
            Reason::EngineError,
            format!("the scan could not be recorded, so it was stopped: {e}"),
        ));
    }
    drop(start_lock);
    note.set_scan(meta.id.clone());

    let (tx, rx) = watch::channel(snap_of(&meta));
    let job = Arc::new(RunningJob {
        id: meta.id.clone(),
        cancellable,
        meta: Mutex::new(meta.clone()),
        writer: tokio::sync::Mutex::new(Some(writer)),
        snap: rx,
        pump: Mutex::new(None),
        cancel_requested: AtomicBool::new(false),
    });
    if let Ok(mut r) = mcp.running.lock() {
        r.insert(job.id.clone(), Arc::clone(&job));
    }
    let handle = tokio::spawn(pump(
        reader,
        Arc::clone(&job),
        Arc::clone(&mcp.jobs),
        Arc::clone(&mcp.running),
        tx,
    ));
    if let Ok(mut p) = job.pump.lock() {
        *p = Some(handle);
    }
    if let Some(f) = plan.on_start {
        f(Arc::clone(&job));
    }

    if plan.wait > 0 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(plan.wait);
        let mut rx = job.snap.clone();
        let mut last_progress = Instant::now() - Duration::from_secs(1);
        // A progress value has to go up with every notification, and the snapshot
        // also changes when only a finding arrived.
        let mut last_done: Option<u64> = None;
        loop {
            if jobs::is_terminal(&rx.borrow_and_update().status) {
                break;
            }
            tokio::select! {
                _ = ct.cancelled() => {
                    // The handle was never handed out, so nobody else can stop this
                    // scan: a cancelled call takes its scan with it.
                    mcp.cancel_running(&job).await;
                    return Err(Refusal::new(
                        Reason::Cancelled,
                        "The call was cancelled before it returned, so its scan was cancelled \
                         too.",
                    ));
                }
                r = rx.changed() => {
                    if r.is_err() {
                        break;
                    }
                    let s = rx.borrow().clone();
                    if last_progress.elapsed() >= Duration::from_millis(500)
                        && last_done.is_none_or(|d| s.done > d)
                    {
                        peer.progress(s.done as f64, Some(s.total as f64), "testing endpoints")
                            .await;
                        last_progress = Instant::now();
                        last_done = Some(s.done);
                    }
                }
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
    }

    let m = job
        .meta
        .lock()
        .map(|m| m.clone())
        .unwrap_or_else(|_| meta.clone());
    let m = if jobs::is_terminal(&m.status) {
        mcp.jobs.read_meta(&m.id).unwrap_or(m)
    } else {
        m
    };
    note.result = Some(json!({"status": m.status, "findings": m.counts.findings}));
    let value = scan_view(&m, mcp.settings.redact);
    let summary = format!(
        "plessor scan {} on {} is {}: {} of {} endpoints done, {} findings. Poll get_scan, and \
         read results with list_findings.",
        m.id,
        untrusted::clean(&origin, 200),
        m.status,
        m.progress.done,
        m.progress.total,
        m.counts.findings
    );
    Ok(Done { value, summary })
}

/// Read a scan's events until it ends, writing the job as it goes.
async fn pump(
    mut reader: LineReader,
    job: Arc<RunningJob>,
    store: Arc<JobStore>,
    running: RunningMap,
    tx: watch::Sender<Snap>,
) {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    heartbeat.tick().await;
    let limit = tokio::time::sleep(SCAN_TIME_LIMIT);
    tokio::pin!(limit);
    let mut last_write = Instant::now();
    let mut seq = 0u64;
    let mut capped = false;

    let update = |f: &mut dyn FnMut(&mut JobMeta)| -> JobMeta {
        let mut m = job.meta.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut m);
        m.clone()
    };

    loop {
        tokio::select! {
            line = reader.next() => match line {
                Ok(Some(Line::Event(v))) => match event_type(&v) {
                    "progress" => {
                        let done = v.get("processed").and_then(|x| x.as_u64());
                        let total = v.get("total").and_then(|x| x.as_u64());
                        let m = update(&mut |m| {
                            if let Some(d) = done { m.progress.done = d; }
                            if let Some(t) = total { m.progress.total = t; }
                        });
                        tx.send_replace(snap_of(&m));
                        if last_write.elapsed() >= Duration::from_secs(1) {
                            let m = update(&mut |m| m.touch());
                            let _ = store.write_meta(&m);
                            last_write = Instant::now();
                        }
                    }
                    "finding" => {
                        let count = job.meta.lock().map(|m| m.counts.findings).unwrap_or(0);
                        if count >= FINDINGS_PER_JOB {
                            if !capped {
                                capped = true;
                                update(&mut |m| m.note(format!(
                                    "more than {FINDINGS_PER_JOB} findings; later ones were not stored"
                                )));
                            }
                            continue;
                        }
                        seq += 1;
                        let f = findings::from_plessor(
                            v.get("data").unwrap_or(&Value::Null),
                            Stamp {
                                id: jobs::new_id("f"),
                                scan_id: &job.id,
                                seq,
                                recorded_ms: jobs::now_ms(),
                            },
                        );
                        let sev = f["severity"].as_str().unwrap_or("unknown").to_string();
                        if store.append_findings(&job.id, std::slice::from_ref(&f)).is_ok() {
                            let m = update(&mut |m| m.count(&sev));
                            tx.send_replace(snap_of(&m));
                            if last_write.elapsed() >= Duration::from_secs(1) {
                                let _ = store.write_meta(&m);
                                last_write = Instant::now();
                            }
                        }
                    }
                    "log" => {
                        let msg = v.get("message").and_then(|x| x.as_str()).unwrap_or("");
                        let msg = untrusted::clean(msg.trim(), untrusted::NOTE_CAP);
                        if !msg.is_empty() {
                            update(&mut |m| m.note(msg.clone()));
                        }
                    }
                    "error" => {
                        let msg = v.get("message").and_then(|x| x.as_str()).unwrap_or("");
                        let msg = untrusted::clean(msg, untrusted::NOTE_CAP);
                        update(&mut |m| m.error = Some(msg.clone()));
                    }
                    "done" => {
                        let stopped = v.get("cancelled").and_then(|c| c.as_bool()) == Some(true);
                        update(&mut |m| {
                            if stopped {
                                m.cancel = Some("stopped".into());
                                m.finish(jobs::CANCELLED);
                            } else {
                                m.progress.phase = "done".into();
                                m.finish(jobs::COMPLETED);
                            }
                        });
                        break;
                    }
                    _ => {}
                },
                Ok(Some(Line::TooLong)) => {
                    update(&mut |m| m.note("skipped an engine event longer than 4 MiB".into()));
                }
                Ok(Some(Line::NotJson)) => {}
                Ok(None) | Err(_) => {
                    let asked = job.cancel_requested.load(Ordering::SeqCst);
                    update(&mut |m| {
                        if asked {
                            m.cancel = Some("requested".into());
                            m.finish(jobs::CANCELLED);
                        } else {
                            if m.error.is_none() {
                                m.error = Some(
                                    "engine closed the connection before finishing".into(),
                                );
                            }
                            m.finish(jobs::FAILED);
                        }
                    });
                    break;
                }
            },
            _ = heartbeat.tick() => {
                let m = update(&mut |m| m.touch());
                let _ = store.write_meta(&m);
                last_write = Instant::now();
            }
            _ = &mut limit => {
                if let Some(w) = job.writer.lock().await.as_mut() {
                    let _ = w.send_cancel().await;
                }
                update(&mut |m| {
                    m.error = Some("time limit".into());
                    m.finish(jobs::FAILED);
                });
                break;
            }
        }
    }
    let m = update(&mut |_| {});
    let _ = store.write_meta(&m);
    if let Ok(mut r) = running.lock() {
        r.remove(&job.id);
    }
    tx.send_replace(snap_of(&m));
    job.writer.lock().await.take();
}
