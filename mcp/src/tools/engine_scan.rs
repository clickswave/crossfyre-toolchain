//! Starting a scan on an engine's daemon and following it, for every tool that runs one:
//! the options that fence it asked about, the person's confirmation, the operation sent
//! with the addresses the guard cleared, and the engine's acknowledgement, which names
//! the scan it keeps. The call returns then, or after `wait_seconds`, and the scan goes
//! on in a task that owns the engine connection and keeps its state in memory for the
//! call that started it. The engine keeps the scan and what it finds, which `get_scan`
//! and `list_findings` read back.

use crate::confirm::WriteAsk;
use crate::core::{
    CallNote, Done, Mcp, Pending, Reason, Refusal, RunningJob, RunningMap, SCAN_TIME_LIMIT, Snap,
};
use crate::engine::{self, Line, LineReader, event_type};
use crate::findings;
use crate::jobs::{self, JobMeta, NewJob};
use crate::peer::ClientPeer;
use crate::{redact, untrusted};
use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// How long plessor has to acknowledge a scan.
const ACK_WAIT: Duration = Duration::from_secs(5);

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

/// A scan whose destinations passed the checks, ready to be confirmed and started.
pub(crate) struct Plan {
    /// The tool the job is recorded under.
    pub tool: &'static str,
    /// What the scan is of, as it is shown: for plessor also what it is sent as the
    /// target, the origin for the injection pass and the base URL for the templates.
    pub target: String,
    pub run: Run,
    /// What the engine keeps of each endpoint with the scan, under its `mcp` settings.
    pub shown_endpoints: Vec<String>,
    pub test_writes: bool,
    /// Where the request came from, kept with the scan.
    pub source: Option<Value>,
    pub wait: u64,
    /// The question for a scan that writes.
    pub write: Option<WriteAsk>,
    /// Called once the scan is running, before the call waits on it.
    pub on_start: Option<Box<dyn FnOnce(Arc<RunningJob>) + Send>>,
}

/// What an engine is asked to run.
pub(crate) enum Run {
    /// The injection pass.
    Inject {
        /// plessor's endpoints, as its operation reads them.
        endpoints: Vec<Value>,
        classes: Vec<String>,
        /// Headers and cookies plessor sends with every probe. Handed over on loopback as
        /// the scan's `auth`, which no engine keeps, and never written to the audit log or
        /// a result.
        auth: Option<Value>,
        /// The entries plessor may follow up to.
        scope: Vec<String>,
    },
    /// plessor's template scan, with the fields of its request that choose the templates.
    Templates {
        fields: Map<String, Value>,
        /// Where the answers to the CVE leads among `fields` go back to.
        leads_to: Option<LeadsTo>,
    },
    /// doorward's port scan, ambulo's content discovery or voyage's enumeration.
    Engine(EngineRun),
}

/// A scan of doorward, ambulo or voyage, as one of their tools plans it.
pub(crate) struct EngineRun {
    pub engine: &'static str,
    pub operation: &'static str,
    /// The options that fence it, which the engine has to say it honours, each set from
    /// what was cleared: `resolve` to the addresses the guard cleared, `block_internal`
    /// as the scope file says, `follow_redirects` off, and `scope` to the file's entries.
    pub options: &'static [&'static str],
    /// The rest of its request.
    pub fields: Map<String, Value>,
    /// Words that follow the request on the connection. None follow when it is empty.
    pub words: Vec<String>,
    /// How long it may take to acknowledge: voyage asks its passive sources first.
    pub ack_wait: Duration,
    pub phase: &'static str,
    pub unit: &'static str,
    pub counting: Counting,
}

/// How a scan says how far it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Counting {
    /// In `progress` events, with what it has done of what it will.
    Progress,
    /// In each result, which says how many it has tried.
    Tested,
    /// One result for each name it tried.
    Results,
}

impl Run {
    fn engine(&self) -> &'static str {
        match self {
            Run::Engine(r) => r.engine,
            _ => "plessor",
        }
    }

    fn operation(&self) -> &'static str {
        match self {
            Run::Inject { .. } => "inject",
            Run::Templates { .. } => "scan",
            Run::Engine(r) => r.operation,
        }
    }

    /// What the scan is doing while it runs, and what its progress counts.
    fn phase(&self) -> (&'static str, &'static str) {
        match self {
            Run::Inject { .. } => ("testing endpoints", "endpoints"),
            Run::Templates { .. } => ("running templates", "templates"),
            Run::Engine(r) => (r.phase, r.unit),
        }
    }

    fn counting(&self) -> Counting {
        match self {
            Run::Engine(r) => r.counting,
            _ => Counting::Progress,
        }
    }

    fn ack_wait(&self) -> Duration {
        match self {
            Run::Engine(r) => r.ack_wait,
            _ => ACK_WAIT,
        }
    }
}

/// toolmark's daemon, which gave a template scan its CVE leads for one host and port, and
/// keeps what the scan said of each.
pub(crate) struct LeadsTo {
    pub toolmark: u16,
    pub host: String,
    pub port: u16,
}

/// A [`LeadsTo`] for one scan, as plessor kept it.
struct Answers {
    to: LeadsTo,
    scan: String,
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
    let name = plan.run.engine();
    let port = mcp.engine(name)?.port;
    let mut conn = engine::connect(port)
        .await
        .map_err(|_| mcp.engine_down(name, port))?;
    let operation = plan.run.operation();
    let (phase, unit) = plan.run.phase();
    let counting = plan.run.counting();
    let ack_wait = plan.run.ack_wait();
    let has_auth = matches!(&plan.run, Run::Inject { auth: Some(_), .. });
    // A captured session goes only to a daemon this user runs. Anyone on the machine can
    // listen on a loopback port while plessor is stopped.
    if has_auth && let Err(why) = conn.runs_as_this_user().await {
        return Err(Refusal::new(
            Reason::EngineUnavailable,
            format!(
                "Whatever is listening on 127.0.0.1:{port} could not be shown to be your \
                 plessor ({why}), so the captured session was not handed to it and nothing \
                 was sent. Another user can listen on that port while plessor is stopped. \
                 Check that `crossfyre extension start plessor` started it as you, and call \
                 again."
            ),
        ));
    }
    // A captured session goes out only past a certificate that checks out, as the
    // Workbench sends it. plessor otherwise accepts any certificate, so whoever answered
    // the handshake for the host would be sent the session.
    let options: &[&str] = match &plan.run {
        Run::Engine(r) => r.options,
        _ if has_auth => &["follow_redirects", "resolve", "verify_certs"],
        _ => &["follow_redirects", "resolve"],
    };
    let pacing = mcp
        .require(&mut conn, name, port, operation, options)
        .await?;
    let clearance = mcp.confirm(pending, peer, plan.write, note, ct).await?;
    if ct.is_cancelled() {
        return Err(Refusal::new(
            Reason::Cancelled,
            "The call was cancelled before anything was sent.",
        ));
    }

    // The engine follows no redirects, since a hop it follows is one this server never
    // sees, and dials a name only at the address the guard cleared for it. Its
    // internal-address filter is on as well, for anything else it connects to.
    let block_internal = clearance.block_internal(mcp.scope.allow_private);
    let mut op = json!({"operation": operation, "response": "stream"});
    if !matches!(plan.run, Run::Engine(_)) {
        op["target"] = json!(plan.target);
        op["test_writes"] = json!(plan.test_writes);
        op["block_internal"] = json!(block_internal);
        op["follow_redirects"] = json!(false);
        op["resolve"] = clearance.pins();
        op["timeout_ms"] = json!(12_000);
    }
    let mut leads_to = None;
    let mut words = Vec::new();
    match plan.run {
        Run::Inject {
            endpoints,
            classes,
            auth,
            scope,
        } => {
            op["endpoints"] = json!(endpoints);
            op["classes"] = json!(classes);
            op["scope"] = json!(scope);
            if let Some(auth) = auth {
                op["auth"] = auth;
                op["verify_certs"] = Value::Bool(true);
            }
        }
        Run::Templates {
            fields,
            leads_to: to,
        } => {
            for (k, v) in fields {
                op[k] = v;
            }
            leads_to = to;
        }
        Run::Engine(run) => {
            for (k, v) in run.fields {
                op[k] = v;
            }
            for option in run.options {
                op[*option] = match *option {
                    "resolve" => clearance.pins(),
                    "block_internal" => json!(block_internal),
                    "follow_redirects" => json!(false),
                    "scope" => json!(mcp.scope.entries),
                    _ => continue,
                };
            }
            if !run.words.is_empty() {
                op[dguard::WORDS_FOLLOW] = json!("crossfyre mcp");
            }
            words = run.words;
        }
    }
    // What this server says of the scan, which the engine keeps with it and gives back to
    // whoever reads it: which tool, which server and scope file, and where it came from.
    op["mcp"] = json!({
        "tool": plan.tool,
        "process": mcp.session,
        "pid": std::process::id(),
        "scope_sha256": mcp.scope.sha256,
        "test_writes": plan.test_writes,
        "endpoints": plan.shown_endpoints,
        "source": plan.source,
    });

    let start_lock = mcp.scan_start.lock().await;
    mcp.check_scan_caps().await?;
    let sent = conn.start(&clearance, &op).await;
    let (mut reader, mut writer) = sent.map_err(|e| {
        Refusal::new(
            Reason::EngineError,
            format!("could not send to {name}: {e}"),
        )
    })?;
    drop(op);
    // The words go before the acknowledgement, which comes once they are all read.
    if !words.is_empty() {
        writer.send_words(&words).await.map_err(|e| {
            Refusal::new(
                Reason::EngineError,
                format!("could not send the words to {name}: {e}"),
            )
        })?;
    }
    let ack = tokio::time::timeout(ack_wait, async {
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
                _ => return Err(format!("{name} closed the connection")),
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err("engine did not acknowledge".into()))
    .map_err(|m| Refusal::new(Reason::EngineError, format!("{name} reported: {m}")))?;
    let cancellable = ack.get("cancellable").and_then(|c| c.as_bool()) == Some(true);
    // The scan is read back by the id the engine kept it as. One it could not keep has no
    // handle to read it by, so it is stopped: asked to, and the connection closed.
    let Some(kept_as) = ack.get("scan").and_then(|s| s.as_str()) else {
        let _ = writer.send_cancel().await;
        return Err(Refusal::new(
            Reason::EngineError,
            format!(
                "{name} could not keep the scan, so it was stopped: check its database with \
                 `crossfyre db status`"
            ),
        ));
    };

    let answers = leads_to.map(|to| Answers {
        to,
        scan: kept_as.to_string(),
    });
    let target = plan.target;
    let mut meta = JobMeta::new(
        &mcp.session,
        NewJob {
            id: crate::kept::scan_id(name, kept_as),
            tool: plan.tool,
            engine: name,
            target: &target,
            endpoints: plan.shown_endpoints,
            scope_sha256: mcp.scope.sha256.clone(),
            cancellable,
            test_writes: plan.test_writes,
        },
    );
    meta.source = plan.source;
    meta.progress.total = match ack.get("total").and_then(Value::as_u64) {
        Some(total) => total,
        None if operation == "inject" => meta.endpoints.len() as u64,
        None => 0,
    };
    meta.progress.phase = phase.into();
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
        Arc::clone(&mcp.running),
        tx,
        answers,
        counting,
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
                        peer.progress(s.done as f64, Some(s.total as f64), phase).await;
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
    note.result = Some(json!({"status": m.status, "findings": m.counts.findings}));
    let mut value = scan_view(&m, mcp.settings.redact);
    // Which pacing the engine runs, as it said before the scan was sent.
    let paced = match &pacing {
        Some(p) => {
            value["pacing"] = json!(p);
            format!(" pacing: {p}.")
        }
        None => String::new(),
    };
    let summary = format!(
        "{name} scan {} on {} is {}: {} of {} {unit} done, {} findings.{paced} Poll get_scan, \
         and read results with list_findings.",
        m.id,
        untrusted::clean(&target, 200),
        m.status,
        m.progress.done,
        m.progress.total,
        m.counts.findings
    );
    Ok(Done { value, summary })
}

/// Read a scan's events until it ends, keeping the scan's state in memory for the call
/// that started it. The engine keeps the scan and what it finds, which is what is read
/// back. What a template scan says of its CVE leads goes back to toolmark, which gave
/// them.
async fn pump(
    mut reader: LineReader,
    job: Arc<RunningJob>,
    running: RunningMap,
    tx: watch::Sender<Snap>,
    answers: Option<Answers>,
    counting: Counting,
) {
    let limit = tokio::time::sleep(SCAN_TIME_LIMIT);
    tokio::pin!(limit);

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
                    }
                    // doorward's open port, ambulo's path and voyage's name: a finding when
                    // it was found, and how far the scan got in each count by result.
                    "result" => {
                        let found = matches!(
                            v.get("status").and_then(|s| s.as_str()),
                            Some("open" | "found")
                        );
                        let tested = v.get("tested").and_then(|t| t.as_u64());
                        let m = update(&mut |m| {
                            match counting {
                                Counting::Tested => {
                                    if let Some(t) = tested {
                                        m.progress.done = t;
                                    }
                                }
                                Counting::Results => m.progress.done += 1,
                                Counting::Progress => {}
                            }
                            if found {
                                m.count("info");
                            }
                        });
                        tx.send_replace(snap_of(&m));
                    }
                    "finding" => {
                        let data = v.get("data").unwrap_or(&Value::Null);
                        let sev = findings::severity(
                            data.get("severity").and_then(|s| s.as_str()).unwrap_or(""),
                        )
                        .to_string();
                        let m = update(&mut |m| m.count(&sev));
                        tx.send_replace(snap_of(&m));
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
                    "lead_answers" => {
                        if let Some(a) = &answers
                            && let Some(back) = cfx_cve::inventory::AnswersBack::from_event(
                                &a.to.host,
                                a.to.port,
                                Some(&a.scan),
                                &v,
                            )
                            && !keep_answers(a.to.toolmark, &back).await
                        {
                            update(&mut |m| {
                                m.note(format!(
                                    "toolmark did not keep the answers to the CVE leads of {}:{}",
                                    untrusted::clean(&a.to.host, 200),
                                    a.to.port
                                ))
                            });
                        }
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
    if let Ok(mut r) = running.lock() {
        r.remove(&job.id);
    }
    tx.send_replace(snap_of(&m));
    job.writer.lock().await.take();
}

/// Hand toolmark's daemon on `port` what a scan said of its leads; whether it kept them.
async fn keep_answers(port: u16, back: &cfx_cve::inventory::AnswersBack) -> bool {
    match engine::connect(port).await {
        Ok(conn) => conn
            .local(&back.request())
            .await
            .is_ok_and(|a| a["status"] == "completed"),
        Err(_) => false,
    }
}
