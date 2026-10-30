//! The server's state, and the one path every tool call takes through it.
//!
//! Every call goes through [`Mcp::call`], which applies the call limit, dispatches,
//! and writes exactly one audit line whatever happened: when it returns, or, for a
//! call still open when the server stops, from [`Mcp::shutdown`]. Every request to a target
//! needs a [`Clearance`], and the only way to get one is [`Mcp::precheck`] followed
//! by [`Mcp::confirm`] (or [`Mcp::clear_hop`] for a redirect). The functions that
//! send take a `&Clearance`, so a tool that skipped the guard would not compile.

use crate::audit::{Audit, now_rfc3339};
use crate::confirm::{Confirmations, WriteAsk};
use crate::engine::{EngineConn, EngineWriter, Support};
use crate::guard::{self, AddrRefusal, Dest, Resolver};
use crate::jobs::{self, JobMeta, JobStore};
use crate::limits::{CallBucket, HostPacer};
use crate::peer::ClientPeer;
use crate::scope_file::LoadedScope;
use crate::{EngineInfo, WorkbenchMode};
use crate::{redact, untrusted};
use cfx_scope::{Guard, Point};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// A scan running longer than this is stopped and marked failed.
pub(crate) const SCAN_TIME_LIMIT: Duration = Duration::from_secs(120 * 60);

/// Why a call did not do what it was asked. The string forms are the `reason` codes
/// a client and the audit log see.
///
/// One list for every backend, so a code means one thing whichever backend refused.
/// The Cloud backend's codes are here before that backend is, which is why nothing
/// builds them yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    NoScope,
    OutOfScope,
    PrivateAddress,
    MetadataAddress,
    Unresolvable,
    RedirectOutOfScope,
    WritesNotAllowed,
    NotConfirmed,
    Declined,
    RateLimited,
    ScanLimit,
    AuditUnavailable,
    EngineUnavailable,
    EngineError,
    RequestFailed,
    InvalidArguments,
    UnknownTool,
    NotFound,
    OtherProcess,
    Cancelled,
    /// No Workbench with Agent access on answers, or the backend is off.
    WorkbenchUnavailable,
    /// The open project's scope refused the destination.
    #[allow(dead_code)]
    WorkbenchOutOfScope,
    /// A handle or cursor names a project that is no longer the open one.
    #[allow(dead_code)]
    ProjectChanged,
    /// The Workbench answered with an error of its own.
    #[allow(dead_code)]
    WorkbenchError,
    #[allow(dead_code)]
    CloudUnavailable,
    #[allow(dead_code)]
    CloudKeyRejected,
    #[allow(dead_code)]
    PermissionDenied,
    #[allow(dead_code)]
    OutOfLocalScope,
    #[allow(dead_code)]
    ApprovalDenied,
    #[allow(dead_code)]
    ApprovalExpired,
    #[allow(dead_code)]
    ApprovalRequired,
    /// The platform's own reason code, passed on as it was sent.
    #[allow(dead_code)]
    CloudRefused(&'static str),
}

impl Reason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Reason::NoScope => "no_scope",
            Reason::OutOfScope => "out_of_scope",
            Reason::PrivateAddress => "private_address",
            Reason::MetadataAddress => "metadata_address",
            Reason::Unresolvable => "unresolvable",
            Reason::RedirectOutOfScope => "redirect_out_of_scope",
            Reason::WritesNotAllowed => "writes_not_allowed",
            Reason::NotConfirmed => "not_confirmed",
            Reason::Declined => "declined",
            Reason::RateLimited => "rate_limited",
            Reason::ScanLimit => "scan_limit",
            Reason::AuditUnavailable => "audit_unavailable",
            Reason::EngineUnavailable => "engine_unavailable",
            Reason::EngineError => "engine_error",
            Reason::RequestFailed => "request_failed",
            Reason::InvalidArguments => "invalid_arguments",
            Reason::UnknownTool => "unknown_tool",
            Reason::NotFound => "not_found",
            Reason::OtherProcess => "other_process",
            Reason::Cancelled => "cancelled",
            Reason::WorkbenchUnavailable => "workbench_unavailable",
            Reason::WorkbenchOutOfScope => "workbench_out_of_scope",
            Reason::ProjectChanged => "project_changed",
            Reason::WorkbenchError => "workbench_error",
            Reason::CloudUnavailable => "cloud_unavailable",
            Reason::CloudKeyRejected => "cloud_key_rejected",
            Reason::PermissionDenied => "permission_denied",
            Reason::OutOfLocalScope => "out_of_local_scope",
            Reason::ApprovalDenied => "approval_denied",
            Reason::ApprovalExpired => "approval_expired",
            Reason::ApprovalRequired => "approval_required",
            Reason::CloudRefused(code) => code,
        }
    }

    /// The audit's `decision`: refused by policy, failed, or cancelled.
    fn decision(self) -> &'static str {
        match self {
            Reason::Cancelled => "cancelled",
            Reason::InvalidArguments
            | Reason::UnknownTool
            | Reason::EngineUnavailable
            | Reason::EngineError
            | Reason::RequestFailed
            | Reason::NotFound
            | Reason::WorkbenchUnavailable
            | Reason::ProjectChanged
            | Reason::WorkbenchError
            | Reason::CloudUnavailable => "error",
            _ => "refused",
        }
    }
}

/// A destination that was not reached, and the check that stopped it.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct RefusedDest {
    pub host: String,
    pub port: u16,
    pub at: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    pub reason: Reason,
    pub message: String,
    pub refused: Vec<RefusedDest>,
    /// Extra fields for the client, such as `retry_after_seconds`.
    pub detail: Option<Value>,
}

impl Refusal {
    pub(crate) fn new(reason: Reason, message: impl Into<String>) -> Self {
        Refusal {
            reason,
            message: message.into(),
            refused: Vec::new(),
            detail: None,
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Refusal::new(Reason::InvalidArguments, message)
    }

    pub(crate) fn with_refused(mut self, refused: Vec<RefusedDest>) -> Self {
        self.refused = refused;
        self
    }

    pub(crate) fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

/// A tool's successful answer, before it is turned into a result.
pub(crate) struct Done {
    pub value: Value,
    /// One line the server wrote, placed above the untrusted sentence.
    pub summary: String,
}

/// What a call records beyond its outcome.
#[derive(Default)]
pub(crate) struct CallNote {
    pub confirmation: Option<&'static str>,
    pub scan_id: Option<String>,
    pub result: Option<Value>,
    /// Refusals inside a call that otherwise succeeded, such as a redirect hop.
    pub refused: Vec<RefusedDest>,
    /// The Workbench a call went to: `{pid, project_uid}`.
    pub workbench: Option<Value>,
    /// This call's number in the session, as its audit line has it.
    pub seq: u64,
    /// Where the scan id is also kept for a line written at shutdown.
    scan_slot: Option<Arc<Mutex<Option<String>>>>,
}

impl CallNote {
    pub(crate) fn set_scan(&mut self, id: String) {
        if let Some(Ok(mut slot)) = self.scan_slot.as_ref().map(|s| s.lock()) {
            *slot = Some(id.clone());
        }
        self.scan_id = Some(id);
    }
}

/// A call that has started and has not written its audit line yet.
struct OpenCall {
    tool: String,
    client: String,
    args: Value,
    started: Instant,
    scan_id: Arc<Mutex<Option<String>>>,
}

/// What the protocol layer sends back.
#[derive(Debug, Clone)]
pub(crate) struct ToolResult {
    pub structured: Option<Value>,
    pub text: String,
    pub is_error: bool,
}

pub(crate) enum CallOutput {
    Result(ToolResult),
    /// A protocol-level error, for a tool name the server does not have.
    InvalidParams(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Intent {
    Read,
    /// Can change or destroy data on the target.
    Write,
}

/// One destination that passed the checks, and the addresses it may be dialled at.
#[derive(Debug, Clone)]
pub(crate) struct Cleared {
    pub dest: Dest,
    pub addrs: Vec<SocketAddr>,
}

/// Passed scope, address, intent, limits and audit health; not yet confirmed.
pub(crate) struct Pending {
    cleared: Vec<Cleared>,
}

/// Permission to send to these destinations. Only this module can make one.
pub(crate) struct Clearance {
    pub cleared: Vec<Cleared>,
    _seal: (),
}

impl Clearance {
    /// Each cleared name with the address it is to be dialled at, as the engines read
    /// it: `[["app.example.com", "203.0.113.7:443"], ...]`. The same address
    /// `send_http_request` connects to. An address literal needs no pin.
    pub(crate) fn pins(&self) -> Value {
        Value::Array(
            self.cleared
                .iter()
                .filter(|c| c.dest.ip.is_none())
                .filter_map(|c| c.addrs.first().map(|a| json!([c.dest.host, a.to_string()])))
                .collect(),
        )
    }

    /// Whether an engine is asked to refuse internal addresses on its connections:
    /// whenever the file does not allow them, unless a destination is an internal
    /// address the file lists by itself, which the filter would refuse too.
    pub(crate) fn block_internal(&self, allow_private: bool) -> bool {
        !allow_private
            && !self.cleared.iter().any(|c| {
                c.dest
                    .ip
                    .is_some_and(|ip| transport::guard::is_internal(&ip))
            })
    }
}

pub(crate) struct TrafficRequest<'a> {
    pub tool: &'a str,
    pub dests: Vec<Dest>,
    pub intent: Intent,
    pub point: Point,
    /// Hold to the per-destination pace.
    pub pace: bool,
    /// Check the scan caps.
    pub scan_start: bool,
}

/// What `status` shows and the engines are reached by.
pub(crate) struct Settings {
    pub version: String,
    pub redact: bool,
    pub engines: Vec<EngineInfo>,
    pub postgres_port: Option<u16>,
    pub workbench: WorkbenchMode,
    /// Where a running Workbench writes its endpoint file. Never from a tool argument.
    pub workbench_dir: Option<PathBuf>,
    pub call_burst: u32,
    pub calls_per_minute: u32,
}

/// A scan's live state, as the pump publishes it.
#[derive(Debug, Clone)]
pub(crate) struct Snap {
    pub status: String,
    pub done: u64,
    pub total: u64,
}

/// A scan this process started and is still reading.
pub(crate) struct RunningJob {
    pub id: String,
    pub cancellable: bool,
    pub meta: Mutex<JobMeta>,
    pub writer: tokio::sync::Mutex<Option<EngineWriter>>,
    pub snap: watch::Receiver<Snap>,
    pub pump: Mutex<Option<JoinHandle<()>>>,
    pub cancel_requested: AtomicBool,
}

pub(crate) type RunningMap = Arc<Mutex<HashMap<String, Arc<RunningJob>>>>;

pub(crate) struct Mcp {
    pub settings: Settings,
    pub dir: PathBuf,
    pub scope: LoadedScope,
    pub guard: Arc<Guard>,
    pub jobs: Arc<JobStore>,
    pub audit: Audit,
    pub calls: CallBucket,
    pub pacer: HostPacer,
    pub confirms: Confirmations,
    pub resolver: Arc<dyn Resolver>,
    pub session: String,
    seq: AtomicU64,
    pub running: RunningMap,
    /// Held from the final cap check to the job being written, so two calls cannot
    /// both take the last slot.
    pub scan_start: tokio::sync::Mutex<()>,
    pub polls: Mutex<HashMap<String, u32>>,
    /// The running Workbenches this server is connected to.
    pub workbench: Arc<crate::workbench::Registry>,
    /// Calls that have not written their audit line, by `seq`. Whichever of the call
    /// and the shutdown takes an entry out writes the line, so it is written once.
    open_calls: Mutex<HashMap<u64, OpenCall>>,
}

impl Mcp {
    pub(crate) fn new(
        settings: Settings,
        dir: PathBuf,
        scope: LoadedScope,
        audit: Audit,
        jobs: JobStore,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let guard = scope.guard();
        let pacer = HostPacer::new(scope.requests_per_second_per_host);
        let calls = CallBucket::new(settings.call_burst, settings.calls_per_minute);
        // With the backend off no Workbench is looked for at all.
        let workbench = crate::workbench::Registry::new(
            match settings.workbench {
                WorkbenchMode::Off => None,
                _ => settings.workbench_dir.clone(),
            },
            settings.version.clone(),
        );
        Mcp {
            workbench,
            settings,
            dir,
            guard,
            jobs: Arc::new(jobs),
            audit,
            calls,
            pacer,
            confirms: Confirmations::new(),
            resolver,
            session: jobs::new_id("m"),
            seq: AtomicU64::new(0),
            running: Arc::new(Mutex::new(HashMap::new())),
            scan_start: tokio::sync::Mutex::new(()),
            polls: Mutex::new(HashMap::new()),
            open_calls: Mutex::new(HashMap::new()),
            scope,
        }
    }

    /// What the tool list holds besides the local engines' tools, now.
    pub(crate) fn backends(&self) -> crate::tools::Backends {
        use crate::tools::WORKBENCH_NAMES;
        crate::tools::Backends {
            workbench: match self.settings.workbench {
                WorkbenchMode::Off => None,
                WorkbenchMode::Always => Some(WORKBENCH_NAMES.to_vec()),
                WorkbenchMode::Auto => Some(self.workbench.listed()),
            },
        }
    }

    pub(crate) fn engine(&self, name: &str) -> Result<&EngineInfo, Refusal> {
        self.settings
            .engines
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| {
                Refusal::new(
                    Reason::EngineUnavailable,
                    format!("{name} is not an engine this crossfyre knows about"),
                )
            })
    }

    /// Ask the engine whether it honours `options` for `operation`, before anything
    /// is sent that it might run without them.
    pub(crate) async fn require(
        &self,
        conn: &mut EngineConn,
        name: &str,
        port: u16,
        operation: &str,
        options: &[&str],
    ) -> Result<(), Refusal> {
        match conn.supports(operation, options).await {
            Support::Yes => Ok(()),
            Support::Old => Err(Refusal::new(
                Reason::EngineUnavailable,
                format!(
                    "{name} on 127.0.0.1:{port} is older than crossfyre mcp needs: it cannot be \
                     told to dial only the addresses this server checked, or to leave redirects \
                     alone, so nothing was sent. Update it with `crossfyre extension update \
                     {name}`, restart it with `crossfyre extension restart {name}`, and call \
                     again."
                ),
            )),
            Support::Failed(why) => Err(Refusal::new(
                Reason::EngineUnavailable,
                format!(
                    "{name} on 127.0.0.1:{port} did not answer as an engine daemon ({}), so \
                     nothing was sent. If the daemons require CFX_DAEMON_TOKEN, the MCP server \
                     needs it too; otherwise restart it with `crossfyre extension restart \
                     {name}`.",
                    untrusted::clean(&why, 200)
                ),
            )),
        }
    }

    pub(crate) fn engine_down(&self, name: &str, port: u16) -> Refusal {
        Refusal::new(
            Reason::EngineUnavailable,
            format!(
                "{name} is not listening on 127.0.0.1:{port}, so nothing was sent. Start it with \
                 `crossfyre extension start {name}` (or install it with `crossfyre extension \
                 install {name}`) and call again."
            ),
        )
    }

    // -----------------------------------------------------------------------
    // The call path

    pub(crate) async fn call(
        &self,
        tool: &str,
        args: Value,
        peer: &dyn ClientPeer,
        ct: CancellationToken,
    ) -> CallOutput {
        let started = Instant::now();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let client = untrusted::clean(&peer.label(), 64);
        let audit_args = redact::audit_args(tool, &args);
        let scan_slot = Arc::new(Mutex::new(None));
        if let Ok(mut open) = self.open_calls.lock() {
            open.insert(
                seq,
                OpenCall {
                    tool: untrusted::clean(tool, 64),
                    client: client.clone(),
                    args: audit_args.clone(),
                    started,
                    scan_id: Arc::clone(&scan_slot),
                },
            );
        }
        let mut note = CallNote {
            scan_slot: Some(scan_slot),
            seq,
            ..Default::default()
        };
        // A name that is not a tool is the same answer however busy the server is.
        let outcome = if !crate::tools::known(tool, &self.backends()) {
            crate::tools::Dispatched::Unknown
        } else {
            match self.calls.take() {
                Err(retry) => crate::tools::Dispatched::Refused(
                    Refusal::new(
                        Reason::RateLimited,
                        format!(
                            "Too many calls: this server takes {} a minute, in bursts of up to \
                             {}. Try again in {retry} s.",
                            self.settings.calls_per_minute, self.settings.call_burst
                        ),
                    )
                    .with_detail(json!({"retry_after_seconds": retry})),
                ),
                Ok(()) => crate::tools::dispatch(self, tool, &args, peer, &ct, &mut note).await,
            }
        };

        let (decision, reason, message, mut refused) = match &outcome {
            crate::tools::Dispatched::Done(_) => ("ok", None, None, Vec::new()),
            crate::tools::Dispatched::Refused(r) => (
                r.reason.decision(),
                Some(r.reason.as_str()),
                Some(redact::redact_text(&r.message)),
                r.refused.clone(),
            ),
            crate::tools::Dispatched::Unknown => (
                "error",
                Some(Reason::UnknownTool.as_str()),
                Some("unknown tool".to_string()),
                Vec::new(),
            ),
        };
        refused.extend(note.refused.iter().cloned());
        // Gone already when the server stopped while this call was open, and the
        // shutdown wrote its line.
        let still_open = self
            .open_calls
            .lock()
            .map(|mut open| open.remove(&seq).is_some())
            .unwrap_or(true);
        if still_open {
            self.audit.write(json!({
                "ts": now_rfc3339(),
                "event": "call",
                "session": self.session,
                "seq": seq,
                "pid": std::process::id(),
                "client": client,
                "tool": untrusted::clean(tool, 64),
                "args": audit_args,
                "scope_sha256": self.scope.sha256,
                "decision": decision,
                "reason": reason,
                "message": message,
                "refused": refused,
                "confirmation": note.confirmation,
                "scan_id": note.scan_id,
                "result": note.result,
                "workbench": note.workbench,
                "duration_ms": started.elapsed().as_millis() as u64,
            }));
        }

        match outcome {
            crate::tools::Dispatched::Done(d) => {
                let text = untrusted::mirror(&d.summary, &d.value);
                CallOutput::Result(ToolResult {
                    structured: Some(d.value),
                    text,
                    is_error: false,
                })
            }
            crate::tools::Dispatched::Refused(r) => CallOutput::Result(refusal_result(&r)),
            crate::tools::Dispatched::Unknown => {
                CallOutput::InvalidParams(format!("unknown tool: {}", untrusted::clean(tool, 64)))
            }
        }
    }

    /// The line for a `tools/call` the protocol layer could not read: arguments that
    /// are not an object, or no tool name. It never reaches [`Mcp::call`], and is
    /// still a call.
    pub(crate) fn record_unreadable_call(&self, client: &str, params: Option<&Value>) {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let tool = params
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .map(|n| untrusted::clean(n, 64));
        let args = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        self.audit.write(json!({
            "ts": now_rfc3339(),
            "event": "call",
            "session": self.session,
            "seq": seq,
            "pid": std::process::id(),
            "client": untrusted::clean(client, 64),
            "tool": tool,
            "args": redact::audit_args(tool.as_deref().unwrap_or(""), &args),
            "scope_sha256": self.scope.sha256,
            "decision": Reason::InvalidArguments.decision(),
            "reason": Reason::InvalidArguments.as_str(),
            "message": "the tools/call parameters could not be read",
            "refused": [],
            "confirmation": null,
            "scan_id": null,
            "result": null,
            "duration_ms": 0,
        }));
    }

    pub(crate) fn audit_event(&self, event: &str, extra: Value) {
        let mut line = json!({
            "ts": now_rfc3339(),
            "event": event,
            "session": self.session,
            "pid": std::process::id(),
            "version": self.settings.version,
            "scope_path": self.scope.path.display().to_string(),
            "scope_sha256": self.scope.sha256,
            "scope_state": self.scope.state.as_str(),
        });
        if let (Some(o), Some(e)) = (line.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        self.audit.write(line);
    }

    // -----------------------------------------------------------------------
    // The guard

    fn no_scope(&self) -> Refusal {
        Refusal::new(
            Reason::NoScope,
            format!(
                "No scope: nothing was sent. The scope file {} is missing or lists no \
                 destinations. Only the person authorised to test the targets should write it \
                 (call get_scope for an example), and the MCP server has to be restarted to \
                 read it.",
                self.scope.path.display()
            ),
        )
    }

    fn address_refusal(&self, d: &Dest, e: AddrRefusal, at: &'static str) -> Refusal {
        let host = untrusted::clean(&d.host, 200);
        let refused = vec![RefusedDest {
            host: host.clone(),
            port: d.port,
            at,
        }];
        // The addresses are not named: which internal address a name points at is
        // worth something to whoever is mapping a network.
        let r = match e {
            AddrRefusal::Private => Refusal::new(
                Reason::PrivateAddress,
                format!(
                    "{host}:{} resolves only to private, loopback or link-local addresses, so \
                     nothing was sent. A name reaches such an address only when the scope file \
                     sets allow_private = true or lists the address itself.",
                    d.port
                ),
            ),
            AddrRefusal::Metadata => Refusal::new(
                Reason::MetadataAddress,
                format!(
                    "{host}:{} resolves to a cloud metadata address, so nothing was sent. That \
                     is refused even with allow_private unless the scope file lists the address \
                     itself.",
                    d.port
                ),
            ),
            AddrRefusal::Unresolvable(why) => Refusal::new(
                Reason::Unresolvable,
                format!(
                    "{host} could not be resolved ({}), so nothing was sent.",
                    untrusted::clean(&why, 200)
                ),
            ),
        };
        r.with_refused(refused)
    }

    /// Scope, address, intent, limits and audit health, in that order. Nothing is sent
    /// to a target or an engine before this returns `Ok`.
    pub(crate) async fn precheck(&self, req: TrafficRequest<'_>) -> Result<Pending, Refusal> {
        if !self.scope.has_entries() {
            return Err(self.no_scope());
        }
        let mut dests: Vec<Dest> = Vec::new();
        for d in req.dests {
            if !dests.iter().any(|x| x.host == d.host && x.port == d.port) {
                dests.push(d);
            }
        }

        // Every destination is checked, not just up to the first refusal, so the
        // answer names all of them and the model is not walked through one at a time.
        let detail = format!("crossfyre mcp {}", req.tool);
        let mut refused = Vec::new();
        for d in &dests {
            if !self.guard.admit(&d.host, d.port, req.point, Some(&detail)) {
                refused.push(RefusedDest {
                    host: untrusted::clean(&d.host, 200),
                    port: d.port,
                    at: "tool_boundary",
                });
            }
        }
        if !refused.is_empty() {
            let list: Vec<String> = refused
                .iter()
                .map(|r| format!("{}:{}", r.host, r.port))
                .collect();
            return Err(Refusal::new(
                Reason::OutOfScope,
                format!(
                    "Out of scope: {}. Nothing was sent. The scope file {} does not list {}. \
                     Only the person authorised to test a destination can add it, and the \
                     server reads the file only when it starts.",
                    list.join(", "),
                    self.scope.path.display(),
                    if list.len() == 1 { "it" } else { "them" }
                ),
            )
            .with_refused(refused));
        }

        let mut cleared = Vec::new();
        for d in dests {
            match guard::resolve_checked(
                &*self.resolver,
                &d,
                &self.scope.scope,
                self.scope.allow_private,
            )
            .await
            {
                Ok(addrs) => cleared.push(Cleared { dest: d, addrs }),
                Err(e) => return Err(self.address_refusal(&d, e, "address")),
            }
        }

        if req.intent == Intent::Write && !self.scope.allow_writes {
            return Err(Refusal::new(
                Reason::WritesNotAllowed,
                "This would send requests that can change or destroy data, and the scope file \
                 does not set allow_writes = true. Nothing was sent.",
            ));
        }
        if req.scan_start {
            self.check_scan_caps()?;
        }
        if req.pace {
            for c in &cleared {
                if let Err(retry) = self.pacer.wait(&c.dest.key()).await {
                    return Err(rate_limited_host(&c.dest, retry));
                }
            }
        }
        if !self.audit.healthy() {
            return Err(audit_down());
        }
        Ok(Pending { cleared })
    }

    /// The person's confirmation, after every other check has passed so nobody is
    /// asked about a destination that would have been refused anyway. A call cancelled
    /// while the question is open ends at once, and counts as nobody having answered.
    pub(crate) async fn confirm(
        &self,
        pending: Pending,
        peer: &dyn ClientPeer,
        write: Option<WriteAsk>,
        note: &mut CallNote,
        ct: &CancellationToken,
    ) -> Result<Clearance, Refusal> {
        let asked = async {
            let kind = match self.confirms.scope(peer, &self.scope).await {
                Ok(kind) => kind,
                Err(r) => {
                    let kind = if r.reason == Reason::Declined {
                        "declined"
                    } else {
                        "not_answered"
                    };
                    return (Some(kind), Err(r));
                }
            };
            if let Some(w) = write
                && let Err(r) = self.confirms.write(peer, w).await
            {
                return (Some(kind), Err(r));
            }
            (Some(kind), Ok(()))
        };
        let (kind, answer) = tokio::select! {
            out = asked => out,
            _ = ct.cancelled() => (None, Err(cancelled_before_sending())),
        };
        note.confirmation = kind;
        answer?;
        Ok(Clearance {
            cleared: pending.cleared,
            _seal: (),
        })
    }

    /// One redirect hop: scope, address and pace again, plus a confirmation when the
    /// hop carries a write somewhere new.
    pub(crate) async fn clear_hop(
        &self,
        dest: Dest,
        peer: &dyn ClientPeer,
        write: Option<WriteAsk>,
        ct: &CancellationToken,
    ) -> Result<Clearance, Refusal> {
        let refused = || {
            vec![RefusedDest {
                host: untrusted::clean(&dest.host, 200),
                port: dest.port,
                at: "redirect_hop",
            }]
        };
        if !self.guard.admit(
            &dest.host,
            dest.port,
            Point::Repeater,
            Some("crossfyre mcp redirect"),
        ) {
            return Err(Refusal::new(
                Reason::RedirectOutOfScope,
                "the redirect points outside the scope file",
            )
            .with_refused(refused()));
        }
        let addrs = guard::resolve_checked(
            &*self.resolver,
            &dest,
            &self.scope.scope,
            self.scope.allow_private,
        )
        .await
        .map_err(|e| self.address_refusal(&dest, e, "redirect_hop"))?;
        if let Err(retry) = self.pacer.wait(&dest.key()).await {
            return Err(rate_limited_host(&dest, retry));
        }
        if !self.audit.healthy() {
            return Err(audit_down());
        }
        if let Some(w) = write {
            tokio::select! {
                r = self.confirms.write(peer, w) => r?,
                _ = ct.cancelled() => return Err(cancelled_before_sending()),
            }
        }
        Ok(Clearance {
            cleared: vec![Cleared { dest, addrs }],
            _seal: (),
        })
    }

    pub(crate) fn check_scan_caps(&self) -> Result<(), Refusal> {
        let now = jobs::now_ms();
        let running = self.jobs.running_fresh(now);
        let max = self.scope.max_concurrent_scans as usize;
        if running >= max {
            return Err(Refusal::new(
                Reason::ScanLimit,
                format!(
                    "{running} scans are running and the scope file allows \
                     max_concurrent_scans = {max}. Wait for one to finish, or cancel one with \
                     cancel_scan."
                ),
            ));
        }
        let starts = self.jobs.starts_since("test_injection", now - 3_600_000);
        let max = self.scope.max_scan_starts_per_hour as usize;
        if starts >= max {
            return Err(Refusal::new(
                Reason::ScanLimit,
                format!(
                    "{starts} scans were started in the last hour and the scope file allows \
                     max_scan_starts_per_hour = {max}."
                ),
            )
            .with_detail(json!({"retry_after_seconds": 600})));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Running scans

    /// Stop a scan this process owns. `stopped` when the engine confirmed it,
    /// `requested` when it could not say so.
    pub(crate) async fn cancel_running(&self, job: &Arc<RunningJob>) -> &'static str {
        job.cancel_requested.store(true, Ordering::SeqCst);
        let sent = match job.writer.lock().await.as_mut() {
            Some(w) => w.send_cancel().await.is_ok(),
            None => false,
        };
        if job.cancellable && sent {
            let mut rx = job.snap.clone();
            let stopped = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if jobs::is_terminal(&rx.borrow_and_update().status) {
                        return true;
                    }
                    if rx.changed().await.is_err() {
                        return jobs::is_terminal(&rx.borrow().status);
                    }
                }
            })
            .await
            .unwrap_or(false);
            if stopped {
                return "stopped";
            }
        }
        // The engine cannot stop the operation, or did not confirm it had. Closing the
        // connection stops a current plessor at its next write; an older one keeps
        // going, which is why this is reported as `requested` and not `stopped`.
        job.writer.lock().await.take();
        let pump = job.pump.lock().ok().and_then(|mut p| p.take());
        if let Some(h) = pump {
            h.abort();
            let _ = h.await;
        }
        let meta = job.meta.lock().ok().map(|mut m| {
            if !jobs::is_terminal(&m.status) {
                m.finish(jobs::CANCELLED);
                m.cancel = Some("requested".into());
                m.note(
                    "cancellation was requested; this engine version keeps running until it \
                     finishes, so update it to stop scans on request"
                        .into(),
                );
            }
            m.clone()
        });
        if let Some(m) = meta {
            let _ = self.jobs.write_meta(&m);
        }
        if let Ok(mut r) = self.running.lock() {
            r.remove(&job.id);
        }
        "requested"
    }

    /// On the way out: write the line for every call still open, ask every running
    /// scan to stop, and record it as interrupted.
    pub(crate) async fn shutdown(&self) {
        let open: Vec<(u64, OpenCall)> = self
            .open_calls
            .lock()
            .map(|mut m| m.drain().collect())
            .unwrap_or_default();
        for (seq, c) in open {
            let scan_id = c.scan_id.lock().ok().and_then(|s| s.clone());
            self.audit.write(json!({
                "ts": now_rfc3339(),
                "event": "call",
                "session": self.session,
                "seq": seq,
                "pid": std::process::id(),
                "client": c.client,
                "tool": c.tool,
                "args": c.args,
                "scope_sha256": self.scope.sha256,
                "decision": "interrupted",
                "reason": null,
                "message": "the server stopped before the call returned",
                "refused": [],
                "confirmation": null,
                "scan_id": scan_id,
                "result": null,
                "duration_ms": c.started.elapsed().as_millis() as u64,
            }));
        }
        let jobs: Vec<Arc<RunningJob>> = self
            .running
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        for job in jobs {
            if let Some(w) = job.writer.lock().await.as_mut() {
                let _ = w.send_cancel().await;
            }
            let pump = job.pump.lock().ok().and_then(|mut p| p.take());
            if let Some(h) = pump {
                h.abort();
                let _ = h.await;
            }
            let meta = job.meta.lock().ok().map(|mut m| {
                if !jobs::is_terminal(&m.status) {
                    m.finish(jobs::INTERRUPTED);
                    m.error = Some("server stopped".into());
                }
                m.clone()
            });
            if let Some(m) = meta {
                let _ = self.jobs.write_meta(&m);
            }
            job.writer.lock().await.take();
        }
        if let Ok(mut r) = self.running.lock() {
            r.clear();
        }
    }
}

fn rate_limited_host(d: &Dest, retry: u64) -> Refusal {
    Refusal::new(
        Reason::RateLimited,
        format!(
            "{} is being sent requests as fast as the scope file's \
             requests_per_second_per_host allows. Try again in {retry} s.",
            untrusted::clean(&d.key(), 200)
        ),
    )
    .with_detail(json!({"retry_after_seconds": retry}))
}

fn cancelled_before_sending() -> Refusal {
    Refusal::new(
        Reason::Cancelled,
        "The call was cancelled before anything was sent.",
    )
}

fn audit_down() -> Refusal {
    Refusal::new(
        Reason::AuditUnavailable,
        "The audit log could not be written, so no traffic is sent until the MCP server is \
         restarted with a writable audit log. Read-only tools still work.",
    )
}

pub(crate) fn refusal_result(r: &Refusal) -> ToolResult {
    let mut j = json!({"reason": r.reason.as_str(), "refused": r.refused});
    if let (Some(o), Some(Value::Object(d))) = (j.as_object_mut(), &r.detail) {
        for (k, v) in d {
            o.insert(k.clone(), v.clone());
        }
    }
    let text = if j.get("target_data").is_some() {
        format!("{}\n{}\n{}", r.message, untrusted::UNTRUSTED_SENTENCE, j)
    } else {
        format!("{}\n{}", r.message, j)
    };
    ToolResult {
        structured: None,
        text,
        is_error: true,
    }
}
