#![allow(dead_code, unused_imports, unused_variables, unused_mut)]
use clap::Subcommand;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Arc, OnceLock};
use sysinfo::System;
use tokio::sync::Semaphore;

pub mod auth;
pub mod cfx_runtime;
pub mod creds;
mod egress;
pub mod executor;
pub mod oast;
mod ops;
pub mod toolchain;

use toolchain::sudo_user::chown_to_invoking_user;

/// Per-workflow metrics so we can log a real-time snapshot ("2 in flight,
/// 1500 done") instead of the misleading cumulative "Processed N" line that
/// makes it look like all ops ran simultaneously.
pub struct WorkflowMetrics {
    in_flight: std::sync::atomic::AtomicUsize,
    completed: std::sync::atomic::AtomicUsize,
    errored: std::sync::atomic::AtomicUsize,
}

static WORKFLOW_METRICS: OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, Arc<WorkflowMetrics>>>,
> = OnceLock::new();

pub fn workflow_metrics(workflow_id: &str) -> Arc<WorkflowMetrics> {
    let map =
        WORKFLOW_METRICS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut m = map.lock().unwrap();
    m.entry(workflow_id.to_string())
        .or_insert_with(|| {
            Arc::new(WorkflowMetrics {
                in_flight: 0.into(),
                completed: 0.into(),
                errored: 0.into(),
            })
        })
        .clone()
}

/// RAII guard that bumps `in_flight` while alive and finalises completed/
/// errored on drop. Lets us track concurrency through the actual permit
/// lifetime without manual decrement at every return path.
pub struct InFlightGuard {
    metrics: Arc<WorkflowMetrics>,
    errored: bool,
}
impl InFlightGuard {
    fn start(metrics: Arc<WorkflowMetrics>) -> Self {
        metrics
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            metrics,
            errored: false,
        }
    }
    fn fail(&mut self) {
        self.errored = true;
    }
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.metrics
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if self.errored {
            self.metrics
                .errored
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.metrics
                .completed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Workflows the operator has halted from the dashboard. Daemon spawn-tasks
/// check this set after waking from the semaphore but before doing the work,
/// so semaphore-queued probes don't fire after a halt.
static CANCELLED_WORKFLOWS: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    OnceLock::new();
pub fn cancelled_workflows() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    CANCELLED_WORKFLOWS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}
pub fn is_workflow_cancelled(id: &str) -> bool {
    cancelled_workflows()
        .lock()
        .map(|s| s.contains(id))
        .unwrap_or(false)
}
pub fn cancel_workflow(id: &str) {
    if let Ok(mut s) = cancelled_workflows().lock() {
        s.insert(id.to_string());
    }
    // Drop this workflow's per-target pace state so the map doesn't accumulate.
    if let Some(map) = WORKFLOW_TARGET_PACE.get()
        && let Ok(mut m) = map.lock()
    {
        m.retain(|(wf, _host), _| wf != id);
    }
}
pub fn resume_workflow(id: &str) {
    if let Ok(mut s) = cancelled_workflows().lock() {
        s.remove(id);
    }
}

/// Heuristic: is a discovered content-discovery URL worth recursing into?
/// Recursive discovery re-runs the wordlist inside found directories, so we
/// only recurse into things that look like directories: redirects (commonly
/// dir -> dir/), paths ending in '/', or an extension-less final path segment
/// (e.g. /admin, /api). Files like /robots.txt are skipped.
fn looks_like_directory(found_url: &str, code: i64) -> bool {
    let path = found_url.split(['?', '#']).next().unwrap_or(found_url);
    if path.ends_with('/') {
        return true;
    }
    if matches!(code, 301 | 302 | 307 | 308) {
        return true;
    }
    let last = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    !last.is_empty() && !last.contains('.')
}

/// Operations this node has already COMPLETED, so a re-dispatch of the same op
/// (e.g. after pause/resume, which re-sprays still-pending ops and can overlap
/// with tasks still draining from the first dispatch) is skipped instead of
/// probing the target a second time. Only completed ops are recorded, so an op
/// that was dropped mid-flight by a pause is still free to re-run on resume.
static DONE_OPS: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();
fn done_ops() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    DONE_OPS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}
pub fn op_is_done(op_id: &str) -> bool {
    done_ops()
        .lock()
        .map(|s| s.contains(op_id))
        .unwrap_or(false)
}
pub fn mark_op_done(op_id: &str) {
    if let Ok(mut s) = done_ops().lock() {
        s.insert(op_id.to_string());
    }
}

/// Per-workflow semaphore registry. Each workflow is sized at the user's
/// configured `tasks` value (from step 5 of the wizard) - so a distributed port scan
/// with tasks=2 keeps exactly 2 probes in flight at any moment, picking up
/// the next op only after one finishes or fails. The semaphore is fair-FIFO
/// so messages drain in order.
///
/// Hard ceiling: pulse can't handle more than ~100 concurrent probes anyway,
/// so we clamp on the upper end regardless of what the user typed.
static WORKFLOW_SEMAPHORES: OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, Arc<Semaphore>>>,
> = OnceLock::new();

pub fn workflow_semaphore(workflow_id: &str, tasks: usize) -> Arc<Semaphore> {
    let map =
        WORKFLOW_SEMAPHORES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut m = map.lock().unwrap();
    m.entry(workflow_id.to_string())
        .or_insert_with(|| {
            let n = tasks.clamp(1, 200);
            Arc::new(Semaphore::new(n))
        })
        .clone()
}

// ---------------------------------------------------------------------------
// Shared per-target pace.
//
// This process sees every content-discovery chunk for a given target host, so
// it holds ONE persistent, health-driven pace per (workflow, host) instead of
// letting each chunk's controller reset to a cold start. The pace is fed by the
// result/error codes the engine streams back and outputs an inter-probe delay
// every chunk against that host shares: under stress the delay grows so the
// chunks slow down together, and as the target recovers it shrinks. The tuning
// of this arrangement lives in the private `adaptive` crate.
// ---------------------------------------------------------------------------
pub struct TargetPace {
    window: std::sync::Mutex<adaptive::HealthWindow>,
    controller: std::sync::Mutex<adaptive::RateController>,
    /// Current coordinated inter-probe delay (ms) for this target.
    delay_ms: std::sync::atomic::AtomicU64,
    /// Current coordinated per-chunk concurrency. Backs off under stress so the
    /// combined volume against a target stays in a healthy range instead of
    /// being pushed into the state where results silently get dropped.
    tasks: std::sync::atomic::AtomicU64,
    /// Result events observed since the last controller tick (tick cadence).
    since_tick: std::sync::atomic::AtomicU64,
}

impl TargetPace {
    pub fn delay(&self) -> u64 {
        self.delay_ms.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn tasks(&self) -> u64 {
        self.tasks.load(std::sync::atomic::Ordering::Relaxed).max(1)
    }

    /// Record one probe outcome and, every so often, advance the controller and
    /// republish the delay + concurrency. Latency isn't available from the mach
    /// stream, so health is driven by response codes only.
    pub fn observe(&self, class: adaptive::ProbeClass) {
        use std::sync::atomic::Ordering;
        {
            let mut w = self.window.lock().unwrap();
            w.record(class, 0);
        }
        let n = self.since_tick.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= adaptive::coord::TICK_EVERY {
            self.since_tick.store(0, Ordering::Relaxed);
            let stats = { self.window.lock().unwrap().stats() };
            let dir = { self.controller.lock().unwrap().tick(&stats) };
            self.delay_ms.store(dir.delay_ms, Ordering::Relaxed);
            self.tasks.store(dir.concurrency as u64, Ordering::Relaxed);
        }
    }
}

/// `(workflow_id, host)` -> the pace controller shared by every task hitting
/// that host in that workflow.
type TargetPaceMap = std::sync::Mutex<std::collections::HashMap<(String, String), Arc<TargetPace>>>;

static WORKFLOW_TARGET_PACE: OnceLock<TargetPaceMap> = OnceLock::new();

/// Get (or create) the coordinated pace for one `(workflow, host)`. `posture`
/// and `base_delay` seed a fresh controller; existing paces are reused so
/// adaptation persists across all of a workflow's chunks against that host.
pub fn target_pace(
    workflow_id: &str,
    host: &str,
    posture: &str,
    base_delay: u64,
    max_tasks: u64,
) -> Arc<TargetPace> {
    let map = WORKFLOW_TARGET_PACE
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut m = map.lock().unwrap();
    m.entry((workflow_id.to_string(), host.to_string()))
        .or_insert_with(|| {
            let p = adaptive::Posture::from_str_lenient(posture);
            let mt = max_tasks.clamp(1, 200) as u32;
            // Envelope + window sizing come from the private `adaptive` crate:
            // concurrency is the primary lever, delay the secondary.
            let caps = adaptive::Caps::for_target(mt);
            Arc::new(TargetPace {
                window: std::sync::Mutex::new(adaptive::HealthWindow::for_target()),
                controller: std::sync::Mutex::new(adaptive::RateController::new_optimistic(
                    p, caps, base_delay,
                )),
                delay_ms: std::sync::atomic::AtomicU64::new(base_delay),
                tasks: std::sync::atomic::AtomicU64::new(mt as u64),
                since_tick: std::sync::atomic::AtomicU64::new(0),
            })
        })
        .clone()
}

/// Classify a mach stream event into a health class from its status verdict and
/// HTTP code. `status` is mach's finding verdict ("found" | "not_found" | "error").
pub fn classify_event(status: &str, code: i64) -> adaptive::ProbeClass {
    use adaptive::ProbeClass;
    if status == "error" {
        return ProbeClass::ConnError;
    }
    match code {
        429 => ProbeClass::RateLimited,
        500..=599 => ProbeClass::ServerError,
        _ if status == "found" => ProbeClass::Success,
        _ => ProbeClass::NotFound,
    }
}

/// Host portion of a target URL, for keying per-target state.
pub fn target_host(url: &str) -> String {
    let after = url.split("://").nth(1).unwrap_or(url);
    let hostport = after.split('/').next().unwrap_or(after);
    hostport.rsplit('@').next().unwrap_or(hostport).to_string()
}

/// Context an operation needs from the node run loop: the NATS publisher and
/// its subjects, node identity, and the HTTP client for claim/completion
/// callbacks. Bundled so both dispatch arms
/// hand an op to run_operation() the same way.
struct OpCtx {
    pub_clone: async_nats::Client,
    status_subj: String,
    result_subj: String,
    node_id: String,
    http: reqwest::Client,
    api_url: String,
    // This node's own api_key, used to authorize credential resolution against
    // the control plane (POST /api/v1/creds/resolve).
    api_key: String,
}

/// Execute one dispatched operation to completion: gate on the per-workflow
/// concurrency permit, claim (unless pre-claimed), run the engine, stream
/// results, and publish operation_completed. The body is moved verbatim from
/// the run loop's `Some("operation")` arm (kept at its original indentation)
/// so the pull-queue path can reuse it unchanged.
async fn run_operation(cmd: serde_json::Value, ctx: OpCtx) {
    let op_id = cmd["operation_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let workflow_id = cmd["workflow_id"].as_str().unwrap_or("").to_string();
    let op_type = cmd["op_type"].as_str().unwrap_or("").to_string();
    let consumption = cmd["consumption"].as_str().unwrap_or("single").to_string();
    let pre_claimed = cmd["pre_claimed"].as_bool().unwrap_or(false);
    let data = cmd["data"].clone();
    let OpCtx {
        pub_clone,
        status_subj,
        result_subj,
        node_id,
        http,
        api_url,
        api_key,
    } = ctx;

    // For distributed port-scan ops, gate on the workflow's
    // per-workflow concurrency permit BEFORE claiming.
    // This keeps unclaimed ops available to other
    // nodes if this one is at capacity, and ensures
    // we genuinely run only `tasks` probes at a time
    // - the next op claims as soon as one finishes.
    let _ws_permit = if op_type == "network-scan-ds" || op_type == "content-discovery-ds" {
        // Port scans use `tasks`; content discovery uses
        // `threads`. Either way it's the workflow-level
        // concurrency the user picked in the wizard.
        let n = data["tasks"]
            .as_i64()
            .or_else(|| data["threads"].as_i64())
            .unwrap_or(10)
            .max(1) as usize;
        let sem = workflow_semaphore(&workflow_id, n);
        Some(sem.acquire_owned().await.ok())
    } else {
        None
    };

    // The operator may have halted this workflow
    // while we were waiting on the semaphore. Drop
    // the permit and exit without doing work.
    if !workflow_id.is_empty() && is_workflow_cancelled(&workflow_id) {
        return;
    }

    // Already completed this op (a pause/resume or a
    // re-dispatch can deliver an op
    // whose first copy already ran). Don't probe twice -
    // but DO re-publish the completion ack, because a
    // re-dispatch usually means the original ack was
    // lost. Silently returning is what
    // leaves a scan parked at 9x% on lost acks.
    if op_is_done(&op_id) {
        let reack = serde_json::json!({
            "type": "operation_completed",
            "operation_id": op_id,
            "workflow_id": workflow_id,
            "found_count": 0,
            "node_id": node_id,
        });
        let _ = pub_clone
            .publish(status_subj.clone(), reack.to_string().into())
            .await;
        return;
    }

    // Track in-flight count through the rest of the
    // closure. Print a stat line on every claim so
    // the operator can see the throttle in action -
    // each line tells them which op just started
    // and how many are now active vs done.
    let _flight = if !workflow_id.is_empty() {
        let m = workflow_metrics(&workflow_id);
        let g = InFlightGuard::start(m.clone());
        use std::sync::atomic::Ordering;
        let ifl = m.in_flight.load(Ordering::Relaxed);
        let done = m.completed.load(Ordering::Relaxed);
        let fail = m.errored.load(Ordering::Relaxed);
        let short = workflow_id.get(..8).unwrap_or(&workflow_id);
        println!("[scan {short}] claim in_flight={ifl} done={done} failed={fail}");
        Some(g)
    } else {
        None
    };

    // For single-consumption ops, try to claim
    // it first - unless the controller marked it
    // pre_claimed (1-node-assigned ops have no
    // race to win, so we skip the HTTP round-trip).
    if consumption == "single" && !pre_claimed {
        let claim_res = http
            .post(format!("{api_url}/api/v1/claim-operation"))
            .json(&serde_json::json!({
                "operation_id": op_id,
                "node_id": node_id,
                // Authenticates the claim. Every other node-facing route already
                // presents this; without it any caller past the authority gate
                // could claim another tenant's queued operations.
                "api_key": api_key,
            }))
            .send()
            .await;

        // Losing the race and failing to ask are NOT the same thing, and treating
        // them the same is what made a broken claim invisible.
        //
        // Both used to collapse into `false`, and the op was then dropped without
        // a word. Losing the race is normal: another node runs it. A 401, a 500 or
        // a dead socket means NOBODY runs it, and because the message is acked
        // once this function returns, the operation vanished: `claimed_by` stayed
        // null, no result ever arrived, and the workflow sat at "running" forever
        // with nothing anywhere saying why. Single-node ops are `pre_claimed` and
        // never come through here, so the whole failure mode hid in the one path
        // that only multi-node scans exercise.
        enum ClaimOutcome {
            Won,
            Lost,
            Failed(String),
        }
        let outcome = match claim_res {
            Ok(res) if res.status().is_success() => {
                let body: serde_json::Value = res.json().await.unwrap_or_default();
                if body["data"]["claimed"].as_bool().unwrap_or(false) {
                    ClaimOutcome::Won
                } else {
                    ClaimOutcome::Lost
                }
            }
            Ok(res) => {
                let code = res.status();
                let body = res.text().await.unwrap_or_default();
                ClaimOutcome::Failed(format!("HTTP {code}: {}", body.trim()))
            }
            Err(e) => ClaimOutcome::Failed(e.to_string()),
        };

        use std::sync::atomic::Ordering;
        match outcome {
            ClaimOutcome::Won => {
                CLAIM_OK.fetch_add(1, Ordering::Relaxed);
            }
            ClaimOutcome::Lost => {
                // Someone else is running it. Nothing to say and nothing to do.
                CLAIM_MISS.fetch_add(1, Ordering::Relaxed);
                return;
            }
            ClaimOutcome::Failed(why) => {
                CLAIM_MISS.fetch_add(1, Ordering::Relaxed);
                let short = workflow_id.get(..8).unwrap_or(&workflow_id);
                eprintln!(
                    "[scan {short}] claim FAILED for op {op_id}: {why}. \
                     This node cannot run it and no other node will be told to; \
                     reporting it so the workflow does not wait forever."
                );
                // Tell the controller. Without this the op is simply gone: the
                // message is acked on return, so nothing redelivers it and
                // nothing times it out. Reporting a completion with no findings
                // lets the workflow finish instead of hanging, and the log line
                // above says why it found nothing.
                let failed = serde_json::json!({
                    "type": "operation_completed",
                    "operation_id": op_id,
                    "workflow_id": workflow_id,
                    "found_count": 0,
                    "node_id": node_id,
                    "error": format!("claim failed: {why}"),
                });
                let _ = pub_clone
                    .publish(status_subj.clone(), failed.to_string().into())
                    .await;
                return;
            }
        }
    } else if pre_claimed {
        use std::sync::atomic::Ordering;
        CLAIM_OK.fetch_add(1, Ordering::Relaxed);
    }
    let env = ops::OpEnv {
        op_id,
        workflow_id,
        data,
        node_id,
        pub_clone,
        status_subj,
        result_subj,
        http,
        api_url,
        api_key,
    };
    if op_type.starts_with("content-discovery-") {
        ops::content_discovery::handle(env).await;
    } else if op_type.starts_with("web-crawl-") {
        ops::web_crawl::handle(env).await;
    } else if op_type.starts_with("subdomain-enum-") {
        ops::subdomain_enum::handle(env).await;
    } else if op_type.starts_with("takeover-") {
        ops::takeover::handle(env).await;
    } else if op_type.starts_with("origin-discovery-") {
        ops::origin_discovery::handle(env).await;
    } else if op_type.starts_with("network-scan-") {
        ops::network_scan::handle(env).await;
    } else if op_type.starts_with("vuln-scan-") {
        ops::vuln_scan::handle(env).await;
    } else if op_type.starts_with("service-enum-") {
        ops::service_enum::handle(env).await;
    } else {
        println!("[op] Unknown op_type: {op_type}");
    }
}

/// Counts claim outcomes so we can log progress summaries instead of per-op spam.
static CLAIM_OK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CLAIM_MISS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Subcommand, Debug)]
pub enum DbCommands {
    /// Start and recreate the database container
    Up,
    /// Stop and remove the database container
    Down,
    /// Start the database container
    Start,
    /// Stop the database container
    Stop,
    /// Restart the database container
    Restart,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    api_key: String,
    node_id: String,
    /// Control plane API URL (set during init)
    pub api_url: String,
    /// NATS server URL (returned by authorize-node)
    #[serde(default = "default_nats_url")]
    nats_url: String,
    nats_nkey_seed: Option<String>,
    nats_user_jwt: Option<String>,
    /// Extensions installed on this node (e.g. ["mach", "voyage"])
    #[serde(default)]
    extensions: Vec<String>,
    /// Deploy-time network identity (tunnel selection + OPSEC toggles).
    /// Stored verbatim from the dashboard so we can re-read it across runs.
    #[serde(default)]
    network: Option<NetworkConfig>,
    /// Whether this node will run commands the control plane sends it:
    /// `shell_exec` (`sh -c`) and `.cfx` extension code.
    ///
    /// Off unless the operator turns it on. Both are authorized server-side
    /// before dispatch, but that is a decision made entirely on the control
    /// plane: a node that never opts in cannot be turned into a shell by
    /// anything that reaches the control plane, including stolen broker
    /// credentials. The node runs as root on a default install, so this is the
    /// difference between compromising the platform and compromising the host.
    ///
    /// Set `remote_exec = true` in `nodes.d/<node-id>.toml` to allow it.
    #[serde(default)]
    pub remote_exec: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NetworkConfig {
    /// Egress profile identifier (opaque here; interpreted by the egress layer).
    #[serde(default)]
    kind: String,
    /// Local path the .ovpn / .conf was written to (set during --init).
    #[serde(default)]
    config_path: Option<String>,
    /// Original filename uploaded by the operator.
    #[serde(default)]
    config_filename: Option<String>,
    /// True if the operator marked the config as needing username/password.
    #[serde(default)]
    needs_creds: bool,
    /// OPSEC flags (best-effort hints for the daemon).
    #[serde(default)]
    kill_switch: bool,
    #[serde(default)]
    dns_over_tunnel: bool,
    #[serde(default)]
    lab_only_routing: bool,
    #[serde(default)]
    wg_endpoint: Option<String>,
    #[serde(default)]
    wg_public_key: Option<String>,
    /// BYO residential / mobile egress proxy URL (`http(s)://` or `socks5://`,
    /// with optional `user:pass@`). When set, engine clients route through it via
    /// `CROSSFYRE_EGRESS_PROXY`. Orthogonal to the tunnel `kind`: a rotating
    /// residential provider is one gateway URL, no netns tunnel needed.
    #[serde(default)]
    proxy: Option<String>,
}

pub fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

/// Resolve the data directory for this invocation. Order of preference:
///   1. `--data-dir <PATH>` (if provided)
///   2. `$SUDO_USER`'s home + `.config/crossfyre`  - keeps the user's data
///      visible when they `sudo crossfyre node up`
///   3. `dirs::config_dir()/crossfyre`
pub fn resolve_data_dir(
    cli_arg: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if let Some(p) = cli_arg {
        return Ok(p.to_path_buf());
    }
    if let Ok(sudo_user) = std::env::var("SUDO_USER")
        && !sudo_user.is_empty()
        && sudo_user != "root"
    {
        // Best effort - fall back to dirs::config_dir() if the home directory
        // can't be resolved (e.g. unusual NSS setup).
        if let Some(home) = home_for_user(&sudo_user) {
            let mut p = home;
            p.push(".config");
            p.push("crossfyre");
            return Ok(p);
        }
    }
    let mut p = dirs::config_dir().ok_or("Could not resolve config directory")?;
    p.push("crossfyre");
    Ok(p)
}

#[cfg(unix)]
pub fn home_for_user(name: &str) -> Option<std::path::PathBuf> {
    use std::ffi::CString;
    let c = CString::new(name).ok()?;
    unsafe {
        let pwd = libc::getpwnam(c.as_ptr());
        if pwd.is_null() {
            return None;
        }
        let dir_ptr = (*pwd).pw_dir;
        if dir_ptr.is_null() {
            return None;
        }
        let cstr = std::ffi::CStr::from_ptr(dir_ptr);
        Some(std::path::PathBuf::from(
            cstr.to_string_lossy().into_owned(),
        ))
    }
}
#[cfg(not(unix))]
pub fn home_for_user(_name: &str) -> Option<std::path::PathBuf> {
    None
}

/// When running under `sudo`, `chown` files we just wrote back to the
/// invoking user so they aren't suddenly owned by root. Best effort - log
/// and continue on failure so writes themselves don't appear to fail.
/// (Thin wrappers around the toolchain helper, kept for readability at the
/// call sites: one name for a single path, one for a tree.)
pub fn chown_to_sudo_user(path: &std::path::Path) {
    chown_to_invoking_user(path);
}

/// Recursively chown every file under `dir` back to the invoking user.
pub fn chown_tree_to_sudo_user(dir: &std::path::Path) {
    chown_to_invoking_user(dir);
}

/// Print a security-posture banner so the operator understands the privilege
/// model: crossfyre *itself* is meant to run as a regular user, but bringing
/// up an isolated network namespace + VPN tunnel needs the kernel's
/// CAP_NET_ADMIN. We solve that by accepting `sudo` invocations and
/// dropping back to $SUDO_USER for anything user-state (configs, the
/// toolchain database, extensions). Plain-root invocations get a soft
/// warning - things still work, but on-disk artifacts end up owned by root.
pub fn print_privilege_banner(needs_root: bool) {
    let euid = unsafe { libc::geteuid() };
    let sudo_user = std::env::var("SUDO_USER")
        .ok()
        .filter(|s| !s.is_empty() && s != "root");
    if euid == 0 && sudo_user.is_none() {
        eprintln!(
            "[security] WARNING: launched as plain root. Re-run with `sudo crossfyre ...` from your user shell."
        );
    } else if euid != 0 && needs_root {
        eprintln!("Please re-run with sudo:");
        eprintln!("  sudo crossfyre node up");
        std::process::exit(1);
    }
}

/// On-disk locations for a single registered node. Several nodes can share
/// one crossfyre config root (`base`) - they're disambiguated by node-id:
///
///   <base>/nodes.d/<node-id>.toml       <- config (what `--init` writes)
///   <base>/nodes.d/<node-id>.pid        <- daemon PID lock
///   <base>/nodes.d/<node-id>.network/   <- egress config + logs
///
/// `base` itself is the value resolved from `--data-dir` / `$SUDO_USER`.
pub struct NodePaths {
    base: std::path::PathBuf,
    node_id: String,
    pub config: std::path::PathBuf,
    pub pid: std::path::PathBuf,
    network_dir: std::path::PathBuf,
}

impl NodePaths {
    pub fn new(base: &std::path::Path, node_id: &str) -> Self {
        let nodes_dir = nodes_dir(base);
        Self {
            base: base.to_path_buf(),
            node_id: node_id.to_string(),
            config: nodes_dir.join(format!("{node_id}.toml")),
            pid: nodes_dir.join(format!("{node_id}.pid")),
            network_dir: nodes_dir.join(format!("{node_id}.network")),
        }
    }
}

/// The directory that holds one `.toml` per registered node.
pub fn nodes_dir(base: &std::path::Path) -> std::path::PathBuf {
    base.join("nodes.d")
}

/// Write a file that holds a credential, owner-readable only.
///
/// The node config carries `nats_nkey_seed`, `nats_user_jwt` and `api_key`, so it
/// needs the treatment `auth.toml` already gets in [`crate::auth`]. It used to be
/// written at the process umask, which in practice meant 0644: three secrets
/// readable by every local account, next to an `auth.toml` that was correctly
/// 0600.
///
/// The permissions are set before the bytes land where possible, so there is no
/// window in which the file exists with the secret in it and the wider mode.
pub fn write_secret_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        // `mode` only applies when the file is created, so an existing file keeps
        // whatever it had. Tighten it explicitly.
        let _ = fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
}

/// Tighten a credential file that an earlier build left world-readable.
///
/// Installs created before [`write_secret_file`] existed still have 0644 configs
/// on disk, and rewriting the file is not part of a normal start. This runs on
/// load so those installs are repaired without operator action, and says so once
/// rather than silently, because the secrets in it should be treated as having
/// been exposed.
#[cfg(unix)]
pub fn repair_secret_file_mode(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = fs::metadata(path) else { return };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 && fs::set_permissions(path, fs::Permissions::from_mode(0o600)).is_ok() {
        eprintln!(
            "[security] {} was mode {:o} (group/other readable) and holds node \
             credentials; tightened to 600. Rotate this node's key if the host \
             has other accounts: `crossfyre node revoke`.",
            path.display(),
            mode
        );
    }
}

#[cfg(not(unix))]
pub fn repair_secret_file_mode(_path: &std::path::Path) {}

/// Validate the `~/.config/crossfyre` layout before booting: the config root
/// must exist and contain a `nodes.d` directory. Returns the list of
/// registered node-ids (one per `nodes.d/<id>.toml`), sorted for stable
/// ordering. Files that don't parse as a node config are skipped with a
/// warning so one corrupt node doesn't block the rest from booting.
pub fn discover_nodes(base: &std::path::Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if !base.exists() {
        return Err(format!(
            "config root {base:?} does not exist - run `crossfyre node init` first"
        )
        .into());
    }
    let nd = nodes_dir(base);
    if !nd.is_dir() {
        return Err(
            format!("{nd:?} is missing - run `crossfyre node init` to register a node").into(),
        );
    }

    let mut ids = Vec::new();
    for entry in fs::read_dir(&nd)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        // Validate it parses as a node config so `--boot` doesn't spawn a
        // daemon that's just going to die on a malformed file.
        match fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|s| toml::from_str::<Config>(&s).map_err(|e| e.to_string()))
        {
            Ok(_) => ids.push(stem.to_string()),
            Err(e) => eprintln!("[boot] WARNING: skipping {path:?} - not a valid node config: {e}"),
        }
    }
    ids.sort();
    Ok(ids)
}

/// One-time migration for hosts initialized before the `nodes.d` layout:
/// move a legacy `<base>/config.toml` to `<base>/nodes.d/<node-id>.toml`
/// (and its `network/` dir to `<node-id>.network/`). Best-effort and silent
/// when there's nothing to migrate.
pub fn migrate_legacy_config(base: &std::path::Path) {
    let legacy = base.join("config.toml");
    if !legacy.is_file() {
        return;
    }
    let Ok(text) = fs::read_to_string(&legacy) else {
        return;
    };
    let Ok(cfg) = toml::from_str::<Config>(&text) else {
        return;
    };
    let paths = NodePaths::new(base, &cfg.node_id);
    if paths.config.exists() {
        return; // already migrated
    }
    if let Err(e) = fs::create_dir_all(nodes_dir(base)) {
        eprintln!("[migrate] Could not create nodes.d: {e}");
        return;
    }
    if fs::rename(&legacy, &paths.config).is_ok() {
        println!("[migrate] Moved legacy config.toml -> {:?}", paths.config);
        let legacy_net = base.join("network");
        if legacy_net.is_dir() && !paths.network_dir.exists() {
            let _ = fs::rename(&legacy_net, &paths.network_dir);
        }
        chown_to_sudo_user(&paths.config);
        chown_tree_to_sudo_user(&nodes_dir(base));
    }
}

/// How often `up` re-scans `nodes.d` to pick up nodes registered (or
/// removed) after it started. 2s keeps a freshly `--init`'d node coming
/// online almost immediately without busy-spinning on the filesystem.
const BOOT_RESCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Spawn one `crossfyre node daemon <node-id>` child pinned to `base`.
pub fn spawn_node_daemon(
    exe: &std::path::Path,
    base: &std::path::Path,
    id: &str,
    force: bool,
) -> Option<std::process::Child> {
    // `exe` is the `node` worker binary; its daemon subcommand is top-level.
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon").arg(id);
    if force {
        cmd.arg("--force");
    }
    // Pin children to the same config root so a custom --data-dir propagates
    // (resolve_data_dir would otherwise re-derive it).
    cmd.arg("--data-dir").arg(base);
    match cmd.spawn() {
        Ok(child) => {
            println!("[boot] Started node {} (pid {})", id, child.id());
            Some(child)
        }
        Err(e) => {
            eprintln!("[boot] FAIL Could not start node {id}: {e}");
            None
        }
    }
}

/// Validate the crossfyre config layout, then keep every registered node
/// online. `up` re-scans `nodes.d` every couple of seconds, so a node
/// registered in another terminal (`crossfyre node init`) is picked up
/// and started without restarting the supervisor - and a node whose `.toml`
/// is removed is stopped. A SIGINT/SIGTERM to the supervisor is forwarded to
/// every child so the whole fleet tears down (tunnels and isolation) together.
pub async fn run_boot(
    force: bool,
    base: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Booting Crossfyre nodes from {base:?}...");

    // Pull a pre-nodes.d single-node install into the new layout if present.
    migrate_legacy_config(base);

    let node_ids = discover_nodes(base)?;
    if node_ids.is_empty() {
        eprintln!(
            "No nodes registered under {:?}.\nRegister one with: crossfyre node init",
            nodes_dir(base)
        );
        std::process::exit(1);
    }

    println!("Found {} node(s): {}", node_ids.len(), node_ids.join(", "));

    let exe = std::env::current_exe()?;
    // node-id -> running daemon child.
    let mut children: std::collections::HashMap<String, std::process::Child> =
        std::collections::HashMap::new();
    // Nodes whose daemon exited on its own (crashed / evicted / duplicate
    // already running). We hold these back from an immediate respawn so a
    // node that fails to start doesn't hot-loop. The hold is cleared once the
    // node's `.toml` disappears, so removing+re-adding it (or restarting boot)
    // gives it a fresh attempt.
    let mut dead: std::collections::HashSet<String> = std::collections::HashSet::new();

    for id in &node_ids {
        if let Some(child) = spawn_node_daemon(&exe, base, id, force) {
            children.insert(id.clone(), child);
        }
    }

    if children.is_empty() {
        return Err("no node daemons could be started".into());
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    let mut rescan = tokio::time::interval(BOOT_RESCAN_INTERVAL);
    rescan.tick().await; // consume the immediate first tick

    println!(
        "[boot] Supervising {} daemon(s); watching {:?} for changes. Press Ctrl+C to stop all.",
        children.len(),
        nodes_dir(base)
    );

    // Supervise loop: reconcile running children against nodes.d on every
    // tick until a shutdown signal arrives.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { println!("\n[boot] Ctrl+C received - stopping all nodes..."); break; }
            _ = sigterm.recv() => { println!("\n[boot] SIGTERM received - stopping all nodes..."); break; }
            _ = rescan.tick() => {
                // 1. Reap children that exited on their own; park them in
                //    `dead` so we don't respawn a flapping node every tick.
                let exited: Vec<String> = children.iter_mut()
                    .filter_map(|(id, child)| match child.try_wait() {
                        Ok(Some(status)) => {
                            println!("[boot] Node {id} exited ({status}). Holding until its config changes.");
                            Some(id.clone())
                        }
                        _ => None,
                    })
                    .collect();
                for id in exited {
                    children.remove(&id);
                    dead.insert(id);
                }

                // 2. Re-scan nodes.d. A read error (e.g. nodes.d briefly gone)
                //    is transient - skip this tick rather than tearing down.
                let current = match discover_nodes(base) {
                    Ok(ids) => ids,
                    Err(e) => { eprintln!("[boot] re-scan skipped: {e}"); continue; }
                };
                let current_set: std::collections::HashSet<&String> = current.iter().collect();

                // 3. Start nodes that appeared and aren't already running/held.
                for id in &current {
                    if !children.contains_key(id) && !dead.contains(id) {
                        println!("[boot] New node detected: {id}");
                        if let Some(child) = spawn_node_daemon(&exe, base, id, force) {
                            children.insert(id.clone(), child);
                        }
                    }
                }

                // 4. Stop nodes whose `.toml` was removed, and clear any hold
                //    so a later re-add gets a fresh start.
                let removed: Vec<String> = children.keys()
                    .filter(|id| !current_set.contains(*id))
                    .cloned()
                    .collect();
                for id in removed {
                    if let Some(mut child) = children.remove(&id) {
                        println!("[boot] Node {} de-registered (config removed) - stopping (pid {}).", id, child.id());
                        #[cfg(unix)]
                        unsafe { libc::kill(child.id() as i32, libc::SIGTERM); }
                        // Reap without blocking the loop; the kernel will
                        // deliver SIGTERM and the daemon tears its tunnel down.
                        let _ = child.try_wait();
                    }
                }
                dead.retain(|id| current_set.contains(id));
            }
        }
    }

    // Shutdown: forward SIGTERM to every child so their egress teardown
    // (Drop guards) runs, give the fleet a moment, then hard-reap.
    for (id, child) in &children {
        #[cfg(unix)]
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        println!("[boot] Sent SIGTERM to node {} (pid {})", id, child.id());
    }
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    for (id, mut child) in children {
        let _ = child.kill();
        let _ = child.wait();
        println!("[boot] Node {id} stopped.");
    }

    Ok(())
}

/// Prompt the operator to paste their node API key (created in the dashboard).
/// With --no-prompt we refuse to block on stdin and require --node-key instead.
pub fn prompt_node_key(no_prompt: bool) -> Result<String, Box<dyn std::error::Error>> {
    if no_prompt {
        return Err("no node key provided: pass --node-key <KEY> (--no-prompt is set)".into());
    }
    use std::io::Write;
    println!("\n  Create a node in the dashboard (Nodes -> create a node) to get its API key.");
    print!("  Paste the node API key: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let key = line.trim().to_string();
    if key.is_empty() {
        return Err("no node key entered".into());
    }
    Ok(key)
}

/// Marker error: the control plane doesn't recognise this node's API key
/// (deleted in the dashboard, or the key was revoked). The daemon treats this
/// as terminal - it stops instead of retrying a key that will never work.
#[derive(Debug)]
pub struct NodeDeleted;
impl std::fmt::Display for NodeDeleted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node not found on the server (deleted or key revoked)")
    }
}
impl std::error::Error for NodeDeleted {}

/// Delete a node's on-disk registration: config + pid lock + network dir.
pub fn remove_node_files(base: &std::path::Path, node_id: &str) -> std::io::Result<()> {
    let paths = NodePaths::new(base, node_id);
    if paths.config.exists() {
        fs::remove_file(&paths.config)?;
    }
    if paths.pid.exists() {
        let _ = fs::remove_file(&paths.pid);
    }
    if paths.network_dir.exists() {
        let _ = fs::remove_dir_all(&paths.network_dir);
    }
    Ok(())
}

/// `crossfyre node remove <id> | --inactive`. Removes a node's local
/// registration; `--inactive` removes every node the server reports as unknown
/// (401 from authorize-node = deleted/revoked).
/// `crossfyre node list`: show the account's node fleet from the control plane,
/// with live online/offline status. Distinct from `node status`, which only
/// reports the node daemons running locally on this host.
pub async fn run_node_list(
    base: &std::path::Path,
    as_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::toolchain::ui::*;

    let Some(account) = auth::load_account(base) else {
        error("You are not logged in");
        hint("Run `crossfyre login` first to see your node fleet.");
        end();
        std::process::exit(1);
    };

    let client = reqwest::Client::new();
    let nodes = auth::list_nodes(&client, &account).await?;

    if as_json {
        println!("{}", serde_json::to_string_pretty(&nodes)?);
        return Ok(());
    }

    title("Crossfyre nodes", &format!("{} total", nodes.len()));

    if nodes.is_empty() {
        hint("No nodes on your account yet.");
        hint("Register this host with `crossfyre node init`.");
        end();
        return Ok(());
    }

    section("Fleet");
    // Dim column header, aligned to the symbol + columns of the rows below.
    println!(
        "    {}",
        dim(&format!(
            "  {:<38} {:<18} {:<9} {}",
            "ID", "NAME", "STATUS", "IP"
        ))
    );
    for n in &nodes {
        let id = n["id"].as_str().unwrap_or("-");
        let name = n["name"].as_str().unwrap_or("-");
        let ip = n["ip"].as_str().unwrap_or("-");
        let status = n["status"].as_str().unwrap_or("unknown");
        let (sym, status_cell) = match status {
            "online" => (check(), green("online")),
            "offline" => (dot(), dim("offline")),
            other => (bang(), yellow(other)),
        };
        // Pad the visible width manually (ANSI codes don't count toward width).
        let pad = 9usize.saturating_sub(status.len());
        println!(
            "    {} {:<38} {:<18} {}{} {}",
            sym,
            id,
            name,
            status_cell,
            " ".repeat(pad),
            ip
        );
    }
    end();
    hint("Online = sending heartbeats now.");
    Ok(())
}

pub async fn run_node_remove(
    base: &std::path::Path,
    node_id: Option<String>,
    inactive: bool,
    all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Reuse the `crossfyre update` look: bold title, dim subtitle, aligned rows
    // with ✓ / • / ! symbols, colored status, and breathing room around it.
    use crate::toolchain::ui::*;

    let ids = discover_nodes(base).unwrap_or_default();
    let after = "Restart the supervisor (crossfyre node up) to apply.";

    println!();
    println!(
        "  {BOLD}Crossfyre node remove{RESET}   {}",
        dim(&format!("{} registered", ids.len()))
    );
    println!();

    if ids.is_empty() {
        println!("  {}", dim("No nodes are registered on this host."));
        println!();
        return Ok(());
    }

    // ── Remove a single node by id or unique prefix ──────────────────────
    if let Some(want) = node_id {
        let matches: Vec<&String> = ids
            .iter()
            .filter(|x| x.as_str() == want || x.starts_with(&want))
            .collect();
        match matches.as_slice() {
            [id] => {
                println!("  {}", dim("Nodes"));
                match remove_node_files(base, id) {
                    Ok(_) => println!(
                        "{}",
                        row(&check(), id, "", &format!("{GREEN}removed{RESET}"))
                    ),
                    Err(e) => println!(
                        "{}",
                        row(
                            &bang(),
                            id,
                            "",
                            &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string()))
                        )
                    ),
                }
                println!();
                println!("  {}", dim(after));
                println!();
            }
            [] => {
                println!(
                    "  {} No registered node matches {BOLD}{want}{RESET}.",
                    bang()
                );
                println!("  {}", dim("Registered nodes"));
                for id in &ids {
                    println!("{}", row(&dot(), id, "", ""));
                }
                println!();
                std::process::exit(1);
            }
            _ => {
                println!(
                    "  {} {BOLD}{want}{RESET} matches several nodes, be more specific:",
                    bang()
                );
                for m in &matches {
                    println!("{}", row(&dot(), m, "", ""));
                }
                println!();
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // ── --all: wipe every locally-registered node ───────────────────────
    if all {
        println!("  {}", dim("Nodes"));
        let mut removed = 0usize;
        for id in &ids {
            match remove_node_files(base, id) {
                Ok(_) => {
                    println!(
                        "{}",
                        row(&check(), id, "", &format!("{GREEN}removed{RESET}"))
                    );
                    removed += 1;
                }
                Err(e) => println!(
                    "{}",
                    row(
                        &bang(),
                        id,
                        "",
                        &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string()))
                    )
                ),
            }
        }
        println!();
        let plural = if removed == 1 { "" } else { "s" };
        println!("  {BOLD}{GREEN}Removed {removed} node{plural}{RESET}");
        if removed > 0 {
            println!("  {}", dim(after));
        }
        println!();
        return Ok(());
    }

    // ── --inactive: only nodes the server no longer knows ───────────────
    if inactive {
        println!("  {}", dim("Nodes"));
        let client = reqwest::Client::new();
        let mut removed = 0usize;
        for id in &ids {
            let paths = NodePaths::new(base, id);
            let cfg: Config = match fs::read_to_string(&paths.config)
                .ok()
                .and_then(|s| toml::from_str(&s).ok())
            {
                Some(c) => c,
                None => {
                    println!(
                        "{}",
                        row(&bang(), id, "", &dim("unreadable config, skipped"))
                    );
                    continue;
                }
            };
            let res = client
                .post(format!("{}/api/v1/authorize-node", cfg.api_url))
                .json(&serde_json::json!({ "api_key": cfg.api_key, "force": false }))
                .send()
                .await;
            match res {
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    match remove_node_files(base, id) {
                        Ok(_) => {
                            println!(
                                "{}",
                                row(
                                    &check(),
                                    id,
                                    "",
                                    &format!("{GREEN}removed{RESET}  {}", dim("not on server"))
                                )
                            );
                            removed += 1;
                        }
                        Err(e) => println!(
                            "{}",
                            row(
                                &bang(),
                                id,
                                "",
                                &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string()))
                            )
                        ),
                    }
                }
                Ok(_) => println!("{}", row(&dot(), id, "", &dim("kept, still on the server"))),
                Err(e) => println!(
                    "{}",
                    row(
                        &bang(),
                        id,
                        "",
                        &dim(&format!("unreachable, skipped ({e})"))
                    )
                ),
            }
        }
        println!();
        let plural = if removed == 1 { "" } else { "s" };
        println!("  {BOLD}{GREEN}Removed {removed} inactive node{plural}{RESET}");
        if removed > 0 {
            println!("  {}", dim(after));
        }
        println!();
        return Ok(());
    }

    // ── No target given: show the choices ───────────────────────────────
    println!("  {}", dim("Choose what to remove:"));
    println!(
        "    {} crossfyre node remove {BOLD}<node-id>{RESET}    {}",
        dot(),
        dim("one node")
    );
    println!(
        "    {} crossfyre node remove {BOLD}--inactive{RESET}   {}",
        dot(),
        dim("nodes deleted in the dashboard")
    );
    println!(
        "    {} crossfyre node remove {BOLD}--all{RESET}        {}",
        dot(),
        dim("every node on this host")
    );
    println!();
    println!("  {}", dim("Registered nodes"));
    for id in &ids {
        println!("{}", row(&dot(), id, "", ""));
    }
    println!();
    std::process::exit(1);
}

pub async fn run_init(
    force: bool,
    api_url: &str,
    data_dir: &std::path::Path,
    no_service: bool,
    node_key: Option<String>,
    no_prompt: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::toolchain::ui::*;

    let host = api_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    title("Crossfyre node init", host);
    field("Control plane", api_url);
    field("Data directory", &data_dir.display().to_string());
    print_privilege_banner(false);

    let client = reqwest::Client::new();

    // Enrol this host. Two routes, in order of how little the operator has to do:
    //
    //  1. A node key was passed (or is pasted): enrol against that exact node.
    //     This is the dashboard flow - create a node there, copy its key here.
    //  2. No key, but we have an account session: ask the server to hand us one.
    //     It claims the account's oldest node that has never come online (every
    //     account is seeded with `default-node-1`) or creates one, and returns a
    //     freshly minted key. This is what makes a single install-and-enrol
    //     command possible, since node keys are stored hashed and cannot be read
    //     back out of the dashboard to paste.
    //
    // Prompting is the last resort, only when there is no session to use.
    // `json_resp` is authorize-node-shaped either way; `node_api_key` is
    // persisted so the daemon can re-authorize on start.
    let (json_resp, node_api_key) = match node_key {
        Some(k) => {
            end();
            section("Register");
            working("Verifying node key…");
            let resp = auth::authorize_existing_node(&client, api_url, &k, force).await?;
            (resp, k)
        }
        None => match auth::load_account(data_dir) {
            Some(account) => {
                end();
                section("Register");
                working("Claiming a node for this host…");
                let resp = auth::provision_node(&client, &account, None).await?;
                let issued = resp["api_key"]
                    .as_str()
                    .ok_or("The server did not return a node key")?
                    .to_string();
                (resp, issued)
            }
            None => {
                let k = prompt_node_key(no_prompt)?;
                end();
                section("Register");
                working("Verifying node key…");
                let resp = auth::authorize_existing_node(&client, api_url, &k, force).await?;
                (resp, k)
            }
        },
    };

    // Server may reject if the node is already online elsewhere
    if json_resp["valid"].as_bool() == Some(false) {
        let node_name = json_resp["node_name"].as_str().unwrap_or("unknown");
        let last_seen = json_resp["last_seen"].as_str().unwrap_or("unknown");
        end();
        error(&format!("Node '{node_name}' is already running elsewhere"));
        field("Last heartbeat", last_seen);
        hint("Run with --force to disconnect it and take over:");
        hint("  crossfyre node init --force");
        std::process::exit(1);
    }

    let node_id = json_resp["node_id"]
        .as_str()
        .ok_or("Failed to extract node_id from server response")?
        .to_string();
    ok(&format!("Node {} verified", dim(&node_id)));

    let nats_nkey_seed = json_resp["nats_nkey_seed"].as_str().map(|s| s.to_string());

    let nats_user_jwt = json_resp["nats_user_jwt"].as_str().map(|s| s.to_string());

    // Resolve per-node on-disk paths (honors --data-dir / $SUDO_USER so the
    // config root stays the invoking user's home). Each node gets its own
    // `nodes.d/<node-id>.toml` so several can share one crossfyre config root.
    let config_dir = data_dir.to_path_buf();
    let paths = NodePaths::new(data_dir, &node_id);

    // Create config root + nodes.d if they don't exist yet.
    let nd = nodes_dir(data_dir);
    if !nd.exists() {
        fs::create_dir_all(&nd)?;
        step(&format!("Created {}", nd.display()));
    }

    // -- Fetch extensions from server -------------------------------------
    let selected_extensions: Vec<String> = json_resp["extensions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if selected_extensions.is_empty() {
        field("Extensions", "none assigned");
    } else {
        field("Extensions", &selected_extensions.join(", "));
    }

    // Extract NATS URL from server response (falls back to localhost for dev)
    let nats_url = json_resp["nats_url"]
        .as_str()
        .unwrap_or("nats://localhost:4222")
        .to_string();

    // -- Network identity (VPN tunnel set on the dashboard) -------------
    let network = egress::process_network_config(&json_resp["network_config"], &paths.network_dir);

    // Write nodes.d/<node-id>.toml (with extensions list + network section)
    let config = Config {
        api_key: node_api_key.clone(),
        node_id,
        api_url: api_url.to_string(),
        nats_url,
        nats_nkey_seed,
        nats_user_jwt,
        extensions: selected_extensions.clone(),
        network: network.clone(),
        // Opt-in: see Config::remote_exec. A fresh node will not run control-plane
        // commands until its operator says so.
        remote_exec: false,
    };
    let config_path = &paths.config;
    let config_toml = toml::to_string(&config)?;
    write_secret_file(config_path, &config_toml)?;
    end();
    section("Configure");
    ok(&format!(
        "Config saved {}",
        dim(&config_path.display().to_string())
    ));

    // Write session file (placeholder empty file for now)
    let session_path = config_dir.join("session");
    if !session_path.exists() {
        fs::write(&session_path, "")?;
        step("Session initialized");
    }

    // -- Set up the toolchain + selected extensions ------------------------
    end();
    section("Toolchain");

    // One-time migration: clean up a pre-merge OrionChain install so the old
    // orion services and binaries don't fight the new ones.
    toolchain::uninstall::cleanup_legacy_orionchain();

    // Put the crossfyre binary at its stable path so OS services have a
    // fixed ExecStart (no-op when already running from /opt/crossfyre/bin).
    let stable_exe = match toolchain::install::ensure_self_installed() {
        Ok(p) => p,
        Err(e) => {
            warn(&format!(
                "could not install binary to {} ({}), continuing from current path",
                toolchain::config::get_bin_dir().display(),
                e
            ));
            std::env::current_exe()?
        }
    };

    // Ensure the `node` worker binary is installed next to crossfyre, so the
    // node service's ExecStart (/opt/crossfyre/bin/node) resolves.
    if let Err(e) = toolchain::install::ensure_node_installed().await {
        warn(&format!("could not install the node worker binary: {e}"));
    }

    // Write the default toolchain config (postgres connection for the
    // extension daemons) if this host doesn't have one yet, then apply any
    // custom service ports the operator chose in the deploy wizard - so the
    // engines and database below install on those ports from the start.
    match toolchain::config::apply_ports_from_json(&json_resp["ports"]) {
        Ok(changed) if !changed.is_empty() => {
            step(&format!(
                "Applied custom service ports: {}",
                changed.join(", ")
            ));
        }
        Ok(_) => {}
        Err(e) => warn(&format!("could not create toolchain config: {e}")),
    }

    // Install each extension assigned to this node: download, verify against
    // the release manifest, enable and start its daemon. The package manager
    // is built in - no external installer involved.
    for ext in &selected_extensions {
        if toolchain::config::is_extension_installed(ext) {
            ok(&format!("{ext} already installed"));
            let _ = toolchain::service::enable(ext);
            let _ = toolchain::service::start(ext);
            continue;
        }
        working(&format!("Installing {ext}"));
        match toolchain::install::install_and_start(ext).await {
            Ok(()) => ok(&format!("{ext} installed and started")),
            Err(e) => {
                fail(&format!("{ext} install failed: {e}"));
                hint(&format!("Run manually: crossfyre extension install {ext}"));
            }
        }
    }

    // Bring up the toolchain database the extensions persist scan state to.
    if !selected_extensions.is_empty() {
        working("Starting the toolchain database");
        match toolchain::db::ensure_up() {
            Ok(()) => ok("Database ready"),
            Err(e) => {
                fail(&format!("Database start failed: {e}"));
                hint("Run manually: crossfyre db up");
            }
        }
    }

    // Register the node supervisor as an OS service so the node survives
    // reboots and closed terminals (Linux; needs root).
    end();
    section("Service");
    if no_service {
        warn("Skipped node service install (--no-service)");
        hint("Run the node with: crossfyre node up");
    } else {
        match toolchain::service::install_node_service(&stable_exe, data_dir) {
            Ok(()) => ok("Node service installed and started (crossfyre-node)"),
            Err(e) => {
                warn(&format!("could not install the node service: {e}"));
                hint("Run the node manually with: sudo crossfyre node up");
            }
        }
    }

    // Update node status on the server
    let status_res = client
        .post(format!("{api_url}/api/v1/node-status"))
        .json(&serde_json::json!({
            "api_key": &node_api_key,
            "status": "initialized",
            "event": "initialization",
            "message": "Node successfully initialized on CLI"
        }))
        .send()
        .await;

    if let Err(e) = status_res {
        warn(&format!(
            "could not update initialization status on the server: {e}"
        ));
    } else if let Ok(res) = status_res
        && !res.status().is_success()
    {
        warn(&format!(
            "server returned {} updating initialization status",
            res.status()
        ));
    }

    // If we ran under sudo, hand ownership of the data dir back to the
    // invoking user so the next non-sudo `--init` (or a plain `cat config.toml`)
    // can still read & write it.
    chown_tree_to_sudo_user(&config_dir);

    end();
    done("Node ready");
    hint("Run `crossfyre node status` to see the daemons.");
    end();
    Ok(())
}

/// Cap shell output at a char boundary so a huge dump can't blow past NATS's
/// max message size. Appends a marker when truncated.
fn shell_cap(s: String) -> String {
    const CAP: usize = 60_000;
    if s.len() <= CAP {
        return s;
    }
    let mut t: String = s.chars().take(CAP).collect();
    t.push_str("\n...[output truncated]");
    t
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

pub fn which_binary(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Call /api/v1/authorize-node to get a fresh JWT+NKey, then persist them
/// to config.toml so the next NATS connect uses valid credentials.
/// Re-authorize the node on every daemon start. The server response is the
/// authoritative source for everything operator-configurable: NATS creds,
/// installed extensions, network identity (VPN), and the proxy chain. Every
/// piece is refreshed in-place so dashboard edits take effect on the next
/// daemon restart without needing the operator to re-run --init.
pub async fn refresh_node_state(
    config: &mut Config,
    config_path: &std::path::Path,
    net_dir: &std::path::Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Refreshing node state from controller...");
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/api/v1/authorize-node", config.api_url))
        .json(&serde_json::json!({ "api_key": &config.api_key, "force": force }))
        .send()
        .await?;

    // 401 = the server doesn't know this api_key (node deleted / key revoked).
    // Surface it as a terminal NodeDeleted error so the daemon stops cleanly
    // instead of retrying a key that will never authorize.
    if res.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Box::new(NodeDeleted));
    }
    if !res.status().is_success() {
        return Err(format!("authorize-node returned {}", res.status()).into());
    }

    let json_resp: serde_json::Value = res.json().await?;

    if json_resp["valid"].as_bool() != Some(true) {
        // Server says this api_key already has a live node elsewhere - the
        // daemon caller must surface this so the operator knows another
        // instance is still holding the slot.
        let node_name = json_resp["node_name"].as_str().unwrap_or("unknown");
        let last_seen = json_resp["last_seen"].as_str().unwrap_or("unknown");
        return Err(format!(
            "node '{node_name}' is already running elsewhere (last heartbeat {last_seen}). Use --force to take over."
        )
        .into());
    }

    if let Some(jwt) = json_resp["nats_user_jwt"].as_str() {
        config.nats_user_jwt = Some(jwt.to_string());
    }
    if let Some(seed) = json_resp["nats_nkey_seed"].as_str() {
        config.nats_nkey_seed = Some(seed.to_string());
    }

    // Refresh the network/VPN config from the server. This rewrites the
    // .ovpn / .conf on disk if the operator uploaded a new one - so an edit
    // in the dashboard plus a daemon restart is enough to switch tunnels.
    let new_network = egress::process_network_config(&json_resp["network_config"], net_dir);
    if new_network != config.network {
        if let Some(ref n) = new_network {
            println!(
                "[network] Tunnel selection: {} (updated from controller).",
                n.kind
            );
        } else {
            println!("[network] No tunnel configured (cleared by controller).");
        }
        config.network = new_network;
    }

    // Persist so next restart also has fresh creds if refresh fails.
    let config_toml = toml::to_string(&config)?;
    write_secret_file(config_path, &config_toml)?;
    // Daemon often runs as root via sudo - the file we just wrote is now
    // root-owned. Hand it back to the invoking user so non-sudo tools can
    // still read it.
    chown_to_sudo_user(config_path);
    if let Some(parent) = config_path.parent() {
        chown_tree_to_sudo_user(parent);
    }
    // Apply any service-port overrides the operator set in the dashboard and
    // reconcile the local services to match. Runs on every daemon start, so a
    // port changed while this node was offline (its live set_ports command was
    // never delivered) still takes effect the moment it reconnects.
    let changed = reconcile_ports(&json_resp["ports"]);
    if !changed.is_empty() {
        println!("[ports] Reconciled service ports: {}", changed.join(", "));
    }

    println!("Node state refreshed and saved.");
    Ok(())
}

/// Apply server-provided port overrides to the host `config.toml` and restart the
/// exact local services whose port moved, so the change takes effect. Shared by
/// the daemon's startup refresh and the live `set_ports` command. Returns the
/// list of services that changed. Safe to call when nothing changed (no-op).
fn reconcile_ports(ports_json: &serde_json::Value) -> Vec<String> {
    let changed = toolchain::config::apply_ports_from_json(ports_json).unwrap_or_default();
    if changed.is_empty() {
        return changed;
    }
    // Postgres port moved: re-provision the container on the new port.
    if changed.iter().any(|c| c == "postgres") {
        match toolchain::config::load_config() {
            Ok(cfg) => {
                let _ = toolchain::db::up(&cfg);
            }
            Err(e) => eprintln!("[ports] FAIL reload config for db: {e}"),
        }
    }
    // Engine port moved: rewrite its unit (ExecStart reads config.toml) + restart.
    for ext in changed.iter().filter(|c| c.as_str() != "postgres") {
        if toolchain::config::is_extension_installed(ext) {
            let _ = toolchain::service::create_service_file(ext);
            let _ = toolchain::service::restart(ext);
        }
    }
    changed
}

/// A stable seed identifying the physical machine this node runs on, so two
/// nodes on the same box group into one host. /etc/machine-id is the canonical
/// Linux host id (stable across reboots, unique per install); the SMBIOS
/// product_uuid corroborates it against cloned machine-ids in some VM images.
/// api_switch stores only the sha256 of this, never the raw value.
fn host_seed() -> String {
    let machine_id = fs::read_to_string("/etc/machine-id")
        .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let product_uuid = fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match (machine_id, product_uuid) {
        (Some(m), Some(p)) => format!("mid:{m}|puuid:{p}"),
        (Some(m), None) => format!("mid:{m}"),
        (None, Some(p)) => format!("puuid:{p}"),
        (None, None) => format!("host:{}", sysinfo::System::host_name().unwrap_or_default()),
    }
}

pub async fn run_daemon(force: bool, paths: &NodePaths) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Crossfyre Node Client Daemon...");
    println!("Node id       : {}", paths.node_id);
    println!("Config root   : {}", paths.base.display());
    print_privilege_banner(std::env::var("CFX_ALLOW_UNPRIV_DAEMON").is_err());

    // --- PID lock: scoped to this node-id, so multiple nodes can coexist in
    // the same config root - each holds its own `nodes.d/<node-id>.pid`. ---
    fs::create_dir_all(nodes_dir(&paths.base))?;
    let pid_path = paths.pid.clone();

    if pid_path.exists() {
        let existing_pid_str = fs::read_to_string(&pid_path).unwrap_or_default();
        let existing_pid: u32 = existing_pid_str.trim().parse().unwrap_or(0);
        if existing_pid > 0 {
            let proc_path = format!("/proc/{existing_pid}");
            if std::path::Path::new(&proc_path).exists() {
                if force {
                    println!("  --force: Terminating existing daemon (PID {existing_pid})...");
                    // SIGTERM the old process
                    unsafe {
                        libc::kill(existing_pid as i32, libc::SIGTERM);
                    }
                    // Give it a moment to exit
                    tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
                } else {
                    eprintln!(
                        "\n  A daemon is already running for node {}.",
                        paths.node_id
                    );
                    eprintln!("  PID            : {existing_pid}");
                    eprintln!("\n  Take it over with:");
                    eprintln!("  crossfyre node daemon {} --force\n", paths.node_id);
                    std::process::exit(1);
                }
            }
        }
    }
    // Write our own PID
    let my_pid = std::process::id();
    fs::write(&pid_path, my_pid.to_string())?;
    chown_to_sudo_user(&pid_path);
    // Remove PID file on exit (best-effort via a drop guard)
    struct PidGuard(std::path::PathBuf);
    impl Drop for PidGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _pid_guard = PidGuard(pid_path);
    // ------------------------------------------------------------------

    // Check if this node's configuration exists
    let config_path = paths.config.clone();

    if !config_path.exists() {
        eprintln!(
            "Configuration for node '{}' not found. Run `crossfyre node init` first. Expected at: {:?}",
            paths.node_id, config_path
        );
        std::process::exit(1);
    }

    // Load config
    // Repair installs written before the config was mode-restricted.
    repair_secret_file_mode(&config_path);
    let config_str = fs::read_to_string(&config_path)?;
    let mut config: Config = toml::from_str(&config_str)?;

    println!("Configuration loaded successfully.");

    // Pull the latest state (creds + network config + extensions) from the
    // controller on every daemon start. The server enforces "one running
    // node per api_key" - so if it returns valid=false we abort instead of
    // falling through to a cached config (which would let two daemons race
    // for the same NATS subjects).
    // Retry a control plane that is not up YET, rather than treating it as fatal.
    //
    // WHY: on a reboot the node service and the control plane start together, and
    // the node usually wins the race. It used to call exit(1) on the resulting
    // connection error; the supervisor then parked it as dead and "held until its
    // config changes", i.e. forever. systemd never intervened either, because
    // Restart=on-failure watches the SUPERVISOR, which stayed perfectly healthy
    // holding a corpse. Net effect: every reboot silently killed the fleet until a
    // human ran `systemctl restart` by hand, and the dashboard just said 0 nodes
    // online without saying why.
    //
    // Only genuinely transient failures are retried. A deleted node, a revoked key
    // or another daemon holding the same api_key are permanent and still exit
    // immediately: retrying those would spin forever hiding a real problem.
    const AUTH_RETRY_WINDOW_SECS: u64 = 600;
    let auth_started = std::time::Instant::now();
    let mut backoff = std::time::Duration::from_secs(2);
    let refresh_result = loop {
        match refresh_node_state(&mut config, &config_path, &paths.network_dir, force).await {
            Ok(()) => break Ok(()),
            Err(e) => {
                let transient = e
                    .downcast_ref::<reqwest::Error>()
                    .map(|re| re.is_connect() || re.is_timeout() || re.is_request())
                    .unwrap_or(false);
                if !transient || auth_started.elapsed().as_secs() >= AUTH_RETRY_WINDOW_SECS {
                    break Err(e);
                }
                eprintln!(
                    "  Control plane not reachable yet ({e}); retrying in {}s",
                    backoff.as_secs()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
            }
        }
    };

    if let Err(e) = refresh_result {
        if e.downcast_ref::<NodeDeleted>().is_some() {
            eprintln!(
                "\n  Node {} not found on the server (deleted in the dashboard, or its key was revoked).",
                paths.node_id
            );
            eprintln!("  Stopping - this node will not be retried.");
            eprintln!("  Clean it up locally with:");
            eprintln!("    crossfyre node remove {}", paths.node_id);
            eprintln!("    crossfyre node remove --inactive   # remove all server-deleted nodes");
            std::process::exit(1);
        }
        eprintln!("\n  Cannot start daemon: {e}");
        eprintln!(
            "  crossfyre node daemon {} --force   # take over this node",
            paths.node_id
        );
        std::process::exit(1);
    }

    // -- Apply isolated egress (if configured) before scanning starts ----
    // We do this after credential refresh (which needs regular internet to
    // reach the controller) and before connecting, so subscriber traffic
    // routes through the configured egress. The guard tears egress down on
    // every exit path (Ctrl+C, SIGTERM, panic, normal return) and is bound to
    // `_egress_guard` so it lives the full daemon lifetime.
    let _egress_guard = config
        .network
        .as_ref()
        .and_then(|net| egress::bring_up(net, &paths.network_dir, &paths.node_id));

    println!("Connecting to Jetstream at {}...", config.nats_url);

    // Connect to NATS
    let nats_url = config.nats_url.as_str();

    // Require JWT credentials - NATS is in operator mode, anonymous connections are rejected
    let (jwt_str, seed_str) = match (&config.nats_user_jwt, &config.nats_nkey_seed) {
        (Some(j), Some(s)) if !j.is_empty() && !s.is_empty() => (j.clone(), s.clone()),
        _ => {
            eprintln!("ERROR: nats_user_jwt or nats_nkey_seed is missing from this node's config.");
            eprintln!(
                "       Run `crossfyre node init` to register this node and get fresh credentials."
            );
            std::process::exit(1);
        }
    };

    println!("Authenticating to Jetstream with dynamically issued User JWT & Seed...");
    let key_pair = std::sync::Arc::new(
        nkeys::KeyPair::from_seed(seed_str.as_str())
            .expect("Invalid nats_nkey_seed in config.toml"),
    );

    // rustls needs an explicit CryptoProvider when more than one is compiled in.
    // Both aws-lc-rs and ring are pulled into this workspace (cortex uses one,
    // oast the other), so the TLS handshake to nexus would otherwise panic with
    // "could not automatically determine the process-level CryptoProvider" - the
    // node comes up but never connects. Idempotent: ignore if already installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let opts = async_nats::ConnectOptions::with_jwt(jwt_str, move |nonce: Vec<u8>| {
        let kp = key_pair.clone();
        async move { kp.sign(&nonce).map_err(async_nats::AuthError::new) }
    })
    // Increase the subscriber buffer so large bursts (e.g. a 65k-op scan)
    // don't overflow and drop messages as "slow consumer".
    .subscription_capacity(1_000_000);

    // TLS to the control plane.
    //
    // This link crosses the public internet: nexus.<zone> is a DNS-only record
    // pointing straight at the box, because NATS is raw TCP and cannot be
    // proxied. Without TLS every workflow dispatch (the target list) and every
    // result (the findings) travelled in cleartext, readable by anyone on the
    // path. nkey auth never protected the payloads, only the identity.
    //
    // The server presents the Cloudflare Origin CA certificate for the zone,
    // which is not in any public trust store, so the root is shipped with this
    // binary and added explicitly. It is written next to the node config because
    // async-nats takes a path rather than bytes.
    //
    // require_tls is set independently of the URL scheme on purpose: without it a
    // downgraded or tampered NATS_PUBLIC_URL (say `nats://`) would silently
    // reconnect in cleartext, which is precisely the failure this is meant to
    // prevent.
    let opts = if nats_url.starts_with("tls://") {
        match write_origin_root_cert() {
            Ok(ca_path) => opts.add_root_certificates(ca_path).require_tls(true),
            Err(e) => {
                eprintln!("ERROR: could not stage the NATS root certificate: {e}");
                return Err(e.into());
            }
        }
    } else {
        eprintln!(
            "WARNING: NATS_PUBLIC_URL is not tls:// - this connection is UNENCRYPTED. \
             Scan targets and findings will cross the network in cleartext."
        );
        opts
    };

    let nats_client = opts.connect(nats_url).await.map_err(|e| {
        eprintln!("ERROR: Failed to connect to NATS: {e}");
        e
    })?;

    // Subscribe to the job/control channel for this node
    let job_subject = format!("cfx.jobs.{}", config.node_id);
    let mut job_sub = nats_client
        .subscribe(job_subject.clone())
        .await
        .map_err(|e| {
            eprintln!("ERROR: Failed to subscribe to {job_subject}: {e}");
            e
        })?;

    // Keep a clone for publishing status updates (nats_client is cheap to clone)
    let publisher = nats_client.clone();
    let status_subject = format!("cfx.node.{}.status", config.node_id);
    let jetstream = async_nats::jetstream::new(nats_client);

    // -- Build full host info on first connect -------------------------------
    let mut sys = System::new_all();
    sys.refresh_all();
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    sys.refresh_all();

    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());
    let os_name = sysinfo::System::long_os_version().unwrap_or_else(|| "unknown".into());
    let arch = std::env::consts::ARCH.to_string();
    let kernel = sysinfo::System::kernel_version().unwrap_or_else(|| "unknown".into());
    let cpu_cores = sys.cpus().len() as i64;
    // Machine fingerprint seed so co-located nodes group into one host.
    let host_seed_str = host_seed();

    // Detect primary local IP
    let ip = {
        use std::net::UdpSocket;
        UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| {
                s.connect("8.8.8.8:80")?;
                s.local_addr()
            })
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "unknown".into())
    };

    let ram_total = sys.total_memory() as i64;
    let ram_used = sys.used_memory() as i64;
    let ram_avail = (sys.total_memory().saturating_sub(sys.used_memory())) as i64;
    let cpu_usage = sys.global_cpu_usage() as i64;

    // Network baseline
    use sysinfo::Networks;
    let mut nets = Networks::new_with_refreshed_list();
    let (mut last_rx, mut last_tx) = nets.iter().fold((0i64, 0i64), |(rx, tx), (_, n)| {
        (
            rx + n.total_received() as i64,
            tx + n.total_transmitted() as i64,
        )
    });

    // -- Send full host_status on first connect ------------------------------
    println!("Connected to Jetstream successfully.");
    println!("Listening for commands on : {job_subject}");
    println!("Publishing status to      : {status_subject}");
    println!("Daemon running. Press Ctrl+C to stop.");

    // -- Validate API key before going online -------------------------------
    // This blocks the node from ever appearing online with a revoked key.
    let http_client = reqwest::Client::new();
    let validate_res = http_client
        .post(format!("{}/api/v1/node-status", config.api_url))
        .json(&serde_json::json!({
            "api_key": &config.api_key,
            "status": "online",
            "event": "initialization",
            "message": serde_json::Value::Null,
            "host_status": serde_json::json!({
                "cpu": cpu_usage,
                "ram_used": ram_used,
                "ram_available": ram_avail,
                "ram_total": ram_total,
                "net_rx": 0,
                "net_tx": 0,
                "hostname": hostname,
                "ip": ip,
                "os": os_name,
                "arch": arch,
                "kernel": kernel,
                "cpu_cores": cpu_cores,
                "host_seed": host_seed_str.clone()
            })
        }))
        .send()
        .await;

    match validate_res {
        Ok(res) if res.status() == 401 => {
            eprintln!("\n[EVICTION] API key has been revoked. This node is no longer authorized.");
            eprintln!(
                "           Run `crossfyre node init` again to re-register with a valid key."
            );
            std::process::exit(1);
        }
        Ok(res) if !res.status().is_success() => {
            eprintln!(
                "Warning: Server returned {} on startup. Continuing...",
                res.status()
            );
        }
        Err(e) => {
            eprintln!("Warning: Could not reach backend on startup: {e}. Continuing offline...");
        }
        _ => {}
    }

    let api_url = config.api_url.clone();
    let api_key = config.api_key.clone();
    let node_id = config.node_id.clone();

    // Ask the controller to re-publish any operations that were assigned
    // to this node and never finished (because we crashed, were killed, or
    // exited mid-scan). The controller filters out halted/finished
    // workflows, so this only revives in-progress runs. Republished
    // messages flow through the normal per-node subscription.
    {
        let resume_res = http_client
            .post(format!("{api_url}/api/v1/resume-pending"))
            .json(&serde_json::json!({ "api_key": api_key }))
            .send()
            .await;
        match resume_res {
            Ok(r) if r.status().is_success() => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    let n = body["data"]["republished"].as_u64().unwrap_or(0);
                    if n > 0 {
                        println!("[resume] Picking up {n} pending operation(s) from prior run");
                    }
                }
            }
            Ok(r) => eprintln!(
                "[resume] Controller returned {} - skipping resume",
                r.status()
            ),
            Err(e) => eprintln!("[resume] Could not reach controller: {e} - skipping resume"),
        }
    }

    // -- Pull-queue consumer -------------------------------------------------
    // Durable pull consumer on this node's work queue. We pull a BOUNDED number
    // of ops at a time - max_ack_pending caps how many un-acked ops the node
    // holds (in-flight or parked on the per-workflow semaphore), so node RAM
    // stays flat no matter how large the scan. We ack only AFTER an op completes,
    // so a crash mid-op redelivers it; the op handler is idempotent (op_is_done
    // re-ack + server-side findings dedup), so a redelivery is cheap, not
    // duplicated work.
    //
    // Runs alongside the push path: the control plane uses one delivery mode, so
    // ops arrive on exactly one channel; handling both makes rollout safe.
    // Best-effort: if the queue is unavailable, the node just runs push-only.
    {
        let node_id_pc = node_id.clone();
        let publisher_pc = publisher.clone();
        let status_subject_pc = status_subject.clone();
        let http_pc = http_client.clone();
        let api_url_pc = api_url.clone();
        let api_key_pc = api_key.clone();
        // Set >= the largest per-workflow concurrency (threads/tasks, capped at
        // 200) so a full-concurrency scan isn't throttled, while still bounding
        // node RAM to a few hundred small op payloads. Tunable per node.
        let max_ack_pending: i64 = std::env::var("CFX_MAX_ACK_PENDING")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(256);
        tokio::spawn(async move {
            // BIND the CFX_WORK stream (api_switch owns creation; node creds grant
            // STREAM.INFO, not CREATE). Retry a bit in case api_switch hasn't
            // created it yet at boot; give up to push-only if it never appears.
            let stream = {
                let mut bound = None;
                for attempt in 0..10u32 {
                    match jetstream.get_stream("CFX_WORK").await {
                        Ok(s) => {
                            bound = Some(s);
                            break;
                        }
                        Err(e) => {
                            if attempt == 9 {
                                eprintln!(
                                    "[work] CFX_WORK stream not available after retries, running push-only: {e}"
                                );
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        }
                    }
                }
                match bound {
                    Some(s) => s,
                    None => return,
                }
            };
            let durable = format!("node-{node_id_pc}");
            let consumer = match stream
                .get_or_create_consumer(
                    durable.as_str(),
                    async_nats::jetstream::consumer::pull::Config {
                        durable_name: Some(durable.clone()),
                        filter_subject: format!("cfx.work.{node_id_pc}"),
                        ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                        ack_wait: std::time::Duration::from_secs(900),
                        max_ack_pending,
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[work] pull consumer unavailable, running push-only: {e}");
                    return;
                }
            };
            let mut messages = match consumer.messages().await {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[work] message stream error, running push-only: {e}");
                    return;
                }
            };
            println!("[work] worker ready (max in-flight={max_ack_pending})");
            while let Some(next) = messages.next().await {
                let msg = match next {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[work] recv error: {e}");
                        continue;
                    }
                };
                let cmd: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = msg.ack().await;
                        continue;
                    }
                };
                // Only "operation" jobs ride the work queue; ack + drop anything else.
                if cmd["type"].as_str() != Some("operation") {
                    let _ = msg.ack().await;
                    continue;
                }
                let ctx = OpCtx {
                    pub_clone: publisher_pc.clone(),
                    status_subj: status_subject_pc.clone(),
                    result_subj: format!("cfx.results.{node_id_pc}"),
                    node_id: node_id_pc.clone(),
                    http: http_pc.clone(),
                    api_url: api_url_pc.clone(),
                    api_key: api_key_pc.clone(),
                };
                tokio::spawn(async move {
                    run_operation(cmd, ctx).await;
                    // Ack after completion: a crash before this redelivers the op
                    // (idempotent). A lost ack self-heals via redelivery + op_is_done.
                    let _ = msg.ack().await;
                });
            }
            eprintln!("[work] pull consumer stream ended");
        });
    }

    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    // Skip the first tick since we already sent the initial status above
    heartbeat_interval.tick().await;
    let mut first_tick = false; // already sent full host_status above, don't duplicate it

    // Proactive credential refresh - fire every 6 days (JWT has a 7-day TTL).
    // If the daemon runs long enough, this prevents silent NATS disconnects.
    let mut refresh_interval =
        tokio::time::interval(tokio::time::Duration::from_secs(6 * 24 * 3600));
    refresh_interval.tick().await; // skip immediate first tick

    // Catch SIGTERM (the default `kill` signal) so the egress teardown
    // path runs - without this, `kill <pid>` would bypass the Drop guard.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    // A revoked key gives a persistent 401; a control-plane restart/deploy gives a TRANSIENT one.
    // Evicting on the first 401 meant a brief blip could permanently kill the node (and, in prod, the
    // whole fleet during a deploy). So only evict after several CONSECUTIVE 401s; any success resets.
    let mut consecutive_401 = 0u32;
    const EVICT_AFTER_401: u32 = 4; // ~20s of sustained auth failure at the 5s interval

    loop {
        tokio::select! {
            // Credential refresh (every 6 days)
            _ = refresh_interval.tick() => {
                println!("[refresh] Proactively refreshing NATS credentials...");
                match refresh_node_state(&mut config, &config_path, &paths.network_dir, false).await {
                    Ok(()) => println!("[refresh] Done. New JWT will take effect on next daemon restart."),
                    Err(e) => eprintln!("[refresh] Warning: credential refresh failed: {e}. JWT still valid for ~1 day."),
                }
                // we don't reconnect NATS in-flight - the current connection uses the
                // old JWT which is still valid for ~1 more day. The refresh just ensures the
                // *saved* config is fresh so a restart works cleanly. A full reconnect would
                // require rebuilding subscriptions and is deferred for a future release.
            }
            // Heartbeat tick
            _ = heartbeat_interval.tick() => {
                sys.refresh_cpu_all();
                sys.refresh_memory();
                nets.refresh(true);

                let cpu   = sys.global_cpu_usage() as i64;
                let r_used  = sys.used_memory() as i64;
                let r_avail = (sys.total_memory().saturating_sub(sys.used_memory())) as i64;
                let (rx_now, tx_now) = nets.iter().fold((0i64, 0i64), |(rx, tx), (_, n)| {
                    (rx + n.total_received() as i64, tx + n.total_transmitted() as i64)
                });
                let net_rx = rx_now - last_rx;
                let net_tx = tx_now - last_tx;
                last_rx = rx_now;
                last_tx = tx_now;

                // Probe only installed extension daemon ports. Ports come from
                // the host config.toml (via engine_port), so a custom port is
                // both probed and reported to the dashboard correctly.
                let ext_status: serde_json::Value = {
                    let mut map = serde_json::Map::new();
                    for ext in crate::toolchain::EXTENSIONS {
                        if !config.extensions.iter().any(|e| e == ext) { continue; }
                        let port = crate::toolchain::config::engine_port(ext);
                        let running = std::net::TcpStream::connect_timeout(
                            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                            std::time::Duration::from_millis(200),
                        ).is_ok();
                        map.insert(ext.to_string(), serde_json::json!({
                            "port": port,
                            "running": running
                        }));
                    }
                    serde_json::Value::Object(map)
                };

                // Toolchain health. The package manager is built into this
                // binary, so "installed" is always true and the version is
                // our own; Postgres is probed on its configured TCP port.
                let toolchain_status: serde_json::Value = {
                    let pg_port = crate::toolchain::config::load_config()
                        .map(|c| c.postgres.port)
                        .unwrap_or(4440);
                    let pg_running = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], pg_port)),
                        std::time::Duration::from_millis(200),
                    ).is_ok();

                    serde_json::json!({
                        "installed": true,
                        "version": format!("crossfyre {}", env!("CARGO_PKG_VERSION")),
                        "postgres": { "port": pg_port, "running": pg_running }
                    })
                };

                let host_status = if first_tick {
                    first_tick = false;
                    serde_json::json!({
                        "cpu": cpu_usage,
                        "ram_used": ram_used,
                        "ram_available": ram_avail,
                        "ram_total": ram_total,
                        "net_rx": 0,
                        "net_tx": 0,
                        "hostname": hostname,
                        "ip": ip,
                        "os": os_name,
                        "arch": arch,
                        "extension_status": ext_status,
                        "toolchain_status": toolchain_status
                    })
                } else {
                    serde_json::json!({
                        "cpu": cpu,
                        "ram_used": r_used,
                        "ram_available": r_avail,
                        "ram_total": ram_total,
                        "net_rx": net_rx,
                        "net_tx": net_tx,
                        "host_seed": host_seed_str.clone(),
                        "extension_status": ext_status,
                        "toolchain_status": toolchain_status
                    })
                };

                let status_res = http_client.post(format!("{api_url}/api/v1/node-status"))
                    .json(&serde_json::json!({
                        "api_key": &api_key,
                        "status": "online",
                        "event": "heartbeat",
                        "message": serde_json::Value::Null,
                        "host_status": host_status
                    }))
                    .send()
                    .await;

                match status_res {
                    Ok(res) if res.status().is_success() => {
                        consecutive_401 = 0;
                        print!(".");
                    }
                    Ok(res) if res.status() == 401 => {
                        consecutive_401 += 1;
                        if consecutive_401 >= EVICT_AFTER_401 {
                            eprintln!("\n[EVICTION] Heartbeat returned 401 x{consecutive_401} - API key has been revoked. Shutting down...");
                            let msg = serde_json::json!({
                                "type": "terminated",
                                "reason": "api_key_revoked",
                                "node_id": &node_id
                            });
                            let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            break;
                        }
                        eprintln!(
                            "Warning: Heartbeat 401 ({consecutive_401}/{EVICT_AFTER_401}) - likely a transient control-plane blip; retrying"
                        );
                    }
                    Ok(res) => eprintln!("Warning: Heartbeat returned {}", res.status()),
                    Err(e) => eprintln!("Warning: Failed to send heartbeat: {e}"),
                }
            }

            // Ctrl+C - graceful shutdown
            _ = tokio::signal::ctrl_c() => {
                let reason = "user_initiated_shutdown";
                println!("\nCtrl+C received. Reason: {reason}. Shutting down...");
                let msg = serde_json::json!({
                    "type": "terminated",
                    "reason": reason,
                    "node_id": &node_id
                });
                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                break;
            }

            // SIGTERM (e.g. `kill <pid>`, systemd stop) - same shutdown path
            _ = sigterm.recv() => {
                let reason = "sigterm_received";
                println!("\nSIGTERM received. Shutting down...");
                let msg = serde_json::json!({
                    "type": "terminated",
                    "reason": reason,
                    "node_id": &node_id
                });
                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                break;
            }

            // Command message from JetStream
            msg = job_sub.next() => {
                if let Some(msg) = msg {
                    let body = std::str::from_utf8(&msg.payload).unwrap_or("");
                    if let Ok(cmd) = serde_json::from_str::<serde_json::Value>(body) {
                        match cmd["type"].as_str() {
                            Some("terminate") => {
                                let reason = cmd["reason"].as_str().unwrap_or("unknown");
                                println!("\nReceived terminate command. Reason: {reason}. Shutting down...");
                                let msg = serde_json::json!({
                                    "type": "terminated",
                                    "reason": reason,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                                break;
                            }
                            Some("cancel_workflow") => {
                                if let Some(wid) = cmd["workflow_id"].as_str() {
                                    println!("[op] Cancelling all in-flight ops for workflow {wid}");
                                    cancel_workflow(wid);
                                }
                            }
                            Some("resume_workflow") => {
                                if let Some(wid) = cmd["workflow_id"].as_str() {
                                    println!("[op] Clearing cancel flag for workflow {wid} (restart)");
                                    resume_workflow(wid);
                                }
                            }
                            // Interactive shell for BYO (self-hosted) nodes. The
                            // request is authorized + BYO-gated server-side in
                            // api_switch before it is ever published here; the
                            // node just runs it and replies to the NATS inbox.
                            Some("shell_exec") => {
                                let command = cmd["command"].as_str().unwrap_or("").to_string();
                                let command_id = cmd["command_id"].as_str().unwrap_or("").to_string();
                                // Node-side consent, which is not the same thing as
                                // the server-side authorization that already ran.
                                // That check lives entirely on the control plane, so
                                // it cannot protect the host from a compromised
                                // control plane or from stolen broker credentials.
                                // This one can. See Config::remote_exec.
                                if !config.remote_exec {
                                    println!("[shell] refused, remote_exec is off: {command}");
                                    let resp = serde_json::json!({
                                        "type": "shell_result",
                                        "command_id": command_id,
                                        "node_id": &node_id,
                                        "ok": false,
                                        "error": "remote execution is disabled on this node; \
                                                  set remote_exec = true in its config to allow it",
                                    });
                                    let _ = publisher
                                        .publish(status_subject.clone(), resp.to_string().into())
                                        .await;
                                    continue;
                                }
                                println!("[shell] exec: {command}");
                                let run = tokio::task::spawn_blocking(move || {
                                    std::process::Command::new("sh").arg("-c").arg(&command).output()
                                })
                                .await;
                                let mut resp = match run {
                                    Ok(Ok(o)) => serde_json::json!({
                                        "ok": true,
                                        "stdout": shell_cap(String::from_utf8_lossy(&o.stdout).into_owned()),
                                        "stderr": shell_cap(String::from_utf8_lossy(&o.stderr).into_owned()),
                                        "exit_code": o.status.code(),
                                    }),
                                    Ok(Err(e)) => serde_json::json!({ "ok": false, "error": e.to_string() }),
                                    Err(e) => serde_json::json!({ "ok": false, "error": format!("task join error: {e}") }),
                                };
                                // Reply on the node's status subject - the only
                                // channel node creds may publish to. api_switch
                                // correlates the result back by command_id.
                                resp["type"] = serde_json::json!("shell_result");
                                resp["command_id"] = serde_json::json!(command_id);
                                resp["node_id"] = serde_json::json!(&node_id);
                                let _ = publisher.publish(status_subject.clone(), resp.to_string().into()).await;
                            }
                            // Bench Repeater: replay/send one HTTP request FROM THE NODE (so egress is
                            // the node's IP, never the browser). Authorized server-side in api_switch;
                            // the node just sends it and replies with the full response by command_id.
                            Some("repeater") => {
                                let command_id = cmd["command_id"].as_str().unwrap_or("").to_string();
                                let method = cmd["method"].as_str().unwrap_or("GET").to_string();
                                let url = cmd["url"].as_str().unwrap_or("").to_string();
                                let body = cmd["body"].as_str().map(|s| s.to_string());
                                let headers: Vec<(String, String)> = cmd["headers"]
                                    .as_array()
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|h| {
                                                let p = h.as_array()?;
                                                Some((p.first()?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string()))
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                let client = http_client.clone();
                                let started = std::time::Instant::now();
                                let m = reqwest::Method::from_bytes(method.as_bytes())
                                    .unwrap_or(reqwest::Method::GET);
                                let mut rb = client.request(m, &url);
                                for (k, v) in &headers {
                                    // Skip hop-by-hop / auto-managed headers reqwest sets itself.
                                    let kl = k.to_ascii_lowercase();
                                    if kl == "host" || kl == "content-length" || kl == "connection" {
                                        continue;
                                    }
                                    rb = rb.header(k.as_str(), v.as_str());
                                }
                                if let Some(b) = body {
                                    rb = rb.body(b);
                                }
                                let mut resp = serde_json::json!({
                                    "type": "repeater_result", "command_id": command_id, "node_id": &node_id,
                                });
                                match rb.send().await {
                                    Ok(r) => {
                                        let status = r.status().as_u16();
                                        let resp_headers: Vec<[String; 2]> = r
                                            .headers()
                                            .iter()
                                            .map(|(k, v)| [k.to_string(), v.to_str().unwrap_or("").to_string()])
                                            .collect();
                                        let text = r.text().await.unwrap_or_default();
                                        resp["ok"] = serde_json::json!(true);
                                        resp["status"] = serde_json::json!(status);
                                        resp["headers"] = serde_json::json!(resp_headers);
                                        resp["body"] = serde_json::json!(text);
                                        resp["duration_ms"] = serde_json::json!(started.elapsed().as_millis() as u64);
                                    }
                                    Err(e) => {
                                        resp["ok"] = serde_json::json!(false);
                                        resp["error"] = serde_json::json!(e.to_string());
                                    }
                                }
                                let _ = publisher.publish(status_subject.clone(), resp.to_string().into()).await;
                            }
                            Some("operation") => {
                                // Hand off to run_operation so the pull path reuses the exact
                                // same execution as the push path.
                                let __ctx = OpCtx {
                                    pub_clone: publisher.clone(),
                                    status_subj: status_subject.clone(),
                                    result_subj: format!("cfx.results.{node_id}"),
                                    node_id: node_id.clone(),
                                    http: http_client.clone(),
                                    api_url: api_url.clone(),
                                    api_key: api_key.clone(),
                                };
                                let __cmd = cmd.clone();
                                tokio::spawn(async move { run_operation(__cmd, __ctx).await; });
                            }
                            Some("execute") => {
                                let job_id = cmd["job_id"].as_str().unwrap_or("unknown").to_string();
                                let script = cmd["script"].as_str().unwrap_or("").to_string();
                                let raw_targets = cmd["targets"].as_array();

                                // Same consent gate as shell_exec: a .cfx job is
                                // arbitrary Python from the control plane, run in
                                // this process's privileges. See Config::remote_exec.
                                if !config.remote_exec {
                                    println!("[execute] refused, remote_exec is off: job_id={job_id}");
                                    let resp = serde_json::json!({
                                        "type": "job_failed",
                                        "job_id": job_id,
                                        "node_id": &node_id,
                                        "error": "remote execution is disabled on this node; \
                                                  set remote_exec = true in its config to allow it",
                                    });
                                    let _ = publisher
                                        .publish(status_subject.clone(), resp.to_string().into())
                                        .await;
                                    continue;
                                }

                                let targets: Vec<(String, String)> = raw_targets
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|t| {
                                                let typ = t["type"].as_str()?;
                                                let val = t["value"].as_str()?;
                                                Some((typ.to_string(), val.to_string()))
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();

                                println!("\n[execute] job_id={} targets={} script_len={}",
                                    job_id, targets.len(), script.len());

                                let ctx = executor::JobContext {
                                    node_id: node_id.clone(),
                                    job_id: job_id.clone(),
                                    script,
                                    targets,
                                };
                                let pub_clone = publisher.clone();
                                let subj = format!("cfx.results.{node_id}");
                                tokio::spawn(async move {
                                    let result = executor::execute_job(ctx, pub_clone, subj).await;
                                    match result {
                                        executor::ExecutionResult::Completed { code } =>
                                            println!("[execute] job={job_id} completed code={code}"),
                                        executor::ExecutionResult::Error { message } =>
                                            eprintln!("[execute] job={job_id} error: {message}"),
                                    }
                                });
                            }
                            Some("install_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[install] Installing extension: {ext}");

                                // Built-in package manager: download + verify +
                                // enable + start in one call.
                                let msg = match toolchain::install::install_and_start(&ext).await {
                                    Ok(()) => {
                                        println!("[install] OK {ext} installed and started");
                                        serde_json::json!({
                                            "type": "extension_installed",
                                            "extension": ext,
                                            "started": true,
                                            "node_id": &node_id
                                        })
                                    }
                                    Err(e) => {
                                        eprintln!("[install] FAIL Failed to install {ext}: {e}");
                                        serde_json::json!({
                                            "type": "extension_install_failed",
                                            "extension": ext,
                                            "step": "install",
                                            "node_id": &node_id
                                        })
                                    }
                                };
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("start_postgres") => {
                                println!("\n[toolchain] Starting PostgreSQL...");
                                let success = match toolchain::db::ensure_up() {
                                    Ok(()) => { println!("[toolchain] OK PostgreSQL started"); true }
                                    Err(e) => { eprintln!("[toolchain] FAIL PostgreSQL failed to start: {e}"); false }
                                };

                                let msg = serde_json::json!({
                                    "type": "postgres_started",
                                    "success": success,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("update_node") => {
                                // Dashboard-triggered self-update from the release
                                // manifest. On success the new binary is on disk;
                                // exit non-zero so the node service's
                                // Restart=on-failure brings us back up as the new
                                // version (a clean exit would stay down).
                                println!("\n[update] Updating crossfyre from the release manifest...");
                                let updated = match toolchain::install::fetch_manifest().await {
                                    Ok(manifest) => {
                                        let cur = toolchain::install::installed_cli_version();
                                        toolchain::install::self_update(&manifest, &cur, false, false).await
                                    }
                                    Err(e) => Err(e),
                                };

                                let (success, restarting) = match &updated {
                                    Ok(true) => (true, true),
                                    Ok(false) => (true, false), // already current
                                    Err(e) => {
                                        eprintln!("[update] FAIL {e}");
                                        (false, false)
                                    }
                                };

                                let msg = serde_json::json!({
                                    "type": "node_updated",
                                    "success": success,
                                    "restarting": restarting,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;

                                if restarting {
                                    println!("[update] Restarting to run the new version...");
                                    // Give the publish a moment to flush.
                                    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
                                    std::process::exit(7);
                                }
                            }
                            Some("remove_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[remove] Removing extension: {ext}");

                                let remove_ok = match toolchain::install::remove(&ext) {
                                    Ok(()) => { println!("[remove] OK {ext} removed"); true }
                                    Err(e) => { eprintln!("[remove] FAIL Failed to remove {ext}: {e}"); false }
                                };

                                let msg = serde_json::json!({
                                    "type": "extension_removed",
                                    "extension": ext,
                                    "success": remove_ok,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("restart_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[restart] Restarting extension: {ext}");

                                let msg = match toolchain::service::restart(&ext) {
                                    Ok(()) => {
                                        println!("[restart] OK {ext} restarted");
                                        serde_json::json!({
                                            "type": "extension_restarted",
                                            "extension": ext,
                                            "success": true,
                                            "node_id": &node_id
                                        })
                                    }
                                    Err(e) => {
                                        eprintln!("[restart] FAIL Failed to restart {ext}: {e}");
                                        serde_json::json!({
                                            "type": "extension_restart_failed",
                                            "extension": ext,
                                            "success": false,
                                            "node_id": &node_id
                                        })
                                    }
                                };
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("reinstall_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[reinstall] Reinstalling extension: {ext}");

                                let success = match toolchain::install::install(&ext, true).await {
                                    Ok(()) => {
                                        println!("[reinstall] OK {ext} reinstalled, starting service...");
                                        let _ = toolchain::service::start(&ext);
                                        true
                                    }
                                    Err(e) => {
                                        eprintln!("[reinstall] FAIL Failed to reinstall {ext}: {e}");
                                        false
                                    }
                                };

                                let msg = serde_json::json!({
                                    "type": if success { "extension_reinstalled" } else { "extension_reinstall_failed" },
                                    "extension": ext,
                                    "success": success,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("stop_extension") => {
                                let ext = cmd["extension"].as_str().unwrap_or("").to_string();
                                println!("\n[stop] Stopping extension: {ext}");

                                let success = match toolchain::service::stop(&ext) {
                                    Ok(()) => { println!("[stop] OK {ext} stopped"); true }
                                    Err(e) => { eprintln!("[stop] FAIL Failed to stop {ext}: {e}"); false }
                                };

                                let msg = serde_json::json!({
                                    "type": if success { "extension_stopped" } else { "extension_stop_failed" },
                                    "extension": ext,
                                    "success": success,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            Some("set_ports") => {
                                // Dashboard changed one or more service ports.
                                // Persist to config.toml, then restart exactly
                                // the services that moved: re-create the DB
                                // container on the new port, and rewrite +
                                // restart each affected engine's unit (the unit
                                // template reads config.toml for its --port).
                                println!("\n[ports] Applying service port changes...");
                                let changed = reconcile_ports(&cmd["ports"]);
                                if !changed.is_empty() {
                                    println!("[ports] Applied: {}", changed.join(", "));
                                }

                                let msg = serde_json::json!({
                                    "type": "ports_applied",
                                    "changed": changed,
                                    "node_id": &node_id
                                });
                                let _ = publisher.publish(status_subject.clone(), msg.to_string().into()).await;
                            }
                            _ => {
                                println!("Received unknown job command: {body}");
                            }
                        }
                    }
                }
            }
        }
    }

    println!("Node daemon stopped.");
    Ok(())
}

/// Run a .cfx script locally without NATS.  For development / testing.
///
/// Usage: crossfyre run tests/test.cfx domain:example.com domain:test.org
pub async fn run_script(
    script_path: &str,
    raw_targets: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let targets: Vec<(String, String)> = raw_targets
        .iter()
        .map(|s| {
            if let Some((t, v)) = s.split_once(':') {
                (t.to_string(), v.to_string())
            } else {
                // Default to "domain" if no type prefix
                ("domain".to_string(), s.to_string())
            }
        })
        .collect();

    println!(
        "Running {} with {} target(s)...\n",
        script_path,
        targets.len()
    );

    let result = executor::execute_local(script_path, targets).await;

    match result {
        executor::ExecutionResult::Completed { code } => {
            println!("\nScript finished with code {code}");
        }
        executor::ExecutionResult::Error { message } => {
            eprintln!("\nScript failed: {message}");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Stage the Cloudflare Origin CA root next to the node config and return its
/// path. async-nats takes a path rather than bytes, so the root is embedded in
/// the binary and written out on connect. Rewritten every time so a truncated or
/// tampered copy on disk cannot persist.
fn write_origin_root_cert() -> std::io::Result<std::path::PathBuf> {
    const ORIGIN_ROOT: &str = include_str!("../assets/cloudflare-origin-root.pem");
    let dir = std::env::var("CFX_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("cfx-nats-root.pem");
    std::fs::write(&path, ORIGIN_ROOT)?;
    Ok(path)
}

#[cfg(test)]
mod security_tests {
    use super::*;

    /// C-2: the node config holds the broker seed, the broker JWT and the
    /// account key. It used to be written at the process umask, which in
    /// practice meant 0644, next to an auth.toml that was correctly 0600.
    #[cfg(unix)]
    #[test]
    fn a_secret_file_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cfx-sec-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("secret.toml");
        write_secret_file(&p, "nats_nkey_seed = \"S...\"").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "written {mode:o}, expected 600");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Overwriting an existing wide-open file must also tighten it: `mode` on
    /// OpenOptions only applies at creation.
    #[cfg(unix)]
    #[test]
    fn rewriting_an_existing_file_tightens_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cfx-sec2-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("secret.toml");
        fs::write(&p, "old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_file(&p, "new").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "left {mode:o} on an existing file");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Installs written before this existed still have 0644 configs on disk, and
    /// a normal start does not rewrite the file, so load-time repair is the only
    /// thing that fixes them.
    #[cfg(unix)]
    #[test]
    fn an_existing_wide_open_config_is_repaired_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cfx-sec3-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("node.toml");
        fs::write(&p, "api_key = \"x\"").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        repair_secret_file_mode(&p);
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "repair left {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// H-2: shell_exec and .cfx run control-plane input in this process's
    /// privileges, and the node runs as root on a default install. Server-side
    /// authorization cannot protect the host from a compromised control plane or
    /// stolen broker credentials, so the node has to consent too, and a config
    /// that never mentions the flag must not consent by accident.
    #[test]
    fn remote_exec_is_off_when_the_config_does_not_mention_it() {
        let cfg: Config = toml::from_str(
            r#"
            api_key = "k"
            node_id = "n"
            api_url = "https://example.invalid"
            "#,
        )
        .expect("a config without remote_exec must still parse");
        assert!(!cfg.remote_exec, "remote execution defaulted ON");
    }

    #[test]
    fn remote_exec_is_honoured_when_explicitly_enabled() {
        let cfg: Config = toml::from_str(
            r#"
            api_key = "k"
            node_id = "n"
            api_url = "https://example.invalid"
            remote_exec = true
            "#,
        )
        .expect("parse");
        assert!(cfg.remote_exec, "an explicit opt-in was ignored");
    }
}
