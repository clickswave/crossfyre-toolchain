use crate::libs::cli_args;
use crate::store::{Outcome, Store, Work};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub url: String,
    pub scan_status: String,
    pub request_status: String,
    pub body_length: i64,
    pub headers_length: i64,
}

#[derive(Debug, Clone)]
pub struct ScanResultTotals {
    pub found: usize,
    pub not_found: usize,
    pub error: usize,
    pub entries: usize,
}

/// What a scan found, and how many of its requests found something, found nothing and
/// failed.
#[derive(Debug)]
pub struct ScanResults {
    pub found: Vec<ScanResult>,
    pub totals: ScanResultTotals,
}

/// Events streamed from the daemon to the fuzz client over TCP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    // Requests actually sent so far, including 429/retry re-sends (>= total).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tested: Option<usize>,
    // Retries this probe needed (>0 = it hit a transient error like 429). The
    // RAW stress signal the node can't otherwise see, since the final outcome is
    // usually recovered. Drives the node's concurrency coordination (Phase C.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    // Adaptive-rate telemetry (kind == "governor"): the controller's current
    // operating point, for the pacing strip. These are the same values the
    // controller already hands the engine each tick, read here rather than
    // decided here. Emitted only in tuning builds; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Present only when redirects were followed AND the response came back from a
    /// different URL than the one probed. The final destination, so the node and
    /// UI can show "requested -> final". Absent for a direct hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
}

pub struct Scanner<S: Store> {
    config: cli_args::Args,
    store: Arc<S>,
}
impl<S: Store> Scanner<S> {
    pub fn new(config: cli_args::Args, store: S) -> Self {
        Scanner {
            config,
            store: Arc::new(store),
        }
    }

    /// Run scan headlessly (no TUI) - used by daemon mode.
    /// Blocks until all work is exhausted, then returns the final results.
    pub async fn run_headless(&self) -> Result<ScanResults, String> {
        let mut join_set = tokio::task::JoinSet::new();

        let arc_config = Arc::new(self.config.clone());
        let arc_throttle = Arc::new(AtomicU64::new(0));
        let arc_tested = Arc::new(AtomicU64::new(0));

        let arc_prober = match crate::prober::Prober::new(&self.config).await {
            Ok(mut prober) => {
                prober.calibrate().await;
                Arc::new(prober)
            }
            Err(e) => {
                eprintln!("Failed to create prober: {e:?}");
                let why = format!("Failed to create prober: {e:?}");
                self.store.log("error", &why).await;
                return Err(why);
            }
        };

        for _ in 0..self.config.tasks {
            join_set.spawn(task_handle(
                Arc::clone(&arc_config),
                Arc::clone(&self.store),
                Arc::clone(&arc_prober),
                Arc::clone(&arc_throttle),
                Arc::clone(&arc_tested),
                None,
            ));
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                eprintln!("Task failed: {e:?}");
                self.store
                    .log("error", &format!("Task failed: {e:?}"))
                    .await;
            }
        }

        self.store.results().await
    }

    /// Run scan headlessly, streaming per-result events through `tx`.
    /// Sends a final "done" event when all work is exhausted.
    pub async fn run_headless_stream(
        &self,
        tx: mpsc::UnboundedSender<StreamEvent>,
    ) -> Result<ScanResults, String> {
        let mut join_set = tokio::task::JoinSet::new();

        let arc_config = Arc::new(self.config.clone());
        let arc_throttle = Arc::new(AtomicU64::new(0));
        let arc_tested = Arc::new(AtomicU64::new(0));
        let arc_tx = Arc::new(tx);

        let arc_prober = match crate::prober::Prober::new(&self.config).await {
            Ok(mut prober) => {
                // Learn the target's soft-404 behaviour before the wordlist runs, so a wildcard
                // "200 for everything" target does not turn every probe into a false finding.
                prober.calibrate().await;
                Arc::new(prober)
            }
            Err(e) => {
                let why = format!("Failed to create prober: {e:?}");
                self.store.log("error", &why).await;
                return Err(why);
            }
        };

        // Adaptive path: a controller ticker sizes concurrency/delay and gates a
        // max-sized worker pool; retries follow the health-aware policy. When
        // neither adaptive flag is set we spawn the fixed pool exactly as before.
        let adaptive_on = self.config.adaptive_rate || self.config.adaptive_resilience;
        let ticker_handle = if adaptive_on {
            let posture = adaptive::Posture::from_str_lenient(&self.config.posture);
            // `tasks` is already the tier-capped ceiling (api_switch clamps it),
            // so it is the max concurrency the controller may ramp to.
            let max_conc = (self.config.tasks.max(1)) as u64;
            let caps = adaptive::Caps {
                min_concurrency: 1,
                max_concurrency: max_conc as u32,
                max_delay_ms: 5_000,
                max_retries: 5,
            };
            let shared = Arc::new(AdaptiveShared {
                window: Mutex::new(adaptive::HealthWindow::new(200, 20)),
                target_conc: AtomicU64::new(if self.config.adaptive_rate {
                    1
                } else {
                    max_conc
                }),
                delay_ms: AtomicU64::new(self.config.interval),
                score_bits: AtomicU64::new(1.0f64.to_bits()),
                rate_on: self.config.adaptive_rate,
                drained: AtomicBool::new(false),
                resilience: adaptive::ResilienceController::new(posture, caps.max_retries),
            });
            let stop = Arc::new(AtomicBool::new(false));
            let ticker = tokio::spawn(controller_tick(
                Arc::clone(&shared),
                posture,
                caps,
                self.config.interval,
                Arc::clone(&stop),
                Some(Arc::clone(&arc_tx)),
            ));
            for i in 0..max_conc {
                join_set.spawn(adaptive_task_handle(
                    Arc::clone(&arc_config),
                    Arc::clone(&self.store),
                    Arc::clone(&arc_prober),
                    Arc::clone(&arc_tested),
                    Arc::clone(&shared),
                    i,
                    Some(Arc::clone(&arc_tx)),
                ));
            }
            let msg = format!(
                "Adaptive engine on: posture={} rate={} resilience={} max_concurrency={}",
                self.config.posture,
                self.config.adaptive_rate,
                self.config.adaptive_resilience,
                max_conc
            );
            eprintln!("[ambulo] {msg}");
            self.store.log("info", &msg).await;
            Some((ticker, stop))
        } else {
            for _ in 0..self.config.tasks {
                join_set.spawn(task_handle(
                    Arc::clone(&arc_config),
                    Arc::clone(&self.store),
                    Arc::clone(&arc_prober),
                    Arc::clone(&arc_throttle),
                    Arc::clone(&arc_tested),
                    Some(Arc::clone(&arc_tx)),
                ));
            }
            None
        };

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                self.store
                    .log("error", &format!("Task failed: {e:?}"))
                    .await;
            }
        }

        // Stop the controller once every worker has exited.
        if let Some((ticker, stop)) = ticker_handle {
            stop.store(true, Ordering::Relaxed);
            ticker.abort();
        }

        let results = self.store.results().await?;

        let _ = arc_tx.send(StreamEvent {
            kind: "done".to_string(),
            found: Some(results.totals.found),
            not_found: Some(results.totals.not_found),
            error: Some(results.totals.error),
            total: Some(results.totals.entries),
            tested: Some(arc_tested.load(Ordering::Relaxed) as usize),
            retries: None,
            operation_id: None,
            url: None,
            status: None,
            code: None,
            body_length: None,
            headers_length: None,
            log_level: None,
            message: None,
            concurrency: None,
            delay_ms: None,
            posture: None,
            score: None,
            final_url: None,
        });

        Ok(results)
    }
}

// Adaptive rate-limit control (shared across all workers of one scan).
const RL_STEP_MS: u64 = 120; // throttle bump per 429
const RL_CAP_MS: u64 = 3_000; // max added delay between probes
const RL_MAX_RETRIES: u32 = 5; // per-probe 429 retries before giving up

/// Parse a `Retry-After: <seconds>` header into milliseconds (capped). The
/// HTTP-date form is uncommon for 429 and is ignored (falls back to backoff).
fn parse_retry_after(headers: &Option<Vec<String>>) -> Option<u64> {
    for h in headers.as_ref()? {
        if let Some(rest) = h.to_ascii_lowercase().strip_prefix("retry-after:")
            && let Ok(secs) = rest.trim().parse::<u64>()
        {
            return Some((secs * 1000).min(30_000));
        }
    }
    None
}

// Worker entry point: every argument is a distinct channel, budget or shared
// handle. Bundling them hides which parts a task actually touches.
#[allow(clippy::too_many_arguments)]
async fn task_handle<S: Store>(
    config: Arc<cli_args::Args>,
    store: Arc<S>,
    prober: Arc<crate::prober::Prober>,
    // Shared adaptive throttle (ms) added between probes; grows on 429s so the
    // whole scan backs off the target and stops losing findings to rate limits.
    throttle: Arc<AtomicU64>,
    // Shared count of requests actually sent (each attempt, incl. 429 retries).
    tested: Arc<AtomicU64>,
    event_tx: Option<Arc<mpsc::UnboundedSender<StreamEvent>>>,
) -> Result<(), sqlx::Error> {
    loop {
        let wait_ms = config.interval + throttle.load(Ordering::Relaxed);
        if wait_ms > 0 {
            sleep(Duration::from_millis(wait_ms)).await;
        }

        // If the result-stream consumer (the node) has disconnected, stop:
        // nobody is listening, so continuing would just keep hammering the
        // target after a pause/halt/delete. The node closes this stream when
        // it receives cancel_workflow, so this is the engine-side half of
        // honoring cancellation. Checked before fetching work, so no further
        // probe is issued once the consumer is gone.
        if let Some(ref tx) = event_tx
            && tx.is_closed()
        {
            store
                .log(
                    "info",
                    "Result stream consumer disconnected - stopping scan",
                )
                .await;
            return Ok(());
        }

        let work = match store.claim().await {
            Ok(Some(work)) => work,
            Ok(None) => {
                store.log("info", "No work available, exiting thread").await;
                return Ok(());
            }
            Err(e) => {
                let msg = format!("Error fetching work: {e}");
                store.log("error", &msg).await;
                emit_log(&event_tx, "error", &msg);
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        tested.fetch_add(1, Ordering::Relaxed);
        let mut probe = prober
            .probe_url(&work, config.random_user_agent_request)
            .await;
        // Rate-limit handling: a 429 usually means the path exists but the target
        // is throttling us. Treating it as "not found" silently loses findings, so
        // back off (Retry-After or exponential) and re-probe, while bumping the
        // shared throttle so every worker slows down until the target recovers.
        let mut rl_attempt = 0u32;
        while matches!(&probe, Ok(r) if r.response.status == 429) {
            let cur = throttle.load(Ordering::Relaxed);
            throttle.store((cur + RL_STEP_MS).min(RL_CAP_MS), Ordering::Relaxed);
            if rl_attempt >= RL_MAX_RETRIES {
                break;
            }
            rl_attempt += 1;
            let backoff = probe
                .as_ref()
                .ok()
                .and_then(|r| parse_retry_after(&r.response.headers))
                .unwrap_or((RL_STEP_MS * (1u64 << rl_attempt.min(5))).min(RL_CAP_MS));
            emit_log(
                &event_tx,
                "debug",
                &format!(
                    "[429] {} rate-limited, backoff {}ms (retry {}/{})",
                    work.url, backoff, rl_attempt, RL_MAX_RETRIES
                ),
            );
            sleep(Duration::from_millis(backoff)).await;
            if let Some(ref tx) = event_tx
                && tx.is_closed()
            {
                return Ok(());
            }
            tested.fetch_add(1, Ordering::Relaxed);
            probe = prober
                .probe_url(&work, config.random_user_agent_request)
                .await;
        }
        // Decay the throttle on any non-429 outcome so the scan speeds back up
        // once the target stops limiting.
        if !matches!(&probe, Ok(r) if r.response.status == 429) {
            let cur = throttle.load(Ordering::Relaxed);
            throttle.store(cur.saturating_sub(RL_STEP_MS), Ordering::Relaxed);
        }
        record_outcome(&*store, &event_tx, &tested, &work, probe, rl_attempt).await;
    }
}

/// Persist a probe outcome and emit its stream event. Shared verbatim by the
/// fixed-pool `task_handle` and the adaptive `adaptive_task_handle` so both
/// record results identically.
async fn record_outcome(
    store: &impl Store,
    event_tx: &Option<Arc<mpsc::UnboundedSender<StreamEvent>>>,
    tested: &AtomicU64,
    work: &Work,
    probe: Result<crate::prober::ProbeResult, crate::prober::ProbeError>,
    retries: u32,
) {
    match probe {
        Ok(result) => {
            let outcome = Outcome {
                status: &result.status,
                code: &result.response.status.to_string(),
                body_length: result.response.body_length,
                headers_length: result.response.headers_length,
            };
            if let Err(e) = store.record(work.entry_id, outcome).await {
                let msg = format!("Failed to update work status: {e}");
                store.log("error", &msg).await;
                emit_log(event_tx, "error", &msg);
                let _ = store.release(work.entry_id).await;
                return;
            }

            emit_log(
                event_tx,
                if result.status == "found" {
                    "info"
                } else {
                    "debug"
                },
                &format!(
                    "[{}] {} {}",
                    result.response.status,
                    result.status.to_uppercase(),
                    work.url
                ),
            );

            if let Some(tx) = event_tx {
                let _ = tx.send(StreamEvent {
                    kind: "result".to_string(),
                    tested: Some(tested.load(Ordering::Relaxed) as usize),
                    retries: Some(retries),
                    url: Some(work.url.clone()),
                    status: Some(result.status.clone()),
                    code: Some(result.response.status.to_string()),
                    body_length: Some(result.response.body_length),
                    headers_length: Some(result.response.headers_length),
                    operation_id: None,
                    total: None,
                    found: None,
                    not_found: None,
                    error: None,
                    log_level: None,
                    message: None,
                    concurrency: None,
                    delay_ms: None,
                    posture: None,
                    score: None,
                    // Only when the response came back from a different URL than we
                    // asked for, i.e. redirects were followed to somewhere else.
                    final_url: (result.response.final_url != work.url)
                        .then(|| result.response.final_url.clone()),
                });
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            store.log("error", &err_msg).await;
            let (entry_status, code) = match &e {
                crate::prober::ProbeError::UnsupportedMethod(_) => ("error", "EXCEPT"),
                crate::prober::ProbeError::RequestFailed(_) => ("error", "0"),
            };
            emit_log(
                event_tx,
                "error",
                &format!("[{}] {} {}", code, work.url, err_msg),
            );
            let outcome = Outcome {
                status: entry_status,
                code,
                body_length: 0,
                headers_length: 0,
            };
            if let Err(e) = store.record(work.entry_id, outcome).await {
                let msg = format!("Failed to update error status: {e}");
                store.log("error", &msg).await;
                emit_log(event_tx, "error", &msg);
                let _ = store.release(work.entry_id).await;
            }
            if let Some(tx) = event_tx {
                let _ = tx.send(StreamEvent {
                    kind: "result".to_string(),
                    tested: Some(tested.load(Ordering::Relaxed) as usize),
                    retries: Some(retries),
                    url: Some(work.url.clone()),
                    status: Some("error".to_string()),
                    code: Some(code.to_string()),
                    body_length: Some(0),
                    headers_length: Some(0),
                    operation_id: None,
                    total: None,
                    found: None,
                    not_found: None,
                    error: None,
                    log_level: None,
                    message: None,
                    concurrency: None,
                    delay_ms: None,
                    posture: None,
                    score: None,
                    final_url: None,
                });
            }
        }
    }
}

fn emit_log(event_tx: &Option<Arc<mpsc::UnboundedSender<StreamEvent>>>, level: &str, msg: &str) {
    if let Some(tx) = event_tx {
        let _ = tx.send(StreamEvent {
            kind: "log".to_string(),
            tested: None,
            retries: None,
            log_level: Some(level.to_string()),
            message: Some(msg.to_string()),
            operation_id: None,
            total: None,
            url: None,
            status: None,
            code: None,
            body_length: None,
            headers_length: None,
            found: None,
            not_found: None,
            error: None,
            concurrency: None,
            delay_ms: None,
            posture: None,
            score: None,
            final_url: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Adaptive path: controller-driven concurrency, delay and retries.
//
// Only used when the scan enables adaptive_rate and/or adaptive_resilience. The
// fixed-pool `task_handle` above is left untouched, so a non-adaptive scan runs
// exactly the code it always did.
// ---------------------------------------------------------------------------

/// Shared state between the controller ticker and the adaptive workers of one
/// scan. All hot-path reads are lock-free atomics; only `window` takes a brief
/// lock per probe to record an outcome.
struct AdaptiveShared {
    /// Rolling target health; workers push outcomes, the ticker reads snapshots.
    window: Mutex<adaptive::HealthWindow>,
    /// Current desired concurrency (workers with index >= this park).
    target_conc: AtomicU64,
    /// Current inter-probe delay in ms.
    delay_ms: AtomicU64,
    /// Latest health score as f64 bits, published by the ticker for resilience.
    score_bits: AtomicU64,
    /// Whether the rate controller drives concurrency+delay (else fixed).
    rate_on: bool,
    /// Set once the work queue is exhausted, so parked workers (those above the
    /// current concurrency target) exit instead of waiting for a ramp that may
    /// never come on a stressed target.
    drained: AtomicBool,
    /// Retry policy decider (always present on the adaptive path).
    resilience: adaptive::ResilienceController,
}

/// Map a probe result to a health class. Success vs NotFound is the finding
/// view; any request failure counts as a drop (same health bucket as timeout).
fn classify(
    probe: &Result<crate::prober::ProbeResult, crate::prober::ProbeError>,
) -> adaptive::ProbeClass {
    use adaptive::ProbeClass;
    match probe {
        Ok(r) => {
            let s = r.response.status;
            if s == 429 {
                ProbeClass::RateLimited
            } else if (500..=599).contains(&s) {
                ProbeClass::ServerError
            } else if r.status == "found" {
                ProbeClass::Success
            } else {
                ProbeClass::NotFound
            }
        }
        Err(crate::prober::ProbeError::RequestFailed(_)) => ProbeClass::ConnError,
        // A method the target can't handle is a config issue, not target stress.
        Err(crate::prober::ProbeError::UnsupportedMethod(_)) => ProbeClass::NotFound,
    }
}

/// Periodic control loop: snapshot health, advance the AIMD controller, publish
/// the new concurrency/delay (when rate-adaptive) and the score (always, for
/// resilience). Runs until `stop` is set.
async fn controller_tick(
    shared: Arc<AdaptiveShared>,
    posture: adaptive::Posture,
    caps: adaptive::Caps,
    start_delay_ms: u64,
    stop: Arc<AtomicBool>,
    // Used only by the tuning build to stream the operating point to the
    // dashboard. Threaded unconditionally so the signature does not fork
    // between builds; the default build simply never reads it.
    event_tx: Option<Arc<mpsc::UnboundedSender<StreamEvent>>>,
) {
    let _ = &event_tx;
    // Optimistic start: begin at full concurrency and back off multiplicatively
    // on 429s. A slow-start ramp never completes within a short content-discovery
    // chunk, so it would leave the whole scan crawling.
    let mut rc = adaptive::RateController::new_optimistic(posture, caps, start_delay_ms);
    #[cfg(feature = "tuning")]
    let mut ticks: u32 = 0;
    loop {
        sleep(Duration::from_millis(250)).await;
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let stats = { shared.window.lock().unwrap().stats() };
        let dir = rc.tick(&stats);
        if shared.rate_on {
            shared
                .target_conc
                .store(dir.concurrency as u64, Ordering::Relaxed);
            shared.delay_ms.store(dir.delay_ms, Ordering::Relaxed);
        }
        shared
            .score_bits
            .store(rc.last_score().to_bits(), Ordering::Relaxed);

        // Publish the operating point about once a second. Only the tuning
        // build compiles this, so a default daemon emits no governor events and
        // its wire stays exactly as it was.
        #[cfg(feature = "tuning")]
        {
            ticks += 1;
            if ticks % 4 == 0
                && let Some(tx) = &event_tx
            {
                let _ = tx.send(StreamEvent {
                    kind: "governor".to_string(),
                    concurrency: Some(dir.concurrency),
                    delay_ms: Some(dir.delay_ms),
                    posture: Some(format!("{:?}", rc.posture()).to_lowercase()),
                    score: Some(rc.last_score()),
                    ..Default::default()
                });
            }
        }
    }
}

/// One adaptive worker. Gates its own activity on the controller's target
/// concurrency, paces on the controller's delay, records each outcome into the
/// shared health window, and retries transient failures per the resilience
/// policy (health-gated when adaptive_resilience is on).
// Worker entry point: every argument is a distinct channel, budget or shared
// handle. Bundling them hides which parts a task actually touches.
#[allow(clippy::too_many_arguments)]
async fn adaptive_task_handle<S: Store>(
    config: Arc<cli_args::Args>,
    store: Arc<S>,
    prober: Arc<crate::prober::Prober>,
    tested: Arc<AtomicU64>,
    shared: Arc<AdaptiveShared>,
    worker_index: u64,
    event_tx: Option<Arc<mpsc::UnboundedSender<StreamEvent>>>,
) -> Result<(), sqlx::Error> {
    loop {
        // Concurrency gate: park while this worker sits above the current target.
        if shared.rate_on {
            while worker_index >= shared.target_conc.load(Ordering::Relaxed).max(1) {
                // Exit if the queue drained (another worker hit RowNotFound) or the
                // consumer disconnected, don't wait for a ramp that may never come.
                if shared.drained.load(Ordering::Relaxed) {
                    return Ok(());
                }
                if let Some(ref tx) = event_tx
                    && tx.is_closed()
                {
                    return Ok(());
                }
                sleep(Duration::from_millis(80)).await;
            }
        }

        // Pace: controller delay when rate-adaptive, else the fixed interval.
        let delay = if shared.rate_on {
            shared.delay_ms.load(Ordering::Relaxed)
        } else {
            config.interval
        };
        if delay > 0 {
            sleep(Duration::from_millis(delay)).await;
        }

        if let Some(ref tx) = event_tx
            && tx.is_closed()
        {
            store
                .log(
                    "info",
                    "Result stream consumer disconnected - stopping scan",
                )
                .await;
            return Ok(());
        }

        let work = match store.claim().await {
            Ok(Some(work)) => work,
            Ok(None) => {
                // Queue empty: signal parked workers to stop, then exit.
                shared.drained.store(true, Ordering::Relaxed);
                store.log("info", "No work available, exiting thread").await;
                return Ok(());
            }
            Err(e) => {
                let msg = format!("Error fetching work: {e}");
                store.log("error", &msg).await;
                emit_log(&event_tx, "error", &msg);
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        // Probe with health-gated retries.
        let mut attempt = 0u32;
        let final_probe = loop {
            tested.fetch_add(1, Ordering::Relaxed);
            let t0 = Instant::now();
            let probe = prober
                .probe_url(&work, config.random_user_agent_request)
                .await;
            let rtt_ms = t0.elapsed().as_millis() as u64;
            let class = classify(&probe);
            {
                shared.window.lock().unwrap().record(class, rtt_ms);
            }

            if adaptive::ResilienceController::retryable(class) {
                // Health-gated when resilience is adaptive; otherwise treat the
                // target as healthy so it retries up to the posture's max.
                let score = if config.adaptive_resilience {
                    f64::from_bits(shared.score_bits.load(Ordering::Relaxed))
                } else {
                    1.0
                };
                let retry_after = probe
                    .as_ref()
                    .ok()
                    .and_then(|r| parse_retry_after(&r.response.headers));
                let d = shared.resilience.decide(
                    class,
                    attempt,
                    &adaptive::HealthStats::empty(),
                    score,
                    retry_after,
                );
                if d.retry {
                    attempt += 1;
                    emit_log(
                        &event_tx,
                        "debug",
                        &format!(
                            "[retry {}] {} (backoff {}ms)",
                            attempt, work.url, d.backoff_ms
                        ),
                    );
                    if d.backoff_ms > 0 {
                        sleep(Duration::from_millis(d.backoff_ms)).await;
                    }
                    if let Some(ref tx) = event_tx
                        && tx.is_closed()
                    {
                        return Ok(());
                    }
                    continue;
                }
            }
            break probe;
        };

        record_outcome(&*store, &event_tx, &tested, &work, final_probe, attempt).await;
    }
}
