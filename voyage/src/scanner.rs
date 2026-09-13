use crate::libs::voyage_db::{VoyageDb, Work};
use crate::scanners::active_scan;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

/// Configuration for a single enumeration run.
#[derive(Clone)]
pub struct EnumConfig {
    pub scan_id: String,
    #[allow(dead_code)] // populated but not read yet; kept so the struct still mirrors its config
    pub domain: String,
    pub tasks: usize,
    pub interval_ms: u64,
    #[allow(dead_code)] // populated but not read yet; kept so the struct still mirrors its config
    pub exclude_passive_sources: Vec<String>,
    pub exclude_active_techniques: Vec<String>,
    pub http_probing_ports: Vec<u16>,
    pub https_probing_ports: Vec<u16>,
    pub active_user_agent: String,
    #[allow(dead_code)] // populated but not read yet; kept so the struct still mirrors its config
    pub passive_user_agent: String,
    pub active_random_user_agent: bool,
    pub dns_server: String,
    /// Adaptive rate limiting for the ACTIVE brute-force: tune concurrency from
    /// DNS health (timeout/SERVFAIL rate). Off = fixed `tasks`.
    pub adaptive_rate: bool,
    /// Adaptive resilience: retry transient DNS failures (lossy UDP) to recover
    /// subdomains that would otherwise be dropped.
    pub adaptive_resilience: bool,
    /// Controller posture: stealth | balanced | throughput.
    pub posture: String,
    /// Evasiveness posture: present as a real browser (default) vs neutral.
    pub evasive: bool,
    /// Attribution token for authorized programs (sent as X-Bug-Bounty).
    pub identify: Option<String>,
    /// Refuse to connect to private / reserved addresses when probing.
    ///
    /// Set by the public free tools. Liveness probing dials whatever names the
    /// passive sources returned for a domain the caller chose, so an attacker
    /// who registers a domain with records pointing inward can otherwise aim
    /// those probes at our own network.
    pub block_internal: bool,
}

/// Events streamed from the daemon to the enum client over TCP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    // Adaptive-rate telemetry (kind == "governor"): the controller's current
    // operating point, for the pacing strip. The same values the controller
    // hands the engine each tick, read here rather than decided here. Emitted
    // only in tuning builds; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

pub struct Scanner {
    pub config: Arc<EnumConfig>,
    pub db: Arc<VoyageDb>,
}

impl Scanner {
    pub fn new(config: EnumConfig, db: Arc<VoyageDb>) -> Self {
        Scanner {
            config: Arc::new(config),
            db,
        }
    }

    /// Emit passive results already in DB, then run active workers and stream all events.
    pub async fn run_headless_stream(
        &self,
        tx: mpsc::UnboundedSender<StreamEvent>,
    ) -> Result<(), sqlx::Error> {
        let arc_tx = Arc::new(tx);

        // Emit passive results first (already inserted by prepare_enum)
        let passive_results = self.db.get_passive_results(&self.config.scan_id).await?;
        for r in &passive_results {
            let _ = arc_tx.send(StreamEvent {
                kind: "result".to_string(),
                subdomain: Some(r.full_subdomain.clone()),
                status: Some("found".to_string()),
                source: Some(r.source.clone()),
                operation_id: None,
                total: None,
                found: None,
                not_found: None,
                log_level: None,
                message: None,
                error: None,
                ..Default::default()
            });
        }

        // Spawn active worker tasks. When adaptive is on, a controller ticker sizes
        // concurrency/delay from live DNS health and the workers gate + retry; else
        // the fixed pool runs exactly as before.
        let mut join_set = tokio::task::JoinSet::new();
        let adaptive_on = self.config.adaptive_rate || self.config.adaptive_resilience;
        let ticker_handle = if adaptive_on {
            let posture = adaptive::Posture::from_str_lenient(&self.config.posture);
            let max_conc = self.config.tasks.max(1) as u64;
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
                delay_ms: AtomicU64::new(self.config.interval_ms),
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
                self.config.interval_ms,
                Arc::clone(&stop),
                Some(Arc::clone(&arc_tx)),
            ));
            for i in 0..max_conc {
                join_set.spawn(adaptive_task_handle(
                    Arc::clone(&self.config),
                    Arc::clone(&self.db),
                    Arc::clone(&arc_tx),
                    Arc::clone(&shared),
                    i,
                ));
            }
            emit_log(
                &Some(Arc::clone(&arc_tx)),
                "info",
                &format!(
                    "Adaptive active enum on: posture={} rate={} resilience={} max_concurrency={}",
                    self.config.posture,
                    self.config.adaptive_rate,
                    self.config.adaptive_resilience,
                    max_conc
                ),
            );
            Some((ticker, stop))
        } else {
            for _ in 0..self.config.tasks {
                join_set.spawn(task_handle(
                    Arc::clone(&self.config),
                    Arc::clone(&self.db),
                    Arc::clone(&arc_tx),
                ));
            }
            None
        };

        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                emit_log(
                    &Some(Arc::clone(&arc_tx)),
                    "error",
                    &format!("Task panicked: {e:?}"),
                );
            }
        }

        if let Some((ticker, stop)) = ticker_handle {
            stop.store(true, Ordering::Relaxed);
            ticker.abort();
        }

        // Get final totals and send "done"
        let (found, not_found) = self
            .db
            .get_scan_totals(&self.config.scan_id)
            .await
            .unwrap_or((0, 0));

        let _ = arc_tx.send(StreamEvent {
            kind: "done".to_string(),
            found: Some(found as usize),
            not_found: Some(not_found as usize),
            total: Some((found + not_found) as usize),
            operation_id: None,
            subdomain: None,
            status: None,
            source: None,
            log_level: None,
            message: None,
            error: None,
            ..Default::default()
        });

        Ok(())
    }
}

async fn task_handle(
    config: Arc<EnumConfig>,
    db: Arc<VoyageDb>,
    event_tx: Arc<mpsc::UnboundedSender<StreamEvent>>,
) -> Result<(), sqlx::Error> {
    let resolver = match crate::libs::dns::create_resolver(Some(config.dns_server.as_str())) {
        Ok(r) => r,
        Err(e) => {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("DNS resolver error: {e}"),
            );
            return Ok(());
        }
    };

    let user_agent = if config.active_random_user_agent {
        crate::libs::rng::user_agent()
    } else {
        config.active_user_agent.clone()
    };

    let mut extra_headers = transport::HeaderMap::new();
    if let Some(token) = &config.identify {
        if let Ok(val) = transport::HeaderValue::from_str(token) {
            extra_headers.insert(transport::HeaderName::from_static("x-bug-bounty"), val);
        }
    }
    let client = match transport::build_client(transport::ClientConfig {
        block_internal: config.block_internal,
        timeout: Some(Duration::from_secs(10)),
        user_agent: Some(user_agent.clone()),
        emulate: config.evasive,
        extra_headers,
        ..Default::default()
    }) {
        Ok(c) => c,
        Err(e) => {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("HTTP client build error: {e}"),
            );
            return Ok(());
        }
    };

    loop {
        if config.interval_ms > 0 {
            sleep(Duration::from_millis(config.interval_ms)).await;
        }

        let work: Work = match db.get_work_one(&config.scan_id).await {
            Ok(w) => w,
            Err(sqlx::Error::RowNotFound) => {
                // No queued work - check if any tasks are still actively scanning
                match db.is_scanning_active(&config.scan_id).await {
                    Ok(true) => {
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    _ => return Ok(()),
                }
            }
            Err(e) => {
                emit_log(
                    &Some(event_tx.clone()),
                    "error",
                    &format!("get_work_one error: {e}"),
                );
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        let scan_result = active_scan::execute(
            &resolver,
            &client,
            &config.exclude_active_techniques,
            &config.http_probing_ports,
            &config.https_probing_ports,
            &work.full_subdomain,
        )
        .await;

        // Log negative results (debug/info level only)
        for neg in &scan_result.negatives {
            emit_log(&Some(event_tx.clone()), &neg.level, &neg.description);
        }

        let status = if scan_result.found {
            "found"
        } else {
            "not_found"
        };
        let source = &scan_result.source;

        if let Err(e) = db.update_work_status(work.entry_id, status, source).await {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("update_work_status failed: {e}"),
            );
            let _ = db.reset_entry_to_queued(work.entry_id).await;
            continue;
        }

        if scan_result.found {
            emit_log(
                &Some(event_tx.clone()),
                "info",
                &format!("FOUND: {} ({})", work.full_subdomain, source),
            );
        }

        let _ = event_tx.send(StreamEvent {
            kind: "result".to_string(),
            subdomain: Some(work.full_subdomain),
            status: Some(status.to_string()),
            source: Some(source.clone()),
            operation_id: None,
            total: None,
            found: None,
            not_found: None,
            log_level: None,
            message: None,
            error: None,
            ..Default::default()
        });
    }
}

fn emit_log(event_tx: &Option<Arc<mpsc::UnboundedSender<StreamEvent>>>, level: &str, msg: &str) {
    if let Some(tx) = event_tx {
        let _ = tx.send(StreamEvent {
            kind: "log".to_string(),
            log_level: Some(level.to_string()),
            message: Some(msg.to_string()),
            operation_id: None,
            total: None,
            subdomain: None,
            status: None,
            source: None,
            found: None,
            not_found: None,
            error: None,
            ..Default::default()
        });
    }
}

// ---------------------------------------------------------------------------
// Adaptive path (active brute-force): controller-driven concurrency + resilience.
// Only used when adaptive_rate and/or adaptive_resilience is set. The fixed pool
// `task_handle` above is left untouched, so a non-adaptive scan is unchanged.
// ---------------------------------------------------------------------------

/// Classify one active-scan outcome for the health signal. A transient DNS
/// failure surfaces as an "error"-level negative (timeout / SERVFAIL / network),
/// vs an "info"-level NXDOMAIN which is a healthy definitive "not found".
fn classify(res: &active_scan::ActiveScanResult) -> adaptive::ProbeClass {
    use adaptive::ProbeClass;
    if res.found {
        return ProbeClass::Success;
    }
    if res.negatives.iter().any(|n| n.level == "error") {
        ProbeClass::Timeout
    } else {
        ProbeClass::NotFound
    }
}

struct AdaptiveShared {
    window: Mutex<adaptive::HealthWindow>,
    target_conc: AtomicU64,
    delay_ms: AtomicU64,
    score_bits: AtomicU64,
    rate_on: bool,
    drained: AtomicBool,
    resilience: adaptive::ResilienceController,
}

async fn controller_tick(
    shared: Arc<AdaptiveShared>,
    posture: adaptive::Posture,
    caps: adaptive::Caps,
    start_delay_ms: u64,
    stop: Arc<AtomicBool>,
    // Used only by the tuning build to stream the operating point to the
    // dashboard. Threaded unconditionally so the signature does not fork.
    event_tx: Option<Arc<mpsc::UnboundedSender<StreamEvent>>>,
) {
    let _ = &event_tx;
    let mut rc = adaptive::RateController::new(posture, caps, start_delay_ms);
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

        // Publish the operating point about once a second. Compiled only in the
        // tuning build, so a default daemon emits no governor events and its
        // wire is unchanged.
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

async fn adaptive_task_handle(
    config: Arc<EnumConfig>,
    db: Arc<VoyageDb>,
    event_tx: Arc<mpsc::UnboundedSender<StreamEvent>>,
    shared: Arc<AdaptiveShared>,
    worker_index: u64,
) -> Result<(), sqlx::Error> {
    let resolver = match crate::libs::dns::create_resolver(Some(config.dns_server.as_str())) {
        Ok(r) => r,
        Err(e) => {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("DNS resolver error: {e}"),
            );
            return Ok(());
        }
    };
    let user_agent = if config.active_random_user_agent {
        crate::libs::rng::user_agent()
    } else {
        config.active_user_agent.clone()
    };
    let mut extra_headers = transport::HeaderMap::new();
    if let Some(token) = &config.identify {
        if let Ok(val) = transport::HeaderValue::from_str(token) {
            extra_headers.insert(transport::HeaderName::from_static("x-bug-bounty"), val);
        }
    }
    let client = match transport::build_client(transport::ClientConfig {
        block_internal: config.block_internal,
        timeout: Some(Duration::from_secs(10)),
        user_agent: Some(user_agent.clone()),
        emulate: config.evasive,
        extra_headers,
        ..Default::default()
    }) {
        Ok(c) => c,
        Err(e) => {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("HTTP client build error: {e}"),
            );
            return Ok(());
        }
    };

    loop {
        // Concurrency gate: park while above the controller's current target.
        if shared.rate_on {
            while worker_index >= shared.target_conc.load(Ordering::Relaxed).max(1) {
                if shared.drained.load(Ordering::Relaxed) {
                    return Ok(());
                }
                sleep(Duration::from_millis(80)).await;
            }
        }
        let delay = if shared.rate_on {
            shared.delay_ms.load(Ordering::Relaxed)
        } else {
            config.interval_ms
        };
        if delay > 0 {
            sleep(Duration::from_millis(delay)).await;
        }

        let work: Work = match db.get_work_one(&config.scan_id).await {
            Ok(w) => w,
            Err(sqlx::Error::RowNotFound) => match db.is_scanning_active(&config.scan_id).await {
                Ok(true) => {
                    sleep(Duration::from_millis(50)).await;
                    continue;
                }
                _ => {
                    shared.drained.store(true, Ordering::Relaxed);
                    return Ok(());
                }
            },
            Err(e) => {
                emit_log(
                    &Some(event_tx.clone()),
                    "error",
                    &format!("get_work_one error: {e}"),
                );
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        // Resolve with health-gated retries: a timed-out/SERVFAIL query on a real
        // subdomain (lossy UDP) is retried instead of being lost.
        let mut attempt = 0u32;
        let scan_result = loop {
            let res = active_scan::execute(
                &resolver,
                &client,
                &config.exclude_active_techniques,
                &config.http_probing_ports,
                &config.https_probing_ports,
                &work.full_subdomain,
            )
            .await;
            let class = classify(&res);
            {
                shared.window.lock().unwrap().record(class, 0);
            }
            if adaptive::ResilienceController::retryable(class) {
                let score = if config.adaptive_resilience {
                    f64::from_bits(shared.score_bits.load(Ordering::Relaxed))
                } else {
                    1.0
                };
                let d = shared.resilience.decide(
                    class,
                    attempt,
                    &adaptive::HealthStats::empty(),
                    score,
                    None,
                );
                if d.retry {
                    attempt += 1;
                    if d.backoff_ms > 0 {
                        sleep(Duration::from_millis(d.backoff_ms)).await;
                    }
                    continue;
                }
            }
            break res;
        };

        for neg in &scan_result.negatives {
            emit_log(&Some(event_tx.clone()), &neg.level, &neg.description);
        }
        let status = if scan_result.found {
            "found"
        } else {
            "not_found"
        };
        let source = &scan_result.source;
        if let Err(e) = db.update_work_status(work.entry_id, status, source).await {
            emit_log(
                &Some(event_tx.clone()),
                "error",
                &format!("update_work_status failed: {e}"),
            );
            let _ = db.reset_entry_to_queued(work.entry_id).await;
            continue;
        }
        if scan_result.found {
            emit_log(
                &Some(event_tx.clone()),
                "info",
                &format!("FOUND: {} ({})", work.full_subdomain, source),
            );
        }
        let _ = event_tx.send(StreamEvent {
            kind: "result".to_string(),
            subdomain: Some(work.full_subdomain),
            status: Some(status.to_string()),
            source: Some(source.clone()),
            operation_id: None,
            total: None,
            found: None,
            not_found: None,
            log_level: None,
            message: None,
            error: None,
            ..Default::default()
        });
    }
}
