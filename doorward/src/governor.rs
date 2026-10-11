//! Adaptive probe-rate governor: the engine-side plumbing around the control loop.
//!
//! A fixed concurrency + fixed timeout scan is both slow and *wrong* over a
//! thin/lossy egress: too many in-flight probes overrun the path, answers get
//! dropped, and open ports get misread as "filtered"; a fixed timeout is also
//! blind to a high-RTT path. So concurrency, the per-probe timeout and the retry
//! budget are all steered from live measurement instead of pinned up front.
//!
//! This module owns the *machinery* of that loop, not the policy: a resizable
//! concurrency limiter, the lock-free window accumulators that tens of thousands
//! of probe tasks report into, and the tick task that snapshots a window and
//! applies the result. The control decision itself, how a window of outcomes
//! maps to the next knobs, lives behind [`adaptive::congestion`] and is fed a
//! plain snapshot each tick, so the policy stays testable without sockets and
//! isn't pinned to this one engine.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

use adaptive::congestion::{self, Decision, Estimator, Window};

// Re-export the policy's public data types so probe code keeps referring to them
// through `governor::` (the loop's outcome/envelope vocabulary).
pub use adaptive::congestion::{Limits, Outcome, Sample};

/// A tokio semaphore whose permit count can grow and shrink at runtime.
///
/// Grow is instant (`add_permits`). Shrink is graceful: we acquire the surplus
/// permits and `forget()` them, which naturally waits for in-flight probes to
/// finish before the concurrency actually drops (the loop throttles itself).
struct DynLimiter {
    sem: Arc<Semaphore>,
    current: AtomicUsize,
}

impl DynLimiter {
    fn new(initial: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(initial)),
            current: AtomicUsize::new(initial),
        }
    }

    async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        // unwrap: we never close the semaphore for the scan's lifetime.
        self.sem.clone().acquire_owned().await.unwrap()
    }

    /// Only ever called from the single governor loop, so `current` has no racing
    /// writer and the read-modify-write is safe without a CAS.
    async fn set(&self, target: usize) {
        let cur = self.current.load(Ordering::Relaxed);
        if target > cur {
            self.sem.add_permits(target - cur);
            self.current.store(target, Ordering::Relaxed);
        } else if target < cur {
            let remove = (cur - target) as u32;
            if let Ok(p) = self.sem.clone().acquire_many_owned(remove).await {
                p.forget();
            }
            self.current.store(target, Ordering::Relaxed);
        }
    }

    fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
}

/// Shared handle: probe tasks read the current knobs + report samples through
/// this; the governor loop owns the control decisions.
pub struct Governor {
    limiter: DynLimiter,
    timeout_ms: AtomicU64,
    retries: AtomicU32,
    limits: Limits,

    // Window accumulators (reset each control tick). Lock-free so tens of
    // thousands of probe tasks can report without contending on a mutex.
    win_sent: AtomicU64,
    win_lost: AtomicU64,
    win_delivered: AtomicU64,
    win_retried: AtomicU64,
    win_recovered: AtomicU64,
    win_rtt_sum_us: AtomicU64,
    min_rtt_us: AtomicU64, // sticky across windows (path floor)

    done: AtomicBool,
    shutdown: Notify,
}

const WINDOW: Duration = Duration::from_millis(congestion::WINDOW_MS);
const NO_RTT: u64 = u64::MAX;

impl Governor {
    pub fn new(initial_conc: usize, initial_timeout_ms: u64, limits: Limits) -> Arc<Self> {
        let initial_conc = initial_conc.clamp(limits.conc_floor, limits.conc_ceil);
        let initial_timeout_ms =
            initial_timeout_ms.clamp(limits.timeout_floor_ms, limits.timeout_ceil_ms);
        Arc::new(Self {
            limiter: DynLimiter::new(initial_conc),
            timeout_ms: AtomicU64::new(initial_timeout_ms),
            retries: AtomicU32::new(limits.retry_floor.max(2).min(limits.retry_ceil)),
            limits,
            win_sent: AtomicU64::new(0),
            win_lost: AtomicU64::new(0),
            win_delivered: AtomicU64::new(0),
            win_retried: AtomicU64::new(0),
            win_recovered: AtomicU64::new(0),
            win_rtt_sum_us: AtomicU64::new(0),
            min_rtt_us: AtomicU64::new(NO_RTT),
            done: AtomicBool::new(false),
            shutdown: Notify::new(),
        })
    }

    /// Acquire a concurrency slot (held for the probe's lifetime).
    pub async fn slot(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.limiter.acquire().await
    }

    /// Current per-probe timeout and retry budget, read at probe time so a
    /// mid-scan adjustment applies to probes not yet issued.
    pub fn probe_params(&self) -> (Duration, u32) {
        (
            Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed)),
            self.retries.load(Ordering::Relaxed),
        )
    }

    /// A finished probe reports its outcome. Lock-free hot path.
    pub fn record(&self, s: &Sample) {
        self.win_sent.fetch_add(1, Ordering::Relaxed);
        if s.attempts > 1 {
            self.win_retried.fetch_add(1, Ordering::Relaxed);
        }
        match s.outcome {
            Outcome::Lost => {
                self.win_lost.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Delivered { rtt_ms } => {
                self.win_delivered.fetch_add(1, Ordering::Relaxed);
                let us = rtt_ms.saturating_mul(1000).max(1);
                self.win_rtt_sum_us.fetch_add(us, Ordering::Relaxed);
                // sticky min-RTT (the path's uncongested floor)
                let mut cur = self.min_rtt_us.load(Ordering::Relaxed);
                while us < cur {
                    match self.min_rtt_us.compare_exchange_weak(
                        cur,
                        us,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(observed) => cur = observed,
                    }
                }
                if s.attempts > 1 {
                    // recovered on retransmit => the network dropped a packet a
                    // retry rescued: hard evidence of loss, not filtering.
                    self.win_recovered.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Signal the loop to stop (called once the probe stream is drained).
    pub fn finish(&self) {
        self.done.store(true, Ordering::Relaxed);
        self.shutdown.notify_one();
    }

    #[allow(dead_code)] // accessor kept alongside the other governor getters
    pub fn concurrency(&self) -> usize {
        self.limiter.current()
    }

    /// The control loop. Runs as its own task, emitting a `Telemetry` snapshot
    /// each tick via `on_tick` (used to surface live state to logs/UI). The
    /// per-window control decision is delegated to [`adaptive::congestion`] so
    /// the policy is unit-testable without real time or sockets.
    pub async fn run<F: Fn(Telemetry)>(self: Arc<Self>, on_tick: F) {
        let mut est = Estimator::warmup(self.timeout_ms.load(Ordering::Relaxed));

        loop {
            // Either a periodic tick, or a shutdown that flushes one final
            // snapshot (so even a sub-window scan surfaces its closing state).
            let shutting = tokio::select! {
                _ = tokio::time::sleep(WINDOW) => false,
                _ = self.shutdown.notified() => true,
            };

            // Snapshot-and-reset the window.
            let w = Window {
                sent: self.win_sent.swap(0, Ordering::Relaxed),
                lost: self.win_lost.swap(0, Ordering::Relaxed),
                delivered: self.win_delivered.swap(0, Ordering::Relaxed),
                retried: self.win_retried.swap(0, Ordering::Relaxed),
                recovered: self.win_recovered.swap(0, Ordering::Relaxed),
                rtt_sum_us: self.win_rtt_sum_us.swap(0, Ordering::Relaxed),
            };
            if w.sent == 0 {
                // Nothing completed this window (all slots still in flight, or
                // the scan hasn't produced answers yet). Don't feed the loop.
                if shutting || self.done.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }

            let min_rtt = {
                let m = self.min_rtt_us.load(Ordering::Relaxed);
                if m == NO_RTT { None } else { Some(m as f64) }
            };
            let cur = self.limiter.current();
            let d: Decision = congestion::decide(&mut est, cur, &w, min_rtt, &self.limits);

            self.timeout_ms.store(d.timeout_ms, Ordering::Relaxed);
            self.retries.store(d.retries, Ordering::Relaxed);

            on_tick(Telemetry {
                concurrency: d.concurrency,
                timeout_ms: d.timeout_ms,
                retries: d.retries,
                srtt_ms: (est.srtt_us / 1000.0).round() as u64,
                min_rtt_ms: (min_rtt.unwrap_or(est.srtt_us) / 1000.0).round() as u64,
                loss_pct: ((w.lost as f64 / w.sent as f64) * 100.0).round() as u64,
                recovered: w.recovered,
                goodput: (w.sent as f64 / WINDOW.as_secs_f64()).round() as u64,
                phase: if est.warmup { "calibrate" } else { "adapt" },
            });

            if shutting || self.done.load(Ordering::Relaxed) {
                break; // final snapshot emitted; no point resizing on the way out
            }
            if d.concurrency != cur {
                self.limiter.set(d.concurrency).await;
            }
        }
    }
}

/// A per-tick snapshot of the control state, surfaced to logs/UI.
pub struct Telemetry {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u32,
    pub srtt_ms: u64,
    pub min_rtt_ms: u64,
    pub loss_pct: u64,
    pub recovered: u64,
    pub goodput: u64,
    pub phase: &'static str,
}
