//! Congestion-window probe-rate control: the policy behind the probe governor.
//!
//! Open baseline. Treats in-flight concurrency like a congestion window (grow
//! while healthy, shrink under loss/latency) and derives the per-probe timeout
//! from measured RTT, but with round, untuned placeholder constants. The tuned
//! control law and its operating numbers live in the private drop-in that
//! replaces this crate in first-party builds.
//!
//! Pure policy: consumes a window of probe outcomes plus a running RTT estimator
//! and returns the next knobs (concurrency / timeout / retries). No I/O, no clock,
//! so it is fully deterministic and unit-testable.

/// How the network treated a single probe (after its retry budget).
#[derive(Clone, Copy)]
pub enum Outcome {
    /// Got a definite answer (SYN-ACK => open, or RST => closed). `rtt_ms` real.
    Delivered { rtt_ms: u64 },
    /// Every attempt timed out. No answer reached us => treated as loss for the
    /// control signal.
    Lost,
}

/// One probe's contribution to the control loop.
pub struct Sample {
    pub outcome: Outcome,
    /// Number of attempts spent (1 = first-try). `> 1` means we retransmitted.
    pub attempts: u32,
}

/// Tunable envelope. Absolute bounds only; the loop finds the operating point
/// inside them from live measurement.
#[derive(Clone, Copy)]
pub struct Limits {
    pub conc_floor: usize,
    pub conc_ceil: usize,
    pub timeout_floor_ms: u64,
    pub timeout_ceil_ms: u64,
    pub retry_floor: u32,
    pub retry_ceil: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            conc_floor: 4,
            conc_ceil: 512,
            timeout_floor_ms: 250,
            timeout_ceil_ms: 12_000,
            retry_floor: 1,
            retry_ceil: 4,
        }
    }
}

/// The control window length, in milliseconds. The engine ticks the loop on this
/// cadence.
pub const WINDOW_MS: u64 = 500;

/// One window's raw counts, filled by the engine from its accumulators.
pub struct Window {
    pub sent: u64,
    pub lost: u64,
    pub delivered: u64,
    pub retried: u64,
    pub recovered: u64,
    pub rtt_sum_us: u64,
}

/// RTT estimator + phase carried across control windows.
pub struct Estimator {
    pub srtt_us: f64,
    pub rttvar_us: f64,
    pub warmup: bool,
}

impl Estimator {
    /// A fresh estimator seeded from an initial timeout guess, in warm-up.
    pub fn warmup(initial_timeout_ms: u64) -> Self {
        Self {
            srtt_us: initial_timeout_ms as f64 * 1000.0,
            rttvar_us: initial_timeout_ms as f64 * 500.0,
            warmup: true,
        }
    }
}

/// The knobs the loop applies after a window.
pub struct Decision {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u32,
}

/// Pure control policy (open baseline): grow concurrency while the window is
/// clean, shrink it on loss or latency inflation, and size the timeout from the
/// RTT estimate. Round placeholder constants; no tuned thresholds.
pub fn decide(
    est: &mut Estimator,
    cur_conc: usize,
    w: &Window,
    min_rtt_us: Option<f64>,
    limits: &Limits,
) -> Decision {
    if let Some(d) = from_module(est, cur_conc, w, min_rtt_us, limits) {
        return d;
    }
    let loss_ratio = w.lost as f64 / w.sent as f64;

    if w.delivered > 0 {
        let mean_us = w.rtt_sum_us as f64 / w.delivered as f64;
        let err = (mean_us - est.srtt_us).abs();
        est.rttvar_us = 0.75 * est.rttvar_us + 0.25 * err;
        est.srtt_us = 0.875 * est.srtt_us + 0.125 * mean_us;
    }
    let min_rtt_us = min_rtt_us.unwrap_or(est.srtt_us);

    let timeout_ms = ((est.srtt_us + 2.0 * est.rttvar_us) / 1000.0).round() as u64;
    let timeout_ms = timeout_ms.clamp(limits.timeout_floor_ms, limits.timeout_ceil_ms);

    // Round placeholder thresholds.
    let congested = loss_ratio > 0.10 || est.srtt_us > 2.0 * min_rtt_us;
    let healthy = loss_ratio < 0.05 && est.srtt_us <= 1.5 * min_rtt_us;

    let concurrency = if congested {
        est.warmup = false;
        ((cur_conc as f64) * 0.5).floor() as usize
    } else if est.warmup && healthy {
        (((cur_conc as f64) * 2.0) as usize).max(cur_conc + 4)
    } else if healthy {
        cur_conc + 1
    } else {
        cur_conc
    }
    .clamp(limits.conc_floor, limits.conc_ceil);

    let retries = if loss_ratio > 0.10 {
        limits.retry_ceil
    } else if loss_ratio < 0.05 {
        limits.retry_floor
    } else {
        ((limits.retry_floor + limits.retry_ceil) / 2).max(1)
    }
    .clamp(limits.retry_floor, limits.retry_ceil);

    let _ = (w.retried, w.recovered);
    Decision {
        concurrency,
        timeout_ms,
        retries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(sent: u64, lost: u64, mean_rtt_ms: u64) -> Window {
        let delivered = sent - lost;
        Window {
            sent,
            lost,
            delivered,
            retried: 0,
            recovered: 0,
            rtt_sum_us: delivered * mean_rtt_ms * 1000,
        }
    }

    #[test]
    fn concurrency_respects_ceiling_and_floor() {
        let limits = Limits {
            conc_ceil: 120,
            ..Limits::default()
        };
        let mut e = Estimator {
            srtt_us: 100_000.0,
            rttvar_us: 10_000.0,
            warmup: false,
        };
        let d = decide(&mut e, 119, &win(1000, 0, 100), Some(100_000.0), &limits);
        assert!(d.concurrency <= 120, "cannot exceed conc_ceil");

        let mut e2 = Estimator {
            srtt_us: 100_000.0,
            rttvar_us: 10_000.0,
            warmup: false,
        };
        let d2 = decide(
            &mut e2,
            limits.conc_floor,
            &win(1000, 500, 100),
            Some(100_000.0),
            &limits,
        );
        assert_eq!(
            d2.concurrency, limits.conc_floor,
            "cannot drop below conc_floor"
        );
    }

    #[test]
    fn loss_backs_off() {
        let mut e = Estimator {
            srtt_us: 100_000.0,
            rttvar_us: 10_000.0,
            warmup: false,
        };
        let d = decide(
            &mut e,
            100,
            &win(1000, 300, 100),
            Some(100_000.0),
            &Limits::default(),
        );
        assert!(d.concurrency < 100, "heavy loss must reduce concurrency");
    }
}

/// The installed module's decision, held to `limits`, with the estimator it carries on;
/// None without a module, or when its answer does not read or carries an estimator that
/// is not a number of microseconds.
fn from_module(
    est: &mut Estimator,
    cur_conc: usize,
    w: &Window,
    min_rtt_us: Option<f64>,
    limits: &Limits,
) -> Option<Decision> {
    #[derive(serde::Serialize)]
    struct CongestionAsk {
        srtt_us: f64,
        rttvar_us: f64,
        warmup: bool,
        concurrency: usize,
        sent: u64,
        lost: u64,
        delivered: u64,
        retried: u64,
        recovered: u64,
        rtt_sum_us: u64,
        min_rtt_us: Option<f64>,
        conc_floor: usize,
        conc_ceil: usize,
        timeout_floor_ms: u64,
        timeout_ceil_ms: u64,
        retry_floor: u32,
        retry_ceil: u32,
    }
    #[derive(serde::Deserialize)]
    struct CongestionAnswer {
        srtt_us: f64,
        rttvar_us: f64,
        warmup: bool,
        concurrency: usize,
        timeout_ms: u64,
        retries: u32,
    }
    let a: CongestionAnswer = crate::backend::ask(
        "congestion.decide",
        &CongestionAsk {
            srtt_us: est.srtt_us,
            rttvar_us: est.rttvar_us,
            warmup: est.warmup,
            concurrency: cur_conc,
            sent: w.sent,
            lost: w.lost,
            delivered: w.delivered,
            retried: w.retried,
            recovered: w.recovered,
            rtt_sum_us: w.rtt_sum_us,
            min_rtt_us,
            conc_floor: limits.conc_floor,
            conc_ceil: limits.conc_ceil,
            timeout_floor_ms: limits.timeout_floor_ms,
            timeout_ceil_ms: limits.timeout_ceil_ms,
            retry_floor: limits.retry_floor,
            retry_ceil: limits.retry_ceil,
        },
    )?;
    let us = |v: f64| v.is_finite() && v >= 0.0;
    if !us(a.srtt_us) || !us(a.rttvar_us) {
        return None;
    }
    est.srtt_us = a.srtt_us;
    est.rttvar_us = a.rttvar_us;
    est.warmup = a.warmup;
    Some(Decision {
        concurrency: a
            .concurrency
            .clamp(limits.conc_floor, limits.conc_ceil.max(limits.conc_floor)),
        timeout_ms: a.timeout_ms.clamp(
            limits.timeout_floor_ms,
            limits.timeout_ceil_ms.max(limits.timeout_floor_ms),
        ),
        retries: a.retries.clamp(
            limits.retry_floor,
            limits.retry_ceil.max(limits.retry_floor),
        ),
    })
}
