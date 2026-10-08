//! Rate control: a health score maps to a concurrency + delay directive.
//!
//! Open baseline. This keeps the public shape of the controller (postures, a
//! composite score, an increase/decrease loop) but uses a single, conservative,
//! untuned profile for every posture. The production tuning, the per-posture
//! constant tables and the tuned control law, lives in the private drop-in that
//! replaces this crate in first-party builds.

use crate::health::HealthStats;
use serde::{Deserialize, Serialize};

/// How aggressive the controller is allowed to be. In this baseline the postures
/// share one profile; the private build resolves each to its own tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Posture {
    /// Quietest: best finding quality. `gentle` names the same posture.
    #[serde(alias = "gentle")]
    Stealth,
    /// A healthy balance of speed and load.
    #[default]
    Balanced,
    /// Pushes hardest for throughput.
    Throughput,
}

impl Posture {
    /// Parse leniently from a wire string; unknown → [`Posture::Balanced`].
    pub fn from_str_lenient(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "gentle" | "stealth" => Posture::Stealth,
            "throughput" => Posture::Throughput,
            _ => Posture::Balanced,
        }
    }

    /// The controller constants this posture resolves to. Baseline: one generic,
    /// conservative profile of round placeholder values for all postures (the
    /// tuned per-posture tables live in the private drop-in).
    pub fn params(self) -> PostureParams {
        PostureParams {
            healthy_wm: 0.75,
            stressed_wm: 0.50,
            inc: 1.0,
            dec: 0.5,
            ss_growth: 1.5,
            ss_exit_frac: 0.5,
            delay_step_ms: 100,
            delay_relief_ms: 50,
            w_rl: 0.25,
            w_se: 0.25,
            w_to: 0.25,
            w_lat: 0.25,
            rl_ref: 0.10,
            se_ref: 0.10,
            to_ref: 0.10,
            lat_ref: 2.0,
            max_retries: 3,
        }
    }
}

/// The controller constants a [`Posture`] resolves to. `*_ref` values are the
/// rate/ratio at which that penalty term is considered "fully bad".
#[derive(Debug, Clone, Copy)]
pub struct PostureParams {
    pub healthy_wm: f64,
    pub stressed_wm: f64,
    pub inc: f64,
    pub dec: f64,
    pub ss_growth: f64,
    pub ss_exit_frac: f64,
    pub delay_step_ms: u64,
    pub delay_relief_ms: u64,
    pub w_rl: f64,
    pub w_se: f64,
    pub w_to: f64,
    pub w_lat: f64,
    pub rl_ref: f64,
    pub se_ref: f64,
    pub to_ref: f64,
    pub lat_ref: f64,
    pub max_retries: u32,
}

/// Composite health score in `[0,1]` (1 = healthy). Baseline: a weighted blend
/// of the stress signals, with any single hard signal able to force it down.
pub fn score(stats: &HealthStats, p: &PostureParams) -> f64 {
    let c = |x: f64| x.clamp(0.0, 1.0);
    let rl = c(stats.rate_limited_rate / p.rl_ref);
    let se = c(stats.server_err_rate / p.se_ref);
    let to = c(stats.timeout_drop_rate / p.to_ref);
    let lat_excess = (stats.latency_inflation - 1.0).max(0.0);
    let lat = c(lat_excess / p.lat_ref);
    let blend = p.w_rl * rl + p.w_se * se + p.w_to * to + p.w_lat * lat;
    let hard = rl.max(se).max(to);
    (1.0 - c(blend.max(hard))).clamp(0.0, 1.0)
}

/// Hard bounds the controller must never cross, regardless of posture. These
/// come from the plan-tier caps (`max_threads`, etc.) and are non-skippable.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub min_concurrency: u32,
    pub max_concurrency: u32,
    pub max_delay_ms: u64,
    pub max_retries: u32,
}

/// What the controller wants the engine to do right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Directive {
    pub concurrency: u32,
    pub delay_ms: u64,
}

/// Minimum outcomes in the window before the controller acts on the score.
const MIN_SAMPLES: usize = 12;

/// Increase-on-healthy / decrease-on-stressed controller for one target.
pub struct RateController {
    posture: Posture,
    p: PostureParams,
    caps: Caps,
    conc: f64,
    delay_ms: u64,
    slow_start: bool,
    last_score: f64,
}

impl RateController {
    /// Start conservative (from the floor) and grow as the target proves healthy.
    pub fn new(posture: Posture, caps: Caps, start_delay_ms: u64) -> Self {
        let p = posture.params();
        let seed = caps.min_concurrency.max(1) as f64;
        RateController {
            posture,
            p,
            caps,
            conc: seed,
            delay_ms: start_delay_ms.min(caps.max_delay_ms),
            slow_start: true,
            last_score: 1.0,
        }
    }

    /// Start at full concurrency and back off under stress instead of ramping up
    /// from the floor. Suited to short, coordinated runs.
    pub fn new_optimistic(posture: Posture, caps: Caps, start_delay_ms: u64) -> Self {
        let p = posture.params();
        RateController {
            posture,
            p,
            caps,
            conc: caps.max_concurrency.max(1) as f64,
            delay_ms: start_delay_ms.min(caps.max_delay_ms),
            slow_start: false,
            last_score: 1.0,
        }
    }

    pub fn posture(&self) -> Posture {
        self.posture
    }

    pub fn last_score(&self) -> f64 {
        self.last_score
    }

    /// The score for a snapshot under this controller's posture (no mutation).
    pub fn score_of(&self, stats: &HealthStats) -> f64 {
        score(stats, &self.p)
    }

    /// Advance one control step from the latest health snapshot and return the
    /// new directive. Call on a fixed cadence.
    pub fn tick(&mut self, stats: &HealthStats) -> Directive {
        let s = score(stats, &self.p);
        self.last_score = s;

        if stats.total < MIN_SAMPLES {
            return self.directive();
        }

        if s >= self.p.healthy_wm {
            if self.slow_start {
                self.conc *= self.p.ss_growth;
                if self.conc >= self.caps.max_concurrency as f64 * self.p.ss_exit_frac {
                    self.slow_start = false;
                }
            } else {
                self.conc += self.p.inc;
            }
            self.delay_ms = self.delay_ms.saturating_sub(self.p.delay_relief_ms);
        } else if s <= self.p.stressed_wm {
            self.conc *= self.p.dec;
            self.slow_start = false;
            self.delay_ms = (self.delay_ms + self.p.delay_step_ms).min(self.caps.max_delay_ms);
        }

        let lo = self.caps.min_concurrency.max(1) as f64;
        let hi = self.caps.max_concurrency.max(1) as f64;
        self.conc = self.conc.clamp(lo, hi);
        self.directive()
    }

    fn directive(&self) -> Directive {
        Directive {
            concurrency: (self.conc.round() as u32).clamp(
                self.caps.min_concurrency.max(1),
                self.caps.max_concurrency.max(1),
            ),
            delay_ms: self.delay_ms.min(self.caps.max_delay_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{HealthWindow, ProbeClass};

    fn caps() -> Caps {
        Caps {
            min_concurrency: 1,
            max_concurrency: 100,
            max_delay_ms: 5_000,
            max_retries: 5,
        }
    }

    #[test]
    fn caps_are_never_exceeded() {
        let tight = Caps {
            min_concurrency: 2,
            max_concurrency: 8,
            max_delay_ms: 1000,
            max_retries: 3,
        };
        let mut rc = RateController::new(Posture::Balanced, tight, 0);
        let mut w = HealthWindow::new(200, 10);
        for _ in 0..100 {
            w.record(ProbeClass::from_status(200), 10);
        }
        for _ in 0..200 {
            let d = rc.tick(&w.stats());
            assert!(
                d.concurrency >= 2 && d.concurrency <= 8,
                "conc out of caps: {}",
                d.concurrency
            );
            assert!(d.delay_ms <= 1000);
        }
    }

    #[test]
    fn holds_until_min_samples() {
        let mut rc = RateController::new(Posture::Balanced, caps(), 0);
        let mut w = HealthWindow::new(200, 10);
        for _ in 0..3 {
            w.record(ProbeClass::from_status(200), 40);
        }
        let d0 = rc.tick(&w.stats());
        let d1 = rc.tick(&w.stats());
        assert_eq!(d0, d1, "should hold below MIN_SAMPLES");
    }
}
