//! Adaptive rate-limiting and resilience control for Crossfyre workflows.
//!
//! ## Open baseline
//!
//! This is the **open reference implementation**: it defines the interface the
//! engines call and provides a conservative, untuned baseline behaviour. The
//! production tuning (the operating constants and the tuned control policy) is a
//! private drop-in that replaces this crate in first-party builds. Everything
//! here is safe to publish and builds standalone; nothing here is the tuned
//! policy. Keep the public type/function signatures stable so the private
//! implementation stays a clean drop-in.
//!
//! Pure logic, no I/O, a workflow engine (ambulo content-discovery, the DS
//! fan-out in `cfx_core`, future scanners) feeds it probe outcomes and asks it,
//! on a tick, how many probes to run concurrently, how long to wait between
//! them, and whether a failed probe is worth retrying.
//!
//! The design goal is to **keep the target healthy**, which is the same thing as
//! keeping findings clean: an overloaded target returns junk (spurious 429/503
//! that look like "exists", timeouts that hide real endpoints). Steering to the
//! edge of healthy removes both the burden and the noise.
//!
//! Three pieces, composable and independent:
//!   - [`HealthWindow`], a rolling record of probe outcomes → a [`HealthStats`]
//!     snapshot (rates + latency inflation vs a warm-up baseline).
//!   - [`RateController`], AIMD control mapping the composite health score to a
//!     concurrency + delay [`Directive`], parameterized by [`Posture`].
//!   - [`ResilienceController`], maps the same score + the error class to a
//!     retry decision, quality-first, hard-capped.
//!
//! Time is not read internally (no `Instant::now`), so behaviour is fully
//! deterministic and unit-testable: callers record `(class, rtt_ms)` and tick.

pub mod challenge;
pub mod congestion;
pub mod coord;
pub mod evasion;
pub mod health;
pub mod identity;
pub mod rate;
pub mod resilience;
pub mod wire;

pub use challenge::{Challenge, Reaction};
pub use congestion::{
    Decision, Estimator, Limits, Outcome, Sample, WINDOW_MS, Window, decide as congestion_decide,
};
pub use health::{HealthStats, HealthWindow, ProbeClass};
pub use rate::{Caps, Directive, Posture, PostureParams, RateController, score};
pub use resilience::{ResilienceController, RetryDecision};
pub use wire::{AdaptiveConfig, ControlDirective, HealthReport};
