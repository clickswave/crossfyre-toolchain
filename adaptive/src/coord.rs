//! Per-target coordination tuning.
//!
//! Open baseline. When many concurrent workers run against one target, a shared
//! pace lets them speed up and slow down together instead of each adapting in
//! isolation. This module holds the *tuning* of that arrangement, the re-eval
//! cadence, the window sizing, the envelope, and the posture seed, with round
//! placeholder values. The tuned numbers live in the private drop-in.

use crate::{Caps, HealthWindow};
use std::sync::OnceLock;

/// How many outcomes a shared pace accumulates before it re-evaluates.
const TICK_EVERY: u64 = 20;

/// Rolling health-window sizing for one shared pace: samples retained, warm-up.
const WINDOW_CAP: usize = 256;
const WINDOW_WARMUP: usize = 32;

/// The cadence and window sizing a shared pace runs on, a module's held to bounds.
#[derive(Clone, Copy)]
struct Cadence {
    tick_every: u64,
    window_cap: usize,
    window_warmup: usize,
}

fn cadence() -> Cadence {
    #[derive(serde::Deserialize)]
    struct Answer {
        tick_every: u64,
        window_cap: usize,
        window_warmup: usize,
    }
    static KEPT: OnceLock<Option<Cadence>> = OnceLock::new();
    crate::backend::ask_once(&KEPT, "coord.params", &(), |a: Answer| {
        let window_cap = a.window_cap.clamp(16, 4096);
        Some(Cadence {
            tick_every: a.tick_every.clamp(1, 1000),
            window_cap,
            window_warmup: a.window_warmup.clamp(1, window_cap),
        })
    })
    .unwrap_or(Cadence {
        tick_every: TICK_EVERY,
        window_cap: WINDOW_CAP,
        window_warmup: WINDOW_WARMUP,
    })
}

/// How many outcomes a shared pace accumulates before it re-evaluates.
pub fn tick_every() -> u64 {
    cadence().tick_every
}

/// Starting aggressiveness for a shared pace, by posture. Baseline: conservative
/// placeholder seeds. A module's answer is held to 1 to 8.
pub fn posture_cap(posture: &str) -> u64 {
    #[derive(serde::Serialize)]
    struct Ask<'a> {
        posture: &'a str,
    }
    if let Some(cap) = crate::backend::ask::<_, u64>("coord.posture_cap", &Ask { posture }) {
        return cap.clamp(1, 8);
    }
    match posture {
        "throughput" => 2,
        _ => 1,
    }
}

impl Caps {
    /// Envelope for one shared per-target pace (open baseline placeholders). A
    /// module's envelope never allows more than `max` at once, and always lets the
    /// pace slow to a second between probes.
    pub fn for_target(max: u32) -> Self {
        #[derive(serde::Serialize)]
        struct Ask {
            max: u32,
        }
        #[derive(serde::Deserialize)]
        struct Answer {
            min_concurrency: u32,
            max_concurrency: u32,
            max_delay_ms: u64,
            max_retries: u32,
        }
        if let Some(a) = crate::backend::ask::<_, Answer>("coord.caps", &Ask { max }) {
            let max_concurrency = a.max_concurrency.clamp(1, max.max(1));
            return Caps {
                min_concurrency: a.min_concurrency.clamp(1, max_concurrency),
                max_concurrency,
                max_delay_ms: a.max_delay_ms.clamp(1_000, 60_000),
                max_retries: a.max_retries.min(10),
            };
        }
        Caps {
            min_concurrency: 1,
            max_concurrency: max,
            max_delay_ms: 5_000,
            max_retries: 5,
        }
    }
}

impl HealthWindow {
    /// A health window sized for one shared per-target pace.
    pub fn for_target() -> Self {
        let c = cadence();
        HealthWindow::new(c.window_cap, c.window_warmup)
    }
}
