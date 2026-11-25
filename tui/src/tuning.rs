//! Live view of how a run is pacing itself.
//!
//! Compiled only under the `tuning` feature. Published builds do not include
//! this module, so neither the panel nor its labels appear in the binary. The
//! pacing behaviour itself lives in the engines; this is a readout, and it is
//! kept out of default builds because the readout describes the behaviour.
//!
//! Tools report through [`Snapshot`], which holds numbers and short strings
//! only. Nothing in here reaches into engine types.

use crate::theme::{self, Tone};
use ratatui::{
    style::Modifier,
    text::{Line, Span},
};

/// What a tool reports each tick. Every field is optional: a tool fills in
/// what it knows and leaves the rest, rather than inventing values to fit.
#[derive(Default, Clone)]
pub struct Snapshot {
    /// Requests in flight right now.
    pub in_flight: Option<usize>,
    /// Ceiling currently being honoured.
    pub limit: Option<usize>,
    /// Observed throughput per second.
    pub rate: Option<f64>,
    /// Short label for the current stance, chosen by the tool.
    pub posture: Option<String>,
    /// Responses that asked us to slow down.
    pub throttled: Option<u64>,
}

impl Snapshot {
    pub fn is_empty(&self) -> bool {
        self.in_flight.is_none()
            && self.limit.is_none()
            && self.rate.is_none()
            && self.posture.is_none()
            && self.throttled.is_none()
    }
}

/// The pacing line, which sits under the counters in the run panel.
pub fn line(snap: &Snapshot) -> Line<'static> {
    let mut spans = Vec::new();

    let mut field = |label: &str, value: String, tone: Tone| {
        if !spans.is_empty() {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(format!("{label} "), theme::label()));
        spans.push(Span::styled(
            value,
            theme::tone(tone).add_modifier(Modifier::BOLD),
        ));
    };

    if let (Some(n), Some(lim)) = (snap.in_flight, snap.limit) {
        field("workers", format!("{n} / {lim}"), Tone::Plain);
    } else if let Some(n) = snap.in_flight {
        field("workers", n.to_string(), Tone::Plain);
    }
    if let Some(r) = snap.rate {
        field("rate", format!("{r:.0}/s"), Tone::Plain);
    }
    if let Some(p) = &snap.posture {
        field("posture", p.clone(), Tone::Accent);
    }
    if let Some(t) = snap.throttled {
        let tone = if t > 0 { Tone::Bad } else { Tone::Plain };
        field("throttled", t.to_string(), tone);
    }

    Line::from(spans)
}
