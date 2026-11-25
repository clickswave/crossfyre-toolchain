//! What a tool reports besides its rows: its counters and its log.
//!
//! Each is plain data, not an engine type, so this crate stays a rendering
//! layer and never becomes a route for internals to travel.

use crate::sheet::{Cell, Column};
use crate::theme::Tone;

/// A counter in the run panel: "found 142".
pub struct Stat {
    pub label: &'static str,
    pub value: String,
    pub tone: Tone,
    /// A count of nothing. A bad counter at zero is not bad, and is not drawn
    /// as though it were.
    zero: bool,
}

impl Stat {
    /// A count, with its thousands grouped.
    pub fn count(label: &'static str, count: usize) -> Self {
        Self {
            label,
            value: grouped(count),
            tone: Tone::Plain,
            zero: count == 0,
        }
    }

    /// A value that is not a single count: "2 of 5".
    pub fn text(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            tone: Tone::Plain,
            zero: false,
        }
    }

    pub fn good(mut self) -> Self {
        self.tone = Tone::Good;
        self
    }

    /// Bad once there is at least one.
    pub fn bad(mut self) -> Self {
        if !self.zero {
            self.tone = Tone::Bad;
        }
        self
    }
}

/// `12000` as `12,000`.
pub fn grouped(count: usize) -> String {
    let digits = count.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// How far a run is.
pub enum Progress {
    /// Work counted out before it began: `done` of `total`.
    Counted { done: usize, total: usize },
    /// Work with no known total, where a bar filling up would be a lie.
    Open { done: usize, unit: &'static str },
    /// Not a run at all: a server that waits.
    None,
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

pub struct LogEntry {
    pub level: Level,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Level {
    Info,
    Warn,
    Error,
    Debug,
}

impl Level {
    /// Parse whatever the wire called it. Anything unrecognised is info, since
    /// dropping a line because its level was spelled oddly is worse than
    /// showing it under the wrong heading.
    pub fn parse(s: &str) -> Self {
        match s {
            "error" | "err" => Level::Error,
            "warn" | "warning" => Level::Warn,
            "debug" | "trace" => Level::Debug,
            _ => Level::Info,
        }
    }

    fn cell(self) -> Cell {
        let (word, tone) = match self {
            Level::Error => ("error", Tone::Bad),
            Level::Warn => ("warn", Tone::Warn),
            Level::Debug => ("debug", Tone::Muted),
            Level::Info => ("info", Tone::Muted),
        };
        Cell::toned(word, tone)
    }
}

/// Scrollback shared by every tool.
#[derive(Default)]
pub struct Logs {
    entries: Vec<LogEntry>,
    /// Keeps memory flat on runs that log heavily. Zero means unbounded.
    cap: usize,
}

impl Logs {
    pub(crate) const COLUMNS: &'static [Column] =
        &[Column::new("Level", 6), Column::rest("Message")];

    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            cap: 5_000,
        }
    }

    pub fn push(&mut self, level: Level, message: impl Into<String>) {
        self.entries.push(LogEntry {
            level,
            message: message.into(),
        });
        if self.cap > 0 && self.entries.len() > self.cap {
            let drop = self.entries.len() - self.cap;
            self.entries.drain(0..drop);
        }
    }

    pub fn info(&mut self, message: impl Into<String>) {
        self.push(Level::Info, message);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// One line, as a row under [`Logs::COLUMNS`].
    pub(crate) fn row(&self, index: usize) -> Vec<Cell> {
        let entry = &self.entries[index];
        vec![entry.level.cell(), Cell::plain(entry.message.clone())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_have_their_thousands_grouped() {
        for (count, shown) in [
            (0, "0"),
            (999, "999"),
            (1_000, "1,000"),
            (12_000, "12,000"),
            (1_234_567, "1,234,567"),
        ] {
            assert_eq!(grouped(count), shown);
        }
    }

    #[test]
    fn a_bad_counter_is_bad_only_above_zero() {
        assert_eq!(Stat::count("Errors", 0).bad().tone, Tone::Plain);
        assert_eq!(Stat::count("Errors", 3).bad().tone, Tone::Bad);
    }

    #[test]
    fn the_log_drops_its_oldest_lines_past_the_cap() {
        let mut logs = Logs::new();
        for i in 0..5_010 {
            logs.info(format!("line {i}"));
        }
        assert_eq!(logs.len(), 5_000);
        assert_eq!(logs.row(0)[1].text, "line 10");
    }
}
