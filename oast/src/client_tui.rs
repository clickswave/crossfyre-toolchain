//! Oast's dashboard.
//!
//! Every other tool runs a scan that finishes; oast is a server that waits, so
//! its dashboard is a feed rather than a progress view. It shows the listeners,
//! how long it has been up, which is the clock in the border, and interactions
//! as they arrive.
//!
//! Only envelope metadata is shown, never interaction contents. The server
//! seals the plaintext and does not keep it, and the dashboard holds to the
//! same line: protocol, source and correlation prefix confirm out-of-band
//! works without putting a captured request on screen.

use crate::store::Envelope;
use cfx_tui::{Cell, Column, Dashboard, Logs, Progress, Stat, Tone, View};

const FEED: char = 'f';
const VIEWS: &[View] = &[View::new(FEED, "Feed")];
const COLUMNS: &[Column] = &[
    Column::new("Time", 10),
    Column::new("Protocol", 10),
    Column::new("Source", 22),
    Column::rest("Correlation"),
];

struct Hit {
    time: String,
    protocol: String,
    source: String,
    correlation: String,
}

/// The dashboard's own state. Fed by envelopes from the store; it never sees
/// an [`crate::store::Interaction`].
pub struct Oast {
    listeners: String,
    dns: usize,
    http: usize,
    hits: Vec<Hit>,
    logs: Logs,
}

impl Oast {
    pub fn new(listeners: String) -> Self {
        Self {
            listeners,
            dns: 0,
            http: 0,
            hits: Vec::new(),
            logs: Logs::new(),
        }
    }

    fn apply(&mut self, env: Envelope) {
        match env.protocol.as_str() {
            "dns" => self.dns += 1,
            _ => self.http += 1,
        }
        self.hits.push(Hit {
            time: fmt_clock(env.at_unix),
            protocol: env.protocol,
            source: env.remote_addr,
            correlation: env.corr_prefix,
        });
        // A server can run for days. Keep the feed bounded so memory stays flat.
        if self.hits.len() > 2_000 {
            self.hits.remove(0);
        }
    }
}

impl Dashboard for Oast {
    fn name(&self) -> &str {
        "OAST"
    }

    fn target(&self) -> &str {
        &self.listeners
    }

    fn doing(&self) -> &'static str {
        "listening"
    }

    // A server is never "done". It runs until the operator quits, so it is
    // listening for the life of the process.
    fn finished(&self) -> bool {
        false
    }

    fn progress(&self) -> Progress {
        Progress::None
    }

    fn stats(&self) -> Vec<Stat> {
        vec![Stat::count("DNS", self.dns), Stat::count("HTTP", self.http)]
    }

    fn columns(&self, _view: char) -> &'static [Column] {
        COLUMNS
    }

    fn len(&self, _view: char) -> usize {
        self.hits.len()
    }

    fn row(&self, _view: char, index: usize) -> Vec<Cell> {
        let hit = &self.hits[index];
        let protocol = match hit.protocol.as_str() {
            "dns" => Tone::Accent,
            "https" => Tone::Good,
            _ => Tone::Plain,
        };
        vec![
            Cell::muted(&hit.time),
            Cell::toned(&hit.protocol, protocol),
            Cell::plain(&hit.source),
            Cell::muted(&hit.correlation),
        ]
    }

    fn views(&self) -> &'static [View] {
        VIEWS
    }

    fn logs(&mut self) -> &mut Logs {
        &mut self.logs
    }
}

/// Drive the dashboard, draining envelopes the store sends. Blocking; the
/// caller runs it on a dedicated thread.
pub fn run(listeners: String, rx: std::sync::mpsc::Receiver<Envelope>) -> std::io::Result<()> {
    let mut app = Oast::new(listeners);
    app.logs.info("listening for interactions");
    cfx_tui::run(&mut app, 100, |app| {
        while let Ok(env) = rx.try_recv() {
            app.apply(env);
        }
    })
}

/// Wall-clock HH:MM:SS in UTC from a unix timestamp, without pulling in a date
/// crate for one field.
fn fmt_clock(unix: u64) -> String {
    let s = unix % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}
