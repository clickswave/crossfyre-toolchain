//! Oast's dashboard.
//!
//! Every other tool runs a scan that finishes; oast is a server that waits, so
//! its dashboard is a feed rather than a progress view. It shows the listeners,
//! how long it has been up, and interactions as they arrive.
//!
//! Only envelope metadata is shown, never interaction contents. The server
//! seals the plaintext and does not keep it, and the dashboard holds to the
//! same line: protocol, source and correlation prefix confirm out-of-band
//! works without putting a captured request on screen.

use crate::store::Envelope;
use cfx_tui::{Dashboard, Logs, Stat, View, widgets};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

const FEED: char = 'f';
const VIEWS: &[View] = &[View::new(FEED, "Feed")];

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
    started_at: std::time::Instant,
    dns: usize,
    http: usize,
    hits: Vec<Hit>,
    table: TableState,
    logs: Logs,
}

impl Oast {
    pub fn new(listeners: String) -> Self {
        Self {
            listeners,
            started_at: std::time::Instant::now(),
            dns: 0,
            http: 0,
            hits: Vec::new(),
            table: TableState::default(),
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
        // A server can run for days. Keep the feed bounded so memory stays flat,
        // and follow the newest line.
        if self.hits.len() > 2_000 {
            self.hits.remove(0);
        }
        self.table.select(Some(self.hits.len().saturating_sub(1)));
    }

    fn render_feed(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(widgets::STATS_HEIGHT),
                Constraint::Min(0),
            ])
            .split(area);

        widgets::stats(
            frame,
            rows[0],
            &[
                Stat::new("Uptime", fmt_uptime(self.started_at.elapsed().as_secs())),
                Stat::new("DNS", self.dns),
                Stat::new("HTTP", self.http),
            ],
        );

        let header = Row::new(
            ["Time", "Protocol", "Source", "Correlation"]
                .iter()
                .map(|h| Cell::from(*h).style(cfx_tui::theme::title())),
        )
        .height(1);

        let body: Vec<Row> = self
            .hits
            .iter()
            .map(|h| {
                let colour = match h.protocol.as_str() {
                    "dns" => cfx_tui::theme::ACCENT,
                    "https" => cfx_tui::theme::GOOD,
                    _ => cfx_tui::theme::TEXT,
                };
                Row::new(vec![
                    Cell::from(h.time.clone()).style(cfx_tui::theme::label()),
                    Cell::from(h.protocol.clone()).style(Style::default().fg(colour)),
                    Cell::from(h.source.clone()),
                    Cell::from(h.correlation.clone()).style(cfx_tui::theme::label()),
                ])
            })
            .collect();

        frame.render_stateful_widget(
            Table::new(body, widgets::table_constraints(&[10, 10, 22]))
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Interactions"))
                .row_highlight_style(cfx_tui::theme::selected()),
            rows[1],
            &mut self.table,
        );
    }
}

impl Dashboard for Oast {
    fn name(&self) -> &str {
        "OAST"
    }

    fn subtitle(&self) -> &str {
        &self.listeners
    }

    // A server is never "done". It runs until the operator quits, so the header
    // stays on RUNNING for the life of the process.
    fn finished(&self) -> bool {
        false
    }

    fn views(&self) -> &'static [View] {
        VIEWS
    }

    fn render(&mut self, key: char, frame: &mut Frame, area: Rect) {
        if key == FEED {
            self.render_feed(frame, area);
        }
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

fn fmt_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Wall-clock HH:MM:SS in UTC from a unix timestamp, without pulling in a date
/// crate for one field.
fn fmt_clock(unix: u64) -> String {
    let s = unix % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}
