//! Plessor's dashboard.
//!
//! Chrome, keys and logs come from `cfx_tui`. What stays here is the part that
//! is about vulnerability scanning: tracking template progress, listing
//! matches worst-first, since a critical three screens down is a critical
//! nobody saw, and listing the templates the scan held back, so a shorter run
//! is not taken for a clean one.

use cfx_tui::{Dashboard, Level, Logs, Stat, View, widgets};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};
use serde_json::Value;
use tokio::sync::mpsc;

const FINDINGS: char = 'f';
const HELD_BACK: char = 'h';
const VIEWS: &[View] = &[
    View::new(FINDINGS, "Findings"),
    View::new(HELD_BACK, "Held back"),
];

struct Finding {
    severity: String,
    name: String,
    matched_at: String,
    /// Rank for sorting: lower is worse, so criticals float to the top.
    rank: u8,
}

/// A template the scan did not run, and why.
struct HeldBack {
    template: String,
    why: String,
}

struct Plessor {
    target: String,
    processed: usize,
    total: usize,
    found: usize,
    critical: usize,
    high: usize,
    findings: Vec<Finding>,
    table: TableState,
    held: Vec<HeldBack>,
    held_table: TableState,
    logs: Logs,
    done: bool,
}

impl Plessor {
    fn new(target: String) -> Self {
        Self {
            target,
            processed: 0,
            total: 0,
            found: 0,
            critical: 0,
            high: 0,
            findings: Vec::new(),
            table: TableState::default(),
            held: Vec::new(),
            held_table: TableState::default(),
            logs: Logs::new(),
            done: false,
        }
    }

    fn apply(&mut self, event: Value) {
        match event["type"].as_str().unwrap_or("") {
            "ack" => {
                if let Some(t) = event["target"].as_str() {
                    self.target = t.to_string();
                    self.logs.info(format!("scanning {t}"));
                }
            }
            "progress" => {
                self.processed = event["processed"].as_u64().unwrap_or(0) as usize;
                self.total = event["total"].as_u64().unwrap_or(0) as usize;
            }
            "finding" => {
                let data = &event["data"];
                let severity = data["severity"].as_str().unwrap_or("info").to_string();
                let rank = severity_rank(&severity);
                match severity.as_str() {
                    "critical" => self.critical += 1,
                    "high" => self.high += 1,
                    _ => {}
                }
                self.found += 1;

                let finding = Finding {
                    severity,
                    name: data["name"].as_str().unwrap_or("-").to_string(),
                    matched_at: data["matched_at"].as_str().unwrap_or("").to_string(),
                    rank,
                };
                // Keep the list ordered by severity as findings arrive, so the
                // worst are always at the top rather than wherever they landed
                // in scan order. Stable within a severity, so equal findings
                // stay in discovery order.
                let at = self.findings.partition_point(|f| f.rank <= finding.rank);
                self.findings.insert(at, finding);
            }
            // What the scan could not test, and why.
            "log" => {
                if let Some(m) = event["message"].as_str() {
                    self.logs.push(Level::Warn, m);
                }
            }
            "templates_held_back" => {
                let why = event["reason"].as_str().unwrap_or("held back");
                for id in event["templates"].as_array().into_iter().flatten() {
                    if let Some(id) = id.as_str() {
                        self.held.push(HeldBack {
                            template: id.to_string(),
                            why: why.to_string(),
                        });
                    }
                }
                if let Some(m) = event["message"].as_str() {
                    self.logs.push(Level::Warn, m);
                }
            }
            "error" => {
                self.done = true;
                self.logs.push(
                    Level::Error,
                    event["message"].as_str().unwrap_or("failed").to_string(),
                );
            }
            "done" => {
                self.done = true;
                if let Some(f) = event["found"].as_u64() {
                    self.found = f as usize;
                }
                self.logs.info(format!(
                    "{} findings ({} critical, {} high)",
                    self.found, self.critical, self.high
                ));
            }
            _ => {}
        }
    }

    fn render_findings(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(widgets::GAUGE_HEIGHT),
                Constraint::Length(widgets::STATS_HEIGHT),
                Constraint::Min(0),
            ])
            .split(area);

        widgets::progress(frame, rows[0], self.processed, self.total, "Templates");
        widgets::stats(
            frame,
            rows[1],
            &[
                Stat::bad("Critical", self.critical),
                Stat::new("High", self.high),
                Stat::new("Total", self.found),
                Stat::new("Held back", self.held.len()),
            ],
        );

        let header = Row::new(
            ["Severity", "Name", "Matched at"]
                .iter()
                .map(|h| Cell::from(*h).style(cfx_tui::theme::title())),
        )
        .height(1);

        let body: Vec<Row> = self
            .findings
            .iter()
            .map(|f| {
                Row::new(vec![
                    Cell::from(f.severity.clone())
                        .style(Style::default().fg(severity_colour(&f.severity))),
                    Cell::from(f.name.clone()),
                    Cell::from(f.matched_at.clone()).style(cfx_tui::theme::label()),
                ])
            })
            .collect();

        frame.render_stateful_widget(
            Table::new(body, widgets::table_constraints(&[10, 44]))
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Findings"))
                .row_highlight_style(cfx_tui::theme::selected()),
            rows[2],
            &mut self.table,
        );
    }

    fn render_held_back(&mut self, frame: &mut Frame, area: Rect) {
        let header = Row::new(
            ["Template", "Why"]
                .iter()
                .map(|h| Cell::from(*h).style(cfx_tui::theme::title())),
        )
        .height(1);
        let body: Vec<Row> = self
            .held
            .iter()
            .map(|h| {
                Row::new(vec![
                    Cell::from(h.template.clone()),
                    Cell::from(h.why.clone()).style(cfx_tui::theme::label()),
                ])
            })
            .collect();
        frame.render_stateful_widget(
            Table::new(body, widgets::table_constraints(&[40]))
                .header(header)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Held back: not run, so not tested"),
                )
                .row_highlight_style(cfx_tui::theme::selected()),
            area,
            &mut self.held_table,
        );
    }
}

/// Lower is worse, so a numeric sort puts criticals first.
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn severity_colour(severity: &str) -> ratatui::style::Color {
    match severity {
        "critical" | "high" => cfx_tui::theme::BAD,
        "medium" => cfx_tui::theme::WARN,
        "low" => cfx_tui::theme::TEXT,
        _ => cfx_tui::theme::MUTED,
    }
}

impl Dashboard for Plessor {
    fn name(&self) -> &str {
        "PLESSOR"
    }

    fn subtitle(&self) -> &str {
        &self.target
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn views(&self) -> &'static [View] {
        VIEWS
    }

    fn render(&mut self, key: char, frame: &mut Frame, area: Rect) {
        match key {
            FINDINGS => self.render_findings(frame, area),
            HELD_BACK => self.render_held_back(frame, area),
            _ => {}
        }
    }

    fn logs(&mut self) -> &mut Logs {
        &mut self.logs
    }
}

/// Errors are Send so the caller can drive this on a spawned task while it
/// keeps reading the socket.
pub async fn run(rx: mpsc::UnboundedReceiver<Value>, target: String) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut app = Plessor::new(target);
        let mut rx = rx;
        cfx_tui::run(&mut app, 50, |app| {
            while let Ok(event) = rx.try_recv() {
                app.apply(event);
            }
        })
    })
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Templates held back, for a product the scan was not told of and for changing the
    /// target, are listed with why, and what the scan says of them is in the log.
    #[test]
    fn held_back_templates_are_listed_with_why() {
        let mut view = Plessor::new("http://app.test".into());
        view.apply(json!({"type": "templates_held_back", "count": 1,
            "templates": ["CVE-2021-41773"], "from": "toolmark's inventory of app.test:80",
            "reason": "toolmark's inventory of app.test:80 names none of its products",
            "message": "1 product templates held back"}));
        view.apply(json!({"type": "templates_held_back", "count": 1,
            "templates": ["mass-assignment-privilege-escalation"],
            "reason": "what it sends changes the target",
            "message": "1 template(s) were NOT run"}));
        let held: Vec<(&str, &str)> = view
            .held
            .iter()
            .map(|h| (h.template.as_str(), h.why.as_str()))
            .collect();
        assert_eq!(
            held,
            [
                (
                    "CVE-2021-41773",
                    "toolmark's inventory of app.test:80 names none of its products"
                ),
                (
                    "mass-assignment-privilege-escalation",
                    "what it sends changes the target"
                ),
            ]
        );
        assert_eq!(view.logs.len(), 2);
    }

    /// A log line from the scan, such as out-of-band callbacks being unavailable, is shown.
    #[test]
    fn what_the_scan_could_not_test_is_in_the_log() {
        let mut view = Plessor::new("http://app.test".into());
        view.apply(json!({"type": "log", "message": "out-of-band callbacks are UNAVAILABLE"}));
        assert_eq!(view.logs.len(), 1);
    }
}
