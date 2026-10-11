//! Toolmark's dashboard.
//!
//! Chrome, keys and logs come from `cfx_tui`. What stays here is the part that
//! is about fingerprinting: sorting findings into technology, service and
//! vulnerability, and showing them as they arrive.
//!
//! Toolmark examines one target rather than working through a list, so there is
//! no total to count against and no gauge. The header shows a running count
//! instead, which is honest about not knowing how much is left.

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
const VIEWS: &[View] = &[View::new(FINDINGS, "Findings")];

struct Finding {
    severity: String,
    kind: String,
    name: String,
    detail: String,
}

struct Toolmark {
    target: String,
    technologies: usize,
    services: usize,
    vulnerabilities: usize,
    findings: Vec<Finding>,
    table: TableState,
    logs: Logs,
    done: bool,
}

impl Toolmark {
    fn new(target: String) -> Self {
        Self {
            target,
            technologies: 0,
            services: 0,
            vulnerabilities: 0,
            findings: Vec::new(),
            table: TableState::default(),
            logs: Logs::new(),
            done: false,
        }
    }

    fn apply(&mut self, event: Value) {
        match event["type"].as_str().unwrap_or("") {
            "ack" => {
                if let Some(t) = event["target"].as_str() {
                    self.target = t.to_string();
                    self.logs.info(format!("fingerprinting {t}"));
                }
            }
            "finding" => {
                let data = &event["data"];
                let kind = data["type"].as_str().unwrap_or("finding").to_string();
                match kind.as_str() {
                    "technology" => self.technologies += 1,
                    "vulnerability" => self.vulnerabilities += 1,
                    _ => self.services += 1,
                }

                // Each finding type carries its own useful second column, so
                // pick per type rather than showing one field that is empty
                // for two of the three.
                let detail = match kind.as_str() {
                    "technology" => data["version"].as_str().unwrap_or("").to_string(),
                    "vulnerability" => data["cve"].as_str().unwrap_or("").to_string(),
                    _ => data["server"].as_str().unwrap_or("").to_string(),
                };

                self.findings.push(Finding {
                    severity: data["severity"].as_str().unwrap_or("info").to_string(),
                    kind,
                    name: data["name"]
                        .as_str()
                        .or_else(|| data["title"].as_str())
                        .unwrap_or("-")
                        .to_string(),
                    detail,
                });
                self.table
                    .select(Some(self.findings.len().saturating_sub(1)));
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
                self.logs.info(format!(
                    "{} technologies, {} services, {} vulnerabilities",
                    self.technologies, self.services, self.vulnerabilities
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

        widgets::progress_open(frame, rows[0], self.findings.len(), "Progress", "findings");
        widgets::stats(
            frame,
            rows[1],
            &[
                Stat::new("Technologies", self.technologies),
                Stat::new("Services", self.services),
                Stat::bad("Vulnerabilities", self.vulnerabilities),
            ],
        );

        let header = Row::new(
            ["Severity", "Type", "Name", "Detail"]
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
                    Cell::from(f.kind.clone()).style(cfx_tui::theme::label()),
                    Cell::from(f.name.clone()),
                    Cell::from(f.detail.clone()).style(cfx_tui::theme::label()),
                ])
            })
            .collect();

        frame.render_stateful_widget(
            Table::new(body, widgets::table_constraints(&[10, 14, 40]))
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Findings"))
                .row_highlight_style(cfx_tui::theme::selected()),
            rows[2],
            &mut self.table,
        );
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

impl Dashboard for Toolmark {
    fn name(&self) -> &str {
        "TOOLMARK"
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
        if key == FINDINGS {
            self.render_findings(frame, area);
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
        let mut app = Toolmark::new(target);
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
