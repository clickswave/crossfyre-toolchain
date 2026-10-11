//! Doorward's dashboard.
//!
//! Chrome, keys and logs come from `cfx_tui`. What stays here is the part that
//! is about port scanning: counting states and listing what answered.

use crate::scanner::StreamEvent;
use cfx_tui::{Dashboard, Level, Logs, Stat, View, widgets};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};
use tokio::sync::mpsc;

const PORTS: char = 'p';
const VIEWS: &[View] = &[View::new(PORTS, "Ports")];

struct Finding {
    host: String,
    port: String,
    status: String,
    service: String,
    latency: String,
    banner: String,
}

struct Doorward {
    operation_id: String,
    total: usize,
    received: usize,
    open: usize,
    closed: usize,
    filtered: usize,
    findings: Vec<Finding>,
    table: TableState,
    logs: Logs,
    done: bool,
    // Latest governor telemetry, for the pacing strip. The daemon already
    // streams `governor` events; this just keeps the newest one. Only built
    // with the tuning feature, so a default binary carries neither the field
    // nor the strip.
    #[cfg(feature = "tuning")]
    pacing: cfx_tui::tuning::Snapshot,
}

impl Doorward {
    fn new(operation_id: String, total: usize) -> Self {
        Self {
            operation_id,
            total,
            received: 0,
            open: 0,
            closed: 0,
            filtered: 0,
            findings: Vec::new(),
            table: TableState::default(),
            logs: Logs::new(),
            done: false,
            #[cfg(feature = "tuning")]
            pacing: cfx_tui::tuning::Snapshot::default(),
        }
    }

    fn apply(&mut self, event: StreamEvent) {
        match event.kind.as_str() {
            "result" => {
                self.received += 1;
                match event.status.as_deref() {
                    Some("open") => self.open += 1,
                    Some("filtered") => self.filtered += 1,
                    _ => self.closed += 1,
                }
                // Keep only what is drawn. A full sweep produces a row per
                // probed port, and holding the closed ones costs memory for
                // something nobody scrolls through.
                if event.status.as_deref() != Some("closed") {
                    self.findings.push(Finding {
                        host: event.host.unwrap_or_else(|| "-".into()),
                        port: event.port.map(|p| p.to_string()).unwrap_or_default(),
                        status: event.status.unwrap_or_else(|| "-".into()),
                        service: event.service.unwrap_or_else(|| "-".into()),
                        latency: event
                            .latency_ms
                            .map(|l| format!("{l}ms"))
                            .unwrap_or_default(),
                        banner: event.banner.unwrap_or_default(),
                    });
                    self.table
                        .select(Some(self.findings.len().saturating_sub(1)));
                }
            }
            "log" => {
                let level = Level::parse(event.log_level.as_deref().unwrap_or("info"));
                self.logs.push(level, event.message.unwrap_or_default());
            }
            "done" => {
                self.done = true;
                if let Some(o) = event.open {
                    self.open = o;
                }
                if let Some(c) = event.closed {
                    self.closed = c;
                }
                if let Some(f) = event.filtered {
                    self.filtered = f;
                }
                self.received = self.open + self.closed + self.filtered;
                self.logs.info(format!(
                    "open {}, closed {}, filtered {}",
                    self.open, self.closed, self.filtered
                ));
            }
            #[cfg(feature = "tuning")]
            "governor" => {
                // Map the governor's public telemetry onto the shared pacing
                // shape. These fields already travel on the wire; this only
                // reads them. Concurrency is the ceiling it is allowing,
                // goodput the useful throughput, phase its current stance, and
                // loss the pressure it is reacting to.
                self.pacing = cfx_tui::tuning::Snapshot {
                    in_flight: None,
                    limit: event.concurrency,
                    rate: event.goodput.map(|g| g as f64),
                    posture: event.phase.clone(),
                    throttled: event.loss_pct,
                };
            }
            _ => {}
        }
    }

    fn render_ports(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(widgets::GAUGE_HEIGHT),
                Constraint::Length(widgets::STATS_HEIGHT),
                Constraint::Min(0),
            ])
            .split(area);

        widgets::progress(frame, rows[0], self.received, self.total, "Progress");
        widgets::stats(
            frame,
            rows[1],
            &[
                Stat::good("Open", self.open),
                Stat::new("Filtered", self.filtered),
                Stat::new("Closed", self.closed),
            ],
        );

        let header = Row::new(
            ["Host", "Port", "State", "Service", "Latency", "Banner"]
                .iter()
                .map(|h| Cell::from(*h).style(cfx_tui::theme::title())),
        )
        .height(1);

        let body: Vec<Row> = self
            .findings
            .iter()
            .map(|f| {
                let colour = match f.status.as_str() {
                    "open" => cfx_tui::theme::GOOD,
                    "filtered" => cfx_tui::theme::WARN,
                    _ => cfx_tui::theme::MUTED,
                };
                Row::new(vec![
                    Cell::from(f.host.clone()),
                    Cell::from(f.port.clone()),
                    Cell::from(f.status.clone()).style(Style::default().fg(colour)),
                    Cell::from(f.service.clone()),
                    Cell::from(f.latency.clone()).style(cfx_tui::theme::label()),
                    Cell::from(f.banner.clone()).style(cfx_tui::theme::label()),
                ])
            })
            .collect();

        frame.render_stateful_widget(
            Table::new(body, widgets::table_constraints(&[22, 7, 9, 14, 9]))
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Results"))
                .row_highlight_style(cfx_tui::theme::selected()),
            rows[2],
            &mut self.table,
        );
    }
}

impl Dashboard for Doorward {
    fn name(&self) -> &str {
        "DOORWARD"
    }

    fn subtitle(&self) -> &str {
        &self.operation_id
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn views(&self) -> &'static [View] {
        VIEWS
    }

    fn render(&mut self, key: char, frame: &mut Frame, area: Rect) {
        if key == PORTS {
            self.render_ports(frame, area);
        }
    }

    fn logs(&mut self) -> &mut Logs {
        &mut self.logs
    }

    #[cfg(feature = "tuning")]
    fn tuning(&self) -> cfx_tui::tuning::Snapshot {
        self.pacing.clone()
    }
}

pub async fn run(
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    operation_id: String,
    total: usize,
    poll_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::spawn_blocking(move || {
        let mut app = Doorward::new(operation_id, total);
        let mut rx = rx;
        cfx_tui::run(&mut app, poll_timeout, |app| {
            while let Ok(event) = rx.try_recv() {
                app.apply(event);
            }
        })
    })
    .await?
    .map_err(|e| -> Box<dyn std::error::Error> { format!("{e}").into() })
}
