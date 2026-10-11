//! Ambulo's dashboard.
//!
//! The chrome, key handling and logs come from `cfx_tui`. What is left here is
//! the part that is actually about content discovery: turning stream events
//! into counters, and drawing the table of what was found.

use crate::scanner::StreamEvent;
use cfx_tui::{Dashboard, Level, Logs, Stat, View, widgets};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};
use tokio::sync::mpsc;

const HITS: char = 'h';
const VIEWS: &[View] = &[View::new(HITS, "Hits")];

struct Hit {
    url: String,
    code: String,
    body: i64,
    headers: i64,
}

struct Ambulo {
    operation_id: String,
    total: usize,
    scanned: usize,
    found: usize,
    not_found: usize,
    errors: usize,
    hits: Vec<Hit>,
    table: TableState,
    logs: Logs,
    done: bool,
    #[cfg(feature = "tuning")]
    pacing: cfx_tui::tuning::Snapshot,
}

impl Ambulo {
    fn new(operation_id: String, total: usize) -> Self {
        Self {
            operation_id,
            total,
            scanned: 0,
            found: 0,
            not_found: 0,
            errors: 0,
            hits: Vec::new(),
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
                self.scanned += 1;
                match event.status.as_deref().unwrap_or("error") {
                    "found" => {
                        self.found += 1;
                        if let Some(url) = event.url {
                            self.hits.push(Hit {
                                url,
                                code: event.code.unwrap_or_default(),
                                body: event.body_length.unwrap_or(0),
                                headers: event.headers_length.unwrap_or(0),
                            });
                            // Follow the newest hit, so a long run reads as a
                            // feed rather than stalling on the first result.
                            self.table.select(Some(self.hits.len().saturating_sub(1)));
                        }
                    }
                    "not_found" => self.not_found += 1,
                    _ => self.errors += 1,
                }
            }
            "log" => {
                let level = Level::parse(event.log_level.as_deref().unwrap_or("info"));
                self.logs.push(level, event.message.unwrap_or_default());
            }
            "done" => {
                self.done = true;
                // Trust the server's totals over ours: events can be dropped
                // on a slow client, and a summary that disagrees with the
                // final line is worse than no summary.
                if let Some(f) = event.found {
                    self.found = f;
                }
                if let Some(n) = event.not_found {
                    self.not_found = n;
                }
                if let Some(e) = event.error {
                    self.errors = e;
                }
                if let Some(t) = event.total {
                    self.scanned = t;
                }
                self.logs.info(format!(
                    "found {}, not found {}, errors {}",
                    self.found, self.not_found, self.errors
                ));
            }
            #[cfg(feature = "tuning")]
            "governor" => {
                self.pacing = cfx_tui::tuning::Snapshot {
                    in_flight: None,
                    limit: event.concurrency.map(|c| c as usize),
                    rate: None,
                    posture: event.posture.clone(),
                    throttled: None,
                };
                // Delay and health score have no dedicated slot; surface them in
                // the logs so a tuning run still has the full picture.
                if let (Some(d), Some(sc)) = (event.delay_ms, event.score) {
                    self.logs.push(
                        cfx_tui::Level::Debug,
                        format!("pacing: delay {d}ms, score {sc:.2}"),
                    );
                }
            }
            _ => {}
        }
    }

    fn render_hits(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(widgets::GAUGE_HEIGHT),
                Constraint::Length(widgets::STATS_HEIGHT),
                Constraint::Min(0),
            ])
            .split(area);

        widgets::progress(frame, rows[0], self.scanned, self.total, "Progress");
        widgets::stats(
            frame,
            rows[1],
            &[
                Stat::good("Found", self.found),
                Stat::new("Not found", self.not_found),
                Stat::bad("Errors", self.errors),
            ],
        );

        let header = Row::new(
            ["Code", "Body", "Headers", "URL"]
                .iter()
                .map(|h| Cell::from(*h).style(cfx_tui::theme::title())),
        )
        .height(1);

        let body: Vec<Row> = self
            .hits
            .iter()
            .map(|h| {
                Row::new(vec![
                    Cell::from(h.code.clone())
                        .style(Style::default().fg(cfx_tui::theme::status_code(&h.code))),
                    Cell::from(h.body.to_string()),
                    Cell::from(h.headers.to_string()),
                    Cell::from(h.url.clone()),
                ])
            })
            .collect();

        frame.render_stateful_widget(
            Table::new(body, widgets::table_constraints(&[6, 10, 10]))
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Found"))
                .row_highlight_style(cfx_tui::theme::selected()),
            rows[2],
            &mut self.table,
        );
    }
}

impl Dashboard for Ambulo {
    fn name(&self) -> &str {
        "AMBULO"
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
        if key == HITS {
            self.render_hits(frame, area);
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
        let mut app = Ambulo::new(operation_id, total);
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
