//! Ambulo's dashboard.
//!
//! The screen, the keys and the logs come from `cfx_tui`. What is left here is
//! the part that is actually about content discovery: turning stream events
//! into counters, and listing what was found.

use crate::scanner::StreamEvent;
use cfx_tui::{Cell, Column, Dashboard, Level, Logs, Progress, Stat, View};
use tokio::sync::mpsc;

const HITS: char = 'h';
const VIEWS: &[View] = &[View::new(HITS, "Hits")];
const COLUMNS: &[Column] = &[
    Column::new("Code", 6),
    Column::new("Body", 10),
    Column::new("Headers", 10),
    Column::rest("URL"),
];

struct Hit {
    url: String,
    code: String,
    body: i64,
    headers: i64,
}

struct Ambulo {
    target: String,
    total: usize,
    scanned: usize,
    found: usize,
    not_found: usize,
    errors: usize,
    hits: Vec<Hit>,
    logs: Logs,
    done: bool,
    #[cfg(feature = "tuning")]
    pacing: cfx_tui::tuning::Snapshot,
}

impl Ambulo {
    fn new(target: String, total: usize) -> Self {
        Self {
            target,
            total,
            scanned: 0,
            found: 0,
            not_found: 0,
            errors: 0,
            hits: Vec::new(),
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
}

impl Dashboard for Ambulo {
    fn name(&self) -> &str {
        "AMBULO"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn finished(&self) -> bool {
        self.done
    }

    fn views(&self) -> &'static [View] {
        VIEWS
    }

    fn progress(&self) -> Progress {
        Progress::Counted {
            done: self.scanned,
            total: self.total,
        }
    }

    fn stats(&self) -> Vec<Stat> {
        vec![
            Stat::count("Found", self.found).good(),
            Stat::count("Not found", self.not_found),
            Stat::count("Errors", self.errors).bad(),
        ]
    }

    fn columns(&self, _view: char) -> &'static [Column] {
        COLUMNS
    }

    fn len(&self, _view: char) -> usize {
        self.hits.len()
    }

    fn row(&self, _view: char, index: usize) -> Vec<Cell> {
        let hit = &self.hits[index];
        vec![
            Cell::status_code(&hit.code),
            Cell::plain(hit.body.to_string()),
            Cell::muted(hit.headers.to_string()),
            Cell::plain(&hit.url),
        ]
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
    target: String,
    operation_id: String,
    total: usize,
    poll_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::spawn_blocking(move || {
        let mut app = Ambulo::new(target, total);
        // The header names the target, so the operation is kept where it can
        // still be read: the first line of the log.
        app.logs.info(format!("operation {operation_id}"));
        let mut rx = rx;
        cfx_tui::run(&mut app, poll_timeout, |app| {
            let mut came = false;
            while let Ok(event) = rx.try_recv() {
                app.apply(event);
                came = true;
            }
            came
        })
    })
    .await?
    .map_err(|e| -> Box<dyn std::error::Error> { format!("{e}").into() })
}
