//! Voyage's dashboard.
//!
//! The screen, the keys and the logs come from `cfx_tui`. What stays here is
//! the part that is about subdomain enumeration: counting results and listing
//! what turned up, alongside the source that found it.

use crate::scanner::StreamEvent;
use cfx_tui::{Cell, Column, Dashboard, Level, Logs, Progress, Stat, View};
use tokio::sync::mpsc;

const FOUND: char = 'f';
const VIEWS: &[View] = &[View::new(FOUND, "Found")];
const COLUMNS: &[Column] = &[Column::new("Source", 14), Column::rest("Subdomain")];

struct Subdomain {
    name: String,
    source: String,
}

struct Voyage {
    target: String,
    total: usize,
    scanned: usize,
    found: usize,
    not_found: usize,
    subdomains: Vec<Subdomain>,
    logs: Logs,
    done: bool,
    #[cfg(feature = "tuning")]
    pacing: cfx_tui::tuning::Snapshot,
}

impl Voyage {
    fn new(target: String, total: usize) -> Self {
        Self {
            target,
            total,
            scanned: 0,
            found: 0,
            not_found: 0,
            subdomains: Vec::new(),
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
                match event.status.as_deref().unwrap_or("not_found") {
                    "found" => {
                        self.found += 1;
                        if let Some(name) = event.subdomain {
                            self.subdomains.push(Subdomain {
                                name,
                                source: event.source.unwrap_or_default(),
                            });
                        }
                    }
                    _ => self.not_found += 1,
                }
            }
            "log" => {
                let level = Level::parse(event.log_level.as_deref().unwrap_or("info"));
                self.logs.push(level, event.message.unwrap_or_default());
            }
            "done" => {
                self.done = true;
                // Prefer the server's totals: events can be dropped on a slow
                // client, and a summary that disagrees with the rows above it
                // is worse than no summary at all.
                if let Some(f) = event.found {
                    self.found = f;
                }
                if let Some(n) = event.not_found {
                    self.not_found = n;
                }
                if let Some(t) = event.total {
                    self.scanned = t;
                }
                self.logs.info(format!(
                    "found {}, not found {}",
                    self.found, self.not_found
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

impl Dashboard for Voyage {
    fn name(&self) -> &str {
        "VOYAGE"
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
        ]
    }

    fn columns(&self, _view: char) -> &'static [Column] {
        COLUMNS
    }

    fn len(&self, _view: char) -> usize {
        self.subdomains.len()
    }

    fn row(&self, _view: char, index: usize) -> Vec<Cell> {
        let found = &self.subdomains[index];
        vec![Cell::muted(&found.source), Cell::plain(&found.name)]
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
        let mut app = Voyage::new(target, total);
        // The header names the target, so the operation is kept where it can
        // still be read: the first line of the log.
        app.logs.info(format!("operation {operation_id}"));
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
