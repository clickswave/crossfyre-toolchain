//! Doorward's dashboard.
//!
//! The screen, the keys and the logs come from `cfx_tui`. What stays here is
//! the part that is about port scanning: counting states and listing what
//! answered.

use crate::scanner::StreamEvent;
use cfx_tui::{Cell, Column, Dashboard, Level, Logs, Progress, Stat, Tone, View};
use tokio::sync::mpsc;

const PORTS: char = 'p';
const VIEWS: &[View] = &[View::new(PORTS, "Ports")];
const COLUMNS: &[Column] = &[
    Column::new("Host", 22),
    Column::new("Port", 7),
    Column::new("State", 9),
    Column::new("Service", 14),
    Column::new("Latency", 9),
    Column::rest("Banner"),
];

struct Finding {
    host: String,
    port: String,
    status: String,
    service: String,
    latency: String,
    banner: String,
}

struct Doorward {
    target: String,
    total: usize,
    received: usize,
    open: usize,
    closed: usize,
    filtered: usize,
    findings: Vec<Finding>,
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
    fn new(target: String, total: usize) -> Self {
        Self {
            target,
            total,
            received: 0,
            open: 0,
            closed: 0,
            filtered: 0,
            findings: Vec::new(),
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
}

impl Dashboard for Doorward {
    fn name(&self) -> &str {
        "DOORWARD"
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
            done: self.received,
            total: self.total,
        }
    }

    fn stats(&self) -> Vec<Stat> {
        vec![
            Stat::count("Open", self.open).good(),
            Stat::count("Filtered", self.filtered),
            Stat::count("Closed", self.closed),
        ]
    }

    fn columns(&self, _view: char) -> &'static [Column] {
        COLUMNS
    }

    fn len(&self, _view: char) -> usize {
        self.findings.len()
    }

    fn row(&self, _view: char, index: usize) -> Vec<Cell> {
        let found = &self.findings[index];
        let state = match found.status.as_str() {
            "open" => Tone::Good,
            "filtered" => Tone::Warn,
            _ => Tone::Muted,
        };
        vec![
            Cell::plain(&found.host),
            Cell::plain(&found.port),
            Cell::toned(&found.status, state),
            Cell::plain(&found.service),
            Cell::muted(&found.latency),
            Cell::muted(&found.banner),
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
        let mut app = Doorward::new(target, total);
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
