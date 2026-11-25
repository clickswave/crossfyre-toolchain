//! Plessor's dashboard.
//!
//! The screen, the keys and the logs come from `cfx_tui`. What stays here is
//! the part that is about vulnerability scanning: tracking template progress, listing
//! matches worst-first, since a critical three screens down is a critical
//! nobody saw, listing the templates the scan held back, so a shorter run is
//! not taken for a clean one, and toolmark's CVE leads for the target beside
//! the findings, with what the templates said of each.

use cfx_tui::{Cell, Column, Dashboard, Level, Logs, Progress, Stat, Tone, View};
use serde_json::Value;
use tokio::sync::mpsc;

const FINDINGS: char = 'f';
const LEADS: char = 'c';
const HELD_BACK: char = 'h';
// None of the three is kept in arrival order: findings are worst first, and the
// other two are lists read from the top. So none follows its newest row.
const VIEWS: &[View] = &[
    View::new(FINDINGS, "Findings").from_top(),
    View::new(LEADS, "CVE leads").from_top(),
    View::new(HELD_BACK, "Held back").from_top(),
];
const FINDING_COLUMNS: &[Column] = &[
    Column::new("Severity", 10),
    Column::new("Name", 44),
    Column::rest("Matched at"),
];
const LEAD_COLUMNS: &[Column] = &[
    Column::new("CVE", 16),
    Column::new("Product", 22),
    Column::new("Severity", 10),
    Column::new("KEV", 4),
    Column::new("Answer", 20),
    Column::rest("By, or why not"),
];
const HELD_BACK_COLUMNS: &[Column] = &[Column::new("Template", 40), Column::rest("Why")];

struct Finding {
    severity: String,
    name: String,
    matched_at: String,
    /// Rank for sorting: lower is worse, so criticals float to the top.
    rank: u8,
}

/// A CVE lead toolmark gave the scan, and what its templates said of it once they ran.
struct Lead {
    cve: String,
    product: String,
    severity: String,
    kev: bool,
    /// Empty until the scan answers.
    answer: String,
    /// The template that answered, or why none did.
    by: String,
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
    leads: Vec<Lead>,
    leads_from: String,
    /// The line said with a lead checked and not found: that it is no proof.
    not_proof: Option<String>,
    held: Vec<HeldBack>,
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
            leads: Vec::new(),
            leads_from: String::new(),
            not_proof: None,
            held: Vec::new(),
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
            "leads" => {
                self.leads_from = event["from"].as_str().unwrap_or_default().to_string();
                let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
                self.leads = event["leads"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|l| Lead {
                        cve: text(&l["cve"]),
                        product: text(&l["product"]),
                        severity: text(&l["severity"]),
                        kev: l["kev"].as_bool().unwrap_or(false),
                        answer: String::new(),
                        by: String::new(),
                    })
                    .collect();
            }
            "lead_answers" => {
                for a in event["answers"].as_array().into_iter().flatten() {
                    let (cve, product) = (a["cve"].as_str(), a["product"].as_str());
                    if let Some(lead) = self.leads.iter_mut().find(|l| {
                        Some(l.cve.as_str()) == cve && Some(l.product.as_str()) == product
                    }) {
                        lead.answer = a["answer"].as_str().unwrap_or_default().to_string();
                        lead.by = a["reason"]
                            .as_str()
                            .or(a["template"].as_str())
                            .unwrap_or_default()
                            .to_string();
                    }
                }
                self.not_proof = event["not_proof"].as_str().map(str::to_string);
                if let Some(m) = event["message"].as_str() {
                    self.logs.info(m);
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

impl Dashboard for Plessor {
    fn name(&self) -> &str {
        "PLESSOR"
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
            done: self.processed,
            total: self.total,
        }
    }

    fn stats(&self) -> Vec<Stat> {
        let confirmed = self
            .leads
            .iter()
            .filter(|l| l.answer == "confirmed")
            .count();
        vec![
            Stat::count("Critical", self.critical).bad(),
            Stat::count("High", self.high),
            Stat::count("Total", self.found),
            Stat::text(
                "Leads confirmed",
                format!("{confirmed} of {}", self.leads.len()),
            ),
        ]
    }

    fn columns(&self, view: char) -> &'static [Column] {
        match view {
            LEADS => LEAD_COLUMNS,
            HELD_BACK => HELD_BACK_COLUMNS,
            _ => FINDING_COLUMNS,
        }
    }

    fn len(&self, view: char) -> usize {
        match view {
            LEADS => self.leads.len(),
            HELD_BACK => self.held.len(),
            _ => self.findings.len(),
        }
    }

    fn row(&self, view: char, index: usize) -> Vec<Cell> {
        match view {
            LEADS => {
                let lead = &self.leads[index];
                let (answer, tone) = match lead.answer.as_str() {
                    "" => ("waiting", Tone::Muted),
                    "confirmed" => ("confirmed", Tone::Bad),
                    other => (other, Tone::Plain),
                };
                vec![
                    Cell::plain(&lead.cve),
                    Cell::plain(&lead.product),
                    Cell::severity(&lead.severity),
                    Cell::plain(if lead.kev { "yes" } else { "" }),
                    Cell::toned(answer, tone),
                    Cell::muted(&lead.by),
                ]
            }
            HELD_BACK => {
                let held = &self.held[index];
                vec![Cell::plain(&held.template), Cell::muted(&held.why)]
            }
            _ => {
                let finding = &self.findings[index];
                vec![
                    Cell::severity(&finding.severity),
                    Cell::plain(&finding.name),
                    Cell::muted(&finding.matched_at),
                ]
            }
        }
    }

    fn note(&self, view: char) -> Option<Cell> {
        match view {
            // A lead checked and not found is no proof, said under the table wherever
            // one is. Until then the line says where the leads came from.
            LEADS => match &self.not_proof {
                Some(line) => Some(Cell::toned(line, Tone::Warn)),
                None if self.leads_from.is_empty() => None,
                None => Some(Cell::muted(format!("From {}.", self.leads_from))),
            },
            HELD_BACK => Some(Cell::muted("Not run, so not tested.")),
            _ => None,
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
            let mut came = false;
            while let Ok(event) = rx.try_recv() {
                app.apply(event);
                came = true;
            }
            came
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

    /// The leads a scan was given are listed as it starts, each answered when the scan
    /// says, with the template that answered or why none did, and the line that a lead
    /// checked and not found is no proof.
    #[test]
    fn the_leads_are_listed_and_answered() {
        let mut view = Plessor::new("http://app.test".into());
        view.apply(json!({"type": "leads", "from": "toolmark's inventory of app.test:80",
            "leads": [
                {"cve": "CVE-2021-41773", "product": "Apache HTTP Server", "severity": "high", "kev": true},
                {"cve": "CVE-2021-42013", "product": "Apache HTTP Server", "severity": "critical"},
                {"cve": "CVE-2099-0001", "product": "Apache HTTP Server", "severity": "low"},
            ]}));
        assert!(view.leads.iter().all(|l| l.answer.is_empty()));
        view.apply(json!({"type": "lead_answers", "answers": [
                {"cve": "CVE-2021-41773", "product": "Apache HTTP Server", "answer": "confirmed",
                 "template": "CVE-2021-41773"},
                {"cve": "CVE-2021-42013", "product": "Apache HTTP Server",
                 "answer": "checked, not found", "template": "CVE-2021-42013"},
                {"cve": "CVE-2099-0001", "product": "Apache HTTP Server", "answer": "not checked",
                 "reason": "no template checks it"},
            ], "not_proof": "not proof the host is safe", "message": "3 CVE leads"}));
        let shown: Vec<(&str, &str)> = view
            .leads
            .iter()
            .map(|l| (l.answer.as_str(), l.by.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                ("confirmed", "CVE-2021-41773"),
                ("checked, not found", "CVE-2021-42013"),
                ("not checked", "no template checks it"),
            ]
        );
        assert_eq!(
            view.not_proof.as_deref(),
            Some("not proof the host is safe")
        );
        assert!(view.leads[0].kev);
    }

    /// A log line from the scan, such as out-of-band callbacks being unavailable, is shown.
    #[test]
    fn what_the_scan_could_not_test_is_in_the_log() {
        let mut view = Plessor::new("http://app.test".into());
        view.apply(json!({"type": "log", "message": "out-of-band callbacks are UNAVAILABLE"}));
        assert_eq!(view.logs.len(), 1);
    }
}
