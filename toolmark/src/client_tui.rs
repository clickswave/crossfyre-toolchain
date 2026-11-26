//! Toolmark's dashboard.
//!
//! The screen, the keys and the logs come from `cfx_tui`. What stays here is
//! the part that is about fingerprinting: sorting findings into technology,
//! service and vulnerability, and listing them as they arrive.
//!
//! Toolmark examines one target rather than working through a list, so there is
//! no total to count against and no bar to fill. It reports a running count
//! instead, which is honest about not knowing how much is left.

use cfx_tui::{Cell, Column, Dashboard, Level, Logs, Progress, Stat, View};
use serde_json::Value;
use tokio::sync::mpsc;

const FINDINGS: char = 'f';
const VIEWS: &[View] = &[View::new(FINDINGS, "Findings")];
const COLUMNS: &[Column] = &[
    Column::new("Severity", 10),
    Column::new("Type", 14),
    Column::new("Name", 40),
    Column::rest("Detail"),
];

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
                    // The run's record of what stands in front of the target, which
                    // is not a service.
                    "environment" => {}
                    _ => self.services += 1,
                }

                // Each finding type carries its own useful second column, so
                // pick per type rather than showing one field that is empty
                // for two of the three.
                let detail = match kind.as_str() {
                    "technology" => match (data["version"].as_str(), data["distro"].as_str()) {
                        (Some(version), Some(distro)) => format!("{version} ({distro})"),
                        (Some(version), None) => version.to_string(),
                        (None, _) => range_text(&data["version_range"]),
                    },
                    "vulnerability" => data["cve"].as_str().unwrap_or("").to_string(),
                    "environment" => match data["recommended_rate"].as_str() {
                        Some(rate) => format!("rate {rate}"),
                        None => String::new(),
                    },
                    _ => data["server"].as_str().unwrap_or("").to_string(),
                };

                let mut name = match kind.as_str() {
                    "environment" => environment_name(data),
                    _ => data["name"]
                        .as_str()
                        .or_else(|| data["title"].as_str())
                        .unwrap_or("-")
                        .to_string(),
                };
                // What could not be told apart from it, said with it.
                let candidates: Vec<&str> = data["candidates"]
                    .as_array()
                    .map(|c| c.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if !candidates.is_empty() {
                    name = format!("{name}, possibly {}", candidates.join(" or "));
                }
                self.findings.push(Finding {
                    severity: data["severity"].as_str().unwrap_or("info").to_string(),
                    kind,
                    name,
                    detail,
                });
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
}

impl Dashboard for Toolmark {
    fn name(&self) -> &str {
        "TOOLMARK"
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
        Progress::Open {
            done: self.findings.len(),
            unit: "findings",
        }
    }

    fn stats(&self) -> Vec<Stat> {
        vec![
            Stat::count("Technologies", self.technologies),
            Stat::count("Services", self.services),
            Stat::count("Vulnerabilities", self.vulnerabilities).bad(),
        ]
    }

    fn columns(&self, _view: char) -> &'static [Column] {
        COLUMNS
    }

    fn len(&self, _view: char) -> usize {
        self.findings.len()
    }

    fn row(&self, _view: char, index: usize) -> Vec<Cell> {
        let finding = &self.findings[index];
        vec![
            Cell::severity(&finding.severity),
            Cell::muted(&finding.kind),
            Cell::plain(&finding.name),
            Cell::muted(&finding.detail),
        ]
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

/// Where a version lies, as `>= 5.0, < 6.5`, or empty for no range.
fn range_text(range: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(since) = range["since"].as_str() {
        parts.push(format!(">= {since}"));
    }
    if let Some(until) = range["until"].as_str() {
        parts.push(format!("< {until}"));
    }
    parts.join(", ")
}

/// What stands in front of the target, from the run's environment record: the WAF
/// seen, if any, and the CDN it is behind.
fn environment_name(data: &Value) -> String {
    let waf = match data["waf_vendor"].as_str() {
        Some(vendor) => format!("WAF: {vendor}"),
        None => "No WAF seen".to_string(),
    };
    match data["cdn"].as_str() {
        Some(cdn) => format!("{waf}, behind {cdn}"),
        None => waf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A technology that could not be told apart from what refines it is listed with
    /// those it may be.
    #[test]
    fn a_technology_is_listed_with_what_it_may_be() {
        let mut view = Toolmark::new("http://example.test/".into());
        for candidates in [json!([]), json!(["Framework B", "Framework C"])] {
            view.apply(json!({"type": "finding", "data": {
                "type": "technology", "name": "Framework A", "version": "2.1",
                "candidates": candidates,
            }}));
        }
        let names: Vec<&str> = view.findings.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Framework A",
                "Framework A, possibly Framework B or Framework C"
            ]
        );
    }

    /// A technology with no exact version shows where its version lies.
    #[test]
    fn a_technology_shows_a_version_range_when_it_has_no_version() {
        let mut view = Toolmark::new("http://example.test/".into());
        for (version, range) in [
            (json!("6.4.2"), json!(null)),
            (json!(null), json!({"since": "5.0", "until": null})),
            (json!(null), json!({"since": "6.4", "until": "6.5"})),
        ] {
            view.apply(json!({"type": "finding", "data": {
                "type": "technology", "name": "WordPress", "version": version,
                "version_range": range,
            }}));
        }
        let details: Vec<&str> = view.findings.iter().map(|f| f.detail.as_str()).collect();
        assert_eq!(details, ["6.4.2", ">= 5.0", ">= 6.4, < 6.5"]);
    }

    /// A technology whose banner named the distribution that built it says so beside the
    /// version.
    #[test]
    fn a_technology_shows_the_distro_that_built_it() {
        let mut view = Toolmark::new("10.0.0.1:22".into());
        for distro in [json!("Ubuntu-3ubuntu0.6"), json!(null)] {
            view.apply(json!({"type": "finding", "data": {
                "type": "technology", "name": "OpenSSH", "version": "8.9p1",
                "distro": distro,
            }}));
        }
        let details: Vec<&str> = view.findings.iter().map(|f| f.detail.as_str()).collect();
        assert_eq!(details, ["8.9p1 (Ubuntu-3ubuntu0.6)", "8.9p1"]);
    }

    /// The run's environment record says what stood in front of the target, and is
    /// not counted as a service.
    #[test]
    fn the_environment_record_says_what_stands_in_front_of_the_target() {
        let mut view = Toolmark::new("http://example.test/".into());
        for (waf, cdn, rate) in [
            (json!(null), json!(null), "normal"),
            (json!("Cloudflare"), json!("Cloudflare"), "low"),
        ] {
            view.apply(json!({"type": "finding", "data": {
                "type": "environment", "severity": "info", "waf_vendor": waf, "cdn": cdn,
                "recommended_rate": rate,
            }}));
        }
        let rows: Vec<(&str, &str)> = view
            .findings
            .iter()
            .map(|f| (f.name.as_str(), f.detail.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("No WAF seen", "rate normal"),
                ("WAF: Cloudflare, behind Cloudflare", "rate low")
            ]
        );
        assert_eq!(view.services, 0);
    }
}
