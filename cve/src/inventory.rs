//! What toolmark's inventory says of one host and port, for a template scan of it: the
//! products that choose its templates and the CVE leads its templates can answer, and
//! the words for each answer. The node and `plessor scan` both ask toolmark's daemon for
//! the inventory and read it here, so a scan from Cloud and one from the command line
//! take the same rows.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// How long what toolmark saw on a host is taken to be what still runs there, when a scan
/// chooses its templates by it. A host's software changes, and a template held back on a
/// fingerprint taken before the change would miss what it was written for; a week is as
/// old as a fingerprint is trusted for that, and an older one chooses nothing, so every
/// template runs. What toolmark found earlier in the same workflow run is always within it.
pub const FRESH_INVENTORY_SECS: i64 = 7 * 24 * 3600;

/// A CVE lead toolmark gives a product it saw on the host, for a scan to answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLead {
    pub cve: String,
    /// The product as toolmark's inventory names it, which its leads are kept under.
    pub product: String,
    #[serde(default)]
    pub severity: String,
    /// On CISA's known-exploited list.
    #[serde(default)]
    pub kev: bool,
}

/// The rows of one host and port fresh enough to go by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fresh {
    /// What toolmark saw there, by its names for them, part:vendor:product.
    pub products: Vec<String>,
    /// The CVE leads of what it saw, once each by CVE and product.
    pub leads: Vec<HostLead>,
    /// Which inventory, and how old, said with the templates held back and the answers.
    pub from: String,
}

/// The host, lowercased, and port a scan of `target` reaches: a URL's, or a host[:port]'s
/// over http.
pub fn host_and_port(target: &str) -> Option<(String, u16)> {
    let with_scheme = if target.contains("://") {
        target.to_string()
    } else {
        format!("http://{target}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    Some((url.host_str()?.to_lowercase(), url.port_or_known_default()?))
}

/// The rows of `inventory`, toolmark's answer to `inventory`, for `host` and `port` last
/// seen within [`FRESH_INVENTORY_SECS`] of `now`. None when no row for them is fresh.
pub fn fresh(inventory: &Value, host: &str, port: u16, now: i64) -> Option<Fresh> {
    let mut products = BTreeSet::new();
    let mut leads: Vec<HostLead> = Vec::new();
    let mut newest: Option<i64> = None;
    for row in inventory["inventory"].as_array()? {
        let same = row["host"]
            .as_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(host))
            && row["port"].as_u64() == Some(u64::from(port));
        let seen = row["last_seen"].as_str().and_then(crate::unix_time);
        let Some(seen) = seen.filter(|t| same && now - t <= FRESH_INVENTORY_SECS) else {
            continue;
        };
        newest = newest.max(Some(seen));
        for name in row["cpe_names"].as_array().into_iter().flatten() {
            if let Some(name) = name.as_str() {
                products.insert(name.to_string());
            }
        }
        let product = row["product"].as_str().unwrap_or_default();
        for lead in row["leads"].as_array().into_iter().flatten() {
            let Some(cve) = lead["cve"].as_str() else {
                continue;
            };
            if !leads.iter().any(|l| l.cve == cve && l.product == product) {
                leads.push(HostLead {
                    cve: cve.to_string(),
                    product: product.to_string(),
                    severity: lead["severity"].as_str().unwrap_or_default().to_string(),
                    kev: lead["kev"].as_bool().unwrap_or(false),
                });
            }
        }
    }
    let newest = newest?;
    let hours = (now - newest).max(0) / 3600;
    let s = if hours == 1 { "" } else { "s" };
    Some(Fresh {
        products: products.into_iter().collect(),
        leads,
        from: format!(
            "toolmark's inventory of {}:{port}, last seen {hours} hour{s} before the scan",
            host.to_lowercase()
        ),
    })
}

/// What a scan's templates said of a lead. Only a template confirms one; a version
/// matched never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Answer {
    /// A template for its CVE found it.
    #[serde(rename = "confirmed")]
    Confirmed,
    /// A template for its CVE ran, and its requests did not trigger it, or no
    /// out-of-band callback came. Never proof the host is safe: see [`NOT_PROOF`].
    #[serde(rename = "checked, not found")]
    NotFound,
    /// No template for its CVE ran, for the reason given with it.
    #[serde(rename = "not checked")]
    NotChecked,
}

impl Answer {
    pub fn as_str(self) -> &'static str {
        match self {
            Answer::Confirmed => "confirmed",
            Answer::NotFound => "checked, not found",
            Answer::NotChecked => "not checked",
        }
    }
}

/// What a scan said of one lead: the row its `lead_answers` event carries, and what the
/// client that gave it the lead writes back to toolmark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeadAnswer {
    pub cve: String,
    pub product: String,
    pub answer: Answer,
    /// The template that answered, when one did or was held back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Why no template checked it, when none did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What a scan said of the leads of one host and port, as the client that gave it the
/// leads writes it back to toolmark, which keeps each answer with its lead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswersBack {
    pub host: String,
    pub port: u16,
    /// The plessor scan that answered, as its ack named it; empty when it was not kept.
    #[serde(default)]
    pub scan: String,
    pub answers: Vec<LeadAnswer>,
}

impl AnswersBack {
    /// The answers of a scan's `lead_answers` event for `host`:`port`, or None when the
    /// event has none it can read.
    pub fn from_event(host: &str, port: u16, scan: Option<&str>, event: &Value) -> Option<Self> {
        let answers: Vec<LeadAnswer> = serde_json::from_value(event["answers"].clone()).ok()?;
        (!answers.is_empty()).then(|| AnswersBack {
            host: host.to_string(),
            port,
            scan: scan.unwrap_or_default().to_string(),
            answers,
        })
    }

    /// The request toolmark's daemon takes them in.
    pub fn request(&self) -> Value {
        let mut request = serde_json::to_value(self).unwrap_or_default();
        request["operation"] = Value::from("lead_answers");
        request["response"] = Value::from("instant");
        request
    }
}

/// Said wherever "checked, not found" is shown.
pub const NOT_PROOF: &str = "Checked, not found is not proof the host is safe: a WAF, \
                             another path, a needed login or another configuration can hide it.";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_795_273_200; // 2026-11-21T15:00:00Z

    fn inventory(rows: Value) -> Value {
        json!({"status": "completed", "inventory": rows})
    }

    /// The products of the host and port that toolmark saw within a week choose the
    /// templates, and the scan says which inventory and how old.
    #[test]
    fn a_fresh_fingerprint_of_the_host_chooses_the_templates() {
        let inv = inventory(json!([
            {"host": "app.test", "port": 443, "cpe_names": ["a:f5:nginx"], "last_seen": "2026-11-21T13:00:00Z"},
            {"host": "APP.test", "port": 443, "cpe_names": ["a:metabase:metabase"], "last_seen": "2026-11-20T15:00:00Z"},
            {"host": "app.test", "port": 443, "cpe_names": [], "last_seen": "2026-11-21T14:00:00Z"},
            {"host": "app.test", "port": 8443, "cpe_names": ["a:apache:tomcat"], "last_seen": "2026-11-21T14:00:00Z"},
            {"host": "other.test", "port": 443, "cpe_names": ["a:grafana:grafana"], "last_seen": "2026-11-21T14:00:00Z"},
        ]));
        let fresh443 = fresh(&inv, "app.test", 443, NOW).unwrap();
        assert_eq!(fresh443.products, ["a:f5:nginx", "a:metabase:metabase"]);
        assert_eq!(
            fresh443.from,
            "toolmark's inventory of app.test:443, last seen 1 hour before the scan"
        );
        assert_eq!(
            fresh(&inv, "app.test", 8443, NOW).unwrap().products,
            ["a:apache:tomcat"]
        );
    }

    /// What toolmark saw more than a week ago chooses nothing, so every template runs, and
    /// so does a host it never saw.
    #[test]
    fn a_stale_fingerprint_or_none_chooses_nothing() {
        let inv = inventory(json!([
            {"host": "app.test", "port": 443, "cpe_names": ["a:f5:nginx"], "last_seen": "2026-11-14T14:59:59Z"},
            {"host": "app.test", "port": 443, "cpe_names": ["a:metabase:metabase"], "last_seen": "not a time"},
        ]));
        assert_eq!(fresh(&inv, "app.test", 443, NOW), None);
        assert_eq!(fresh(&inv, "unseen.test", 443, NOW), None);
        let week = inventory(json!([
            {"host": "app.test", "port": 443, "cpe_names": ["a:f5:nginx"], "last_seen": "2026-11-14T15:00:00Z"},
        ]));
        assert!(
            fresh(&week, "app.test", 443, NOW).is_some(),
            "a week is fresh"
        );
    }

    /// The leads of the fresh rows come with the products, once each, under the product
    /// toolmark keeps them by; a stale row's leads do not.
    #[test]
    fn the_leads_of_the_fresh_rows_come_too() {
        let inv = inventory(json!([
            {"host": "app.test", "port": 80, "product": "Apache HTTP Server",
             "cpe_names": ["a:apache:http_server"], "last_seen": "2026-11-21T14:00:00Z",
             "leads": [
                {"cve": "CVE-2021-41773", "severity": "high", "kev": true},
                {"cve": "CVE-2021-42013", "severity": "critical"},
             ]},
            {"host": "app.test", "port": 80, "product": "Apache HTTP Server",
             "cpe_names": ["a:apache:http_server"], "last_seen": "2026-11-21T13:00:00Z",
             "leads": [{"cve": "CVE-2021-41773", "severity": "high", "kev": true}]},
            {"host": "app.test", "port": 80, "product": "Old Thing",
             "cpe_names": ["a:old:thing"], "last_seen": "2026-11-01T00:00:00Z",
             "leads": [{"cve": "CVE-2099-0001", "severity": "low"}]},
        ]));
        let leads = fresh(&inv, "app.test", 80, NOW).unwrap().leads;
        let lead = |cve: &str, severity: &str, kev: bool| HostLead {
            cve: cve.into(),
            product: "Apache HTTP Server".into(),
            severity: severity.into(),
            kev,
        };
        assert_eq!(
            leads,
            [
                lead("CVE-2021-41773", "high", true),
                lead("CVE-2021-42013", "critical", false)
            ]
        );
    }

    /// A target names its host, lowercased, and its port, or the scheme's.
    #[test]
    fn a_target_names_its_host_and_port() {
        assert_eq!(
            host_and_port("https://APP.test/path"),
            Some(("app.test".into(), 443))
        );
        assert_eq!(
            host_and_port("app.test:8443"),
            Some(("app.test".into(), 8443))
        );
        assert_eq!(host_and_port("app.test"), Some(("app.test".into(), 80)));
    }

    /// The answers of a scan's event go back to toolmark for their host and port, with the
    /// scan that gave them, as the `lead_answers` request; an event with none sends none.
    #[test]
    fn the_answers_go_back_as_toolmark_takes_them() {
        let event = json!({"type": "lead_answers", "answers": [
            {"cve": "CVE-2021-41773", "product": "Apache HTTP Server", "answer": "confirmed",
             "template": "CVE-2021-41773"},
            {"cve": "CVE-2099-0001", "product": "Apache HTTP Server", "answer": "not checked",
             "reason": "no template checks it"},
        ]});
        let back = AnswersBack::from_event("app.test", 80, Some("s1"), &event).unwrap();
        assert_eq!(
            back.request(),
            json!({"operation": "lead_answers", "response": "instant", "host": "app.test",
                   "port": 80, "scan": "s1", "answers": event["answers"]})
        );
        let parsed: AnswersBack = serde_json::from_value(back.request()).unwrap();
        assert_eq!(parsed, back);
        assert!(AnswersBack::from_event("app.test", 80, None, &json!({"answers": []})).is_none());
        assert!(
            AnswersBack::from_event(
                "app.test",
                80,
                None,
                &json!({"answers": [{"cve": "x",
                "product": "y", "answer": "not exploitable"}]})
            )
            .is_none(),
            "only the three answers are read"
        );
    }

    /// An answer is written as it is shown, and a negative one never as "not exploitable".
    #[test]
    fn the_answers_are_written_as_they_are_shown() {
        for (answer, said) in [
            (Answer::Confirmed, "confirmed"),
            (Answer::NotFound, "checked, not found"),
            (Answer::NotChecked, "not checked"),
        ] {
            assert_eq!(answer.as_str(), said);
            assert_eq!(serde_json::to_value(answer).unwrap(), json!(said));
        }
        assert!(NOT_PROOF.contains("not proof the host is safe"));
    }
}
