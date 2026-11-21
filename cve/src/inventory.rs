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
