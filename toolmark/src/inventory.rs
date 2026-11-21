//! `toolmark inventory`: what toolmark knows runs where, from its inventory view.

use serde_json::{Value, json};
use std::io;

/// The inventory `answer` with the CVE leads `cves` gives each product at its version,
/// and the data they come from.
pub fn with_leads(mut answer: Value, cves: &crate::cve::Cves) -> Value {
    let Some(rows) = answer["inventory"].as_array_mut() else {
        return answer;
    };
    for row in rows.iter_mut() {
        let names: Vec<cfx_cve::Cpe> = row["cpe_names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|n| cfx_cve::Cpe::parse(n.as_str()?))
            .collect();
        let version = row["version"].as_str().unwrap_or_default().to_string();
        let distro = row["distro"]
            .as_str()
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        let leads = if names.is_empty() || version.is_empty() {
            Vec::new()
        } else {
            cves.leads(&names, &version, distro.as_deref()).0
        };
        row["leads"] = leads
            .iter()
            .map(|l| {
                json!({
                    "cve": l.cve, "severity": l.known.severity, "cvss": l.known.score,
                    "kev": l.known.kev, "epss": l.known.epss, "possible": l.possible,
                    "backport": l.backport,
                })
            })
            .collect();
    }
    let from = cves.from();
    for row in rows.iter_mut() {
        row["cve_data"] = json!(from);
    }
    answer["cve_data"] = json!(from);
    answer
}

/// `rows`, the inventory the daemon answered with, as the `inventory` command shows it: in
/// a table when `tui`, and otherwise written out a JSON object a line.
///
/// Blocking, and expects to own the terminal when `tui`. Under tokio, wrap the call in
/// `spawn_blocking`.
pub fn show(rows: &[Value], tui: bool) -> io::Result<()> {
    if !tui {
        return print(&mut io::stdout().lock(), rows);
    }
    cfx_tui::table::show(&list(rows))
}

/// `rows` written to `out` a JSON object a line. A reader that stops early, as `head`
/// does, has what it wanted, and is not an error.
fn print(out: &mut impl io::Write, rows: &[Value]) -> io::Result<()> {
    let written = rows.iter().try_for_each(|row| writeln!(out, "{row}"));
    match written {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// The inventory as the table shows it: a host and port, the product, its version, its
/// vendor, its CVE leads with how many are known to be exploited, and when it was last
/// seen, to the minute.
fn list(rows: &[Value]) -> cfx_tui::table::List<'static> {
    let text = |row: &Value, key: &str| row[key].as_str().unwrap_or_default().to_string();
    let or_dash = |s: String| if s.is_empty() { "-".to_string() } else { s };
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let seen = text(row, "last_seen");
            let leads = row["leads"].as_array().map_or(0, Vec::len);
            let kev = row["leads"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|l| l["kev"] == true)
                .count();
            vec![
                format!("{}:{}", text(row, "host"), row["port"]),
                text(row, "product"),
                or_dash(text(row, "version")),
                or_dash(text(row, "vendor")),
                match (leads, kev) {
                    (0, _) => "-".to_string(),
                    (n, 0) => n.to_string(),
                    (n, k) => format!("{n} ({k} KEV)"),
                },
                seen.get(..16)
                    .map(|m| format!("{} UTC", m.replace('T', " ")))
                    .unwrap_or(seen),
            ]
        })
        .collect();
    let mut hosts: Vec<&String> = table.iter().map(|r| &r[0]).collect();
    hosts.sort();
    hosts.dedup();
    let plural =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    cfx_tui::table::List {
        name: "TOOLMARK",
        title: "INVENTORY",
        summary: format!(
            "{} on {}{}",
            plural(table.len(), "product", "products"),
            plural(hosts.len(), "host", "hosts"),
            rows.first()
                .and_then(|r| r["cve_data"].as_str())
                .map(|from| format!(", CVE leads from {from}"))
                .unwrap_or_default()
        ),
        header: &[
            "HOST",
            "PRODUCT",
            "VERSION",
            "VENDOR",
            "CVE LEADS",
            "LAST SEEN",
        ],
        widths: &[26, 24, 14, 14, 12],
        rows: table,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_inventory_reads_as_hosts_products_and_versions() {
        let rows = [
            json!({"host": "app.test", "port": 443, "vendor": "f5", "product": "Nginx",
                   "version": "1.24.0", "cpe": "", "last_seen": "2026-11-20T03:31:00Z"}),
            json!({"host": "app.test", "port": 443, "vendor": "", "product": "Laravel",
                   "version": "", "cpe": "", "last_seen": "2026-11-20T03:31:05Z"}),
            json!({"host": "db.test", "port": 8080, "vendor": "phpmyadmin",
                   "product": "phpMyAdmin", "version": "5.2.1", "cpe": "",
                   "last_seen": "2026-11-19T22:00:00Z"}),
        ];
        let list = list(&rows);
        assert_eq!(list.summary, "3 products on 2 hosts");
        assert_eq!(
            list.rows[1],
            [
                "app.test:443",
                "Laravel",
                "-",
                "-",
                "-",
                "2026-11-20 03:31 UTC"
            ]
        );
        assert_eq!(list.rows[2][..3], ["db.test:8080", "phpMyAdmin", "5.2.1"]);
    }

    /// Each product held at a version gets the leads the CVE data gives it, counted in
    /// the table with those known to be exploited, and the answer says which data.
    #[test]
    fn each_product_gets_its_cve_leads() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(
            folder.path().join(crate::cve::DATASET_FILE),
            r#"{"format": 1, "sequence": 6, "made": "2026-11-23T15:00:00Z", "products": [
              {"part": "a", "vendor": "f5", "product": "nginx", "affected": [
                {"cve": "CVE-2099-0050", "ranges": [{"lt": "1.25.0"}]},
                {"cve": "CVE-2099-0051", "ranges": [{"lt": "1.25.0"}]}]}],
             "cves": {"CVE-2099-0050": {"kev": true, "severity": "high"}, "CVE-2099-0051": {}}}"#,
        )
        .unwrap();
        let nginx = cfx_cve::Cpe::new("a", "f5", "nginx");
        let cves = crate::cve::Cves::load(
            Some(folder.path()),
            &[nginx].into(),
            crate::cve::DATASET_URL,
        );
        let answer = json!({"status": "completed", "inventory": [
            {"host": "app.test", "port": 443, "product": "Nginx", "version": "1.24.0",
             "cpe_names": ["a:f5:nginx"], "distro": "Ubuntu", "last_seen": "2026-11-20T03:31:00Z"},
            {"host": "app.test", "port": 443, "product": "Laravel", "version": "",
             "cpe_names": [], "distro": "", "last_seen": "2026-11-20T03:31:00Z"},
        ]});
        let answer = with_leads(answer, &cves);
        assert_eq!(answer["cve_data"], "CVE dataset 6 of 2026-11-23");
        let rows = answer["inventory"].as_array().unwrap();
        assert_eq!(rows[0]["leads"][0]["cve"], "CVE-2099-0050");
        assert_eq!(rows[0]["leads"][0]["backport"], true);
        assert_eq!(rows[1]["leads"], json!([]));
        assert_eq!(list(rows).rows[0][4], "2 (1 KEV)");
        assert_eq!(
            list(rows).summary,
            "2 products on 1 host, CVE leads from CVE dataset 6 of 2026-11-23"
        );
        assert_eq!(list(rows).rows[1][4], "-");
    }

    /// Written out for a reader that stops early, as `toolmark inventory | head` has.
    #[test]
    fn a_reader_that_stops_early_is_not_an_error() {
        struct Closed;
        impl io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let rows = [json!({"host": "a.test", "port": 80, "product": "Nginx"})];
        assert!(print(&mut Closed, &rows).is_ok());
        let mut kept = Vec::new();
        print(&mut kept, &rows).unwrap();
        assert_eq!(String::from_utf8(kept).unwrap().lines().count(), 1);
    }
}
