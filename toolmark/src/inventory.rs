//! `toolmark inventory`: what toolmark knows runs where, from its inventory view.

use serde_json::Value;
use std::io;

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
/// vendor and when it was last seen, to the minute.
fn list(rows: &[Value]) -> cfx_tui::table::List<'static> {
    let text = |row: &Value, key: &str| row[key].as_str().unwrap_or_default().to_string();
    let or_dash = |s: String| if s.is_empty() { "-".to_string() } else { s };
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let seen = text(row, "last_seen");
            vec![
                format!("{}:{}", text(row, "host"), row["port"]),
                text(row, "product"),
                or_dash(text(row, "version")),
                or_dash(text(row, "vendor")),
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
            "{} on {}",
            plural(table.len(), "product", "products"),
            plural(hosts.len(), "host", "hosts")
        ),
        header: &["HOST", "PRODUCT", "VERSION", "VENDOR", "LAST SEEN"],
        widths: &[26, 24, 14, 14],
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
            ["app.test:443", "Laravel", "-", "-", "2026-11-20 03:31 UTC"]
        );
        assert_eq!(list.rows[2][..3], ["db.test:8080", "phpMyAdmin", "5.2.1"]);
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
