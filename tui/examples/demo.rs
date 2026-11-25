//! The dashboard on made-up data, to look at it without a daemon or a target.
//!
//! ```sh
//! cargo run -p cfx_tui --example demo -- plessor
//! CROSSFYRE_THEME=light cargo run -p cfx_tui --example demo -- doorward
//! NO_COLOR=1 cargo run -p cfx_tui --example demo
//! ```
//!
//! Takes voyage, doorward, ambulo, toolmark or plessor, and voyage when given
//! nothing. Rows arrive a few a second and the run ends after about a minute.

use cfx_tui::{Cell, Column, Dashboard, Logs, Progress, Stat, Tone, View};
use std::time::Instant;

/// What a column holds, which decides how its cells are toned.
#[derive(Clone, Copy)]
enum Kind {
    Plain,
    Muted,
    Severity,
    Status,
    State,
}

struct Sheet {
    columns: &'static [Column],
    kinds: &'static [Kind],
    rows: &'static [&'static [&'static str]],
    note: Option<&'static str>,
}

struct Tool {
    name: &'static str,
    target: &'static str,
    /// The work to count through, or none for a run with no total.
    total: Option<usize>,
    views: &'static [View],
    /// One per view, in the views' order. The first fills as the run goes on.
    sheets: &'static [Sheet],
    stats: fn(&Demo) -> Vec<Stat>,
}

struct Demo {
    tool: &'static Tool,
    started: Instant,
    logs: Logs,
    logged: usize,
}

impl Demo {
    /// How far through the run the demo is, from nothing to all of it.
    fn share(&self) -> f64 {
        (self.started.elapsed().as_secs_f64() / 60.0).min(1.0)
    }

    /// Rows of the first view that have arrived.
    fn arrived(&self) -> usize {
        let all = self.tool.sheets[0].rows.len();
        ((self.share() * 4.0).min(1.0) * all as f64).round() as usize
    }

    fn sheet(&self, view: char) -> &'static Sheet {
        let at = self.tool.views.iter().position(|v| v.key == view);
        &self.tool.sheets[at.unwrap_or(0)]
    }

    fn pump(&mut self) {
        while self.logged < self.arrived() {
            let row = self.tool.sheets[0].rows[self.logged];
            self.logs.info(format!("found {}", row.join(" ")));
            self.logged += 1;
        }
    }
}

impl Dashboard for Demo {
    fn name(&self) -> &str {
        self.tool.name
    }

    fn target(&self) -> &str {
        self.tool.target
    }

    fn finished(&self) -> bool {
        self.share() >= 1.0
    }

    fn progress(&self) -> Progress {
        match self.tool.total {
            Some(total) => Progress::Counted {
                done: (self.share() * total as f64) as usize,
                total,
            },
            None => Progress::Open {
                done: self.arrived(),
                unit: "findings",
            },
        }
    }

    fn stats(&self) -> Vec<Stat> {
        (self.tool.stats)(self)
    }

    fn views(&self) -> &'static [View] {
        self.tool.views
    }

    fn columns(&self, view: char) -> &'static [Column] {
        self.sheet(view).columns
    }

    fn len(&self, view: char) -> usize {
        if view == self.tool.views[0].key {
            self.arrived()
        } else {
            self.sheet(view).rows.len()
        }
    }

    fn row(&self, view: char, index: usize) -> Vec<Cell> {
        let sheet = self.sheet(view);
        sheet.rows[index]
            .iter()
            .zip(sheet.kinds)
            .map(|(text, kind)| match kind {
                Kind::Plain => Cell::plain(*text),
                Kind::Muted => Cell::muted(*text),
                Kind::Severity => Cell::severity(*text),
                Kind::Status => Cell::status_code(*text),
                Kind::State => Cell::toned(
                    *text,
                    match *text {
                        "open" => Tone::Good,
                        "filtered" => Tone::Warn,
                        _ => Tone::Muted,
                    },
                ),
            })
            .collect()
    }

    fn note(&self, view: char) -> Option<Cell> {
        self.sheet(view).note.map(Cell::muted)
    }

    fn logs(&mut self) -> &mut Logs {
        &mut self.logs
    }
}

const VOYAGE: Tool = Tool {
    name: "VOYAGE",
    target: "orbital.example",
    total: Some(12_000),
    views: &[View::new('f', "Found")],
    sheets: &[Sheet {
        columns: &[Column::new("Source", 14), Column::rest("Subdomain")],
        kinds: &[Kind::Muted, Kind::Plain],
        rows: &[
            &["crt.sh", "api.orbital.example"],
            &["crt.sh", "www.orbital.example"],
            &["dns", "mail.orbital.example"],
            &["wordlist", "dev.orbital.example"],
            &["crt.sh", "staging.orbital.example"],
            &["wordlist", "vpn.orbital.example"],
            &["crt.sh", "grafana.orbital.example"],
            &["dns", "ns1.orbital.example"],
            &["dns", "ns2.orbital.example"],
            &["wordlist", "admin.orbital.example"],
            &["crt.sh", "auth.orbital.example"],
            &["crt.sh", "cdn.orbital.example"],
            &["wordlist", "git.orbital.example"],
            &["wordlist", "jenkins.orbital.example"],
            &["crt.sh", "status.orbital.example"],
            &["dns", "mx1.orbital.example"],
            &["wordlist", "test.orbital.example"],
            &["crt.sh", "billing.orbital.example"],
            &["wordlist", "beta.orbital.example"],
            &["crt.sh", "api-internal.orbital.example"],
            &["wordlist", "backup.orbital.example"],
            &["dns", "autodiscover.orbital.example"],
            &["crt.sh", "shop.orbital.example"],
            &["wordlist", "old.orbital.example"],
        ],
        note: None,
    }],
    stats: |demo| {
        let done = (demo.share() * 12_000.0) as usize;
        vec![
            Stat::count("Found", demo.arrived()).good(),
            Stat::count("Not found", done.saturating_sub(demo.arrived())),
        ]
    },
};

const DOORWARD: Tool = Tool {
    name: "DOORWARD",
    target: "10.20.0.0/24",
    total: Some(25_400),
    views: &[View::new('p', "Ports")],
    sheets: &[Sheet {
        columns: &[
            Column::new("Host", 22),
            Column::new("Port", 7),
            Column::new("State", 9),
            Column::new("Service", 14),
            Column::new("Latency", 9),
            Column::rest("Banner"),
        ],
        kinds: &[
            Kind::Plain,
            Kind::Plain,
            Kind::State,
            Kind::Plain,
            Kind::Muted,
            Kind::Muted,
        ],
        rows: &[
            &[
                "10.20.0.4",
                "22",
                "open",
                "ssh",
                "2ms",
                "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
            ],
            &["10.20.0.4", "80", "open", "http", "3ms", "nginx/1.24.0"],
            &["10.20.0.4", "443", "open", "https", "3ms", "nginx/1.24.0"],
            &[
                "10.20.0.9",
                "22",
                "open",
                "ssh",
                "2ms",
                "SSH-2.0-OpenSSH_8.9p1",
            ],
            &["10.20.0.9", "5432", "open", "postgresql", "1ms", ""],
            &["10.20.0.12", "3306", "filtered", "mysql", "", ""],
            &["10.20.0.14", "6379", "open", "redis", "1ms", "redis 7.2.4"],
            &[
                "10.20.0.21",
                "8080",
                "open",
                "http-alt",
                "4ms",
                "Jetty(10.0.18)",
            ],
            &["10.20.0.21", "8443", "open", "https-alt", "5ms", ""],
            &[
                "10.20.0.23",
                "25",
                "open",
                "smtp",
                "6ms",
                "220 mx1 ESMTP Postfix",
            ],
            &["10.20.0.30", "445", "filtered", "microsoft-ds", "", ""],
            &["10.20.0.30", "3389", "open", "ms-wbt-server", "9ms", ""],
            &["10.20.0.41", "9200", "open", "elasticsearch", "2ms", ""],
            &["10.20.0.41", "5601", "open", "kibana", "3ms", ""],
            &[
                "10.20.0.52",
                "21",
                "open",
                "ftp",
                "4ms",
                "220 ProFTPD Server ready",
            ],
            &["10.20.0.60", "53", "open", "domain", "1ms", ""],
        ],
        note: None,
    }],
    stats: |demo| {
        let done = (demo.share() * 25_400.0) as usize;
        vec![
            Stat::count("Open", demo.arrived()).good(),
            Stat::count("Filtered", done / 200),
            Stat::count("Closed", done.saturating_sub(demo.arrived() + done / 200)),
        ]
    },
};

const AMBULO: Tool = Tool {
    name: "AMBULO",
    target: "https://shop.orbital.example",
    total: Some(43_000),
    views: &[View::new('h', "Hits")],
    sheets: &[Sheet {
        columns: &[
            Column::new("Code", 6),
            Column::new("Body", 10),
            Column::new("Headers", 10),
            Column::rest("URL"),
        ],
        kinds: &[Kind::Status, Kind::Plain, Kind::Muted, Kind::Plain],
        rows: &[
            &["200", "14212", "412", "https://shop.orbital.example/login"],
            &["301", "0", "298", "https://shop.orbital.example/admin"],
            &[
                "200",
                "2104",
                "388",
                "https://shop.orbital.example/robots.txt",
            ],
            &["403", "153", "301", "https://shop.orbital.example/.git/"],
            &[
                "200",
                "8733",
                "402",
                "https://shop.orbital.example/api/docs",
            ],
            &[
                "401",
                "62",
                "344",
                "https://shop.orbital.example/api/v1/users",
            ],
            &["302", "0", "310", "https://shop.orbital.example/account"],
            &["500", "1120", "290", "https://shop.orbital.example/debug"],
            &[
                "200",
                "96412",
                "420",
                "https://shop.orbital.example/static/app.js",
            ],
            &[
                "403",
                "153",
                "301",
                "https://shop.orbital.example/server-status",
            ],
            &["200", "4410", "399", "https://shop.orbital.example/cart"],
            &["405", "0", "280", "https://shop.orbital.example/graphql"],
            &[
                "200",
                "22940",
                "415",
                "https://shop.orbital.example/checkout",
            ],
            &["200", "733", "362", "https://shop.orbital.example/health"],
        ],
        note: None,
    }],
    stats: |demo| {
        let done = (demo.share() * 43_000.0) as usize;
        vec![
            Stat::count("Found", demo.arrived()).good(),
            Stat::count("Not found", done.saturating_sub(demo.arrived())),
            Stat::count("Errors", done / 3_500).bad(),
        ]
    },
};

const TOOLMARK: Tool = Tool {
    name: "TOOLMARK",
    target: "app.orbital.example",
    total: None,
    views: &[View::new('f', "Findings")],
    sheets: &[Sheet {
        columns: &[
            Column::new("Severity", 10),
            Column::new("Type", 14),
            Column::new("Name", 40),
            Column::rest("Detail"),
        ],
        kinds: &[Kind::Severity, Kind::Muted, Kind::Plain, Kind::Muted],
        rows: &[
            &["info", "technology", "Nginx", "1.24.0"],
            &["info", "technology", "PHP", "8.2.12"],
            &["info", "technology", "WordPress", "6.4.2"],
            &["info", "technology", "WooCommerce", ">= 8.0, < 8.5"],
            &["info", "technology", "jQuery", "3.7.1"],
            &["info", "technology", "Bootstrap", "5.3.2"],
            &["info", "service", "OpenSSH", "8.9p1 (Ubuntu-3ubuntu0.6)"],
            &["info", "service", "Postfix", ""],
            &["high", "vulnerability", "WooCommerce", "CVE-2099-10432"],
            &["medium", "vulnerability", "OpenSSH", "CVE-2099-20781"],
        ],
        note: None,
    }],
    stats: |demo| {
        let seen = demo.arrived();
        vec![
            Stat::count("Technologies", seen.min(6)),
            Stat::count("Services", seen.saturating_sub(6).min(2)),
            Stat::count("Vulnerabilities", seen.saturating_sub(8)).bad(),
        ]
    },
};

const PLESSOR: Tool = Tool {
    name: "PLESSOR",
    target: "https://app.orbital.example",
    total: Some(6_480),
    views: &[
        View::new('f', "Findings").from_top(),
        View::new('c', "CVE leads").from_top(),
        View::new('h', "Held back").from_top(),
    ],
    sheets: &[
        Sheet {
            columns: &[
                Column::new("Severity", 10),
                Column::new("Name", 44),
                Column::rest("Matched at"),
            ],
            kinds: &[Kind::Severity, Kind::Plain, Kind::Muted],
            rows: &[
                &[
                    "critical",
                    "WooCommerce Payments authentication bypass",
                    "/wp-json/wc/v3/",
                ],
                &["high", "Exposed .git directory", "/.git/config"],
                &[
                    "high",
                    "WordPress debug log readable",
                    "/wp-content/debug.log",
                ],
                &["high", "PHP info page", "/info.php"],
                &["medium", "Directory listing", "/wp-content/uploads/"],
                &["medium", "XML-RPC enabled", "/xmlrpc.php"],
                &["medium", "Missing HSTS header", "/"],
                &["low", "Server version disclosed", "/"],
                &["low", "Cookie without the Secure flag", "/wp-login.php"],
                &["info", "WordPress user enumeration", "/wp-json/wp/v2/users"],
                &["info", "robots.txt found", "/robots.txt"],
            ],
            note: None,
        },
        Sheet {
            columns: &[
                Column::new("CVE", 16),
                Column::new("Product", 22),
                Column::new("Severity", 10),
                Column::new("KEV", 4),
                Column::new("Answer", 20),
                Column::rest("By, or why not"),
            ],
            kinds: &[
                Kind::Plain,
                Kind::Plain,
                Kind::Severity,
                Kind::Plain,
                Kind::Plain,
                Kind::Muted,
            ],
            rows: &[
                &[
                    "CVE-2099-10432",
                    "WooCommerce",
                    "critical",
                    "yes",
                    "confirmed",
                    "CVE-2099-10432",
                ],
                &[
                    "CVE-2099-20781",
                    "OpenSSH",
                    "medium",
                    "",
                    "not checked",
                    "no template checks it",
                ],
                &[
                    "CVE-2099-31007",
                    "WordPress",
                    "high",
                    "",
                    "checked, not found",
                    "CVE-2099-31007",
                ],
            ],
            note: Some(
                "From toolmark's inventory of app.orbital.example:443. A lead checked and not found is not proof the host is safe.",
            ),
        },
        Sheet {
            columns: &[Column::new("Template", 40), Column::rest("Why")],
            kinds: &[Kind::Plain, Kind::Muted],
            rows: &[
                &[
                    "mass-assignment-privilege-escalation",
                    "what it sends changes the target",
                ],
                &["account-takeover-reset", "what it sends changes the target"],
                &["CVE-2099-41773", "the inventory names none of its products"],
            ],
            note: Some("Not run, so not tested."),
        },
    ],
    stats: |demo| {
        let seen = demo.arrived();
        vec![
            Stat::count("Critical", seen.min(1)).bad(),
            Stat::count("High", seen.saturating_sub(1).min(3)),
            Stat::count("Total", seen),
            Stat::text("Leads confirmed", "1 of 3"),
        ]
    },
};

fn main() -> std::io::Result<()> {
    let tool: &'static Tool = match std::env::args().nth(1).as_deref() {
        None | Some("voyage") => &VOYAGE,
        Some("doorward") => &DOORWARD,
        Some("ambulo") => &AMBULO,
        Some("toolmark") => &TOOLMARK,
        Some("plessor") => &PLESSOR,
        Some(other) => {
            eprintln!("No demo for {other}. Give voyage, doorward, ambulo, toolmark or plessor.");
            std::process::exit(2);
        }
    };
    if !cfx_tui::available() {
        eprintln!("The demo draws a dashboard, so it needs a terminal to draw on.");
        std::process::exit(2);
    }
    let mut demo = Demo {
        tool,
        started: Instant::now(),
        logs: Logs::new(),
        logged: 0,
    };
    demo.logs.info("this is made-up data");
    cfx_tui::run(&mut demo, 50, Demo::pump)
}
