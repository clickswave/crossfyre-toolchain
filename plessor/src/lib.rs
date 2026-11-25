//! The scanning engine, as a library.
//!
//! This crate was a binary and nothing else for most of its life, which meant that
//! everything in it was reachable only by running it. Three things other parts of the
//! product need were sitting here unreachable: byte-exact request sending, host scope
//! matching, and the race-condition harness. A desktop proxy cannot shell out to a
//! scanner to send one request.
//!
//! The public surface is deliberately small. Most of this crate is the scanner's own
//! business and exposing it would make every internal rename a breaking change for
//! somebody. What is public is what another crate has an actual reason to call:
//!
//! - [`rawhttp`], for sending bytes exactly as written. Normalising a request is correct
//!   for a client and wrong for a tool whose job is to send malformed ones.
//! - [`scope`], because there are three host-scope implementations in this product and
//!   two of them disagree about whether a wildcard admits the apex. A credential's host
//!   scope is an authorisation boundary, so that disagreement is a defect rather than a
//!   style difference, and the way out is one implementation. It now lives in `cfx_scope`
//!   and is re-exported here under its old name: the proxy needs it too, and nothing
//!   under the capture core can depend on this crate to get it.
//! - [`race`], for the check-then-write window, which needs careful ordering and is
//!   worth exactly nothing reimplemented casually somewhere else.
//!
//! The scanner itself, its daemon, the daemon's storage and the command line are behind
//! the `daemon` feature, which is on by default and which the binary needs. Without it
//! this library is [`rawhttp`] and [`scope`] alone, which is what a crate that only
//! sends requests links: it gets no daemon and no database.

#[cfg(feature = "daemon")]
mod authz;
#[cfg(feature = "daemon")]
mod chain;
#[cfg(feature = "daemon")]
mod client_tui;
#[cfg(feature = "daemon")]
mod daemon;
#[cfg(feature = "daemon")]
mod deserial;
#[cfg(feature = "daemon")]
mod discover;
#[cfg(feature = "daemon")]
mod dsl;
#[cfg(feature = "daemon")]
mod engine;
#[cfg(feature = "daemon")]
mod exposure;
#[cfg(feature = "daemon")]
mod flow;
#[cfg(feature = "daemon")]
mod fuzz;
#[cfg(feature = "daemon")]
mod graphql;
#[cfg(feature = "daemon")]
mod inject;
#[cfg(feature = "daemon")]
mod leads;
#[cfg(feature = "daemon")]
mod ledger;
#[cfg(feature = "daemon")]
pub mod libs;
#[cfg(feature = "daemon")]
mod oast;
#[cfg(feature = "daemon")]
mod plessor_db;
#[cfg(feature = "daemon")]
mod probe;
#[cfg(feature = "daemon")]
mod proof;
#[cfg(feature = "daemon")]
pub mod race;
pub mod rawhttp;
pub use cfx_scope as scope;
#[cfg(feature = "daemon")]
mod secrets;
#[cfg(feature = "daemon")]
mod smuggle;
#[cfg(feature = "daemon")]
mod solver;
#[cfg(feature = "daemon")]
mod ssrf;
#[cfg(feature = "daemon")]
mod tamper;
#[cfg(feature = "daemon")]
mod template;
// Tests for the request guards and the scope fence, counted at a socket like
// writes_rail below.
#[cfg(test)]
#[cfg(feature = "daemon")]
mod action_rail;
#[cfg(test)]
#[cfg(feature = "daemon")]
mod scope_rail;
// One test for the rail five engines each had to learn separately. Not a module
// with anything in it: the test IS the artefact.
#[cfg(feature = "daemon")]
mod verify;
#[cfg(test)]
#[cfg(feature = "daemon")]
mod writes_rail;
#[cfg(feature = "daemon")]
mod xml;

#[cfg(feature = "daemon")]
use crate::libs::cli_args::{Cli, Commands};
#[cfg(feature = "daemon")]
use clap::CommandFactory;
#[cfg(feature = "daemon")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Run a parsed command line.
///
/// Here rather than in `main` so the binary is argument parsing and a call, and so the
/// dispatch can be exercised without spawning a process.
#[cfg(feature = "daemon")]
pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(cli.command, Some(Commands::Daemon)) {
        return daemon::run(cli.port, daemon::Role::Plessor).await;
    }

    // The daemon every command below talks to, started when it is not running.
    let daemon = engine_daemon("plessor", cli.port, !cli.no_autostart);

    match cli.command {
        Some(Commands::Scan(args)) => {
            // What toolmark saw on the target lately, unless the products are given: it
            // chooses the templates, and its CVE leads go to be answered. toolmark is
            // asked, never started.
            let place = cfx_cve::inventory::host_and_port(&args.target);
            let toolmark = match (&args.products, &place) {
                (None, Some(_)) => {
                    let port = toolmark_port(args.toolmark_port);
                    Some((engine_daemon("toolmark", port, false), port))
                }
                _ => None,
            };
            let fresh = match (&toolmark, &place) {
                (Some((toolmark, tport)), Some((host, port))) => {
                    what_toolmark_saw(toolmark, *tport, host, *port).await
                }
                _ => None,
            };
            let req = scan_request(&args, fresh.as_ref())?;
            let ran = send_stream(
                &daemon,
                req,
                cfx_tui::wanted(cli.no_tui),
                args.target.clone(),
            )
            .await?;
            // The answers to its leads go back to toolmark, which keeps them for its
            // inventory to show.
            if let (Some((toolmark, _)), Some((host, port)), Some(answers)) =
                (&toolmark, &place, &ran.answers)
                && let Some(back) = cfx_cve::inventory::AnswersBack::from_event(
                    host,
                    *port,
                    ran.scan.as_deref(),
                    answers,
                )
                && let Err(e) = dguard::ask(toolmark, &back.request()).await
            {
                eprintln!("toolmark did not keep the answers to the leads of {host}:{port}: {e}");
            }
            Ok(())
        }
        Some(Commands::Inject(args)) => {
            let mut urls = args.urls.clone();
            if urls.is_empty() {
                use std::io::{BufRead, IsTerminal};
                let stdin = std::io::stdin();
                if stdin.is_terminal() {
                    return Err("give URLs to test, or pipe them in one per line".into());
                }
                for line in stdin.lock().lines() {
                    let line = line?;
                    if !line.trim().is_empty() {
                        urls.push(line.trim().to_string());
                    }
                }
            }
            let batches = inject_requests(
                &urls,
                args.cookie.as_deref(),
                &args.headers,
                args.data.as_deref(),
            )?;
            for (origin, req) in batches {
                send_stream(&daemon, req, cfx_tui::wanted(cli.no_tui), origin).await?;
            }
            Ok(())
        }
        Some(Commands::Exec(args)) => {
            let mut payload: serde_json::Value =
                serde_json::from_str(&args.json).map_err(|e| format!("Invalid JSON: {e}"))?;
            if payload.get("response").is_none() {
                payload["response"] = serde_json::json!("stream");
            }
            let target = payload["target"].as_str().unwrap_or("").to_string();
            send_stream(&daemon, payload, false, target).await?;
            Ok(())
        }
        Some(Commands::Scans) => {
            let scans = dguard::list_scans(&daemon).await?;
            let tui = cfx_tui::wanted(cli.no_tui);
            let chosen =
                tokio::task::spawn_blocking(move || cfx_tui::scans::show("PLESSOR", &scans, tui))
                    .await??;
            match chosen {
                Some(scan) => {
                    let id = scan["id"].as_str().unwrap_or_default();
                    let target = scan["target"].as_str().unwrap_or_default().to_string();
                    send_stream(&daemon, dguard::resume_request(id), tui, target).await?;
                    Ok(())
                }
                None => Ok(()),
            }
        }
        Some(Commands::Findings(args)) => {
            let mut ask = serde_json::json!({
                "operation": "findings", "response": "instant", "limit": args.limit,
            });
            if let Some(scan) = &args.scan {
                ask["scan"] = serde_json::json!(scan);
            }
            let answer = dguard::ask(&daemon, &ask).await?;
            let rows = answer["findings"].as_array().cloned().unwrap_or_default();
            let tui = cfx_tui::wanted(cli.no_tui);
            tokio::task::spawn_blocking(move || show_findings(&rows, tui)).await??;
            Ok(())
        }
        Some(Commands::Verify(args)) => {
            let answer = dguard::ask(&daemon, &verify_request(&args)?).await?;
            println!("{answer}");
            Ok(())
        }
        Some(Commands::Check(args)) => {
            let known = match &args.known {
                Some(path) => Some(
                    std::fs::read_to_string(path)
                        .map_err(|e| format!("{}: {e}", path.display()))?
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string)
                        .collect(),
                ),
                None => None,
            };
            let problems = template::check_dir(&args.dir, known.as_ref());
            for problem in &problems {
                println!("{problem}");
            }
            if problems.is_empty() {
                Ok(())
            } else {
                Err(format!("{} problem(s) in {}", problems.len(), args.dir.display()).into())
            }
        }
        Some(Commands::Db { action }) => dguard::run_db(&daemon, &action).await,
        Some(Commands::Completions { shell }) => {
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "plessor", &mut script);
            print_all(&script)?;
            Ok(())
        }
        Some(Commands::Man) => {
            let mut page = Vec::new();
            clap_mangen::Man::new(Cli::command()).render(&mut page)?;
            print_all(&page)?;
            Ok(())
        }
        Some(Commands::Daemon) | None => {
            eprintln!(
                "No command given. Use `plessor scan <target>`, `plessor inject <url>...`, `plessor exec <json>`, or `plessor daemon`."
            );
            std::process::exit(1);
        }
    }
}

/// The `plessor-authz` command: plessor's authorization testing as a daemon of its own,
/// on its own port and schema, which runs `authz` and nothing else.
#[cfg(feature = "daemon")]
pub async fn run_authz(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Some(Commands::Daemon) => daemon::run(cli.port, daemon::Role::Authz).await,
        _ => Err("plessor-authz runs only as a daemon: plessor-authz daemon --port <port>".into()),
    }
}

/// `engine`'s daemon on `port`. A test build refuses the engines' real ports: an engine of
/// the operator's may be listening on one, so every test gives a port of its own.
#[cfg(feature = "daemon")]
fn engine_daemon(engine: &'static str, port: u16, autostart: bool) -> dguard::Daemon {
    #[cfg(test)]
    if dguard::ports::RESERVED.contains(&port) {
        panic!("a test asked for {engine}'s port {port}: a test reaches no engine of the host's");
    }
    dguard::Daemon::new(engine, port, autostart)
}

/// toolmark's port: --toolmark-port, else where every client finds an engine's, the
/// toolchain's config.toml or the protocol's. A test build never reads the toolchain's
/// config, so a test always gives the port.
#[cfg(feature = "daemon")]
fn toolmark_port(given: Option<u16>) -> u16 {
    #[cfg(test)]
    let port = given.expect("a test gives toolmark's port");
    #[cfg(not(test))]
    let port = given
        .or_else(|| dguard::ports::engine_port("toolmark"))
        .unwrap_or(dguard::ports::TOOLMARK);
    port
}

/// What toolmark's daemon on `tport` saw on `host`:`port` lately, or None when it saw
/// nothing fresh there. When it does not answer the scan runs every template and answers
/// no leads, and says so in a line.
#[cfg(feature = "daemon")]
async fn what_toolmark_saw(
    toolmark: &dguard::Daemon,
    tport: u16,
    host: &str,
    port: u16,
) -> Option<cfx_cve::inventory::Fresh> {
    match dguard::answer(toolmark, "inventory").await {
        Ok(inventory) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            cfx_cve::inventory::fresh(&inventory, host, port, now)
        }
        Err(_) => {
            eprintln!(
                "toolmark is not answering on port {tport}, so every template runs and no CVE \
                 leads are answered"
            );
            None
        }
    }
}

/// The daemon request for `plessor scan`.
///
/// It asks for the starter pack, which the daemon leaves off for anyone who does
/// not ask (the node sends its own scans). A templates directory goes as an
/// absolute path, because the daemon resolves it from its own working directory,
/// which is wherever its service started it. The products given choose the templates;
/// without them, what toolmark saw lately, `fresh`, does, and gives the leads.
#[cfg(feature = "daemon")]
fn scan_request(
    args: &libs::cli_args::ScanArgs,
    fresh: Option<&cfx_cve::inventory::Fresh>,
) -> Result<serde_json::Value, String> {
    let mut req = serde_json::json!({
        "operation": "scan",
        "response": "stream",
        "target": args.target,
        "pack": true,
        "all_templates": args.all_templates,
    });
    if let Some(products) = &args.products {
        req["products"] = serde_json::json!(products);
        req["products_from"] = serde_json::json!("the products given with --products");
    } else if let Some(fresh) = fresh {
        req["products"] = serde_json::json!(fresh.products);
        req["leads"] = serde_json::json!(fresh.leads);
        req["products_from"] = serde_json::json!(fresh.from);
    }
    if let Some(dir) = args.templates.as_deref() {
        let abs = std::fs::canonicalize(dir)
            .ok()
            .filter(|p| p.is_dir())
            .ok_or_else(|| format!("--templates {dir}: not a directory"))?;
        req["templates_dir"] = serde_json::json!(abs.to_string_lossy());
    }
    Ok(req)
}

/// `-H` headers, each "Name: value", as a map of name to value.
#[cfg(feature = "daemon")]
fn header_map(headers: &[String]) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let mut map = serde_json::Map::new();
    for h in headers {
        let (name, value) = h
            .split_once(':')
            .ok_or_else(|| format!("-H {h:?}: expected \"Name: value\""))?;
        map.insert(name.trim().to_string(), serde_json::json!(value.trim()));
    }
    Ok(map)
}

/// The daemon request for `plessor verify`: the finding, and the credential for the slots
/// its proof names, in the shape a scan takes it.
#[cfg(feature = "daemon")]
fn verify_request(args: &libs::cli_args::VerifyArgs) -> Result<serde_json::Value, String> {
    let mut req = serde_json::json!({
        "operation": "verify",
        "response": "instant",
        "finding": args.id,
        "test_writes": args.test_writes,
    });
    let headers = header_map(&args.headers)?;
    if args.cookie.is_some() || !headers.is_empty() {
        req["auth"] = serde_json::json!({
            "cookies": args.cookie.as_deref().unwrap_or(""),
            "headers": headers,
        });
    }
    Ok(req)
}

/// `rows`, the findings the daemon answered with, in a table when `tui`, and otherwise a
/// JSON object a line. A finding with no proof, as an injection or authorization finding
/// is, says so, as it cannot be verified.
#[cfg(feature = "daemon")]
fn show_findings(rows: &[serde_json::Value], tui: bool) -> std::io::Result<()> {
    if !tui {
        let mut out = String::new();
        for row in rows {
            out.push_str(&row.to_string());
            out.push('\n');
        }
        return print_all(out.as_bytes());
    }
    cfx_tui::table::show(&findings_list(rows))
}

#[cfg(feature = "daemon")]
const FINDINGS_COLUMNS: &[cfx_tui::Column] = &[
    cfx_tui::Column::new("ID", 8),
    cfx_tui::Column::new("Severity", 10),
    cfx_tui::Column::new("Name", 34),
    cfx_tui::Column::new("Where", 40),
    cfx_tui::Column::new("Proof", 14),
    cfx_tui::Column::rest("Found"),
];

/// The findings as the table shows them.
#[cfg(feature = "daemon")]
fn findings_list(rows: &[serde_json::Value]) -> cfx_tui::table::List {
    let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
    let has_proof = |row: &serde_json::Value| row["data"].get("proof").is_some();
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let found = text(&row["found"]);
            vec![
                row["id"].to_string(),
                text(&row["data"]["severity"]),
                text(&row["data"]["name"]),
                text(&row["data"]["matched_at"]),
                if has_proof(row) {
                    "yes".to_string()
                } else {
                    "no proof kept".to_string()
                },
                found
                    .get(..16)
                    .map(|m| format!("{} UTC", m.replace('T', " ")))
                    .unwrap_or(found),
            ]
        })
        .collect();
    let proofs = rows.iter().filter(|r| has_proof(r)).count();
    cfx_tui::table::List {
        name: "PLESSOR",
        title: "Findings",
        summary: format!(
            "{} findings, {proofs} with a proof: `plessor verify <id>` checks one again",
            table.len()
        ),
        columns: FINDINGS_COLUMNS,
        rows: table,
    }
}

/// The daemon requests for `plessor inject`, one per origin, each paired with the
/// origin it targets.
///
/// One per origin because the injection pass drops any endpoint on a host other
/// than its target, so URLs from two hosts in one request would test only the
/// first host's and say nothing about the rest. Origins keep the order their first
/// URL arrived in.
#[cfg(feature = "daemon")]
fn inject_requests(
    urls: &[String],
    cookie: Option<&str>,
    headers: &[String],
    data: Option<&str>,
) -> Result<Vec<(String, serde_json::Value)>, String> {
    let header_map = header_map(headers)?;
    // Decoded as a form is, so `a=b+c` tests the value "b c".
    let body: Vec<serde_json::Value> = match data {
        Some(d) => reqwest::Url::parse(&format!("http://form.invalid/?{d}"))
            .map_err(|e| format!("-d {d:?}: {e}"))?
            .query_pairs()
            .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
            .collect(),
        None => Vec::new(),
    };
    let method = if data.is_some() { "POST" } else { "GET" };

    let mut batches: Vec<(String, Vec<serde_json::Value>)> = Vec::new();
    for raw in urls {
        let url = reqwest::Url::parse(raw).map_err(|e| format!("{raw}: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(format!("{raw}: not an http or https URL"));
        }
        let origin = url.origin().ascii_serialization();
        let endpoint = serde_json::json!({
            "method": method,
            "url": url.as_str(),
            "body": body,
            "body_type": "form",
        });
        match batches.iter_mut().find(|(o, _)| *o == origin) {
            Some((_, endpoints)) => endpoints.push(endpoint),
            None => batches.push((origin, vec![endpoint])),
        }
    }
    if batches.is_empty() {
        return Err("no URLs to test".into());
    }

    Ok(batches
        .into_iter()
        .map(|(origin, endpoints)| {
            let mut req = serde_json::json!({
                "operation": "inject",
                "response": "stream",
                "target": origin,
                "endpoints": endpoints,
            });
            if cookie.is_some() || !header_map.is_empty() {
                req["auth"] = serde_json::json!({
                    "cookies": cookie.unwrap_or(""),
                    "headers": header_map,
                });
            }
            (origin, req)
        })
        .collect())
}

/// Write `bytes` to stdout. A reader that stops early, as `head` does, closes the pipe,
/// and that is not an error: the rest was not wanted. clap_complete panics on any failed
/// write, so what it generates is kept in memory and written from here.
#[cfg(feature = "daemon")]
fn print_all(bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        done => done,
    }
}

/// What a client keeps of an operation's stream once it is done: the scan its ack named,
/// and its answers to the leads it was given.
#[cfg(feature = "daemon")]
#[derive(Default)]
struct Ran {
    scan: Option<String>,
    answers: Option<serde_json::Value>,
}

#[cfg(feature = "daemon")]
impl Ran {
    fn saw(&mut self, event: &serde_json::Value) {
        match event["type"].as_str() {
            Some("ack") => self.scan = event["scan"].as_str().map(str::to_string),
            Some("lead_answers") => self.answers = Some(event.clone()),
            _ => {}
        }
    }
}

#[cfg(feature = "daemon")]
async fn send_stream(
    daemon: &dguard::Daemon,
    req: serde_json::Value,
    tui: bool,
    target: String,
) -> Result<Ran, Box<dyn std::error::Error>> {
    let stream = daemon.connect().await?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut s = dguard::encode(&req);
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    // Set when the daemon reports an error, so the exit code can carry it.
    let mut failed = false;
    let mut ran = Ran::default();

    // Only take over the terminal when there is one. Under the node stdout is
    // a pipe, and drawing into it would put escape sequences in a log file.
    if tui {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let dashboard = tokio::spawn(client_tui::run(rx, target));

        while let Some(line) = lines.next_line().await? {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                let t = v["type"].as_str().unwrap_or("").to_string();
                ran.saw(&v);
                let _ = tx.send(v);
                if t == "error" {
                    failed = true;
                }
                if t == "done" || t == "error" {
                    break;
                }
            }
        }
        drop(tx);
        dashboard.await??;
        if failed {
            std::process::exit(1);
        }
        return Ok(ran);
    }

    while let Some(line) = lines.next_line().await? {
        println!("{line}");
        if dguard::is_error(&line) {
            failed = true;
            break;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            ran.saw(&v);
            if v["type"].as_str() == Some("done") {
                break;
            }
        }
    }
    // Exit non-zero without a second message: the error line is already on
    // stdout, and the caller should be able to read `$?` instead of parsing it.
    if failed {
        std::process::exit(1);
    }
    Ok(ran)
}

#[cfg(test)]
#[cfg(feature = "daemon")]
mod tests {
    use super::{
        Ran, engine_daemon, findings_list, inject_requests, scan_request, toolmark_port,
        verify_request,
    };
    use crate::libs;
    use crate::libs::cli_args::{Cli, Commands};
    use clap::Parser;

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Without `pack`, an installed `plessor scan` ran twelve checks and never the
    /// hundred templates beside them.
    fn scan(args: &[&str]) -> libs::cli_args::ScanArgs {
        let cli = Cli::try_parse_from(["plessor", "scan"].iter().chain(args)).unwrap();
        match cli.command {
            Some(Commands::Scan(a)) => a,
            _ => unreachable!("a scan was parsed"),
        }
    }

    #[test]
    fn scan_asks_for_the_pack() {
        let req = scan_request(&scan(&["http://h"]), None).unwrap();
        assert_eq!(req["pack"], true);
        assert!(req.get("templates_dir").is_none());
        assert!(
            req.get("products").is_none(),
            "with no products, every template runs"
        );
        assert_eq!(req["all_templates"], false);
    }

    /// The products toolmark names go to the daemon with where they came from, and
    /// --all-templates says to run everything whatever they say.
    #[test]
    fn products_and_all_templates_go_to_the_daemon() {
        let req = scan_request(
            &scan(&[
                "http://h",
                "--products",
                "a:apache:http_server,a:metabase:metabase",
                "--all-templates",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            req["products"],
            serde_json::json!(["a:apache:http_server", "a:metabase:metabase"])
        );
        assert_eq!(req["products_from"], "the products given with --products");
        assert_eq!(req["all_templates"], true);
    }

    /// What toolmark saw lately chooses the templates and gives the leads, said with where
    /// it came from; products given by hand are what the scan goes by instead.
    #[test]
    fn what_toolmark_saw_goes_to_the_daemon() {
        let fresh = cfx_cve::inventory::Fresh {
            products: vec!["a:apache:http_server".into()],
            leads: vec![cfx_cve::inventory::HostLead {
                cve: "CVE-2021-41773".into(),
                product: "Apache HTTP Server".into(),
                severity: "high".into(),
                kev: true,
            }],
            from: "toolmark's inventory of h:80, last seen 1 hour before the scan".into(),
        };
        let req = scan_request(&scan(&["http://h"]), Some(&fresh)).unwrap();
        assert_eq!(req["products"], serde_json::json!(["a:apache:http_server"]));
        assert_eq!(req["leads"][0]["cve"], "CVE-2021-41773");
        assert_eq!(req["products_from"], fresh.from);
        let given = scan_request(
            &scan(&["http://h", "--products", "a:f5:nginx"]),
            Some(&fresh),
        )
        .unwrap();
        assert_eq!(given["products"], serde_json::json!(["a:f5:nginx"]));
        assert!(given.get("leads").is_none());
    }

    /// The stream's ack names the scan and its last event the answers to the leads, which
    /// the client keeps to hand toolmark.
    #[test]
    fn the_stream_keeps_the_scan_and_its_answers() {
        let mut ran = Ran::default();
        for event in [
            serde_json::json!({"type": "ack", "scan": "s1"}),
            serde_json::json!({"type": "finding"}),
            serde_json::json!({"type": "lead_answers", "answers": []}),
            serde_json::json!({"type": "done"}),
        ] {
            ran.saw(&event);
        }
        assert_eq!(ran.scan.as_deref(), Some("s1"));
        assert_eq!(ran.answers.unwrap()["type"], "lead_answers");
    }

    /// `plessor verify` asks for the finding by its id, with the credential the slots need
    /// as a scan takes it, and only when one is given.
    #[test]
    fn verify_asks_by_id_with_the_credential_given() {
        let args =
            |argv: &[&str]| match Cli::try_parse_from(["plessor", "verify"].iter().chain(argv))
                .unwrap()
                .command
            {
                Some(Commands::Verify(a)) => a,
                _ => unreachable!("a verify was parsed"),
            };
        let plain = verify_request(&args(&["7"])).unwrap();
        assert_eq!(plain["finding"], 7);
        assert_eq!(plain["test_writes"], false);
        assert!(plain.get("auth").is_none());
        let given = verify_request(&args(&[
            "7",
            "--cookie",
            "s=1",
            "-H",
            "X-Api-Token: t0",
            "--test-writes",
        ]))
        .unwrap();
        assert_eq!(
            given["auth"],
            serde_json::json!({"cookies": "s=1", "headers": {"X-Api-Token": "t0"}})
        );
        assert_eq!(given["test_writes"], true);
        assert!(verify_request(&args(&["7", "-H", "no colon"])).is_err());
    }

    /// The findings table says which have no proof, and so cannot be verified.
    #[test]
    fn the_findings_say_which_have_no_proof() {
        let list = findings_list(&[
            serde_json::json!({"id": 2, "data": {"severity": "high", "name": "a",
                               "matched_at": "http://h/a", "proof": {"format": 1}},
                               "found": "2026-11-21T12:00:00Z"}),
            serde_json::json!({"id": 3, "data": {"severity": "high", "name": "b",
                               "matched_at": "http://h/b"}, "found": "2026-11-21T11:00:00Z"}),
        ]);
        assert_eq!(list.rows[0][4], "yes");
        assert_eq!(list.rows[1][4], "no proof kept");
        assert_eq!(list.rows[0][5], "2026-11-21 12:00 UTC");
        assert!(list.summary.starts_with("2 findings, 1 with a proof"));
    }

    /// A test build refuses the engines' real ports, where the operator's own engines may
    /// listen, and never reads the toolchain's config for toolmark's.
    #[test]
    fn a_test_reaches_no_engine_of_the_hosts() {
        for port in [4440, 4444, 4445] {
            let refused = std::panic::catch_unwind(|| engine_daemon("toolmark", port, false));
            assert!(refused.is_err(), "port {port} was let through");
        }
        let _ = engine_daemon("toolmark", 14444, false);
        assert!(std::panic::catch_unwind(|| toolmark_port(None)).is_err());
        assert_eq!(toolmark_port(Some(14444)), 14444);
    }

    #[test]
    fn a_templates_folder_goes_to_the_daemon_as_an_absolute_path() {
        let here = env!("CARGO_MANIFEST_DIR");
        let dir = format!("{here}/templates");
        let req = scan_request(&scan(&["http://h", "--templates", &dir]), None).unwrap();
        let sent = req["templates_dir"].as_str().unwrap();
        assert!(std::path::Path::new(sent).is_absolute());
        assert!(sent.ends_with("templates"));
        let gone = format!("{here}/no-such-folder");
        assert!(scan_request(&scan(&["http://h", "--templates", &gone]), None).is_err());
    }

    /// The injection pass drops endpoints on any host but its target, so two
    /// hosts in one request would leave the second untested without a word.
    #[test]
    fn urls_on_two_hosts_become_two_requests() {
        let batches = inject_requests(
            &urls(&[
                "http://a.test/x?id=1",
                "http://b.test:8080/y?q=2",
                "http://a.test/z?p=3",
            ]),
            None,
            &[],
            None,
        )
        .unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].0, "http://a.test");
        assert_eq!(batches[0].1["target"], "http://a.test");
        assert_eq!(batches[0].1["endpoints"].as_array().unwrap().len(), 2);
        assert_eq!(batches[1].0, "http://b.test:8080");
        assert_eq!(
            batches[1].1["endpoints"][0]["url"],
            "http://b.test:8080/y?q=2"
        );
        assert_eq!(batches[0].1["endpoints"][0]["method"], "GET");
        assert!(batches[0].1.get("auth").is_none());
    }

    #[test]
    fn a_login_cookie_and_headers_go_with_every_request() {
        let batches = inject_requests(
            &urls(&["http://a.test/x?id=1"]),
            Some("PHPSESSID=abc; security=low"),
            &["X-Api-Key: k1".to_string()],
            None,
        )
        .unwrap();
        let auth = &batches[0].1["auth"];
        assert_eq!(auth["cookies"], "PHPSESSID=abc; security=low");
        assert_eq!(auth["headers"]["X-Api-Key"], "k1");
        assert!(
            inject_requests(&urls(&["http://a.test/"]), None, &["nocolon".into()], None).is_err()
        );
    }

    /// A form is decoded as a browser would encode it, and tested as a POST.
    #[test]
    fn a_form_body_is_sent_as_a_post_with_its_fields() {
        let batches = inject_requests(
            &urls(&["http://a.test/login"]),
            None,
            &[],
            Some("user=gordon+b&pass=a%26b"),
        )
        .unwrap();
        let ep = &batches[0].1["endpoints"][0];
        assert_eq!(ep["method"], "POST");
        assert_eq!(ep["body_type"], "form");
        assert_eq!(ep["body"][0]["name"], "user");
        assert_eq!(ep["body"][0]["value"], "gordon b");
        assert_eq!(ep["body"][1]["value"], "a&b");
    }

    #[test]
    fn only_web_urls_are_accepted() {
        assert!(inject_requests(&urls(&["ftp://a.test/x"]), None, &[], None).is_err());
        assert!(inject_requests(&urls(&["not a url"]), None, &[], None).is_err());
        assert!(inject_requests(&[], None, &[], None).is_err());
    }
}
