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
        return daemon::run(cli.port).await;
    }

    // The daemon every command below talks to, started when it is not running.
    let daemon = dguard::Daemon::new("plessor", cli.port, !cli.no_autostart);

    match cli.command {
        Some(Commands::Scan(args)) => {
            let req = scan_request(&args)?;
            send_stream(
                &daemon,
                req,
                cfx_tui::wanted(cli.no_tui),
                args.target.clone(),
            )
            .await
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
            send_stream(&daemon, payload, false, target).await
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
                    send_stream(&daemon, dguard::resume_request(id), tui, target).await
                }
                None => Ok(()),
            }
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
        Some(Commands::Daemon) | None => {
            eprintln!(
                "No command given. Use `plessor scan <target>`, `plessor inject <url>...`, `plessor exec <json>`, or `plessor daemon`."
            );
            std::process::exit(1);
        }
    }
}

/// The daemon request for `plessor scan`.
///
/// It asks for the starter pack, which the daemon leaves off for anyone who does
/// not ask (the node sends its own scans). A templates directory goes as an
/// absolute path, because the daemon resolves it from its own working directory,
/// which is wherever its service started it.
#[cfg(feature = "daemon")]
fn scan_request(args: &libs::cli_args::ScanArgs) -> Result<serde_json::Value, String> {
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
    let mut header_map = serde_json::Map::new();
    for h in headers {
        let (name, value) = h
            .split_once(':')
            .ok_or_else(|| format!("-H {h:?}: expected \"Name: value\""))?;
        header_map.insert(name.trim().to_string(), serde_json::json!(value.trim()));
    }
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

#[cfg(feature = "daemon")]
async fn send_stream(
    daemon: &dguard::Daemon,
    req: serde_json::Value,
    tui: bool,
    target: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = daemon.connect().await?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut s = dguard::encode(&req);
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    // Set when the daemon reports an error, so the exit code can carry it.
    let mut failed = false;

    // Only take over the terminal when there is one. Under the node stdout is
    // a pipe, and drawing into it would put escape sequences in a log file.
    if tui {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let dashboard = tokio::spawn(client_tui::run(rx, target));

        while let Some(line) = lines.next_line().await? {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                let t = v["type"].as_str().unwrap_or("").to_string();
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
        return Ok(());
    }

    while let Some(line) = lines.next_line().await? {
        println!("{line}");
        if dguard::is_error(&line) {
            failed = true;
            break;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
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
    Ok(())
}

#[cfg(test)]
#[cfg(feature = "daemon")]
mod tests {
    use super::{inject_requests, scan_request};
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
        let req = scan_request(&scan(&["http://h"])).unwrap();
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
        let req = scan_request(&scan(&[
            "http://h",
            "--products",
            "a:apache:http_server,a:metabase:metabase",
            "--all-templates",
        ]))
        .unwrap();
        assert_eq!(
            req["products"],
            serde_json::json!(["a:apache:http_server", "a:metabase:metabase"])
        );
        assert_eq!(req["products_from"], "the products given with --products");
        assert_eq!(req["all_templates"], true);
    }

    #[test]
    fn a_templates_folder_goes_to_the_daemon_as_an_absolute_path() {
        let here = env!("CARGO_MANIFEST_DIR");
        let dir = format!("{here}/templates");
        let req = scan_request(&scan(&["http://h", "--templates", &dir])).unwrap();
        let sent = req["templates_dir"].as_str().unwrap();
        assert!(std::path::Path::new(sent).is_absolute());
        assert!(sent.ends_with("templates"));
        let gone = format!("{here}/no-such-folder");
        assert!(scan_request(&scan(&["http://h", "--templates", &gone])).is_err());
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
