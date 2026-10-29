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

mod authz;
mod chain;
mod client_tui;
mod daemon;
mod deserial;
mod discover;
mod dsl;
mod engine;
mod exposure;
mod flow;
mod fuzz;
mod graphql;
mod inject;
pub mod libs;
mod oast;
mod probe;
pub mod race;
pub mod rawhttp;
pub use cfx_scope as scope;
mod secrets;
mod smuggle;
mod solver;
mod ssrf;
mod tamper;
mod template;
// Tests for the request guards and the scope fence, counted at a socket like
// writes_rail below.
#[cfg(test)]
mod action_rail;
#[cfg(test)]
mod scope_rail;
// One test for the rail five engines each had to learn separately. Not a module
// with anything in it: the test IS the artefact.
#[cfg(test)]
mod writes_rail;
mod xml;

use crate::libs::cli_args::{Cli, Commands};
use clap::CommandFactory;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Run a parsed command line.
///
/// Here rather than in `main` so the binary is argument parsing and a call, and so the
/// dispatch can be exercised without spawning a process.
pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Plessor is stateless: no DB, a vulnerability-detection TCP service.
    if cli.daemon {
        return daemon::run(cli.port).await;
    }

    match cli.command {
        Some(Commands::Scan(args)) => {
            let req = scan_request(&args.target, args.templates.as_deref())?;
            send_stream(
                cli.port,
                req,
                cfx_tui::wanted(cli.tui, cli.no_tui, false),
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
                send_stream(
                    cli.port,
                    req,
                    cfx_tui::wanted(cli.tui, cli.no_tui, false),
                    origin,
                )
                .await?;
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
            send_stream(
                cli.port,
                payload,
                cfx_tui::wanted(cli.tui, cli.no_tui, false),
                target,
            )
            .await
        }
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "plessor",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        None => {
            eprintln!(
                "No command given. Use `plessor scan <target>`, `plessor inject <url>...`, `plessor exec <json>`, or `plessor --daemon`."
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
fn scan_request(target: &str, templates: Option<&str>) -> Result<serde_json::Value, String> {
    let mut req = serde_json::json!({
        "operation": "scan",
        "response": "stream",
        "target": target,
        "pack": true,
    });
    if let Some(dir) = templates {
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

async fn send_stream(
    port: u16,
    req: serde_json::Value,
    tui: bool,
    target: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .map_err(|_| {
            format!(
                "Plessor daemon is not running on port {port}. Start it first with: plessor --daemon"
            )
        })?;
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
mod tests {
    use super::{inject_requests, scan_request};

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Without `pack`, an installed `plessor scan` ran twelve checks and never the
    /// hundred templates beside them.
    #[test]
    fn scan_asks_for_the_pack() {
        let req = scan_request("http://h", None).unwrap();
        assert_eq!(req["pack"], true);
        assert!(req.get("templates_dir").is_none());
    }

    #[test]
    fn a_templates_folder_goes_to_the_daemon_as_an_absolute_path() {
        let here = env!("CARGO_MANIFEST_DIR");
        let req = scan_request("http://h", Some(&format!("{here}/templates"))).unwrap();
        let sent = req["templates_dir"].as_str().unwrap();
        assert!(std::path::Path::new(sent).is_absolute());
        assert!(sent.ends_with("templates"));
        assert!(scan_request("http://h", Some(&format!("{here}/no-such-folder"))).is_err());
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
