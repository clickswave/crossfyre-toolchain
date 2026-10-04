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
//!   style difference, and the way out is one implementation.
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
pub mod scope;
mod secrets;
mod smuggle;
mod solver;
mod ssrf;
mod tamper;
mod template;
// One test for the rail five engines each had to learn separately. Not a module
// with anything in it: the test IS the artefact.
#[cfg(test)]
mod writes_rail;
mod xml;

use crate::libs::cli_args::{Cli, Commands};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Run a parsed command line.
///
/// Here rather than in `main` so the binary is argument parsing and a call, and so the
/// dispatch can be exercised without spawning a process.
pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Cortex is stateless: no DB, a vulnerability-detection TCP service.
    if cli.daemon {
        return daemon::run(cli.port).await;
    }

    match cli.command {
        Some(Commands::Scan(args)) => {
            let req = serde_json::json!({
                "operation": "scan",
                "response": "stream",
                "target": args.target,
            });
            send_stream(
                cli.port,
                req,
                cfx_tui::wanted(cli.tui, cli.no_tui, false),
                args.target.clone(),
            )
            .await
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
        None => {
            eprintln!(
                "No command given. Use `cortex scan <target>`, `cortex exec <json>`, or `cortex --daemon`."
            );
            std::process::exit(1);
        }
    }
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
                "Cortex daemon is not running on port {port}. Start it first with: cortex --daemon"
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
