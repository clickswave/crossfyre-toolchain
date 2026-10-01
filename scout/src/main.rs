use crate::libs::cli_args::{Cli, Commands};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

mod client_tui;
mod cve;
mod daemon;
mod fingerprint;
mod libs;
mod services;
mod signatures;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Scout is stateless: no DB, just a fingerprinting TCP service.
    if cli.daemon {
        return daemon::run(cli.port).await;
    }

    match cli.command {
        Some(Commands::Scan(args)) => {
            let req = serde_json::json!({
                "operation": "fingerprint",
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
        Some(Commands::Services(args)) => {
            let req = serde_json::json!({
                "operation": "services",
                "response": "stream",
                "targets": args.targets,
                "auth_checks": !args.no_auth_checks,
                "timeout_ms": args.timeout_ms,
            });
            let label = args.targets.join(", ");
            send_stream(
                cli.port,
                req,
                cfx_tui::wanted(cli.tui, cli.no_tui, false),
                label,
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
                "No command given. Use `scout scan <target>`, `scout services <host:port>...`, `scout exec <json>`, or `scout --daemon`."
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
                "Scout daemon is not running on port {port}. Start it first with: scout --daemon"
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
        // Drop the sender so the dashboard stops pumping, then let the user
        // read the results for as long as they want before it returns.
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
