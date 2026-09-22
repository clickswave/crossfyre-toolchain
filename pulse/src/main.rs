use crate::libs::cli_args::{Cli, Commands, DbArgs, ScanExecArgs};
use crate::scanner::StreamEvent;
use clap::Parser;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

mod client_tui;
mod daemon;
mod governor;
mod libs;
mod scanner;

/// Mirrors the toolchain config at ~/.config/crossfyre/config.toml
#[derive(Debug, Deserialize)]
struct ToolchainConfig {
    postgres: PostgresConfig,
}

#[derive(Debug, Deserialize)]
struct PostgresConfig {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    #[allow(dead_code)]
    db_name: String,
}

fn load_toolchain_config() -> Result<ToolchainConfig, Box<dyn std::error::Error>> {
    let config_path = dirs::home_dir()
        .ok_or("Could not find home directory")?
        .join(".config")
        .join("crossfyre")
        .join("config.toml");

    let contents = std::fs::read_to_string(&config_path).map_err(|e| {
        format!(
            "Cannot read toolchain config at {}: {}. Run 'crossfyre init' first.",
            config_path.display(),
            e
        )
    })?;

    let config: ToolchainConfig = toml::from_str(&contents)?;
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // -----------------------------------------------------------------------
    // Daemon mode - starts the TCP service and connects to postgres
    // -----------------------------------------------------------------------
    if cli.daemon {
        let toolchain_cfg = load_toolchain_config()?;

        // Postgres being briefly unreachable is not a reason to exit: systemd
        // would restart us straight into the same failure, which is how one
        // host logged 2,663 restarts and reported nothing but "down". Wait for
        // it, saying so each time, and start as soon as it answers.
        let pulse_db = dguard::wait_for(
            // Name the endpoint and the fix. "pool timed out while waiting
            // for an open connection" is true and useless: it does not say
            // which host, which port, or that the container may simply not
            // have been created on this machine yet.
            &format!(
                "postgres at {}:{} (create it with `crossfyre db up`)",
                toolchain_cfg.postgres.host, toolchain_cfg.postgres.port
            ),
            std::time::Duration::from_secs(3600),
            || async {
                let db = libs::pulse_db::PulseDb::init(
                    &toolchain_cfg.postgres.host,
                    toolchain_cfg.postgres.port,
                    &toolchain_cfg.postgres.user,
                    toolchain_cfg.postgres.password.as_deref(),
                )
                .await
                .map_err(|e| e.to_string())?;
                db.create_tables().await.map_err(|e| e.to_string())?;
                Ok::<_, String>(db)
            },
        )
        .await?;

        return daemon::run(cli.port, pulse_db).await;
    }

    // -----------------------------------------------------------------------
    // Db subcommand
    // -----------------------------------------------------------------------
    if let Some(Commands::Db(db_args)) = &cli.command {
        return handle_db(db_args.clone(), cli.port).await;
    }

    // -----------------------------------------------------------------------
    // ScanExec subcommand - send raw JSON to daemon
    // -----------------------------------------------------------------------
    if let Some(Commands::ScanExec(exec_args)) = &cli.command {
        return handle_scan_exec(exec_args.clone(), cli.port).await;
    }

    // -----------------------------------------------------------------------
    // Scan subcommand - client that talks to the running daemon
    // -----------------------------------------------------------------------
    let scan_args = match cli.command {
        Some(Commands::Scan(args)) => args,
        _ => {
            eprintln!(
                "No command given. Use `pulse scan`, `pulse scan-exec`, `pulse db`, or `pulse --daemon`. Try --help."
            );
            std::process::exit(1);
        }
    };

    if scan_args.targets.is_empty() {
        eprintln!("Error: --targets is required");
        std::process::exit(1);
    }

    // Connect to the daemon
    let daemon_addr = format!("127.0.0.1:{}", cli.port);
    let stream = TcpStream::connect(&daemon_addr).await.map_err(|_| {
        format!(
            "Pulse daemon is not running on port {}.\nStart it first with: pulse --daemon",
            cli.port
        )
    })?;

    let ports = libs::cli_args::resolve_ports(&scan_args.ports);

    // Build and send the stream scan request
    let request = serde_json::json!({
        "operation": "scan",
        "response": "stream",
        "save": true,
        "targets": scan_args.targets,
        "ports": ports,
        "technique": scan_args.technique.to_string(),
        "tasks": scan_args.tasks,
        "timeout": scan_args.timeout,
        "delay": scan_args.delay,
        "service_detection": scan_args.service_detection,
    });

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = serde_json::to_string(&request)?;
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;

    // Read the ack event
    let mut lines = BufReader::new(reader).lines();
    let ack_line = lines
        .next_line()
        .await?
        .ok_or("Daemon closed connection before ack")?;
    let ack: StreamEvent = serde_json::from_str(&ack_line)?;

    if ack.kind == "error" {
        eprintln!("Error: {}", ack.message.as_deref().unwrap_or("unknown"));
        std::process::exit(1);
    }

    let operation_id = ack.operation_id.unwrap_or_else(|| "unknown".to_string());
    let total = ack.total.unwrap_or(0);
    let poll_timeout = scan_args.event_poll_timeout;

    // Spawn background reader for stream events
    let (tx, rx) = mpsc::unbounded_channel::<StreamEvent>();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(ev) = serde_json::from_str::<StreamEvent>(&line) {
                let done = ev.kind == "done";
                let _ = tx.send(ev);
                if done {
                    break;
                }
            }
        }
    });

    // Run the TUI
    client_tui::run(rx, operation_id, total, poll_timeout).await?;

    Ok(())
}

async fn handle_db(args: DbArgs, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    if !args.full_reset {
        eprintln!("No action specified. Try: pulse db --full-reset");
        std::process::exit(1);
    }

    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .map_err(|_| {
            format!(
                "Pulse daemon is not running on port {port}. Start it first with: pulse --daemon"
            )
        })?;

    let request = serde_json::json!({ "operation": "db_reset", "response": "instant" });
    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = serde_json::to_string(&request)?;
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        let resp: serde_json::Value = serde_json::from_str(&line)?;
        match resp["status"].as_str().unwrap_or("error") {
            "completed" => println!("{}", resp["message"].as_str().unwrap_or("Done.")),
            _ => eprintln!("Error: {}", resp["message"].as_str().unwrap_or("unknown")),
        }
    }

    Ok(())
}

async fn handle_scan_exec(args: ScanExecArgs, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload: serde_json::Value =
        serde_json::from_str(&args.json).map_err(|e| format!("Invalid JSON: {e}"))?;

    payload["operation"] = serde_json::json!("probe");
    payload["response"] = serde_json::json!("instant");

    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .map_err(|_| {
            format!(
                "Pulse daemon is not running on port {port}. Start it first with: pulse --daemon"
            )
        })?;
    let _ = stream.set_nodelay(true);

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = serde_json::to_string(&payload)?;
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        println!("{line}");
    }

    Ok(())
}
