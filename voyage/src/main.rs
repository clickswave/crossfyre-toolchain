use crate::libs::cli_args::{Cli, Commands, DbArgs, ExecArgs, OriginArgs};
use crate::scanner::StreamEvent;
use clap::Parser;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

mod axfr;
mod client_tui;
mod daemon;
mod libs;
mod scanner;
mod scanners;
mod takeover;

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
    // Daemon mode - starts the TCP service and connects directly to postgres
    // -----------------------------------------------------------------------
    if cli.daemon {
        let toolchain_cfg = load_toolchain_config()?;

        // Postgres being briefly unreachable is not a reason to exit: systemd
        // would restart us straight into the same failure, which is how one
        // host logged 2,663 restarts and reported nothing but "down". Wait for
        // it, saying so each time, and start as soon as it answers.
        let voyage_db = dguard::wait_for(
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
                let db = libs::voyage_db::VoyageDb::init(
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

        return daemon::run(cli.port, voyage_db).await;
    }

    // -----------------------------------------------------------------------
    // Db subcommand - send db_reset to daemon
    // -----------------------------------------------------------------------
    if let Some(Commands::Db(db_args)) = &cli.command {
        return handle_db(db_args.clone(), cli.port).await;
    }

    if let Some(Commands::Exec(exec_args)) = &cli.command {
        return handle_enum_exec(exec_args.clone(), cli.port).await;
    }

    // -----------------------------------------------------------------------
    // Origin subcommand - self-contained origin discovery (no daemon needed)
    // -----------------------------------------------------------------------
    if let Some(Commands::Origin(origin_args)) = &cli.command {
        return handle_origin(origin_args.clone()).await;
    }

    if let Some(Commands::Axfr(args)) = &cli.command {
        return handle_axfr(args.clone(), cli.port).await;
    }

    // -----------------------------------------------------------------------
    // Scan subcommand - client that talks to the running daemon
    // -----------------------------------------------------------------------
    let mut enum_args = match cli.command {
        Some(Commands::Scan(args)) => args,
        Some(Commands::Exec(_))
        | Some(Commands::Db(_))
        | Some(Commands::Origin(_))
        | Some(Commands::Axfr(_))
        | None => {
            eprintln!(
                "No command given. Use `voyage scan`, `voyage exec`, `voyage db`, or `voyage --daemon`. Try --help."
            );
            std::process::exit(1);
        }
    };

    if enum_args.interactive {
        enum_args
            .interactive_fill()
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }

    if enum_args.domain.is_empty() {
        eprintln!("Error: --domain is required (or use --interactive)");
        std::process::exit(1);
    }

    if enum_args.disable_passive_enum && enum_args.disable_active_enum {
        eprintln!("Error: cannot disable both passive and active enumeration");
        std::process::exit(1);
    }

    if !enum_args.disable_active_enum && enum_args.wordlist_path.is_empty() {
        eprintln!(
            "Error: --wordlist-path is required for active enumeration (or use --disable-active-enum / --interactive)"
        );
        std::process::exit(1);
    }

    // Connect to the daemon
    let daemon_addr = format!("127.0.0.1:{}", cli.port);
    let stream = TcpStream::connect(&daemon_addr).await.map_err(|_| {
        format!(
            "Voyage daemon is not running on port {}.\nStart it first with: voyage --daemon",
            cli.port
        )
    })?;

    // Build and send the stream enum request
    let request = serde_json::json!({
        "operation": "enum",
        "response": "stream",
        "save": true,
        "domain": enum_args.domain[0],
        "wordlist": enum_args.wordlist_path,
        "tasks": enum_args.tasks,
        "fresh_start": enum_args.fresh_start,
        "disable_passive": enum_args.disable_passive_enum,
        "disable_active": enum_args.disable_active_enum,
        "exclude_passive_sources": enum_args.exclude_passive_source,
        "exclude_active_techniques": enum_args.exclude_active_technique,
        "http_probing_ports": enum_args.http_probing_port,
        "https_probing_ports": enum_args.https_probing_port,
        "active_user_agent": enum_args.active_user_agent,
        "passive_user_agent": enum_args.passive_user_agent,
    });

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = dguard::encode(&request);
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;

    // Read the "ack" event to get operation_id and total
    let mut lines = BufReader::new(reader).lines();
    let ack_line = lines
        .next_line()
        .await?
        .ok_or("Daemon closed connection before ack")?;
    let ack: StreamEvent = serde_json::from_str(&ack_line)?;

    if ack.kind == "error" {
        eprintln!(
            "Error: {}",
            ack.message.unwrap_or_else(|| "scan error".to_string())
        );
        std::process::exit(1);
    }

    let operation_id = ack.operation_id.unwrap_or_else(|| "unknown".to_string());
    let total = ack.total.unwrap_or(0);
    let poll_timeout = enum_args.event_poll_timeout;

    if cfx_tui::wanted(cli.tui, cli.no_tui, true) {
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

        // Blocks until the user quits or the run completes.
        client_tui::run(rx, operation_id, total, poll_timeout).await?;
        return Ok(());
    }

    // No terminal, or --no-tui: forward the daemon's own newline-delimited JSON
    // so the output stays parseable. The ack is part of that stream, so it goes
    // out too rather than being swallowed by the line that read it.
    println!("{ack_line}");
    while let Some(line) = lines.next_line().await? {
        println!("{line}");
        if dguard::is_error(&line) {
            std::process::exit(1);
        }
        if serde_json::from_str::<StreamEvent>(&line).is_ok_and(|ev| ev.kind == "done") {
            break;
        }
    }

    Ok(())
}

async fn handle_db(args: DbArgs, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    if !args.full_reset {
        eprintln!("No action specified. Try: voyage db --full-reset");
        std::process::exit(1);
    }

    let daemon_addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&daemon_addr).await.map_err(|_| {
        format!(
            "Voyage daemon is not running on port {port}.\nStart it first with: voyage --daemon"
        )
    })?;

    let request = serde_json::json!({ "operation": "db_reset", "response": "instant" });
    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = dguard::encode(&request);
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

async fn handle_origin(args: OriginArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.domain.trim().is_empty() {
        eprintln!("Error: --domain is required");
        std::process::exit(1);
    }

    let log = |line: String| eprintln!("  {line}");
    let findings =
        scanners::origin::discover(&args.domain, args.timeout, !args.no_evasive, &log).await;

    if args.json {
        let arr: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "ip": f.ip.to_string(),
                    "host": f.host,
                    "confidence": f.confidence,
                    "note": f.note,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else if findings.is_empty() {
        println!(
            "\nNo origin candidates found behind the CDN for {}.",
            args.domain
        );
    } else {
        println!("\nOrigin candidates for {}:", args.domain);
        for f in &findings {
            println!(
                "  [{}] {} (via {}) - {}",
                f.confidence, f.ip, f.host, f.note
            );
        }
    }

    Ok(())
}

async fn handle_enum_exec(args: ExecArgs, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the caller's JSON and fill in the operation if they did not name one.
    let mut payload: serde_json::Value =
        serde_json::from_str(&args.json).map_err(|e| format!("Invalid JSON: {e}"))?;

    // Must be an object. Indexing a non-object panicked inside serde_json, so
    // `exec '[1,2]'` aborted with a library backtrace instead of an error.
    let Some(obj) = payload.as_object_mut() else {
        return Err("JSON payload must be an object".into());
    };
    // Default rather than overwrite. These were assigned unconditionally, so an
    // `operation` the caller asked for was accepted and then silently dropped.
    obj.entry("operation")
        .or_insert_with(|| serde_json::json!("probe"));
    obj.entry("response")
        .or_insert_with(|| serde_json::json!("instant"));

    let daemon_addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&daemon_addr).await.map_err(|_| {
        format!(
            "Voyage daemon is not running on port {port}.\nStart it first with: voyage --daemon"
        )
    })?;
    let _ = stream.set_nodelay(true);

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = dguard::encode(&payload);
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        println!("{line}");
        // The reply already says what went wrong, so exit non-zero without
        // printing a second time: stdout stays pure JSON for the caller, and a
        // script can read `$?` instead of parsing it.
        if dguard::is_error(&line) {
            std::process::exit(1);
        }
    }

    Ok(())
}

/// `voyage axfr`: ask the daemon for a zone transfer and print what comes back.
async fn handle_axfr(
    args: crate::libs::cli_args::AxfrArgs,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .map_err(|_| {
            format!("Voyage daemon is not running on port {port}. Start it with: voyage --daemon")
        })?;
    let request = serde_json::json!({
        "operation": "axfr",
        "response": "stream",
        "domain": args.domain,
        "dns_server": args.dns_server,
        "timeout_ms": args.timeout,
    });
    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = dguard::encode(&request);
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        match v["type"].as_str().unwrap_or("") {
            "result" => println!("{}", v["subdomain"].as_str().unwrap_or("")),
            "finding" => eprintln!("[!] {}", v["data"]["name"].as_str().unwrap_or("")),
            "log" | "error" => eprintln!("[-] {}", v["message"].as_str().unwrap_or("")),
            "done" => break,
            _ => {}
        }
    }
    Ok(())
}
