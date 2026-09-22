use crate::libs::cli_args::{Cli, Commands, DbArgs, ScanExecArgs};
use crate::scanner::StreamEvent;
use clap::Parser;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

mod browser;
mod client_tui;
mod crawler;
mod daemon;
mod exporter;
mod libs;
mod prober;
mod routetable;
mod scanner;
mod spa;
mod tui;

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

        let dummy_config = libs::cli_args::ScanArgs {
            url: vec![],
            wordlist_path: String::new(),
            fuzz_marker: "::FUZZ::".to_string(),
            cookies: vec![],
            headers: vec![],
            basic_auth: String::new(),
            store_cookies: false,
            success_status_codes: vec![200],
            follow_redirects: true,
            follow_redirects_depth: 5,
            http_method: libs::cli_args::HttpMethod::Get,
            interval: 0,
            tasks: 1,
            fresh_start: false,
            random_user_agent_scan: false,
            random_user_agent_request: false,
            append_slash: false,
            save_response_body: false,
            save_response_headers: false,
            user_agent: adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None)
                .user_agent,
            evasive: true,
            identify: None,
            no_exit_banner: true,
            recreate_db: false,
            launch_delay: 0,
            log_level: libs::cli_args::LogLevel::Info,
            output_format: libs::cli_args::OutputFormat::Text,
            output_path: String::new(),
            event_poll_timeout: 1000,
            enable_offset_pagination: false,
            interactive: false,
            adaptive_rate: false,
            adaptive_resilience: false,
            posture: "balanced".to_string(),
        };

        // Postgres being briefly unreachable is not a reason to exit: systemd
        // would restart us straight into the same failure, which is how one
        // host logged 2,663 restarts and reported nothing but "down". Wait for
        // it, saying so each time, and start as soon as it answers.
        // Bind before the database is reachable, and answer while waiting.
        //
        // Binding after the database meant a database problem looked exactly
        // like a dead engine: the port was closed, the node reported the
        // extension as not running, and every web_crawl failed with nothing to
        // go on. Binding early on its own would be worse, because the node
        // would call mach healthy while requests silently queued. So bind,
        // accept, and tell each caller precisely what is wrong until the
        // database answers.
        let addr = dguard::bind_addr(cli.port);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        eprintln!("Mach daemon listening on {addr} (waiting for database)");

        // Name the endpoint and the fix. "pool timed out while waiting for an
        // open connection" is true and useless: it does not say which host,
        // which port, or that the container may simply not have been created on
        // this machine yet.
        let db_label = format!(
            "postgres at {}:{} (create it with `crossfyre db up`)",
            toolchain_cfg.postgres.host, toolchain_cfg.postgres.port
        );
        let db_fut = dguard::wait_for(&db_label, std::time::Duration::from_secs(3600), || async {
            let db = libs::mach_db::MachDb::init(
                &toolchain_cfg.postgres.host,
                toolchain_cfg.postgres.port,
                &toolchain_cfg.postgres.user,
                toolchain_cfg.postgres.password.as_deref(),
                &dummy_config,
            )
            .await
            .map_err(|e| e.to_string())?;
            db.create_tables().await.map_err(|e| e.to_string())?;
            Ok::<_, String>(db)
        });
        tokio::pin!(db_fut);

        // Do not answer yet. An ordinary start reaches the database in well
        // under a second, and a caller arriving inside that window should be
        // served, not refused. The port is already bound, so such a caller
        // waits in the listen backlog for a moment and is then served for real.
        //
        // Answering immediately made every start a race the caller usually
        // lost. The oracle harness treats an accepted connection as readiness,
        // so it connected the instant the port opened, got the not-ready error,
        // and four mach cases failed reporting nothing at all. The node's
        // extension check reads that same signal, so in production it would
        // call mach healthy and then collect errors from it.
        //
        // Once the grace is gone this is an outage rather than a slow start,
        // and then saying why beats making anyone wait.
        const READY_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

        let mach_db = match tokio::time::timeout(READY_GRACE, &mut db_fut).await {
            Ok(res) => res?,
            Err(_) => loop {
                tokio::select! {
                    res = &mut db_fut => break res?,
                    accepted = listener.accept() => {
                        if let Ok((mut sock, _)) = accepted {
                            tokio::spawn(async move {
                                use tokio::io::AsyncWriteExt;
                                let msg = serde_json::json!({
                                    "type": "error",
                                    "message": "mach is not ready: waiting for its \
                                                database. Create it with `crossfyre db up`.",
                                });
                                let _ = sock.write_all(format!("{msg}\n").as_bytes()).await;
                                let _ = sock.flush().await;
                            });
                        }
                    }
                }
            },
        };

        return daemon::run_on(listener, mach_db).await;
    }

    // -----------------------------------------------------------------------
    // Db subcommand - database management (connects directly to postgres)
    // -----------------------------------------------------------------------
    if let Some(Commands::Db(db_args)) = &cli.command {
        return handle_db(db_args.clone(), cli.port).await;
    }

    if let Some(Commands::ScanExec(exec_args)) = &cli.command {
        return handle_fuzz_exec(exec_args.clone(), cli.port).await;
    }

    // -----------------------------------------------------------------------
    // Fuzz subcommand - client that talks to the running daemon
    // -----------------------------------------------------------------------
    let mut fuzz_args = match cli.command {
        Some(Commands::Scan(args)) => args,
        Some(Commands::ScanExec(_)) | Some(Commands::Db(_)) | None => {
            eprintln!(
                "No command given. Use `mach scan`, `mach scan-exec`, `mach db`, or `mach --daemon`. Try --help."
            );
            std::process::exit(1);
        }
    };

    if fuzz_args.interactive {
        fuzz_args
            .interactive_fill()
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }

    if fuzz_args.url.is_empty() {
        eprintln!("Error: --url is required (or use --interactive)");
        std::process::exit(1);
    }
    if fuzz_args.wordlist_path.is_empty() {
        eprintln!("Error: --wordlist-path is required (or use --interactive)");
        std::process::exit(1);
    }

    if fuzz_args.launch_delay > 0 {
        std::thread::sleep(std::time::Duration::from_secs(
            fuzz_args.launch_delay as u64,
        ));
    }

    fuzz_args
        .validate_urls()
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Connect to the daemon
    let daemon_addr = format!("127.0.0.1:{}", cli.port);
    let stream = TcpStream::connect(&daemon_addr).await.map_err(|_| {
        format!(
            "Mach daemon is not running on port {}.\nStart it first with: mach --daemon",
            cli.port
        )
    })?;

    // Resolve wordlist to absolute path (daemon runs from a different cwd)
    let wordlist_abs = std::fs::canonicalize(&fuzz_args.wordlist_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| fuzz_args.wordlist_path.clone());

    // Build and send the stream scan request
    let request = serde_json::json!({
        "operation": "scan",
        "response": "stream",
        "save": true,
        "endpoint": fuzz_args.url[0],
        "wordlist": wordlist_abs,
        "method": fuzz_args.http_method.to_string(),
        "tasks": fuzz_args.tasks,
        "follow_redirects": fuzz_args.follow_redirects,
        "follow_redirects_depth": fuzz_args.follow_redirects_depth,
        "fresh_start": fuzz_args.fresh_start,
        "fuzz_marker": fuzz_args.fuzz_marker,
        "success_status_codes": fuzz_args.success_status_codes,
    });

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = serde_json::to_string(&request)?;
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
        eprintln!("Error: {}", ack.message.as_deref().unwrap_or("unknown"));
        std::process::exit(1);
    }

    let operation_id = ack.operation_id.unwrap_or_else(|| "unknown".to_string());
    let total = ack.total.unwrap_or(0);
    let poll_timeout = fuzz_args.event_poll_timeout;

    // Spawn a task to read stream events and send them to the TUI channel
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

    // Run the TUI - blocks until user presses q or scan completes
    client_tui::run(rx, operation_id, total, poll_timeout).await?;

    Ok(())
}

async fn handle_db(args: DbArgs, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    if !args.full_reset {
        eprintln!("No action specified. Try: mach db --full-reset");
        std::process::exit(1);
    }

    let daemon_addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&daemon_addr).await.map_err(|_| {
        format!("Mach daemon is not running on port {port}.\nStart it first with: mach --daemon")
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

async fn handle_fuzz_exec(args: ScanExecArgs, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the user's JSON, inject operation="probe" and response="instant"
    let mut payload: serde_json::Value =
        serde_json::from_str(&args.json).map_err(|e| format!("Invalid JSON: {e}"))?;

    payload["operation"] = serde_json::json!("probe");
    payload["response"] = serde_json::json!("instant");

    let daemon_addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&daemon_addr).await.map_err(|_| {
        format!("Mach daemon is not running on port {port}.\nStart it first with: mach --daemon")
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
