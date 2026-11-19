use crate::libs::cli_args::{Cli, Commands, DbArgs, ExecArgs};
use crate::scanner::StreamEvent;
use clap::{CommandFactory, Parser};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

mod client_tui;
mod daemon;
mod governor;
mod libs;
mod scanner;

// An error is printed as the sentence it is. Returned from `main`, Rust prints it in
// debug form: in quotes, with a line break shown as a backslash and an n.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // -----------------------------------------------------------------------
    // Daemon mode - starts the TCP service and connects to postgres
    // -----------------------------------------------------------------------
    if matches!(cli.command, Some(Commands::Daemon)) {
        // Postgres being briefly unreachable is not a reason to exit: systemd
        // would restart us straight into the same failure, which is how one
        // host logged 2,663 restarts and reported nothing but "down". Wait for
        // it, saying why each time, and start as soon as it answers.
        let doorward_db = dguard::wait_for(
            "the database",
            std::time::Duration::from_secs(3600),
            || async {
                let pool = cfx_db::ensure_ready(libs::doorward_db::DATABASE)
                    .await
                    .map_err(|e| e.to_string())?;
                let db = libs::doorward_db::DoorwardDb::new(pool);
                db.create_tables().await.map_err(|e| e.to_string())?;
                Ok::<_, String>(db)
            },
        )
        .await?;

        return daemon::run(cli.port, doorward_db).await;
    }

    // The daemon every command below talks to, started when it is not running.
    let daemon = dguard::Daemon::new("doorward", cli.port, !cli.no_autostart);

    // -----------------------------------------------------------------------
    // Db subcommand
    // -----------------------------------------------------------------------
    if let Some(Commands::Db(db_args)) = &cli.command {
        return handle_db(db_args.clone(), &daemon).await;
    }

    // -----------------------------------------------------------------------
    // Exec subcommand - send raw JSON to daemon
    // -----------------------------------------------------------------------
    if let Some(Commands::Exec(exec_args)) = &cli.command {
        return handle_scan_exec(exec_args.clone(), &daemon).await;
    }

    // -----------------------------------------------------------------------
    // Completions subcommand - print a shell completion script (no daemon needed)
    // -----------------------------------------------------------------------
    if let Some(Commands::Completions { shell }) = &cli.command {
        let mut script = Vec::new();
        clap_complete::generate(*shell, &mut Cli::command(), "doorward", &mut script);
        print_all(&script)?;
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Scan subcommand - client that talks to the running daemon
    // -----------------------------------------------------------------------
    let scan_args = match cli.command {
        Some(Commands::Scan(args)) => args,
        _ => {
            eprintln!(
                "No command given. Use `doorward scan`, `doorward exec`, `doorward db`, or `doorward daemon`. Try --help."
            );
            std::process::exit(1);
        }
    };

    if scan_args.targets.is_empty() {
        eprintln!("Error: --targets is required");
        std::process::exit(1);
    }

    let stream = daemon.connect().await?;

    let ports = libs::cli_args::resolve_ports(&scan_args.ports);

    // On stderr, so a piped scan's JSON on stdout stays clean.
    if let Some(notice) = scan_args.technique.notice() {
        eprintln!("{notice}");
    }

    // Build and send the stream scan request
    let request = serde_json::json!({
        "operation": "scan",
        "response": "stream",
        "save": true,
        "targets": scan_args.targets,
        "ports": ports,
        "technique": scan_args.technique.runs(),
        "tasks": scan_args.tasks,
        "timeout": scan_args.timeout,
        "delay": scan_args.delay,
        "service_detection": scan_args.service_detection,
    });

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = dguard::encode(&request);
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

/// Write `bytes` to stdout. A reader that stops early, as `head` does, closes the pipe,
/// and that is not an error: the rest was not wanted. clap_complete panics on any failed
/// write, so what it generates is kept in memory and written from here.
fn print_all(bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        done => done,
    }
}

async fn handle_db(
    args: DbArgs,
    daemon: &dguard::Daemon,
) -> Result<(), Box<dyn std::error::Error>> {
    if !args.full_reset {
        eprintln!("No action given. See `doorward db --help`.");
        std::process::exit(1);
    }

    let stream = daemon.connect().await?;

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

async fn handle_scan_exec(
    args: ExecArgs,
    daemon: &dguard::Daemon,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let stream = daemon.connect().await?;
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
