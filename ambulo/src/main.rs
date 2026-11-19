use crate::libs::cli_args::{Cli, Commands, DbArgs, ExecArgs, ScanArgs};
use crate::scanner::StreamEvent;
use clap::{CommandFactory, Parser};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    // Daemon mode - starts the TCP service and connects directly to postgres
    // -----------------------------------------------------------------------
    if matches!(cli.command, Some(Commands::Daemon)) {
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
            egress: transport::Egress::Inherit,
        };

        // Postgres being briefly unreachable is not a reason to exit: systemd
        // would restart us straight into the same failure, which is how one
        // host logged 2,663 restarts and reported nothing but "down". Wait for
        // it, saying why each time, and start as soon as it answers.
        // Bind before the database is reachable, and answer while waiting.
        //
        // Binding after the database meant a database problem looked exactly
        // like a dead engine: the port was closed, the node reported the
        // extension as not running, and every web_crawl failed with nothing to
        // go on. Binding early on its own would be worse, because the node
        // would call ambulo healthy while requests silently queued. So bind,
        // accept, and tell each caller precisely what is wrong until the
        // database answers.
        let addr = dguard::bind_addr(cli.port);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        eprintln!("Ambulo daemon listening on {addr} (waiting for database)");

        // Why the last try failed, for whoever connects before one succeeds.
        let not_ready = std::sync::Mutex::new(String::from("no answer yet"));
        let db_fut = dguard::wait_for(
            "the database",
            std::time::Duration::from_secs(3600),
            || async {
                let ready = async {
                    let pool = cfx_db::ensure_ready(libs::ambulo_db::DATABASE)
                        .await
                        .map_err(|e| e.to_string())?;
                    let db = libs::ambulo_db::AmbuloDb::new(pool, &dummy_config);
                    db.create_tables().await.map_err(|e| e.to_string())?;
                    Ok::<_, String>(db)
                }
                .await;
                if let Err(why) = &ready
                    && let Ok(mut last) = not_ready.lock()
                {
                    last.clone_from(why);
                }
                ready
            },
        );
        tokio::pin!(db_fut);

        // Do not answer yet. An ordinary start reaches the database in well
        // under a second, and a caller arriving inside that window should be
        // served, not refused. The port is already bound, so such a caller
        // waits in the listen backlog for a moment and is then served for real.
        //
        // Answering immediately made every start a race the caller usually
        // lost. The oracle harness treats an accepted connection as readiness,
        // so it connected the instant the port opened, got the not-ready error,
        // and four ambulo cases failed reporting nothing at all. The node's
        // extension check reads that same signal, so in production it would
        // call ambulo healthy and then collect errors from it.
        //
        // Once the grace is gone this is an outage rather than a slow start,
        // and then saying why beats making anyone wait.
        const READY_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

        let ambulo_db = match tokio::time::timeout(READY_GRACE, &mut db_fut).await {
            Ok(res) => res?,
            Err(_) => loop {
                tokio::select! {
                    res = &mut db_fut => break res?,
                    accepted = listener.accept() => {
                        if let Ok((sock, _)) = accepted {
                            let why = not_ready.lock().map(|w| w.clone()).unwrap_or_default();
                            tokio::spawn(daemon::answer_not_ready(sock, why));
                        }
                    }
                }
            },
        };

        return daemon::run_on(listener, ambulo_db).await;
    }

    // The daemon every command below talks to, started when it is not running.
    let daemon = dguard::Daemon::new("ambulo", cli.port, !cli.no_autostart);

    // -----------------------------------------------------------------------
    // Db subcommand - database management (connects directly to postgres)
    // -----------------------------------------------------------------------
    if let Some(Commands::Db(db_args)) = &cli.command {
        return handle_db(db_args.clone(), &daemon).await;
    }

    if let Some(Commands::Exec(exec_args)) = &cli.command {
        return handle_fuzz_exec(exec_args.clone(), &daemon).await;
    }

    // -----------------------------------------------------------------------
    // Completions subcommand - print a shell completion script (no daemon needed)
    // -----------------------------------------------------------------------
    if let Some(Commands::Completions { shell }) = &cli.command {
        let mut script = Vec::new();
        clap_complete::generate(*shell, &mut Cli::command(), "ambulo", &mut script);
        print_all(&script)?;
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Fuzz subcommand - client that talks to the running daemon
    // -----------------------------------------------------------------------
    let mut fuzz_args = match cli.command {
        Some(Commands::Scan(args)) => args,
        Some(Commands::Exec(_))
        | Some(Commands::Db(_))
        | Some(Commands::Completions { .. })
        | Some(Commands::Daemon)
        | None => {
            eprintln!(
                "No command given. Use `ambulo scan <url>...`, `ambulo exec <json>`, `ambulo db`, or `ambulo daemon`. Try --help."
            );
            std::process::exit(1);
        }
    };

    if fuzz_args.interactive {
        fuzz_args
            .interactive_fill()
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }

    if fuzz_args.wordlist_path.is_empty() {
        eprintln!("Error: a wordlist is needed: -w <wordlist> (or use --interactive)");
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

    // The wordlist is read here and its words sent after the request, so the daemon
    // opens no path for this scan and any file this user can read will do.
    let wordlist = std::path::Path::new(&fuzz_args.wordlist_path);
    let tui = cfx_tui::wanted(cli.no_tui);
    for url in &fuzz_args.url {
        scan_url(&daemon, &fuzz_args, url, wordlist, tui).await?;
    }
    Ok(())
}

/// One scan of `url` by the daemon with the words of the file at `wordlist`: drawn on
/// the dashboard when `tui`, and otherwise written out as the daemon's own
/// newline-delimited JSON.
async fn scan_url(
    daemon: &dguard::Daemon,
    fuzz_args: &ScanArgs,
    url: &str,
    wordlist: &std::path::Path,
    tui: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = daemon.connect().await?;

    // Build and send the stream scan request
    let mut request = serde_json::json!({
        "operation": "scan",
        "response": "stream",
        "save": true,
        "endpoint": url,
        "method": fuzz_args.http_method.to_string(),
        "tasks": fuzz_args.tasks,
        "follow_redirects": fuzz_args.follow_redirects,
        "follow_redirects_depth": fuzz_args.follow_redirects_depth,
        "fresh_start": fuzz_args.fresh_start,
        "fuzz_marker": fuzz_args.fuzz_marker,
        "success_status_codes": fuzz_args.success_status_codes,
    });
    request[dguard::WORDS_FOLLOW] = dguard::list_name(wordlist).into();

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = dguard::encode(&request);
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;
    let sent = dguard::send_words(&mut writer, wordlist).await;
    // Read the "ack" event to get operation_id and total. A daemon that refused the
    // scan says why here, which is more use than a write it stopped reading.
    let mut lines = BufReader::new(reader).lines();
    let ack_line = match lines.next_line().await? {
        Some(line) => line,
        None => {
            return Err(sent
                .err()
                .unwrap_or_else(|| "Daemon closed connection before ack".to_string())
                .into());
        }
    };
    let ack: StreamEvent = serde_json::from_str(&ack_line)?;

    if ack.kind == "error" {
        eprintln!("Error: {}", ack.message.as_deref().unwrap_or("unknown"));
        std::process::exit(1);
    }
    sent?;

    let operation_id = ack.operation_id.unwrap_or_else(|| "unknown".to_string());
    let total = ack.total.unwrap_or(0);
    let poll_timeout = fuzz_args.event_poll_timeout;

    if tui {
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
        eprintln!("No action given. See `ambulo db --help`.");
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

/// The request `exec` sends for the caller's JSON, with the operation, the response
/// mode and, for a probe, an operation id filled in where the caller left them out. The
/// daemon files a probe's result under its operation id and refuses a probe without
/// one, so the README's own example was refused.
fn exec_request(json: &str) -> Result<serde_json::Value, String> {
    let mut payload: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("Invalid JSON: {e}"))?;

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
    if obj.get("operation").and_then(|o| o.as_str()) == Some("probe") {
        obj.entry("operation_id")
            .or_insert_with(|| serde_json::json!(uuid::Uuid::new_v4().to_string()));
    }
    Ok(payload)
}

async fn handle_fuzz_exec(
    args: ExecArgs,
    daemon: &dguard::Daemon,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the caller's JSON and fill in the operation if they did not name one.
    let payload = exec_request(&args.json)?;

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

#[cfg(test)]
mod exec_tests {
    use super::exec_request;

    #[test]
    fn the_readme_example_is_a_probe_the_daemon_accepts() {
        let req = exec_request(
            r#"{"url":"https://example.com/robots.txt","success_codes":[200],"method":"get"}"#,
        )
        .expect("an object");
        assert_eq!(req["operation"], "probe");
        let parsed: Result<crate::daemon::ProbeParams, _> = serde_json::from_value(req);
        assert!(parsed.is_ok(), "the daemon refuses it: {:?}", parsed.err());
    }

    #[test]
    fn what_the_caller_named_is_kept() {
        let req =
            exec_request(r#"{"operation":"probe","operation_id":"mine","response":"stream"}"#)
                .expect("an object");
        assert_eq!(req["operation_id"], "mine");
        assert_eq!(req["response"], "stream");
        assert!(exec_request("[1,2]").is_err());
    }
}
