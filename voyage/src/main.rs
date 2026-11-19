use crate::libs::cli_args::{Cli, Commands, ExecArgs, OriginArgs, ScanArgs};
use crate::scanner::StreamEvent;
use clap::{CommandFactory, Parser};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

mod axfr;
mod client_tui;
mod daemon;
mod libs;
mod scanner;
mod scanners;
mod store;
mod takeover;

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
        // Postgres being briefly unreachable is not a reason to exit: systemd
        // would restart us straight into the same failure, which is how one
        // host logged 2,663 restarts and reported nothing but "down". Wait for
        // it, saying why each time, and start as soon as it answers.
        let voyage_db = dguard::wait_for(
            "the database",
            std::time::Duration::from_secs(3600),
            || async {
                let pool = cfx_db::ensure_ready(&libs::voyage_db::ENGINE)
                    .await
                    .map_err(|e| e.to_string())?;
                cfx_db::scans::stop_abandoned(&pool)
                    .await
                    .map_err(|e| e.to_string())?;
                let db = libs::voyage_db::VoyageDb::new(pool);
                Ok::<_, String>(db)
            },
        )
        .await?;

        return daemon::run(cli.port, voyage_db).await;
    }

    // The daemon every command below talks to, started when it is not running.
    let daemon = dguard::Daemon::new("voyage", cli.port, !cli.no_autostart);

    // -----------------------------------------------------------------------
    // Db subcommand: sent to the daemon, which keeps the scans
    // -----------------------------------------------------------------------
    if let Some(Commands::Db { action }) = &cli.command {
        return dguard::run_db(&daemon, action).await;
    }

    if let Some(Commands::Exec(exec_args)) = &cli.command {
        return handle_enum_exec(exec_args.clone(), &daemon).await;
    }

    // -----------------------------------------------------------------------
    // Origin subcommand - self-contained origin discovery (no daemon needed)
    // -----------------------------------------------------------------------
    if let Some(Commands::Origin(origin_args)) = &cli.command {
        return handle_origin(origin_args.clone()).await;
    }

    if let Some(Commands::Axfr(args)) = &cli.command {
        return handle_axfr(args.clone(), &daemon).await;
    }

    // -----------------------------------------------------------------------
    // Completions subcommand - print a shell completion script (no daemon needed)
    // -----------------------------------------------------------------------
    if let Some(Commands::Completions { shell }) = &cli.command {
        let mut script = Vec::new();
        clap_complete::generate(*shell, &mut Cli::command(), "voyage", &mut script);
        print_all(&script)?;
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Scan subcommand - client that talks to the running daemon
    // -----------------------------------------------------------------------
    let mut enum_args = match cli.command {
        Some(Commands::Scan(args)) => args,
        Some(Commands::Exec(_))
        | Some(Commands::Db { .. })
        | Some(Commands::Origin(_))
        | Some(Commands::Axfr(_))
        | Some(Commands::Completions { .. })
        | Some(Commands::Daemon)
        | None => {
            eprintln!(
                "No command given. Use `voyage scan <domain>...`, `voyage exec <json>`, `voyage db`, or `voyage daemon`. Try --help."
            );
            std::process::exit(1);
        }
    };

    if enum_args.interactive {
        enum_args
            .interactive_fill()
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }

    // Without a wordlist only the passive sources run, and with those off as well there
    // is nothing to run.
    match enum_args.passive_only() {
        Ok(note) => {
            if let Some(note) = note {
                eprintln!("{note}");
            }
        }
        Err(why) => {
            eprintln!("Error: {why}");
            std::process::exit(1);
        }
    }

    // A wordlist is read here and its words sent after the request, so the daemon
    // opens no path for this scan and any file this user can read will do.
    let wordlist = (!enum_args.wordlist_path.is_empty())
        .then(|| std::path::Path::new(&enum_args.wordlist_path));
    let tui = cfx_tui::wanted(cli.no_tui);
    for domain in &enum_args.domain {
        scan_domain(&daemon, &enum_args, domain, wordlist, tui).await?;
    }
    Ok(())
}

/// The stream enumeration request for `domain` with every flag of `args` the daemon
/// honours, the interval between requests as `delay`. `active` says whether words
/// follow it for the active part.
fn enum_request(args: &ScanArgs, domain: &str, active: bool) -> serde_json::Value {
    serde_json::json!({
        "operation": "enum",
        "response": "stream",
        "save": true,
        "domain": domain,
        "tasks": args.tasks,
        "delay": args.interval,
        "fresh_start": args.fresh_start,
        "disable_passive": args.disable_passive_enum,
        "disable_active": !active,
        "exclude_passive_sources": args.exclude_passive_source,
        "exclude_active_techniques": args.exclude_active_technique,
        "http_probing_ports": args.http_probing_port,
        "https_probing_ports": args.https_probing_port,
        "active_user_agent": args.active_user_agent,
        "active_random_user_agent": args.active_random_user_agent,
        "passive_user_agent": args.passive_user_agent,
    })
}

/// Whether event `line` is shown at log level `least`: every event but a log line below
/// it.
fn shown(line: &str, least: &libs::cli_args::LogLevel) -> bool {
    let rank = |level: &str| {
        ["debug", "info", "warn", "error"]
            .iter()
            .position(|l| *l == level)
    };
    match serde_json::from_str::<StreamEvent>(line) {
        Ok(ev) if ev.kind == "log" => {
            rank(ev.log_level.as_deref().unwrap_or("info")) >= rank(&least.to_string())
        }
        _ => true,
    }
}

/// One enumeration of `domain` by the daemon, with the words of the file at `wordlist`
/// when there is one: drawn on the dashboard when `tui`, and otherwise written out as
/// the daemon's own newline-delimited JSON.
async fn scan_domain(
    daemon: &dguard::Daemon,
    enum_args: &ScanArgs,
    domain: &str,
    wordlist: Option<&std::path::Path>,
    tui: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = daemon.connect().await?;

    let mut request = enum_request(enum_args, domain, wordlist.is_some());
    if let Some(wordlist) = wordlist {
        request[dguard::WORDS_FOLLOW] = dguard::list_name(wordlist).into();
    }

    let (reader, mut writer) = tokio::io::split(stream);
    let mut req_str = dguard::encode(&request);
    req_str.push('\n');
    writer.write_all(req_str.as_bytes()).await?;
    let sent = match wordlist {
        Some(wordlist) => dguard::send_words(&mut writer, wordlist).await,
        None => Ok(()),
    };
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
        eprintln!(
            "Error: {}",
            ack.message.unwrap_or_else(|| "scan error".to_string())
        );
        std::process::exit(1);
    }
    sent?;

    let operation_id = ack.operation_id.unwrap_or_else(|| "unknown".to_string());
    let total = ack.total.unwrap_or(0);
    let poll_timeout = enum_args.event_poll_timeout;
    let least = enum_args.log_level.clone();

    if tui {
        let (tx, rx) = mpsc::unbounded_channel::<StreamEvent>();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                if !shown(&line, &least) {
                    continue;
                }
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
        if shown(&line, &least) {
            println!("{line}");
        }
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

async fn handle_origin(args: OriginArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.domain.trim().is_empty() {
        eprintln!("Error: the domain is empty");
        std::process::exit(1);
    }

    let log = |line: String| eprintln!("  {line}");
    let egress = transport::Egress::Inherit;
    if let Some(why) = scanners::origin::refused(&egress) {
        eprintln!("Error: {why}. CROSSFYRE_EGRESS_PROXY is set.");
        std::process::exit(1);
    }
    let findings =
        scanners::origin::discover(&args.domain, args.timeout, !args.no_evasive, &egress, &log)
            .await;

    if args.json || !to_terminal() {
        for line in origin_json(&findings) {
            println!("{line}");
        }
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

/// Whether stdout is a terminal, where `origin` and `axfr` write text. Piped or
/// redirected, they write JSON lines, as every engine's commands do.
fn to_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// `origin`'s findings as JSON lines: a result for each candidate, and then done.
fn origin_json(findings: &[scanners::origin::OriginFinding]) -> Vec<String> {
    findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "type": "result",
                "ip": f.ip.to_string(),
                "host": f.host,
                "confidence": f.confidence,
                "note": f.note,
            })
            .to_string()
        })
        .chain(std::iter::once(
            serde_json::json!({"type": "done", "found": findings.len()}).to_string(),
        ))
        .collect()
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

async fn handle_enum_exec(
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

/// `voyage axfr`: ask the daemon for a zone transfer and print what comes back.
async fn handle_axfr(
    args: crate::libs::cli_args::AxfrArgs,
    daemon: &dguard::Daemon,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = daemon.connect().await?;
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

    let json = !to_terminal();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        match axfr_shown(&line, json) {
            Some(Shown::Out(text)) => println!("{text}"),
            Some(Shown::Err(text)) => eprintln!("{text}"),
            None => {}
        }
        if serde_json::from_str::<serde_json::Value>(&line).is_ok_and(|v| v["type"] == "done") {
            break;
        }
    }
    Ok(())
}

/// What `axfr` shows of a line from the daemon, and where.
#[derive(Debug, PartialEq, Eq)]
enum Shown {
    Out(String),
    Err(String),
}

/// A line the daemon sent `axfr`, as it is shown: piped (`json`), the line itself; in a
/// terminal, a name it found on stdout, and what else happened on stderr.
fn axfr_shown(line: &str, json: bool) -> Option<Shown> {
    let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
    if json {
        return Some(Shown::Out(line.to_string()));
    }
    match v["type"].as_str().unwrap_or("") {
        "result" => Some(Shown::Out(
            v["subdomain"].as_str().unwrap_or("").to_string(),
        )),
        "finding" => Some(Shown::Err(format!(
            "[!] {}",
            v["data"]["name"].as_str().unwrap_or("")
        ))),
        "log" | "error" => Some(Shown::Err(format!(
            "[-] {}",
            v["message"].as_str().unwrap_or("")
        ))),
        _ => None,
    }
}

#[cfg(test)]
mod piped_tests {
    use super::*;

    fn finding(ip: &str) -> scanners::origin::OriginFinding {
        scanners::origin::OriginFinding {
            ip: ip.parse().unwrap(),
            host: "direct.lab.test".to_string(),
            confidence: "likely",
            note: "answers for the site".to_string(),
        }
    }

    /// Piped, `origin` writes one JSON line per candidate and then one that it is done,
    /// as every engine's commands do. It wrote a pretty-printed array, a line of which
    /// was not JSON on its own.
    #[test]
    fn origin_writes_json_lines() {
        let lines = origin_json(&[finding("192.0.2.1"), finding("192.0.2.2")]);
        let parsed: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("a line of JSON"))
            .collect();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0]["type"], "result");
        assert_eq!(parsed[0]["ip"], "192.0.2.1");
        assert_eq!(parsed[1]["host"], "direct.lab.test");
        assert_eq!(parsed[2], serde_json::json!({"type": "done", "found": 2}));
        assert_eq!(
            origin_json(&[]),
            [serde_json::json!({"type": "done", "found": 0}).to_string()]
        );
    }

    /// Piped, `axfr` passes on the daemon's JSON lines; in a terminal it prints the
    /// names, and what else happened on stderr.
    #[test]
    fn axfr_writes_json_lines_when_piped_and_names_in_a_terminal() {
        let result = r#"{"type":"result","subdomain":"www.lab.test","status":"found"}"#;
        let log = r#"{"type":"log","message":"ns1.lab.test refused the transfer"}"#;
        let done = r#"{"type":"done","total":1}"#;
        assert_eq!(
            axfr_shown(result, true),
            Some(Shown::Out(result.to_string()))
        );
        assert_eq!(axfr_shown(log, true), Some(Shown::Out(log.to_string())));
        assert_eq!(axfr_shown(done, true), Some(Shown::Out(done.to_string())));
        assert_eq!(
            axfr_shown(result, false),
            Some(Shown::Out("www.lab.test".to_string()))
        );
        assert_eq!(
            axfr_shown(log, false),
            Some(Shown::Err(
                "[-] ns1.lab.test refused the transfer".to_string()
            ))
        );
        assert_eq!(axfr_shown(done, false), None);
    }
}

#[cfg(test)]
mod exec_tests {
    use super::exec_request;

    #[test]
    fn the_readme_example_is_a_probe_the_daemon_accepts() {
        let req =
            exec_request(r#"{"domain":"api.example.com","volatility":0}"#).expect("an object");
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
