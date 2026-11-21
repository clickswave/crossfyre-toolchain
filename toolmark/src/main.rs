use crate::libs::cli_args::{Cli, Commands};
use clap::{CommandFactory, Parser};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod client_tui;
mod cve;
mod daemon;
mod fingerprint;
mod inventory;
mod knowledge;
mod libs;
mod observe;
mod rematch;
mod services;
mod signatures;

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

    if matches!(cli.command, Some(Commands::Daemon)) {
        // The database being briefly unreachable is not a reason to exit: wait for it,
        // saying why each time, and start as soon as it answers.
        let db = dguard::wait_for(
            "the database",
            std::time::Duration::from_secs(3600),
            || async {
                let pool = cfx_db::ensure_ready(&libs::toolmark_db::ENGINE)
                    .await
                    .map_err(|e| e.to_string())?;
                cfx_db::scans::stop_abandoned(&pool)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok::<_, String>(libs::toolmark_db::ToolmarkDb::new(pool))
            },
        )
        .await?;
        // What `crossfyre update` put in the toolchain directory, or what is compiled in.
        let dir = dguard::toolchain_dir();
        let knowledge = std::sync::Arc::new(knowledge::Knowledge::load(dir.as_deref()));
        return daemon::run(cli.port, db, knowledge).await;
    }

    // The daemon every command below talks to, started when it is not running.
    let daemon = dguard::Daemon::new("toolmark", cli.port, !cli.no_autostart);

    match cli.command {
        Some(Commands::Scan(args)) => {
            let req = args.request();
            send_stream(
                &daemon,
                req,
                cfx_tui::wanted(cli.no_tui),
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
            send_stream(&daemon, req, cfx_tui::wanted(cli.no_tui), label).await
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
            tokio::task::spawn_blocking(move || cfx_tui::scans::show("TOOLMARK", &scans, tui))
                .await??;
            Ok(())
        }
        Some(Commands::Rematch) => {
            let req = serde_json::json!({"operation": "rematch", "response": "stream"});
            let label = "the pages toolmark kept".to_string();
            send_stream(&daemon, req, cfx_tui::wanted(cli.no_tui), label).await
        }
        Some(Commands::Inventory) => {
            let answer = dguard::answer(&daemon, "inventory").await?;
            let rows = answer["inventory"].as_array().cloned().unwrap_or_default();
            let tui = cfx_tui::wanted(cli.no_tui);
            tokio::task::spawn_blocking(move || inventory::show(&rows, tui)).await??;
            Ok(())
        }
        Some(Commands::Db { action }) => dguard::run_db(&daemon, &action).await,
        Some(Commands::Completions { shell }) => {
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "toolmark", &mut script);
            print_all(&script)?;
            Ok(())
        }
        Some(Commands::Check(args)) => check(&args),
        Some(Commands::Daemon) | None => {
            eprintln!(
                "No command given. Use `toolmark scan <target>`, `toolmark services <host:port>...`, `toolmark exec <json>`, or `toolmark daemon`."
            );
            std::process::exit(1);
        }
    }
}

/// `toolmark check`: the signatures in a folder and the mappings in another, read as
/// toolmark reads a pack, each problem printed; and, when all of it loads, the products
/// the signatures name written out, by the names toolmark gives what it finds: a plessor
/// template names its product that way, since plessor matches it against what toolmark
/// saw, which carries no aliases.
fn check(args: &libs::cli_args::CheckArgs) -> Result<(), Box<dyn std::error::Error>> {
    let signatures = files_in(&args.dir, |name| name.ends_with(".yaml"))?;
    let mappings = files_in(&args.mappings, knowledge::is_mapping)?;
    let (signatures, _) = match knowledge::read(&pairs(&signatures), &pairs(&mappings)) {
        Ok(read) => read,
        Err(problems) => {
            for problem in &problems {
                println!("{problem}");
            }
            return Err(format!("{} problem(s) in {}", problems.len(), args.dir.display()).into());
        }
    };
    if let Some(path) = &args.names {
        let mut names: Vec<String> = signatures
            .cpes()
            .iter()
            .map(|c| format!("{}:{}", c.vendor, c.product))
            .collect();
        names.sort();
        names.dedup();
        std::fs::write(path, names.join("\n") + "\n")?;
    }
    Ok(())
}

/// `files` as names and texts.
fn pairs(files: &[(String, String)]) -> Vec<(&str, &str)> {
    files
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect()
}

/// The files directly in `dir` whose names `wanted` takes, by name and text, in order.
fn files_in(
    dir: &std::path::Path,
    wanted: impl Fn(&str) -> bool,
) -> Result<Vec<(String, String)>, String> {
    let fail = |e: std::io::Error| format!("{}: {e}", dir.display());
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(fail)? {
        let path = entry.map_err(fail)?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_file() && wanted(name) {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            files.push((name.to_string(), text));
        }
    }
    files.sort();
    Ok(files)
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

#[cfg(test)]
mod tests {
    /// The shipped signatures and mappings pass the check, the names it writes for
    /// plessor's check are the ones toolmark gives what it finds, without aliases, and a
    /// mapping it cannot read is a problem.
    #[test]
    fn the_shipped_signatures_and_mappings_pass_the_check() {
        let root = env!("CARGO_MANIFEST_DIR");
        let out = tempfile::tempdir().unwrap();
        let names = out.path().join("names.txt");
        let args = |mappings: &std::path::Path| super::libs::cli_args::CheckArgs {
            dir: format!("{root}/signatures").into(),
            mappings: mappings.to_path_buf(),
            names: Some(names.clone()),
        };
        super::check(&args(std::path::Path::new(&format!("{root}/data")))).unwrap();
        let written = std::fs::read_to_string(&names).unwrap();
        let lines: Vec<&str> = written.lines().collect();
        assert!(lines.contains(&"zimbra:collaboration"));
        assert!(
            !lines.contains(&"synacor:zimbra_collaboration_suite"),
            "an alias is not what toolmark names what it finds"
        );
        assert!(lines.windows(2).all(|w| w[0] < w[1]), "sorted, once each");

        // No mappings: neither file, nor the stamp table NetScaler's signature names.
        let empty = tempfile::tempdir().unwrap();
        let err = super::check(&args(empty.path())).unwrap_err();
        assert!(err.to_string().starts_with("3 problem(s)"), "{err}");
    }

    /// A folder's .yaml files are read as a pack's are, a file that does not load is a
    /// problem that names it, and what is not a .yaml file is not read.
    #[test]
    fn a_signature_that_does_not_load_is_named_and_other_files_are_not_read() {
        let root = env!("CARGO_MANIFEST_DIR");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("acme.yaml"),
            "id: acme\ninfo: { name: Acme, category: Test }\ndetect: { header: { name: server, regex: acme } }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("broken.yaml"), "id: [").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "id: [").unwrap();
        let args = super::libs::cli_args::CheckArgs {
            dir: dir.path().to_path_buf(),
            mappings: format!("{root}/data").into(),
            names: None,
        };
        let err = super::check(&args).unwrap_err();
        assert!(err.to_string().starts_with("1 problem(s)"), "{err}");
        std::fs::remove_file(dir.path().join("broken.yaml")).unwrap();
        super::check(&args).unwrap();
    }
}
