//! .cfx scripts, run in the `cfx-script` helper process.
//!
//! Python used to be embedded here through pyo3, which linked every binary built on
//! this crate, the CLI and the node, against the build machine's own libpython. The
//! released binaries needed `libpython3.14.so.1.0` and the loader refused them on
//! Debian 12, Ubuntu 22.04 and Ubuntu 24.04 before `main` ran, for every command,
//! although only scripts need Python at all. The interpreter now lives in the
//! `cfx-script` binary (its main.rs documents the protocol). This module finds it,
//! hands it the job on stdin, and forwards each line it writes.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Everything needed to run a .cfx script.
pub struct JobContext {
    pub node_id: String,
    pub job_id: String,
    /// The raw .cfx script source code.
    pub script: String,
    /// (type, value) pairs injected as targets.
    pub targets: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum ExecutionResult {
    Completed { code: i32 },
    Error { message: String },
}

const HELPER: &str = "cfx-script";

/// The version of the protocol between the caller and the helper, sent as `protocol` in
/// every job. The helper refuses a job that names another and says why, so a node and a
/// cfx-script from releases that speak differently fail loudly instead of misreading
/// each other. Raise it whenever either side changes what the other reads.
pub const PROTOCOL_VERSION: u32 = 1;

/// The variable that hands the helper the caller's toolchain directory, so engine ports
/// come from the same config.toml. Not part of the job JSON, because a path need not be
/// UTF-8 and a JSON string must be: building the job with such a path in it panicked.
pub const TOOLCHAIN_DIR_ENV: &str = "CFX_SCRIPT_TOOLCHAIN_DIR";

/// How many of the helper's last stderr lines are kept to explain a failure.
const STDERR_TAIL: usize = 20;

/// How long the stderr reader may go on after the helper has exited before the job ends
/// without it. Everything the helper wrote is in the pipe by then, and the reader takes
/// it in well within this.
const STDERR_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Where the helper is: `CROSSFYRE_CFX_SCRIPT` when set, else beside this binary
/// (the installer puts it next to `node` and the CLI), else on PATH.
pub fn helper_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("CROSSFYRE_CFX_SCRIPT") {
        return Some(PathBuf::from(p));
    }
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(HELPER)))
        .filter(|p| p.is_file());
    if beside.is_some() {
        return beside;
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(HELPER))
            .find(|p| p.is_file())
    })
}

/// A line from the helper's stdout as a message, or `None` when it is not one.
///
/// Anything else on stdout is a bug in the helper or in something it loaded, and the
/// caller reports it as a log line rather than dropping it.
fn as_message(line: &str) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    match v.get("type").and_then(|t| t.as_str()) {
        Some("result" | "log" | "completed") => Some(v),
        _ => None,
    }
}

/// Read the next line into `buf`, as bytes and without its line ending. False at EOF or
/// on a read error.
async fn read_line(
    reader: &mut BufReader<impl tokio::io::AsyncRead + Unpin>,
    buf: &mut Vec<u8>,
) -> bool {
    buf.clear();
    match reader.read_until(b'\n', buf).await {
        Ok(0) | Err(_) => false,
        Ok(_) => {
            if buf.last() == Some(&b'\n') {
                buf.pop();
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
            }
            true
        }
    }
}

/// Why a helper that never said `completed` stopped, from its exit status and the
/// tail of what it wrote to stderr.
fn explain_exit(status: Option<std::process::ExitStatus>, tail: &[String]) -> String {
    let python = tail
        .iter()
        .find(|l| l.contains("libpython") || l.contains("error while loading shared libraries"));
    if let Some(line) = python {
        return format!(
            "cfx-script could not start: {line}. It runs .cfx scripts with the Python it was \
             built against; install that Python's shared library, or build cfx-script on \
             this machine. Nothing else in Crossfyre needs Python."
        );
    }
    let how = match status {
        Some(s) => format!("exited with {s}"),
        None => "stopped".to_string(),
    };
    match tail.last() {
        Some(last) => format!("cfx-script {how} before the script finished: {last}"),
        None => format!("cfx-script {how} before the script finished"),
    }
}

/// Run one job in the helper at `helper`, passing each message it writes to `on_message`
/// in order.
///
/// When the helper reports `completed` itself, that is the outcome. When it never does
/// (it is missing, cannot load Python, or dies), the returned `Error` says why and
/// `on_message` has seen nothing that ends the job, so the caller has to end it.
pub async fn run_helper(
    helper: &Path,
    ctx: &JobContext,
    toolchain_dir: Option<&Path>,
    mut on_message: impl FnMut(serde_json::Value),
) -> (ExecutionResult, bool) {
    let mut command = tokio::process::Command::new(helper);
    match toolchain_dir {
        Some(dir) => command.env(TOOLCHAIN_DIR_ENV, dir),
        None => command.env_remove(TOOLCHAIN_DIR_ENV),
    };
    let mut child = match command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                ExecutionResult::Error {
                    message: format!(
                        "cfx-script is not installed ({} not found). .cfx scripts run in that \
                         helper; put it next to this binary or on PATH, or point \
                         CROSSFYRE_CFX_SCRIPT at it.",
                        helper.display()
                    ),
                },
                false,
            );
        }
        Err(e) => {
            return (
                ExecutionResult::Error {
                    message: format!("could not start cfx-script at {}: {e}", helper.display()),
                },
                false,
            );
        }
    };

    // The helper's stderr is the script's own output: pass it through as it comes,
    // and keep the end of it in case it explains a failure. Read before the job is
    // written, so a helper that writes to stderr first can never block on a full pipe.
    //
    // Read to EOF whatever arrives. This used tokio's `lines()`, which ends with an
    // error at the first line that is not UTF-8, such as a Latin-1 header a tool
    // echoed. The reader stopped there and closed the pipe, the helper's next write to
    // stderr failed, and the script died of it.
    let tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
    let stderr_task = child.stderr.take().map(|stderr| {
        let tail = Arc::clone(&tail);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut buf = Vec::new();
            while read_line(&mut reader, &mut buf).await {
                let line = String::from_utf8_lossy(&buf).into_owned();
                eprintln!("{line}");
                let mut t = tail.lock().unwrap_or_else(|p| p.into_inner());
                if t.len() == STDERR_TAIL {
                    t.pop_front();
                }
                t.push_back(line);
            }
        })
    });

    let job = serde_json::json!({
        "protocol": PROTOCOL_VERSION,
        "node_id": ctx.node_id,
        "job_id": ctx.job_id,
        "script": ctx.script,
        "targets": ctx.targets,
    });
    if let Some(mut stdin) = child.stdin.take() {
        // A helper that dies before reading the job closes the pipe; that failure is
        // reported from its exit below, so the write error itself adds nothing.
        let _ = stdin.write_all(job.to_string().as_bytes()).await;
        let _ = stdin.shutdown().await;
    }

    let mut completed: Option<i32> = None;
    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let mut buf = Vec::new();
        while read_line(&mut reader, &mut buf).await {
            let line = String::from_utf8_lossy(&buf);
            if line.trim().is_empty() {
                continue;
            }
            // A line that is not UTF-8 cannot be a message. It is reported like any
            // other stray line, and reading goes on to the helper's `completed`.
            let parsed = std::str::from_utf8(&buf).ok().and_then(as_message);
            let msg = parsed.unwrap_or_else(|| {
                serde_json::json!({
                    "type": "log",
                    "job_id": ctx.job_id,
                    "message": format!("cfx-script wrote something that is not a message: {line}"),
                })
            });
            if msg["type"] == "completed" {
                completed = Some(msg["code"].as_i64().unwrap_or(1) as i32);
                on_message(msg);
                break;
            }
            on_message(msg);
        }
    }

    let status = child.wait().await.ok();
    if let Some(task) = stderr_task {
        // A process the script started in the background inherits the helper's stderr,
        // and the pipe stays open for as long as that process runs, so reading it to EOF
        // held the job until the process exited, or for good. After the grace the reader
        // is left running by itself, and still passes on whatever that process writes.
        let _ = tokio::time::timeout(STDERR_GRACE, task).await;
    }

    match completed {
        Some(0) => (ExecutionResult::Completed { code: 0 }, true),
        Some(code) => (
            ExecutionResult::Error {
                message: format!("the script failed with code {code}; its log says why"),
            },
            true,
        ),
        None => {
            let tail: Vec<String> = tail
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .cloned()
                .collect();
            (
                ExecutionResult::Error {
                    message: explain_exit(status, &tail),
                },
                false,
            )
        }
    }
}

/// Run a .cfx job from the control plane and publish what it produces on
/// `result_subject`.
///
/// Every job ends with exactly one `completed` on the subject: the helper's own, or,
/// when the helper never got that far, one this function publishes with code 1 after
/// a log line saying why. Without it the control plane shows the job running forever.
pub async fn execute_job(
    ctx: JobContext,
    publisher: async_nats::Client,
    result_subject: String,
) -> ExecutionResult {
    let Some(helper) = helper_path() else {
        let message = "cfx-script is not installed, so this node cannot run .cfx scripts. \
                       Put it next to the node binary or on PATH."
            .to_string();
        publish_failure(&publisher, &result_subject, &ctx.job_id, &message).await;
        return ExecutionResult::Error { message };
    };

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let publisher_for_drain = publisher.clone();
    let subject_for_drain = result_subject.clone();
    let drain = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = publisher_for_drain
                .publish(subject_for_drain.clone(), msg.to_string().into())
                .await;
        }
    });

    let toolchain_dir = crate::toolchain::config::get_toolchain_dir();
    let (result, ended) = run_helper(&helper, &ctx, Some(&toolchain_dir), |msg| {
        let _ = tx.send(msg);
    })
    .await;
    drop(tx);
    let _ = drain.await;

    if !ended {
        if let ExecutionResult::Error { message } = &result {
            publish_failure(&publisher, &result_subject, &ctx.job_id, message).await;
        }
    }
    result
}

/// A log line with the reason, then `completed` with code 1.
async fn publish_failure(
    publisher: &async_nats::Client,
    subject: &str,
    job_id: &str,
    message: &str,
) {
    for msg in [
        serde_json::json!({"type": "log", "job_id": job_id, "message": message}),
        serde_json::json!({"type": "completed", "job_id": job_id, "code": 1}),
    ] {
        let _ = publisher
            .publish(subject.to_string(), msg.to_string().into())
            .await;
    }
}

/// Run a .cfx script locally, without NATS, printing each message. Used by
/// `crossfyre run <file>`.
pub async fn execute_local(script_path: &str, targets: Vec<(String, String)>) -> ExecutionResult {
    let script = match std::fs::read_to_string(script_path) {
        Ok(s) => s,
        Err(e) => {
            return ExecutionResult::Error {
                message: format!("Cannot read '{script_path}': {e}"),
            };
        }
    };
    let Some(helper) = helper_path() else {
        return ExecutionResult::Error {
            message: "cfx-script is not installed. .cfx scripts run in that helper; put it \
                      next to this binary or on PATH, or point CROSSFYRE_CFX_SCRIPT at it."
                .to_string(),
        };
    };

    let ctx = JobContext {
        node_id: "local".to_string(),
        job_id: "local-test".to_string(),
        script,
        targets,
    };
    let toolchain_dir = crate::toolchain::config::get_toolchain_dir();
    let (result, _) = run_helper(&helper, &ctx, Some(&toolchain_dir), |msg| {
        let job = msg["job_id"].as_str().unwrap_or("?");
        match msg["type"].as_str() {
            Some("result") => println!("[result] job={job} data={}", msg["data"]),
            Some("log") => println!(
                "[log]    job={job} {}",
                msg["message"].as_str().unwrap_or("")
            ),
            Some("completed") => println!("[done]   job={job} code={}", msg["code"]),
            _ => {}
        }
    })
    .await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn ctx() -> JobContext {
        JobContext {
            node_id: "n1".into(),
            job_id: "j1".into(),
            script: "print('hi')".into(),
            targets: vec![("domain".into(), "example.com".into())],
        }
    }

    /// A stand-in helper: a shell script with the given body, in a fresh directory.
    fn fake_helper(name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cfx-helper-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cfx-script");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    async fn collect(helper: &Path) -> (ExecutionResult, bool, Vec<serde_json::Value>) {
        collect_with(helper, None).await
    }

    /// Run the helper and gather what it sends, trying the spawn again while it fails
    /// with ETXTBSY.
    ///
    /// Each test writes its fake helper and then executes it while other tests fork. A
    /// child forked while the file was open for writing holds that descriptor until it
    /// execs, and executing the file in that window fails with "Text file busy". The
    /// window closes once those children exec. A lock around the write and the spawn
    /// would not close it, because any test in this binary that forks opens it.
    async fn collect_with(
        helper: &Path,
        toolchain_dir: Option<&Path>,
    ) -> (ExecutionResult, bool, Vec<serde_json::Value>) {
        let busy = std::io::Error::from_raw_os_error(libc::ETXTBSY).to_string();
        for _ in 0..100 {
            let mut seen = Vec::new();
            let (r, ended) = run_helper(helper, &ctx(), toolchain_dir, |m| seen.push(m)).await;
            match &r {
                ExecutionResult::Error { message } if message.ends_with(&busy) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                _ => return (r, ended, seen),
            }
        }
        panic!("{} was still busy after a second", helper.display());
    }

    #[tokio::test]
    async fn messages_arrive_in_order_and_the_helpers_completed_ends_the_job() {
        let h = fake_helper(
            "ok",
            r#"cat >/dev/null
echo '{"type":"log","job_id":"j1","message":"start"}'
echo '{"type":"result","job_id":"j1","data":{"n":1}}'
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let (r, ended, seen) = collect(&h).await;
        assert!(matches!(r, ExecutionResult::Completed { code: 0 }), "{r:?}");
        assert!(ended);
        let types: Vec<&str> = seen.iter().map(|m| m["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["log", "result", "completed"]);
        assert_eq!(seen[1]["data"]["n"], 1);
    }

    #[tokio::test]
    async fn the_job_reaches_the_helper_on_stdin() {
        let h = fake_helper(
            "stdin",
            r#"job=$(cat)
case "$job" in *'"job_id":"j1"'*'"script":"print('"'"'hi'"'"')"'*) ok=yes;; *) ok=no;; esac
echo "{\"type\":\"log\",\"job_id\":\"j1\",\"message\":\"$ok\"}"
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let (_, _, seen) = collect(&h).await;
        assert_eq!(
            seen[0]["message"], "yes",
            "the helper did not get the job: {seen:?}"
        );
    }

    #[tokio::test]
    async fn the_job_names_the_protocol_it_speaks() {
        // The helper refuses a job from another protocol, so every job has to say which
        // one it speaks.
        let h = fake_helper(
            "protocol",
            r#"cat >"$(dirname "$0")/job.json"
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let (r, _, _) = collect(&h).await;
        assert!(matches!(r, ExecutionResult::Completed { code: 0 }), "{r:?}");
        let job: serde_json::Value =
            serde_json::from_slice(&std::fs::read(h.with_file_name("job.json")).unwrap()).unwrap();
        assert_eq!(job["protocol"], PROTOCOL_VERSION, "{job}");
    }

    #[tokio::test]
    async fn a_script_that_failed_is_an_error_the_helper_already_ended() {
        let h = fake_helper(
            "fail",
            r#"cat >/dev/null
echo '{"type":"log","job_id":"j1","message":"Script error: boom"}'
echo '{"type":"completed","job_id":"j1","code":1}'
exit 1"#,
        );
        let (r, ended, seen) = collect(&h).await;
        assert!(matches!(r, ExecutionResult::Error { .. }), "{r:?}");
        assert!(
            ended,
            "the helper sent completed, so the caller must not send another"
        );
        assert_eq!(seen.last().unwrap()["code"], 1);
    }

    #[tokio::test]
    async fn a_helper_that_dies_without_completed_leaves_the_caller_to_end_the_job() {
        let h = fake_helper("dies", "cat >/dev/null\necho 'something broke' >&2\nexit 3");
        let (r, ended, seen) = collect(&h).await;
        assert!(!ended);
        assert!(seen.is_empty());
        match r {
            ExecutionResult::Error { message } => {
                assert!(message.contains("before the script finished"), "{message}");
                assert!(message.contains("something broke"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_missing_libpython_is_named_as_such() {
        let h = fake_helper(
            "nopython",
            "cat >/dev/null\necho 'cfx-script: error while loading shared libraries: libpython3.11.so.1.0: cannot open shared object file' >&2\nexit 127",
        );
        let (r, ended, _) = collect(&h).await;
        assert!(!ended);
        match r {
            ExecutionResult::Error { message } => {
                assert!(message.contains("libpython3.11"), "{message}");
                assert!(
                    message.contains("Nothing else in Crossfyre needs Python"),
                    "{message}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_missing_helper_says_it_is_not_installed() {
        let gone = std::env::temp_dir().join("cfx-helper-that-is-not-there/cfx-script");
        let (r, ended, _) = collect(&gone).await;
        assert!(!ended);
        match r {
            ExecutionResult::Error { message } => {
                assert!(message.contains("not installed"), "{message}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_stderr_line_that_is_not_utf8_does_not_stop_the_reader() {
        // A tool's Latin-1 output, such as a server header that curl -v echoes. The
        // reader used to stop at that line and close the pipe, so the helper's next
        // write to stderr failed and the script died of it.
        let h = fake_helper(
            "latin1-stderr",
            r#"cat >/dev/null
printf 'Server: caf\351\n' >&2
sleep 0.2
echo 'progress: 50%' >&2
echo '{"type":"result","job_id":"j1","data":{"n":2}}'
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let (r, ended, seen) = collect(&h).await;
        assert!(matches!(r, ExecutionResult::Completed { code: 0 }), "{r:?}");
        assert!(ended);
        let types: Vec<&str> = seen.iter().map(|m| m["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["result", "completed"]);
    }

    #[tokio::test]
    async fn a_stdout_line_that_is_not_utf8_is_a_stray_line_and_reading_goes_on() {
        let h = fake_helper(
            "latin1-stdout",
            r#"cat >/dev/null
printf 'title: caf\351\n'
echo '{"type":"result","job_id":"j1","data":{"n":2}}'
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let (r, ended, seen) = collect(&h).await;
        assert!(matches!(r, ExecutionResult::Completed { code: 0 }), "{r:?}");
        assert!(ended);
        let types: Vec<&str> = seen.iter().map(|m| m["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["log", "result", "completed"]);
        let stray = seen[0]["message"].as_str().unwrap();
        assert!(stray.contains("title: caf\u{fffd}"), "{stray}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_toolchain_dir_that_is_not_utf8_reaches_the_helper_unchanged() {
        // A home directory need not be UTF-8. Building the job JSON with such a path in
        // it panicked, and the job task died before it published anything.
        use std::os::unix::ffi::OsStrExt;
        let dir = Path::new(std::ffi::OsStr::from_bytes(
            b"/home/jos\xe9/.config/crossfyre",
        ));
        let h = fake_helper(
            "nonutf8-dir",
            r#"cat >/dev/null
want=$(printf '/home/jos\351/.config/crossfyre')
[ "$CFX_SCRIPT_TOOLCHAIN_DIR" = "$want" ] && got=yes || got=no
echo "{\"type\":\"log\",\"job_id\":\"j1\",\"message\":\"$got\"}"
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let (r, ended, seen) = collect_with(&h, Some(dir)).await;
        assert!(matches!(r, ExecutionResult::Completed { code: 0 }), "{r:?}");
        assert!(ended);
        assert_eq!(
            seen[0]["message"], "yes",
            "the helper did not get the directory: {seen:?}"
        );
    }

    /// Stop the background process a fake helper left, whose pid it wrote beside itself.
    fn stop_holder(helper: &Path) {
        if let Ok(pid) = std::fs::read_to_string(helper.with_file_name("holder.pid")) {
            let _ = std::process::Command::new("kill").arg(pid.trim()).status();
        }
    }

    #[tokio::test]
    async fn a_process_left_running_on_the_helpers_stderr_does_not_hold_up_the_job() {
        // A script's tool started in the background inherits the helper's stderr, and
        // holds the pipe open for as long as it runs. The caller read that pipe to EOF
        // after the helper exited, so the job waited for the tool.
        let h = fake_helper(
            "holder-ok",
            r#"cat >/dev/null
sleep 20 >/dev/null &
echo $! >"$(dirname "$0")/holder.pid"
echo '{"type":"result","job_id":"j1","data":{"n":1}}'
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let started = std::time::Instant::now();
        let (r, ended, seen) = collect(&h).await;
        let took = started.elapsed();
        stop_holder(&h);
        assert!(matches!(r, ExecutionResult::Completed { code: 0 }), "{r:?}");
        assert!(ended);
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(took < std::time::Duration::from_secs(10), "took {took:?}");
    }

    #[tokio::test]
    async fn a_helper_that_dies_with_a_process_on_its_stderr_still_says_why() {
        // The same, for a helper that never sent `completed`: what it wrote before it
        // exited still explains the failure.
        let h = fake_helper(
            "holder-dies",
            r#"cat >/dev/null
echo 'something broke' >&2
sleep 20 >/dev/null &
echo $! >"$(dirname "$0")/holder.pid"
exit 3"#,
        );
        let started = std::time::Instant::now();
        let (r, ended, _) = collect(&h).await;
        let took = started.elapsed();
        stop_holder(&h);
        assert!(!ended);
        match r {
            ExecutionResult::Error { message } => {
                assert!(message.contains("something broke"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        assert!(took < std::time::Duration::from_secs(10), "took {took:?}");
    }

    #[tokio::test]
    async fn stray_stdout_is_reported_as_a_log_line_not_dropped() {
        let h = fake_helper(
            "stray",
            r#"cat >/dev/null
echo 'not json'
echo '{"type":"completed","job_id":"j1","code":0}'"#,
        );
        let (_, _, seen) = collect(&h).await;
        assert_eq!(seen[0]["type"], "log");
        assert!(seen[0]["message"].as_str().unwrap().contains("not json"));
    }
}
