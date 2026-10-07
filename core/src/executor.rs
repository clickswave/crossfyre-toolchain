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

/// How many of the helper's last stderr lines are kept to explain a failure.
const STDERR_TAIL: usize = 20;

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
    let mut child = match tokio::process::Command::new(helper)
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
    let tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
    let stderr_task = child.stderr.take().map(|stderr| {
        let tail = Arc::clone(&tail);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
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
        "node_id": ctx.node_id,
        "job_id": ctx.job_id,
        "script": ctx.script,
        "targets": ctx.targets,
        "toolchain_dir": toolchain_dir,
    });
    if let Some(mut stdin) = child.stdin.take() {
        // A helper that dies before reading the job closes the pipe; that failure is
        // reported from its exit below, so the write error itself adds nothing.
        let _ = stdin.write_all(job.to_string().as_bytes()).await;
        let _ = stdin.shutdown().await;
    }

    let mut completed: Option<i32> = None;
    if let Some(stdout) = child.stdout.take() {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let msg = as_message(&line).unwrap_or_else(|| {
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
        let _ = task.await;
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
        let mut seen = Vec::new();
        let (r, ended) = run_helper(helper, &ctx(), None, |m| seen.push(m)).await;
        (r, ended, seen)
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
