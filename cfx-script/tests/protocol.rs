//! The helper against a real interpreter: what a script does, as the node and the CLI
//! will read it.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

struct Run {
    status: i32,
    messages: Vec<serde_json::Value>,
    stderr: String,
}

/// How long a helper may run before the test kills it and fails.
const LIMIT: Duration = Duration::from_secs(60);

/// The limit for a test whose script would keep a helper running for good if the helper
/// waited for the wrong thing. Each of these runs in well under a second when it passes.
const HANG: Duration = Duration::from_secs(15);

fn run(stdin: &str) -> Run {
    run_with_env(stdin, &[], LIMIT)
}

fn run_within(stdin: &str, limit: Duration) -> Run {
    run_with_env(stdin, &[], limit)
}

fn run_with_env(stdin: &str, env: &[(&str, &std::ffi::OsStr)], limit: Duration) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cfx-script"))
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cfx-script starts");
    // A helper that waits for something that never happens would hang the whole run, so
    // it is killed after `limit`. The child is not reaped until wait_with_output returns,
    // so its pid cannot have been reused when the kill is sent.
    let pid = child.id().to_string();
    let (done, waiting) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        let late = waiting.recv_timeout(limit) == Err(std::sync::mpsc::RecvTimeoutError::Timeout);
        if late {
            let _ = Command::new("kill").args(["-KILL", &pid]).status();
        }
        late
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    drop(done);
    assert!(
        !watchdog.join().unwrap(),
        "cfx-script was still running after {limit:?} and was killed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Lossy, so that a byte that is not UTF-8 fails the check below and names the line it
    // was in, rather than failing here with only its offset.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let messages = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not a message: {l:?}: {e}")))
        .collect();
    Run {
        status: out.status.code().unwrap_or(-1),
        messages,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn job(script: &str) -> String {
    serde_json::json!({
        "protocol": cfx_core::executor::PROTOCOL_VERSION,
        "node_id": "n1",
        "job_id": "j1",
        "script": script,
        "targets": [["domain", "example.com"]],
    })
    .to_string()
}

/// A job as `job` builds it, but naming `protocol`, or no protocol at all.
fn job_speaking(script: &str, protocol: Option<u64>) -> String {
    let mut job: serde_json::Value = serde_json::from_str(&job(script)).unwrap();
    match protocol {
        Some(p) => job["protocol"] = p.into(),
        None => {
            job.as_object_mut().unwrap().remove("protocol");
        }
    }
    job.to_string()
}

fn types(r: &Run) -> Vec<&str> {
    r.messages
        .iter()
        .map(|m| m["type"].as_str().unwrap())
        .collect()
}

#[test]
fn results_logs_and_completion_come_back_as_messages_and_print_goes_to_stderr() {
    let r = run(&job(r#"
import cfxs, targets
def run():
    print("hello from the script")
    s = cfxs.connect()
    s.log("starting")
    s.send_result({"targets": [t.value for t in targets.get_all()]})
    s.signal.completed(0)
"#));
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["log", "result", "completed"]);
    assert_eq!(r.messages[1]["data"]["targets"][0], "example.com");
    assert_eq!(r.messages[2]["code"], 0);
    assert!(r.messages.iter().all(|m| m["job_id"] == "j1"));
    assert!(
        r.stderr.contains("hello from the script"),
        "print() should reach stderr: {}",
        r.stderr
    );
}

#[test]
fn a_job_from_another_protocol_is_refused_with_code_two_and_says_so() {
    // A node and a helper from releases that speak differently. The script must not run:
    // what it would be handed, and how its messages would be read, are not what it
    // was written for.
    let r = run(&job_speaking("print('ran')\n", Some(999)));
    assert_eq!(r.status, 2, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["log", "completed"]);
    assert_eq!(r.messages[1]["code"], 2);
    let said = r.messages[0]["message"].as_str().unwrap();
    assert!(said.contains("protocol 999"), "{said}");
    assert!(said.contains("crossfyre update"), "{said}");
    assert!(!r.stderr.contains("ran"), "the script ran: {}", r.stderr);
}

#[test]
fn a_job_that_names_no_protocol_is_refused_with_code_two_and_says_so() {
    let r = run(&job_speaking("print('ran')\n", None));
    assert_eq!(r.status, 2, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["log", "completed"]);
    let said = r.messages[0]["message"].as_str().unwrap();
    assert!(said.contains("names no protocol"), "{said}");
    assert!(!r.stderr.contains("ran"), "the script ran: {}", r.stderr);
}

#[test]
fn what_a_script_writes_to_fd_1_goes_to_stderr_and_never_among_the_messages() {
    // Everything here inherits or wraps fd 1: a tool started without capture_output,
    // os.system, sys.__stdout__ and a raw write. A tool's output with no newline used to
    // be glued onto the next message, and a byte that is not UTF-8 ended the reader.
    let r = run(&job(r#"
import cfxs, os, subprocess, sys
def run():
    s = cfxs.connect()
    subprocess.run(["printf", "scanning 3 hosts..."])
    s.send_result({"host": "a"})
    os.system("printf done")
    sys.__stdout__.write("from sys.__stdout__\n")
    sys.__stdout__.flush()
    os.write(1, b"straight to fd 1\n")
    subprocess.run(["printf", "title: caf\\351\\n"])
    s.send_result({"host": "b"})
"#));
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["result", "result", "completed"]);
    assert_eq!(r.messages[0]["data"]["host"], "a");
    assert_eq!(r.messages[1]["data"]["host"], "b");
    assert_eq!(r.messages[2]["code"], 0);
    for text in [
        "scanning 3 hosts...",
        "done",
        "from sys.__stdout__",
        "straight to fd 1",
        "title: caf\u{fffd}",
    ] {
        assert!(
            r.stderr.contains(text),
            "{text:?} should reach stderr: {}",
            r.stderr
        );
    }
}

#[test]
fn a_child_process_inherits_no_descriptor_but_0_1_and_2() {
    // The messages travel on a descriptor of their own, and it must close on exec. A child
    // that held it could write among the messages, and would hold the pipe open after the
    // helper exits.
    let r = run(&job(r#"
import cfxs, fcntl, os
def run():
    held = []
    for name in os.listdir("/dev/fd"):
        fd = int(name)
        try:
            inherited = not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        except OSError:
            continue  # the directory listing's own descriptor, closed by now
        if fd > 2 and inherited:
            held.append(fd)
    cfxs.connect().send_result({"inherited": held})
"#));
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["result", "completed"]);
    assert_eq!(r.messages[0]["data"]["inherited"], serde_json::json!([]));
}

#[cfg(unix)]
#[test]
fn the_toolchain_dir_comes_from_the_environment_even_when_it_is_not_utf8() {
    // JSON cannot carry a path that is not UTF-8, so the directory arrives in the
    // environment. The config.toml there moves mach to 5999, and a script sees it.
    use std::os::unix::ffi::OsStrExt;
    let base = std::env::temp_dir().join(format!("cfx-script-dir-{}", std::process::id()));
    let dir = base.join(std::ffi::OsStr::from_bytes(b"jos\xe9"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        "[postgres]\nhost = \"localhost\"\nport = 4440\nuser = \"postgres\"\n\
         db_name = \"crossfyre\"\n\n[container]\n\n[extensions]\nmach = 5999\n",
    )
    .unwrap();
    let r = run_with_env(
        &job("import cfxs, extensions\ndef run():\n    \
             cfxs.connect().send_result({'port': extensions.get('mach').port})\n"),
        &[("CFX_SCRIPT_TOOLCHAIN_DIR", dir.as_os_str())],
        LIMIT,
    );
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["result", "completed"]);
    assert_eq!(r.messages[0]["data"]["port"], 5999);
}

#[test]
fn a_script_that_never_signals_still_ends_with_completed() {
    let r = run(&job("x = 1 + 1\n"));
    assert_eq!(r.status, 0);
    assert_eq!(types(&r), ["completed"]);
    assert_eq!(r.messages[0]["code"], 0);
}

#[test]
fn a_script_that_raises_logs_why_and_completes_with_code_one() {
    let r = run(&job("def run():\n    raise ValueError('boom')\n"));
    assert_eq!(r.status, 1);
    assert_eq!(types(&r), ["log", "completed"]);
    let why = r.messages[0]["message"].as_str().unwrap();
    assert!(why.contains("boom"), "{why}");
    assert_eq!(r.messages[1]["code"], 1);
}

#[test]
fn a_raise_after_a_server_object_exists_does_not_hang() {
    // The traceback keeps the frame, the frame keeps `s`, and `s` keeps a sender: the
    // case that used to hang the runner forever.
    let r = run(&job(
        "import cfxs\ndef run():\n    s = cfxs.connect()\n    s.log('about to fail')\n    raise RuntimeError('late')\n",
    ));
    assert_eq!(r.status, 1);
    assert_eq!(types(&r), ["log", "log", "completed"]);
}

#[test]
fn threads_still_running_when_run_returns_finish_before_the_job_ends() {
    // python3 waits for non-daemon threads before it exits, and so must the helper. The
    // last thread's own `completed` is the one that ends the job.
    let r = run(&job(r#"
import cfxs, threading, time
def work(s, i):
    time.sleep(0.1 * (i + 1))
    s.send_result({"i": i})
    if i == 2:
        s.signal.completed(4)
def run():
    s = cfxs.connect()
    for i in range(3):
        threading.Thread(target=work, args=(s, i)).start()
"#));
    assert_eq!(types(&r), ["result", "result", "result", "completed"]);
    let order: Vec<i64> = r.messages[..3]
        .iter()
        .map(|m| m["data"]["i"].as_i64().unwrap())
        .collect();
    assert_eq!(order, [0, 1, 2]);
    assert_eq!(r.messages[3]["code"], 4, "the script's own completed");
    assert_eq!(r.status, 1, "a script that reported failure exits 1");
}

#[test]
fn a_thread_pool_left_running_finishes_its_work_before_the_job_ends() {
    // The pool is never shut down and stays referenced, so its idle workers wait on
    // their queue until interpreter shutdown tells them to stop. Joining the threads
    // without that step would wait forever.
    let r = run(&job(r#"
import cfxs, time
from concurrent.futures import ThreadPoolExecutor
pool = ThreadPoolExecutor(2)
def work(s, i):
    time.sleep(0.05 * (i + 1))
    s.send_result({"i": i})
def run():
    s = cfxs.connect()
    for i in range(3):
        pool.submit(work, s, i)
"#));
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["result", "result", "result", "completed"]);
    assert_eq!(r.messages[3]["code"], 0);
}

#[test]
fn a_script_that_raises_fails_at_once_and_its_threads_are_not_waited_for() {
    // The raise skips the `None` that would stop the consumer, as a raise usually skips
    // whatever stops a script's threads. Waiting for them kept the failed job running
    // for good, with no `completed` at all.
    let r = run_within(
        &job(r#"
import cfxs, queue, threading
q = queue.Queue()
def consume():
    while q.get() is not None:
        pass
def run():
    cfxs.connect()
    threading.Thread(target=consume).start()
    q.put("example.com")
    raise ValueError("bad target")
    q.put(None)
"#),
        HANG,
    );
    assert_eq!(r.status, 1, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["log", "completed"]);
    let why = r.messages[0]["message"].as_str().unwrap();
    assert!(why.contains("bad target"), "{why}");
    assert_eq!(r.messages[1]["code"], 1);
}

#[test]
fn a_thread_that_never_finishes_does_not_hold_a_job_the_script_already_completed() {
    // Once `completed` is out the job is over, and nothing a thread sends afterwards
    // reaches anyone. Waiting for this one kept the helper running for good.
    let r = run_within(
        &job(r#"
import cfxs, threading
def run():
    threading.Thread(target=threading.Event().wait).start()
    s = cfxs.connect()
    s.send_result({"n": 1})
    s.signal.completed(0)
"#),
        HANG,
    );
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["result", "completed"]);
    assert_eq!(r.messages[1]["code"], 0);
}

#[test]
fn a_completed_sent_while_the_helper_waits_for_threads_ends_the_job() {
    // `run()` returns with two threads left. One finishes the job; the other waits for
    // something that never happens, and the helper must not wait for it after that.
    let r = run_within(
        &job(r#"
import cfxs, threading, time
def finish(s):
    time.sleep(0.2)
    s.send_result({"n": 1})
    s.signal.completed(3)
def run():
    s = cfxs.connect()
    threading.Thread(target=threading.Event().wait).start()
    threading.Thread(target=finish, args=(s,)).start()
"#),
        HANG,
    );
    assert_eq!(types(&r), ["result", "completed"], "stderr: {}", r.stderr);
    assert_eq!(r.messages[1]["code"], 3, "the script's own completed");
    assert_eq!(r.status, 1, "a script that reported failure exits 1");
}

#[test]
fn a_script_that_closes_the_message_descriptor_is_told_so_and_the_helper_does_not_crash() {
    // A script can close descriptors it did not open, and the helper's message pipe is
    // one of them. Nothing more can be reported after that, and the helper says why. It
    // used to abort as it closed the pipe a second time on the way out.
    let r = run_within(
        &job(r#"
import cfxs, os, time
def run():
    s = cfxs.connect()
    s.send_result({"n": 1})
    time.sleep(0.2)
    os.closerange(3, 64)
    s.send_result({"n": 2})
"#),
        HANG,
    );
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["result"]);
    assert_eq!(r.messages[0]["data"]["n"], 1);
    assert!(
        r.stderr.contains("the script closed fd 3"),
        "stderr: {}",
        r.stderr
    );
}

#[test]
fn a_file_the_script_opens_on_the_message_descriptor_gets_no_messages() {
    // After closerange, the next file the script opens takes the number the message pipe
    // had. The helper wrote the job's messages into that file.
    let path = std::env::temp_dir().join(format!("cfx-script-notes-{}", std::process::id()));
    let r = run_within(
        &job(&format!(
            r#"
import cfxs, os, sys, time
def run():
    s = cfxs.connect()
    os.closerange(3, 64)
    with open({path:?}, "w") as f:
        print("notes are on fd", f.fileno(), file=sys.stderr)
        s.send_result({{"n": 1}})
        time.sleep(0.2)
        f.write("notes\n")
"#,
            path = path.to_str().unwrap()
        )),
        HANG,
    );
    let notes = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    assert!(
        r.stderr.contains("notes are on fd 3"),
        "the file did not get the pipe's number, so this proves nothing: {}",
        r.stderr
    );
    assert_eq!(notes, "notes\n", "stderr: {}", r.stderr);
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert!(r.messages.is_empty(), "{:?}", r.messages);
}

#[test]
fn a_daemon_thread_is_not_waited_for() {
    // As at interpreter exit: a daemon thread is abandoned, never joined.
    let r = run(&job(r#"
import threading, time
def forever():
    while True:
        time.sleep(1)
def run():
    threading.Thread(target=forever, daemon=True).start()
"#));
    assert_eq!(r.status, 0, "stderr: {}", r.stderr);
    assert_eq!(types(&r), ["completed"]);
}

#[test]
fn only_one_completed_when_the_script_signals_and_then_returns() {
    let r = run(&job(
        "import cfxs\ndef run():\n    cfxs.connect().signal.completed(0)\n",
    ));
    assert_eq!(types(&r), ["completed"]);
}

#[test]
fn a_job_that_is_not_json_is_refused_with_code_two() {
    let r = run("this is not a job");
    assert_eq!(r.status, 2);
    assert_eq!(types(&r), ["log", "completed"]);
    assert_eq!(r.messages[1]["code"], 2);
}
