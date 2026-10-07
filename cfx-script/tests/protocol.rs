//! The helper against a real interpreter: what a script does, as the node and the CLI
//! will read it.

use std::io::Write;
use std::process::{Command, Stdio};

struct Run {
    status: i32,
    messages: Vec<serde_json::Value>,
    stderr: String,
}

fn run(stdin: &str) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cfx-script"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cfx-script starts");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
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
        "node_id": "n1",
        "job_id": "j1",
        "script": script,
        "targets": [["domain", "example.com"]],
    })
    .to_string()
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
