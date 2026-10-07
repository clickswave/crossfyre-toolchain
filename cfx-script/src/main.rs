//! Runs one .cfx script in an embedded Python interpreter.
//!
//! The node and the CLI used to embed Python themselves, through pyo3. That linked
//! them against the libpython of whichever machine built them, and the released
//! binaries named `libpython3.14.so.1.0`: the dynamic loader refused them on Debian 12
//! (Python 3.11), Ubuntu 22.04 (3.10) and 24.04 (3.12) before `main` ran, for every
//! user and every command, although only `.cfx` scripts need Python at all. So the
//! interpreter lives here, in its own process, and the node and the CLI start
//! anywhere; only a script needs a Python this binary can load.
//!
//! The protocol is small. The job arrives on stdin as one JSON object:
//!
//! ```json
//! {"node_id": "...", "job_id": "...", "script": "...", "targets": [["domain", "example.com"]],
//!  "toolchain_dir": "/home/user/.config/crossfyre"}
//! ```
//!
//! and every message the script produces goes to stdout as one JSON object per line,
//! in the shape the node publishes on its results subject:
//!
//! ```json
//! {"type": "result", "job_id": "...", "data": {...}}
//! {"type": "log", "job_id": "...", "message": "..."}
//! {"type": "completed", "job_id": "...", "code": 0}
//! ```
//!
//! stdout carries nothing else: the script's own `print()` output goes to stderr,
//! which the caller passes through. The last line is always a `completed`, and the
//! exit status says the same thing: 0 when the script finished, 1 when it raised,
//! 2 when the job itself could not be read.

mod runtime;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use runtime::cfxs::CfxMessage;
use serde::Deserialize;
use std::ffi::CString;
use std::io::{Read, Write};

#[derive(Deserialize)]
struct Job {
    node_id: String,
    job_id: String,
    script: String,
    #[serde(default)]
    targets: Vec<(String, String)>,
    /// The caller's toolchain directory, so engine ports come from the same
    /// config.toml the caller reads.
    #[serde(default)]
    toolchain_dir: Option<std::path::PathBuf>,
}

fn main() {
    let mut raw = String::new();
    let job: Job = match std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_str(&raw).map_err(|e| e.to_string()))
    {
        Ok(job) => job,
        Err(e) => {
            emit(&CfxMessage::Log {
                job_id: String::new(),
                message: format!("cfx-script: could not read the job on stdin: {e}"),
            });
            emit(&CfxMessage::Completed {
                job_id: String::new(),
                code: 2,
            });
            std::process::exit(2);
        }
    };
    if let Some(dir) = job.toolchain_dir.clone() {
        cfx_core::toolchain::config::set_toolchain_dir(dir);
    }
    std::process::exit(run(job));
}

/// Run the job, write every message to stdout, and return the exit status.
fn run(job: Job) -> i32 {
    let (tx, rx) = std::sync::mpsc::channel::<CfxMessage>();
    let job_id = job.job_id.clone();

    // Messages are written as they arrive, so a long scan's results reach the
    // control plane while it runs rather than all at once at the end.
    let writer = std::thread::spawn(move || {
        let mut finished = None;
        while let Ok(msg) = rx.recv() {
            if let CfxMessage::Completed { code, .. } = &msg {
                finished = Some(*code);
            }
            emit(&msg);
            if finished.is_some() {
                break;
            }
        }
        finished
    });

    // Kept so the writer can be told the job is over. A script that raises leaves a
    // traceback holding its frame, the frame holds the `server` object, and that
    // holds a clone of the sender, so the channel would never close on its own.
    let stopper = tx.clone();

    runtime::targets::inject(job.targets.clone());
    runtime::cfxs::inject(job.node_id.clone(), job.job_id.clone(), tx);
    runtime::extensions::inject_defaults();
    runtime::nodes::inject(vec![(job.node_id.clone(), "self".to_string())]);

    let outcome = run_python(&job.script);

    runtime::targets::clear();
    runtime::cfxs::clear();
    runtime::extensions::clear();
    runtime::nodes::clear();

    let code = match outcome {
        Ok(()) => 0,
        Err(message) => {
            let _ = stopper.send(CfxMessage::Log {
                job_id: job_id.clone(),
                message,
            });
            1
        }
    };
    // The script may have signalled completion itself. If it did not, the job is
    // finished now, and saying so is what stops the control plane showing it as
    // running forever.
    let _ = stopper.send(CfxMessage::Completed { job_id, code });
    drop(stopper);

    match writer.join() {
        Ok(Some(reported)) if reported != 0 && code == 0 => 1,
        _ => code,
    }
}

/// One message as one JSON line on stdout, flushed at once.
fn emit(msg: &CfxMessage) {
    let line = match msg {
        CfxMessage::Result { job_id, data } => {
            serde_json::json!({"type": "result", "job_id": job_id, "data": data})
        }
        CfxMessage::Log { job_id, message } => {
            serde_json::json!({"type": "log", "job_id": job_id, "message": message})
        }
        CfxMessage::Completed { job_id, code } => {
            serde_json::json!({"type": "completed", "job_id": job_id, "code": code})
        }
    };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Point the script's stdout at stderr, line-buffered.
///
/// stdout is the protocol, so a `print()` there would be read as a malformed
/// message. stderr reaches the operator: the node's log, or the terminal for
/// `crossfyre run`. Line buffering matters because the interpreter is never
/// finalised; with Python's default block buffering a script's output sat in a
/// buffer that was thrown away at exit, and appeared all at once if at all.
fn prepare_streams(py: Python<'_>) {
    let Ok(sys) = py.import("sys") else { return };
    if let Ok(stream) = sys.getattr("stderr") {
        let kwargs = PyDict::new(py);
        if kwargs.set_item("line_buffering", true).is_ok() {
            // Absent on a replaced stream that is not a TextIOWrapper; the
            // explicit flush in `flush_std` still covers that case.
            let _ = stream.call_method("reconfigure", (), Some(&kwargs));
        }
        let _ = sys.setattr("stdout", stream);
    }
}

/// Flush the interpreter's streams. Safe to call twice.
fn flush_std(py: Python<'_>) {
    let Ok(sys) = py.import("sys") else { return };
    for name in ["stdout", "stderr"] {
        if let Ok(stream) = sys.getattr(name) {
            let _ = stream.call_method0("flush");
        }
    }
}

/// Execute the script as `__main__`, then call its `run()` if it defines one.
fn run_python(script: &str) -> Result<(), String> {
    Python::attach(|py| {
        let result = (|| -> PyResult<()> {
            runtime::register_modules(py)?;
            prepare_streams(py);

            let globals = PyDict::new(py);
            globals.set_item("__name__", "__main__")?;
            let code = CString::new(script).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid script: {e}"))
            })?;
            py.run(&code, Some(&globals), None)?;

            if let Ok(Some(run_fn)) = globals.get_item("run") {
                run_fn.call0()?;
            }
            Ok(())
        })();

        // Flush whether the script succeeded or raised: output produced before an
        // exception is exactly the output needed to diagnose it.
        flush_std(py);
        result.map_err(|e| format!("Script error: {e}"))
    })
}
