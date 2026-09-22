use crate::cfx_runtime;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::ffi::CString;

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

/// Put the interpreter's stdout and stderr in line-buffered mode.
///
/// The embedded interpreter is never finalised, so Python's default block
/// buffering means a script's `print()` output sits in a buffer that is thrown
/// away when the process exits. Every `print()` in a .cfx script was silently
/// discarded, including the ones in the shipped examples, unless the author
/// happened to call `sys.stdout.flush()` by hand.
///
/// Line buffering also makes output appear *while* a scan runs rather than all
/// at once at the end, which is the difference between watching progress and
/// staring at nothing for twenty seconds.
fn set_line_buffered(py: Python<'_>) {
    let Ok(sys) = py.import("sys") else { return };
    for name in ["stdout", "stderr"] {
        if let Ok(stream) = sys.getattr(name) {
            let kwargs = PyDict::new(py);
            if kwargs.set_item("line_buffering", true).is_ok() {
                // Absent on a replaced stream that is not a TextIOWrapper; the
                // explicit flush in `flush_std` still covers that case.
                let _ = stream.call_method("reconfigure", (), Some(&kwargs));
            }
        }
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

/// Run Python with injected context, execute the script, call run() if defined.
fn run_python(ctx: &JobContext) -> PyResult<()> {
    Python::attach(|py| {
        cfx_runtime::register_modules(py)?;
        set_line_buffered(py);

        let result = (|| -> PyResult<()> {
            let globals = PyDict::new(py);
            globals.set_item("__name__", "__main__")?;

            let code = CString::new(ctx.script.as_str()).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid script: {e}"))
            })?;
            py.run(&code, Some(&globals), None)?;

            // Call run() if it exists
            if let Ok(Some(run_fn)) = globals.get_item("run") {
                run_fn.call0()?;
            }

            Ok(())
        })();

        // Flush whether the script succeeded or raised: output produced before
        // an exception is exactly the output you need to diagnose it.
        flush_std(py);
        result
    })
}

/// Execute a .cfx script inside an embedded Python interpreter.
///
/// Results stream back through the returned receiver.  The function
/// blocks on `spawn_blocking` so the caller can `.await` it from the
/// async runtime without holding the GIL.
pub async fn execute_job(
    ctx: JobContext,
    publisher: async_nats::Client,
    result_subject: String,
) -> ExecutionResult {
    let (tx, rx) = std::sync::mpsc::channel::<cfx_runtime::cfxs::CfxMessage>();

    // ── Drain channel → NATS in a background tokio task ──────────────
    let drain = tokio::spawn(async move {
        while let Ok(msg) = rx.recv() {
            let payload = match &msg {
                cfx_runtime::cfxs::CfxMessage::Result { job_id, data } => {
                    serde_json::json!({
                        "type": "result",
                        "job_id": job_id,
                        "data": data,
                    })
                }
                cfx_runtime::cfxs::CfxMessage::Log { job_id, message } => {
                    serde_json::json!({
                        "type": "log",
                        "job_id": job_id,
                        "message": message,
                    })
                }
                cfx_runtime::cfxs::CfxMessage::Completed { job_id, code } => {
                    let p = serde_json::json!({
                        "type": "completed",
                        "job_id": job_id,
                        "code": code,
                    });
                    let _ = publisher
                        .publish(result_subject.clone(), p.to_string().into())
                        .await;
                    return;
                }
            };
            let _ = publisher
                .publish(result_subject.clone(), payload.to_string().into())
                .await;
        }
    });

    // Kept so the drain task can be released deterministically when the script
    // fails. See the note in `execute_local`: a raised exception keeps a Python
    // traceback alive, which keeps a clone of this sender alive, so the channel
    // never closes on its own. In this path the consequence is worse than a
    // hung CLI: no `completed` is ever published, so the control plane sees the
    // job running forever and the node leaks the blocking task.
    let stopper = tx.clone();
    let stopper_job_id = ctx.job_id.clone();

    // ── Run Python in a blocking thread ──────────────────────────────
    let handle = tokio::task::spawn_blocking(move || -> ExecutionResult {
        cfx_runtime::targets::inject(ctx.targets.clone());
        cfx_runtime::cfxs::inject(ctx.node_id.clone(), ctx.job_id.clone(), tx);
        cfx_runtime::extensions::inject_defaults();
        cfx_runtime::nodes::inject(vec![(ctx.node_id.clone(), "self".to_string())]);

        let result = run_python(&ctx);

        // Cleanup statics regardless of outcome
        cfx_runtime::targets::clear();
        cfx_runtime::cfxs::clear();
        cfx_runtime::extensions::clear();
        cfx_runtime::nodes::clear();

        match result {
            Ok(()) => ExecutionResult::Completed { code: 0 },
            Err(e) => ExecutionResult::Error {
                message: format!("Script error: {e}"),
            },
        }
    });

    let exec_result = match handle.await {
        Ok(r) => r,
        Err(e) => ExecutionResult::Error {
            message: format!("Task panicked: {e}"),
        },
    };

    // Tell the control plane the job failed, then release the drain task.
    if let ExecutionResult::Error { message } = &exec_result {
        let _ = stopper.send(cfx_runtime::cfxs::CfxMessage::Log {
            job_id: stopper_job_id.clone(),
            message: message.clone(),
        });
        let _ = stopper.send(cfx_runtime::cfxs::CfxMessage::Completed {
            job_id: stopper_job_id,
            code: 1,
        });
    }
    drop(stopper);

    // The drain task exits on `completed`, or once every sender is dropped.
    let _ = drain.await;
    exec_result
}

/// Convenience: execute a .cfx script locally without NATS.
/// Prints results to stdout.  Used for `cfx_controller node --run <file>`.
pub async fn execute_local(script_path: &str, targets: Vec<(String, String)>) -> ExecutionResult {
    let script = match std::fs::read_to_string(script_path) {
        Ok(s) => s,
        Err(e) => {
            return ExecutionResult::Error {
                message: format!("Cannot read '{script_path}': {e}"),
            };
        }
    };

    let (tx, rx) = std::sync::mpsc::channel::<cfx_runtime::cfxs::CfxMessage>();
    // Kept so the printer can be stopped deterministically. Relying on the
    // channel closing is not enough: a script that raises leaves a Python
    // traceback holding the frame, the frame holds the `server` object, and
    // that object holds a clone of this sender. The channel therefore never
    // closes and the runner hangs forever on a script error, which is how a
    // simple typo used to produce no output and no exit.
    let stopper = tx.clone();

    // Print messages to stdout instead of publishing to NATS.
    let printer = tokio::spawn(async move {
        while let Ok(msg) = rx.recv() {
            match msg {
                cfx_runtime::cfxs::CfxMessage::Result { job_id, data } => {
                    println!("[result] job={job_id} data={data}");
                }
                cfx_runtime::cfxs::CfxMessage::Log { job_id, message } => {
                    println!("[log]    job={job_id} {message}");
                }
                cfx_runtime::cfxs::CfxMessage::Completed { job_id, code } => {
                    println!("[done]   job={job_id} code={code}");
                    return;
                }
            }
        }
    });

    let ctx = JobContext {
        node_id: "local".to_string(),
        job_id: "local-test".to_string(),
        script,
        targets,
    };

    let handle = tokio::task::spawn_blocking(move || -> ExecutionResult {
        cfx_runtime::targets::inject(ctx.targets.clone());
        cfx_runtime::cfxs::inject(ctx.node_id.clone(), ctx.job_id.clone(), tx);
        cfx_runtime::extensions::inject_defaults();
        cfx_runtime::nodes::inject(vec![(ctx.node_id.clone(), "self".to_string())]);

        let result = run_python(&ctx);

        cfx_runtime::targets::clear();
        cfx_runtime::cfxs::clear();
        cfx_runtime::extensions::clear();
        cfx_runtime::nodes::clear();

        match result {
            Ok(()) => ExecutionResult::Completed { code: 0 },
            Err(e) => ExecutionResult::Error {
                message: format!("Script error: {e}"),
            },
        }
    });

    let exec_result = match handle.await {
        Ok(r) => r,
        Err(e) => ExecutionResult::Error {
            message: format!("Task panicked: {e}"),
        },
    };

    // Report the failure where the operator will see it, then release the
    // printer. Without the explicit Completed the task would wait on a channel
    // the interpreter is still holding open.
    if let ExecutionResult::Error { message } = &exec_result {
        eprintln!("[error]  job=local-test {message}");
        let _ = stopper.send(cfx_runtime::cfxs::CfxMessage::Completed {
            job_id: "local-test".to_string(),
            code: 1,
        });
    }
    drop(stopper);

    let _ = printer.await;
    exec_result
}
