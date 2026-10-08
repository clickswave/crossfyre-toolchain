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
//! {"protocol": 1, "node_id": "...", "job_id": "...", "script": "...",
//!  "targets": [["domain", "example.com"]]}
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
//! `protocol` is `cfx_core::executor::PROTOCOL_VERSION` in the build that sent the job.
//! A job that names another is refused with a message saying so: a node and a
//! cfx-script from releases that speak differently would otherwise misread each
//! other. The caller's toolchain directory, where engine ports are configured, comes
//! in the environment as `CFX_SCRIPT_TOOLCHAIN_DIR`, because a path need not be UTF-8
//! and a JSON string must be.
//!
//! stdout carries nothing else. Before Python starts, the helper moves the pipe it was
//! given as stdout to a descriptor of its own and points fd 1 at stderr, so `print()`,
//! `sys.__stdout__`, C extensions and every process the script starts write to stderr,
//! which the caller passes through. The last line is always a `completed`, and the
//! exit status says the same thing: 0 when the script finished, 1 when it raised,
//! 2 when the job could not be read or names another protocol.

mod runtime;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use runtime::cfxs::CfxMessage;
use serde::Deserialize;
use std::ffi::CString;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]
struct Job {
    node_id: String,
    job_id: String,
    script: String,
    #[serde(default)]
    targets: Vec<(String, String)>,
}

fn main() {
    let mut pipe = Messages::new(take_stdout());
    let job = match read_job() {
        Ok(job) => job,
        Err(message) => {
            pipe.send(&CfxMessage::Log {
                job_id: String::new(),
                message,
            });
            pipe.send(&CfxMessage::Completed {
                job_id: String::new(),
                code: 2,
            });
            std::process::exit(2);
        }
    };
    // The caller's toolchain directory, so engine ports come from the same config.toml
    // the caller reads. Read as an OsStr: it need not be UTF-8.
    if let Some(dir) =
        std::env::var_os(cfx_core::executor::TOOLCHAIN_DIR_ENV).filter(|dir| !dir.is_empty())
    {
        cfx_core::toolchain::config::set_toolchain_dir(dir.into());
    }
    std::process::exit(run(job, pipe));
}

/// The job on stdin, or why it cannot be run.
///
/// The protocol version is checked before any other field is read, because in another
/// protocol the fields may mean something else.
fn read_job() -> Result<Job, String> {
    let unreadable = |e: String| format!("cfx-script: could not read the job on stdin: {e}");
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| unreadable(e.to_string()))?;
    let job: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| unreadable(e.to_string()))?;
    let ours = cfx_core::executor::PROTOCOL_VERSION;
    match job.get("protocol") {
        Some(p) if p.as_u64() == Some(u64::from(ours)) => {}
        Some(p) => {
            return Err(format!(
                "cfx-script speaks protocol {ours}, but this job is protocol {p}, so the node \
                 or CLI that sent it is from another release. Run `crossfyre update` to \
                 install the two from the same release."
            ));
        }
        None => {
            return Err(format!(
                "cfx-script speaks protocol {ours}, but this job names no protocol, so the \
                 node or CLI that sent it is older than this cfx-script. Run `crossfyre \
                 update` to install the two from the same release."
            ));
        }
    }
    serde_json::from_value(job).map_err(|e| unreadable(e.to_string()))
}

/// Keep the caller's pipe on a descriptor of its own for the messages, and point fd 1
/// at stderr.
///
/// The caller reads messages from the pipe it gave the helper as fd 1, and a script
/// reaches fd 1 in more ways than `print()`: a tool run without `capture_output` or
/// through `os.system` inherits it, and a C extension's `printf` and Python's own
/// `sys.__stdout__` write to it. Their bytes landed among the messages: a tool's last
/// line without a newline was glued onto the next message, and a byte that was not
/// UTF-8 ended the caller's reader. So the pipe moves to a descriptor that closes on
/// exec and that only `Messages` writes to, and fd 1 becomes a copy of fd 2, which the
/// caller passes through to the operator. It has to happen before Python starts,
/// because Python wraps fd 1 as `sys.__stdout__` when it does.
///
/// `None` when the helper was started with fd 1 closed; the messages then go nowhere,
/// as they did before.
fn take_stdout() -> Option<std::fs::File> {
    use std::os::fd::{AsFd, AsRawFd};
    // Duplicated with F_DUPFD_CLOEXEC, so no process the script starts inherits it.
    let pipe = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(std::fs::File::from);
    // SAFETY: dup2 and close act on fd 1 alone. Nothing in this process holds it yet:
    // the messages have their own descriptor above, and Python has not started.
    let moved = unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } != -1
        || std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .is_ok_and(|null| unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) } != -1);
    if !moved {
        // No stderr and no /dev/null. A closed fd 1 is still better than the caller's
        // pipe left where any child can write to it.
        unsafe { libc::close(libc::STDOUT_FILENO) };
    }
    pipe
}

/// Where the job is, as far as the writer has to know when it sends a `completed`.
#[derive(Clone, Copy, PartialEq)]
enum Stage {
    /// The main thread is running the script, or ending the job after it.
    Main,
    /// `run()` returned, and the main thread is waiting for the threads the script left.
    Waiting,
    /// A `completed` has gone out. The caller stops reading there, so nothing sent
    /// after it reaches anyone.
    Ended,
}

fn lock(stage: &Mutex<Stage>) -> std::sync::MutexGuard<'_, Stage> {
    stage.lock().unwrap_or_else(|p| p.into_inner())
}

/// The exit status for a job that ended with `code`, given the code of the script's own
/// `completed`, if it sent one.
fn exit_status(code: i32, reported: Option<i32>) -> i32 {
    match reported {
        Some(reported) if reported != 0 && code == 0 => 1,
        _ => code,
    }
}

/// Run the job, write every message to `pipe`, and return the exit status.
fn run(job: Job, mut pipe: Messages) -> i32 {
    let (tx, rx) = std::sync::mpsc::channel::<CfxMessage>();
    let job_id = job.job_id.clone();
    let stage = Arc::new(Mutex::new(Stage::Main));

    // Messages are written as they arrive, so a long scan's results reach the
    // control plane while it runs rather than all at once at the end.
    let writer = {
        let stage = Arc::clone(&stage);
        std::thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                let finished = match &msg {
                    CfxMessage::Completed { code, .. } => Some(*code),
                    _ => None,
                };
                pipe.send(&msg);
                let Some(code) = finished else { continue };
                let mut stage = lock(&stage);
                if *stage == Stage::Waiting {
                    // The job ended while the main thread waits for the script's
                    // threads. Nothing they send from here on reaches anyone, and one of
                    // them may never finish, so the helper exits now. The lock stays
                    // held, so the main thread cannot get as far as exiting too.
                    std::process::exit(exit_status(0, Some(code)));
                }
                *stage = Stage::Ended;
                return Some(code);
            }
            None
        })
    };

    // Kept so the writer can be told the job is over. A script that raises leaves a
    // traceback holding its frame, the frame holds the `server` object, and that
    // holds a clone of the sender, so the channel would never close on its own.
    let stopper = tx.clone();

    runtime::targets::inject(job.targets.clone());
    runtime::cfxs::inject(job.node_id.clone(), job.job_id.clone(), tx);
    runtime::extensions::inject_defaults();
    runtime::nodes::inject(vec![(job.node_id.clone(), "self".to_string())]);

    let outcome = run_python(&job.script);

    let code = match outcome {
        Ok(()) => {
            // Threads the script left running still need the context cleared below,
            // and their results belong before the final `completed`.
            wait_for_threads(&stage);
            0
        }
        Err(message) => {
            // The failure is the job's outcome, and it is sent at once. The script's
            // threads are not waited for: a raise usually skips whatever would have
            // stopped them, such as the `None` a consumer waits for, and waiting kept
            // a failed job running for good.
            let _ = stopper.send(CfxMessage::Log {
                job_id: job_id.clone(),
                message,
            });
            1
        }
    };

    runtime::targets::clear();
    runtime::cfxs::clear();
    runtime::extensions::clear();
    runtime::nodes::clear();

    // The script may have signalled completion itself. If it did not, the job is
    // finished now, and saying so is what stops the control plane showing it as
    // running forever.
    let _ = stopper.send(CfxMessage::Completed { job_id, code });
    drop(stopper);

    exit_status(code, writer.join().ok().flatten())
}

/// The caller's pipe, which the messages go out on.
///
/// It is an ordinary descriptor in the script's process, so a script that closes
/// descriptors it did not open, as `os.closerange(3, n)` does, closes this one too, and
/// the next file the script opens takes its number. Writing then put the messages in the
/// script's file, and closing it on the way out closed the script's file or, in a debug
/// build, aborted the helper. So each write first checks that the descriptor is still the
/// pipe, and once it is not, the helper says so on stderr and leaves the number alone.
struct Messages {
    pipe: Option<std::fs::File>,
    /// The pipe's device and inode when the helper took it.
    id: Option<(u64, u64)>,
}

impl Messages {
    fn new(pipe: Option<std::fs::File>) -> Self {
        let id = pipe.as_ref().and_then(identity);
        Messages { pipe, id }
    }

    /// The pipe, or `None` once the script has closed it.
    fn live(&mut self) -> Option<&std::fs::File> {
        use std::os::fd::AsRawFd;
        let pipe = self.pipe.take()?;
        if self.id.is_none() || identity(&pipe) == self.id {
            return Some(&*self.pipe.insert(pipe));
        }
        eprintln!(
            "cfx-script: the script closed fd {}, the pipe its messages go out on, so \
             nothing it sends from now on can be reported",
            pipe.as_raw_fd()
        );
        std::mem::forget(pipe);
        None
    }

    /// One message as one JSON line, in a single write.
    fn send(&mut self, msg: &CfxMessage) {
        let Some(mut out) = self.live() else { return };
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
        // Unbuffered, so the line is built whole and goes out in one write.
        let mut text = line.to_string();
        text.push('\n');
        let _ = out.write_all(text.as_bytes());
    }
}

impl Drop for Messages {
    fn drop(&mut self) {
        if let Some(pipe) = self.pipe.take()
            && self.id.is_some()
            && identity(&pipe) != self.id
        {
            std::mem::forget(pipe);
        }
    }
}

/// The device and inode a descriptor refers to, or `None` when it is closed.
fn identity(file: &std::fs::File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    file.metadata().ok().map(|m| (m.dev(), m.ino()))
}

/// Point the script's `sys.stdout` at `sys.stderr`, line-buffered.
///
/// fd 1 already leads to stderr (see `take_stdout`), but `sys.stdout` keeps a buffer of
/// its own, so `print()` would reach the operator late and out of order with what the
/// script writes to `sys.stderr`. stderr reaches the operator: the node's log, or the
/// terminal for `crossfyre run`. Line buffering matters because the interpreter is never
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

/// Flush the interpreter's streams, and the originals a script can still write to
/// as `sys.__stdout__` and `sys.__stderr__`. Safe to call twice.
fn flush_std(py: Python<'_>) {
    let Ok(sys) = py.import("sys") else { return };
    for name in ["stdout", "stderr", "__stdout__", "__stderr__"] {
        if let Ok(stream) = sys.getattr(name) {
            let _ = stream.call_method0("flush");
        }
    }
}

/// Wait for the script's non-daemon threads, as the interpreter does before it exits.
///
/// The interpreter here is never finalised, so the helper used to exit as soon as
/// `run()` returned, and a thread or a pool the script left at work was killed with its
/// results unsent. `threading._shutdown` is what `Py_FinalizeEx` calls at this point: it
/// runs the hooks that tell a `ThreadPoolExecutor`'s idle workers to stop, then joins
/// every non-daemon thread, including any started while it waits. As in finalisation,
/// there is nothing to wait for when the script never imported `threading`.
///
/// Unlike finalisation, the wait stops when the job ends. There is no wait when the
/// script has already sent its `completed`, and a `completed` that a thread sends during
/// the wait makes the writer exit the helper (see `run`). A thread that serves forever or
/// waits for work that never comes would otherwise hold a finished job open for good.
fn wait_for_threads(stage: &Mutex<Stage>) {
    {
        let mut stage = lock(stage);
        if *stage == Stage::Ended {
            return;
        }
        *stage = Stage::Waiting;
    }
    Python::attach(|py| {
        let threading = py
            .import("sys")
            .and_then(|sys| sys.getattr("modules"))
            .and_then(|modules| modules.get_item("threading"));
        if let Ok(threading) = threading
            && let Err(e) = threading.call_method0("_shutdown")
        {
            e.print(py);
        }
        flush_std(py);
    });
    // The main thread ends the job from here. A thread's `completed` that the writer has
    // not reached yet still counts, as it would have before the wait.
    *lock(stage) = Stage::Main;
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
