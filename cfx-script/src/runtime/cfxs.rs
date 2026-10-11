use pyo3::prelude::*;
use std::sync::Mutex;

// ── Message types sent from Python back to Rust ──────────────────────

#[derive(Debug)]
pub enum CfxMessage {
    Result {
        job_id: String,
        data: serde_json::Value,
    },
    Log {
        job_id: String,
        message: String,
    },
    Completed {
        job_id: String,
        code: i32,
    },
}

// ── Context injected from Rust before script execution ───────────────

struct CfxContext {
    node_id: String,
    job_id: String,
    tx: std::sync::mpsc::Sender<CfxMessage>,
}

static CONTEXT: Mutex<Option<CfxContext>> = Mutex::new(None);

/// Inject the NATS bridge context before running a .cfx script.
pub fn inject(node_id: String, job_id: String, tx: std::sync::mpsc::Sender<CfxMessage>) {
    *CONTEXT.lock().unwrap() = Some(CfxContext {
        node_id,
        job_id,
        tx,
    });
}

pub fn clear() {
    *CONTEXT.lock().unwrap() = None;
}

// ── Python types ─────────────────────────────────────────────────────

/// Signal helper - `server.signal.completed(0)`
#[pyclass]
pub struct Signal {
    job_id: String,
    tx: std::sync::mpsc::Sender<CfxMessage>,
}

#[pymethods]
impl Signal {
    /// Signal that the script has finished.
    fn completed(&self, code: i32) -> PyResult<()> {
        self.tx
            .send(CfxMessage::Completed {
                job_id: self.job_id.clone(),
                code,
            })
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to send completion signal: {e}"
                ))
            })
    }
}

/// The handle returned by `cfxs.connect()`.
#[pyclass]
pub struct ServerHandle {
    node_id: String,
    job_id: String,
    tx: std::sync::mpsc::Sender<CfxMessage>,
}

#[pymethods]
impl ServerHandle {
    /// Send a result dict back to the control plane.
    fn send_result(&self, data: Bound<'_, pyo3::types::PyAny>) -> PyResult<()> {
        let value: serde_json::Value = pythonize::depythonize(&data)?;
        self.tx
            .send(CfxMessage::Result {
                job_id: self.job_id.clone(),
                data: value,
            })
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to send result: {e}"))
            })
    }

    /// Send a log message.
    fn log(&self, message: &str) -> PyResult<()> {
        self.tx
            .send(CfxMessage::Log {
                job_id: self.job_id.clone(),
                message: message.to_string(),
            })
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to send log: {e}"))
            })
    }

    #[getter]
    fn signal(&self) -> Signal {
        Signal {
            job_id: self.job_id.clone(),
            tx: self.tx.clone(),
        }
    }

    #[getter]
    fn node_id(&self) -> &str {
        &self.node_id
    }

    #[getter]
    fn job_id(&self) -> &str {
        &self.job_id
    }
}

// ── Module‑level function ────────────────────────────────────────────

/// Returns a ServerHandle connected to the Rust async runtime.
#[pyfunction]
fn connect() -> PyResult<ServerHandle> {
    let guard = CONTEXT.lock().unwrap();
    let ctx = guard.as_ref().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "cfxs.connect() called but no execution context is available",
        )
    })?;
    Ok(ServerHandle {
        node_id: ctx.node_id.clone(),
        job_id: ctx.job_id.clone(),
        tx: ctx.tx.clone(),
    })
}

pub fn make_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "cfxs")?;
    m.add_function(wrap_pyfunction!(connect, &m)?)?;
    m.add_class::<ServerHandle>()?;
    m.add_class::<Signal>()?;
    Ok(m)
}
