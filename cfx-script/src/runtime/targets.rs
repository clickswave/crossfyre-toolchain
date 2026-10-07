use pyo3::prelude::*;
use std::sync::Mutex;

/// A single target from the workflow's target_scope.
#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug)]
pub struct Target {
    type_: String,
    value_: String,
}

#[pymethods]
impl Target {
    /// Exposed as `target.type` in Python.
    #[getter(r#type)]
    fn get_type(&self) -> &str {
        &self.type_
    }

    /// Exposed as `target.value` in Python.
    #[getter]
    fn value(&self) -> &str {
        &self.value_
    }

    fn __repr__(&self) -> String {
        format!("Target(type='{}', value='{}')", self.type_, self.value_)
    }
}

// ── Injection from Rust ──────────────────────────────────────────────

static TARGETS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// Called from Rust before Python execution to inject targets.
pub fn inject(targets: Vec<(String, String)>) {
    let mut guard = TARGETS.lock().unwrap();
    *guard = targets;
}

/// Clear injected targets (called after execution).
pub fn clear() {
    let mut guard = TARGETS.lock().unwrap();
    guard.clear();
}

// ── Python module ────────────────────────────────────────────────────

#[pyfunction]
fn get_all() -> Vec<Target> {
    let guard = TARGETS.lock().unwrap();
    guard
        .iter()
        .map(|(t, v)| Target {
            type_: t.clone(),
            value_: v.clone(),
        })
        .collect()
}

pub fn make_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "targets")?;
    m.add_function(wrap_pyfunction!(get_all, &m)?)?;
    m.add_class::<Target>()?;
    Ok(m)
}
