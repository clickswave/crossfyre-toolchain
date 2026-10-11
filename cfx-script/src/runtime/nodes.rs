use pyo3::prelude::*;
use std::sync::Mutex;

#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug)]
pub struct Node {
    id_: String,
    name_: String,
}

#[pymethods]
impl Node {
    #[getter]
    fn id(&self) -> &str {
        &self.id_
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name_
    }

    fn __repr__(&self) -> String {
        format!("Node(id='{}', name='{}')", self.id_, self.name_)
    }
}

static NODES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

pub fn inject(nodes: Vec<(String, String)>) {
    *NODES.lock().unwrap() = nodes;
}

pub fn clear() {
    NODES.lock().unwrap().clear();
}

#[pyfunction]
fn get_all() -> Vec<Node> {
    let guard = NODES.lock().unwrap();
    guard
        .iter()
        .map(|(id, name)| Node {
            id_: id.clone(),
            name_: name.clone(),
        })
        .collect()
}

/// Get the current node (the one executing this script).
#[pyfunction]
fn current() -> PyResult<Node> {
    let guard = NODES.lock().unwrap();
    guard
        .first()
        .map(|(id, name)| Node {
            id_: id.clone(),
            name_: name.clone(),
        })
        .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("No node context available"))
}

pub fn make_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "nodes")?;
    m.add_function(wrap_pyfunction!(get_all, &m)?)?;
    m.add_function(wrap_pyfunction!(current, &m)?)?;
    m.add_class::<Node>()?;
    Ok(m)
}
