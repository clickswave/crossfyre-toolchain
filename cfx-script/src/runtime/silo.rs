use pyo3::prelude::*;

/// Load a file and return its lines as a list of strings.
/// In the future this can resolve paths from Cloudflare R2 or a local cache.
#[pyfunction]
fn load(path: &str) -> PyResult<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| pyo3::exceptions::PyFileNotFoundError::new_err(format!("{path}: {e}")))?;
    Ok(contents
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

pub fn make_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "silo")?;
    m.add_function(wrap_pyfunction!(load, &m)?)?;
    Ok(m)
}
