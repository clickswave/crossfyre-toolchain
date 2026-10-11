pub mod cfxs;
pub mod extensions;
pub mod nodes;
pub mod silo;
pub mod targets;

use pyo3::prelude::*;

/// Register all cfx_runtime submodules into Python's sys.modules
/// so that .cfx scripts can `import targets`, `import cfxs`, etc.
pub fn register_modules(py: Python<'_>) -> PyResult<()> {
    let sys = py.import("sys")?;
    let modules = sys.getattr("modules")?;

    let targets_mod = targets::make_module(py)?;
    let extensions_mod = extensions::make_module(py)?;
    let cfxs_mod = cfxs::make_module(py)?;
    let silo_mod = silo::make_module(py)?;
    let nodes_mod = nodes::make_module(py)?;

    modules.set_item("targets", &targets_mod)?;
    modules.set_item("extensions", &extensions_mod)?;
    modules.set_item("cfxs", &cfxs_mod)?;
    modules.set_item("silo", &silo_mod)?;
    modules.set_item("nodes", &nodes_mod)?;

    Ok(())
}
