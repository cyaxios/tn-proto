//! Combined PyO3 extension for the single `tn-proto` wheel.
//!
//! Historically the Python package depended on two separately-published
//! Rust wheels (`tn-core` exposing `tn_core._core`, `tn-btn` exposing
//! `tn_btn._core`). They always shipped on the same version axis, so we
//! fold both into one extension here: `tn._native` with a `core`
//! submodule (the former `tn_core._core`) and a `btn` submodule (the
//! former `tn_btn._core`). One `pip install tn-proto` now carries both
//! Rust runtimes in a single wheel.

use pyo3::prelude::*;
use pyo3::types::PyModule;

#[pymodule]
#[pyo3(name = "_native")]
fn native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // core submodule = former tn_core._core
    let core = PyModule::new(py, "core")?;
    tn_core_py::populate(py, &core)?;
    m.add_submodule(&core)?;

    // btn submodule = former tn_btn._core
    let btn = PyModule::new(py, "btn")?;
    tn_btn_py::populate(&btn)?;
    m.add_submodule(&btn)?;

    // PyO3 only wires attribute access for submodules; register them (and
    // the nested `core.admin`) in sys.modules so explicit imports like
    // `from tn._native.core import Runtime` and
    // `from tn._native.core.admin import reduce` resolve.
    let modules = py.import("sys")?.getattr("modules")?;
    modules.set_item("tn._native.core", &core)?;
    modules.set_item("tn._native.btn", &btn)?;
    if let Ok(admin) = core.getattr("admin") {
        modules.set_item("tn._native.core.admin", &admin)?;
    }
    Ok(())
}
