use pyo3::prelude::*;
use tn_core::governed::UseContext;

use super::{guard, to_py};

/// Validated immutable Rust use tuple; Python adds no admission rules.
#[pyclass(frozen, eq, module = "tn.governed", name = "UseContext")]
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PyUseContext {
    pub inner: UseContext,
}

#[pymethods]
impl PyUseContext {
    #[new]
    fn new(application: &str, purpose: &str, operation: &str) -> PyResult<Self> {
        guard(|| {
            UseContext::new(application, purpose, operation)
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }
    #[getter]
    fn application(&self) -> &str {
        self.inner.application()
    }
    #[getter]
    fn purpose(&self) -> &str {
        self.inner.purpose()
    }
    #[getter]
    fn operation(&self) -> &str {
        self.inner.operation()
    }
    fn __repr__(&self) -> String {
        format!(
            "UseContext(application={:?}, purpose={:?}, operation={:?})",
            self.inner.application(),
            self.inner.purpose(),
            self.inner.operation()
        )
    }
}
