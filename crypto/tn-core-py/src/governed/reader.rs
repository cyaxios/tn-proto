use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBool;
use serde_json::Value;
use std::sync::Arc;
use tn_core::governed::{AdmittedObject, GovernanceView, GovernedReader, OpenedObject};

use super::objects::{PyDraft, PyGovernance, PyObject};
use super::{codec, guard, to_py};

/// Independent snapshot of the explicitly supplied group-reading capability.
#[pyclass(frozen, module = "tn.governed", name = "GovernedReader")]
pub(super) struct PyReader {
    pub inner: Arc<GovernedReader>,
}

#[pymethods]
impl PyReader {
    fn governance(&self, py: Python<'_>, object: &PyObject) -> PyResult<PyGovernanceView> {
        guard(|| {
            py.allow_threads(|| self.inner.governance(&object.inner))
                .map(|inner| PyGovernanceView { inner })
                .map_err(to_py)
        })
    }
    fn open(
        &self,
        py: Python<'_>,
        admitted: &PyAdmitted,
        groups: Vec<String>,
    ) -> PyResult<PyOpened> {
        guard(|| {
            py.allow_threads(|| self.inner.open(&admitted.inner, &groups))
                .map(|inner| PyOpened { inner })
                .map_err(to_py)
        })
    }
}

/// Authenticated governance and its source before application admission.
#[pyclass(frozen, module = "tn.governed", name = "GovernanceView")]
pub(super) struct PyGovernanceView {
    pub inner: GovernanceView,
}

#[pymethods]
impl PyGovernanceView {
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.governance().clone(),
        }
    }
    #[getter]
    fn object(&self) -> PyObject {
        PyObject {
            inner: self.inner.object().clone(),
        }
    }
    /// Evaluate permitted use. The callback must return bool; its errors propagate.
    fn authorize(&self, operation: &str, decision: &Bound<'_, PyAny>) -> PyResult<PyAdmitted> {
        guard(|| {
            if operation.trim().is_empty() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "operation must be nonempty",
                ));
            }
            let answer = decision.call1((self.governance(), operation))?;
            if !answer.is_instance_of::<PyBool>() {
                return Err(PyTypeError::new_err("governance decision must return bool"));
            }
            let allow = answer.extract::<bool>()?;
            self.inner
                .clone()
                .authorize(operation, |_, _| Ok(allow))
                .map(|inner| PyAdmitted { inner })
                .map_err(to_py)
        })
    }
}

/// Source admitted by the application for a named operation.
#[pyclass(frozen, module = "tn.governed", name = "AdmittedObject")]
pub(super) struct PyAdmitted {
    pub inner: AdmittedObject,
}

#[pymethods]
impl PyAdmitted {
    #[getter]
    fn operation(&self) -> &str {
        self.inner.operation()
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.governance().clone(),
        }
    }
    #[getter]
    fn object(&self) -> PyObject {
        PyObject {
            inner: self.inner.object().clone(),
        }
    }
}

/// Selected plaintext together with its accepted contract and original source.
#[pyclass(frozen, module = "tn.governed", name = "OpenedObject")]
pub(super) struct PyOpened {
    pub inner: OpenedObject,
}

#[pymethods]
impl PyOpened {
    #[getter]
    fn groups<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| {
            codec::to_python(
                py,
                &Value::Object(self.inner.groups().clone().into_iter().collect()),
            )
        })
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.governance().clone(),
        }
    }
    #[getter]
    fn object(&self) -> PyObject {
        PyObject {
            inner: self.inner.object().clone(),
        }
    }
    #[getter]
    fn hidden_groups(&self) -> Vec<String> {
        self.inner
            .hidden_groups()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }
    fn derive(&self, object_type: &str) -> PyResult<PyDraft> {
        guard(|| {
            self.inner
                .derive(object_type)
                .map(|inner| PyDraft { inner })
                .map_err(to_py)
        })
    }
    fn derive_under(&self, object_type: &str, governance: &PyGovernance) -> PyResult<PyDraft> {
        guard(|| {
            self.inner
                .derive_under(object_type, governance.inner.clone())
                .map(|inner| PyDraft { inner })
                .map_err(to_py)
        })
    }
}
