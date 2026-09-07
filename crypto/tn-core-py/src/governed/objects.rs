use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use serde_json::Value;
use tn_core::governed::{Governance, GovernedDraft, GovernedObject};

use super::{codec, guard, to_py};

/// A typed contract selected from parsed policy content.
#[pyclass(frozen, module = "tn.governed", name = "Governance")]
pub(super) struct PyGovernance {
    pub inner: Governance,
}

#[pymethods]
impl PyGovernance {
    #[staticmethod]
    fn from_markdown(
        governed_by: &str,
        markdown: &str,
        policy_id: &str,
        object_type: &str,
    ) -> PyResult<Self> {
        guard(|| {
            Governance::from_markdown(governed_by, markdown, policy_id, object_type)
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }
    #[getter]
    fn governed_by(&self) -> &str {
        self.inner.governed_by()
    }
    #[getter]
    fn policy_ref(&self) -> &str {
        self.inner.policy_ref()
    }
    #[getter]
    fn fields<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| codec::to_python(py, &Value::Object(self.inner.fields().clone())))
    }
    fn get<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        guard(|| codec::to_python(py, self.inner.get(name).unwrap_or(&Value::Null)))
    }
    fn matches_contract(&self, expected: &Self) -> bool {
        self.inner.matches_contract(&expected.inner)
    }
    #[getter]
    fn revision_id(&self) -> Option<&str> {
        self.inner.revision_id()
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<Self>> {
        self.inner
            .policies()
            .map(|items| items.into_iter().map(|inner| Self { inner }).collect())
            .map_err(to_py)
    }
    #[getter]
    fn sources(&self) -> PyResult<Vec<super::data::PySource>> {
        self.inner
            .source_references()
            .map(|items| {
                items
                    .into_iter()
                    .map(|inner| super::data::PySource { inner })
                    .collect()
            })
            .map_err(to_py)
    }
}

/// An immutable draft; adding a business group returns a new draft.
#[pyclass(frozen, module = "tn.governed", name = "GovernedDraft")]
pub(super) struct PyDraft {
    pub inner: GovernedDraft,
}

#[pymethods]
impl PyDraft {
    #[new]
    fn new(object_type: &str, governance: &PyGovernance) -> PyResult<Self> {
        guard(|| {
            GovernedDraft::new(object_type, governance.inner.clone())
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }
    fn group(&self, name: &str, fields: &Bound<'_, PyDict>) -> PyResult<Self> {
        guard(|| {
            self.inner
                .clone()
                .group(name, codec::fields(fields)?)
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.governance().clone(),
        }
    }
}

/// Verified signed envelope retaining its exact transport bytes.
#[pyclass(frozen, module = "tn.governed", name = "GovernedObject")]
pub(super) struct PyObject {
    pub inner: GovernedObject,
}

#[pymethods]
impl PyObject {
    #[staticmethod]
    fn parse(py: Python<'_>, wire: &Bound<'_, PyAny>) -> PyResult<Self> {
        guard(|| {
            let wire = codec::wire(wire)?;
            py.allow_threads(|| GovernedObject::parse(&wire))
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }
    #[getter]
    fn wire(&self) -> &str {
        self.inner.wire()
    }
    #[getter]
    fn id(&self) -> &str {
        self.inner.id()
    }
    #[getter]
    fn writer(&self) -> &str {
        self.inner.writer()
    }
    #[getter]
    fn object_type(&self) -> &str {
        self.inner.object_type()
    }
    #[getter]
    fn group_names(&self) -> Vec<String> {
        self.inner
            .group_names()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }
    #[getter]
    fn envelope<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| codec::to_python(py, &Value::Object(self.inner.envelope().clone())))
    }
    fn __str__(&self) -> &str {
        self.inner.wire()
    }
    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.wire().as_bytes())
    }
    fn __repr__(&self) -> String {
        format!(
            "GovernedObject(type={:?}, id={:?})",
            self.inner.object_type(),
            self.inner.id()
        )
    }
}
