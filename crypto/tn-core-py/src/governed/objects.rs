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
    #[getter]
    fn dataset_bindings(&self) -> PyResult<Vec<super::dataset::PyDatasetBinding>> {
        self.inner
            .dataset_bindings()
            .map(|bindings| {
                bindings
                    .into_iter()
                    .map(|inner| super::dataset::PyDatasetBinding { inner })
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
    fn read(py: Python<'_>, source: &Bound<'_, PyAny>) -> PyResult<Self> {
        guard(|| {
            let inner = if source.hasattr("read")? {
                let value = source.call_method0("read")?;
                let bytes = value.downcast::<PyBytes>()?.as_bytes().to_vec();
                py.allow_threads(|| GovernedObject::read(bytes.as_slice()))
                    .map_err(to_py)?
            } else {
                let path: std::path::PathBuf = source.extract()?;
                py.allow_threads(|| GovernedObject::read(std::fs::File::open(path)?))
                    .map_err(to_py)?
            };
            Ok(Self { inner })
        })
    }
    fn write(&self, py: Python<'_>, destination: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| write_publication(py, &self.inner, destination))
    }
    fn forward<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.forward())
    }
    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| codec::to_python(py, &Value::Object(self.inner.inspect().clone())))
    }
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

/// Adapt Python binary streams while preserving exact Rust publication bytes.
pub(super) fn write_publication(
    py: Python<'_>,
    publication: &GovernedObject,
    destination: &Bound<'_, PyAny>,
) -> PyResult<()> {
    if destination.hasattr("write")? {
        let mut stream = PythonWriter {
            destination,
            error: None,
        };
        let result = publication.write(&mut stream);
        if let Some(error) = stream.error {
            return Err(error);
        }
        result.map_err(to_py)
    } else {
        let path: std::path::PathBuf = destination.extract()?;
        py.allow_threads(|| publication.write(std::fs::File::create(path)?))
            .map_err(to_py)
    }
}

// Only language conversion belongs here. Rust's write_all handles partial writes.
struct PythonWriter<'a, 'py> {
    destination: &'a Bound<'py, PyAny>,
    error: Option<PyErr>,
}
impl std::io::Write for PythonWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = (|| -> PyResult<usize> {
            let count: usize = self
                .destination
                .call_method1("write", (PyBytes::new(self.destination.py(), bytes),))?
                .extract()?;
            if count > bytes.len() {
                return Err(pyo3::exceptions::PyOSError::new_err(
                    "binary stream reported an invalid write count",
                ));
            }
            Ok(count)
        })();
        result.map_err(|error| {
            self.error = Some(error);
            std::io::Error::other("Python binary stream write failed")
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
