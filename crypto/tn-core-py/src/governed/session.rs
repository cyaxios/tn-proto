use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tn_core::governed::{GovernedDraft, GovernedObject};
use tn_core::runtime::Objects;

use super::objects::{PyDraft, PyGovernance, PyObject};
use super::reader::{PyAdmitted, PyGovernanceView, PyOpened, PyReader};
use super::{codec, guard, to_py, GovernedError, SessionClosed};

/// Independent governed session. Construction creates in-memory BTN material;
/// from_config loads an existing object context. Each instance closes separately.
#[pyclass(frozen, module = "tn.governed", name = "Session")]
pub(super) struct PySession {
    pub(super) context: Arc<Mutex<Option<Arc<Objects<'static>>>>>,
}

impl PySession {
    fn from_context(context: Objects<'static>) -> Self {
        Self {
            context: Arc::new(Mutex::new(Some(Arc::new(context)))),
        }
    }
    pub(super) fn context(&self) -> PyResult<Arc<Objects<'static>>> {
        self.context
            .lock()
            .map_err(|_| GovernedError::new_err("session lock poisoned"))?
            .clone()
            .ok_or_else(|| SessionClosed::new_err("this governed session is closed"))
    }
}

#[pymethods]
impl PySession {
    #[new]
    #[pyo3(signature = (policy, *, groups=None, policy_id="agents.md"))]
    fn new(
        py: Python<'_>,
        policy: &str,
        groups: Option<Vec<String>>,
        policy_id: &str,
    ) -> PyResult<Self> {
        guard(|| {
            let groups = groups.unwrap_or_else(|| vec!["default".to_owned()]);
            let names: Vec<_> = groups.iter().map(String::as_str).collect();
            py.allow_threads(|| Objects::ephemeral(policy, policy_id, &names))
                .map(Self::from_context)
                .map_err(to_py)
        })
    }
    #[staticmethod]
    fn from_config(py: Python<'_>, path: PathBuf) -> PyResult<Self> {
        guard(|| {
            py.allow_threads(|| Objects::open(&path))
                .map(Self::from_context)
                .map_err(to_py)
        })
    }
    #[pyo3(signature=(fields, policy, *, object_type, group="default"))]
    fn create_obj(
        &self,
        py: Python<'_>,
        fields: &Bound<'_, pyo3::types::PyDict>,
        policy: &PyGovernance,
        object_type: &str,
        group: &str,
    ) -> PyResult<super::data::PyData> {
        super::data::create(self, py, fields, policy, object_type, group)
    }
    #[pyo3(signature=(sealed, *, purpose, decide, groups=None))]
    fn receive(
        &self,
        py: Python<'_>,
        sealed: &Bound<'_, PyAny>,
        purpose: &str,
        decide: &Bound<'_, PyAny>,
        groups: Option<Vec<String>>,
    ) -> PyResult<super::data::PyData> {
        super::data::receive(
            self,
            py,
            sealed,
            purpose,
            groups.unwrap_or_else(|| vec!["default".to_owned()]),
            decide,
        )
    }
    fn check_groups(
        &self,
        py: Python<'_>,
        groups: Vec<String>,
    ) -> PyResult<super::data::PyPublication> {
        guard(|| {
            let context = self.context()?;
            py.allow_threads(|| context.check_groups(groups))
                .map(|inner| super::data::PyPublication { inner })
                .map_err(to_py)
        })
    }
    fn require_groups(&self, py: Python<'_>, groups: Vec<String>) -> PyResult<()> {
        guard(|| {
            let context = self.context()?;
            py.allow_threads(|| context.require_groups(groups))
                .map_err(to_py)
        })
    }
    #[getter]
    fn did(&self) -> PyResult<String> {
        guard(|| Ok(self.context()?.did().to_owned()))
    }
    #[getter]
    fn closed(&self) -> PyResult<bool> {
        Ok(self
            .context
            .lock()
            .map_err(|_| GovernedError::new_err("session lock poisoned"))?
            .is_none())
    }
    fn close(&self) -> PyResult<()> {
        let context = self
            .context
            .lock()
            .map_err(|_| GovernedError::new_err("session lock poisoned"))?
            .take();
        drop(context);
        Ok(())
    }
    fn __enter__(slf: PyRef<'_, Self>) -> PyResult<PyRef<'_, Self>> {
        slf.context()?;
        Ok(slf)
    }
    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        self.close()?;
        Ok(false)
    }
    #[pyo3(signature = (object_type, *, governance=None))]
    fn draft(&self, object_type: &str, governance: Option<&PyGovernance>) -> PyResult<PyDraft> {
        guard(|| {
            let context = self.context()?;
            match governance {
                Some(contract) => GovernedDraft::new(object_type, contract.inner.clone()),
                None => context.draft(object_type),
            }
            .map(|inner| PyDraft { inner })
            .map_err(to_py)
        })
    }
    fn policy(&self, object_type: &str) -> PyResult<PyGovernance> {
        guard(|| {
            self.context()?
                .draft(object_type)
                .map(|draft| PyGovernance {
                    inner: draft.governance().clone(),
                })
                .map_err(to_py)
        })
    }
    fn seal(&self, py: Python<'_>, draft: &PyDraft) -> PyResult<PyObject> {
        guard(|| {
            let context = self.context()?;
            let draft = draft.inner.clone();
            py.allow_threads(|| context.seal(draft))
                .map(|inner| PyObject { inner })
                .map_err(to_py)
        })
    }
    fn verify(&self, py: Python<'_>, wire: &Bound<'_, PyAny>) -> PyResult<PyObject> {
        guard(|| {
            self.context()?;
            let wire = codec::wire(wire)?;
            py.allow_threads(|| GovernedObject::parse(&wire))
                .map(|inner| PyObject { inner })
                .map_err(to_py)
        })
    }
    #[pyo3(signature = (*, groups=None))]
    fn reader(&self, py: Python<'_>, groups: Option<Vec<String>>) -> PyResult<PyReader> {
        guard(|| {
            let context = self.context()?;
            py.allow_threads(|| match groups {
                Some(groups) => context.reader_for(groups),
                None => context.reader(),
            })
            .map(|inner| PyReader {
                inner: Arc::new(inner),
            })
            .map_err(to_py)
        })
    }
    fn governance(&self, py: Python<'_>, object: &PyObject) -> PyResult<PyGovernanceView> {
        guard(|| {
            let context = self.context()?;
            py.allow_threads(|| context.reader_for(["tn.agents"])?.governance(&object.inner))
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
            let context = self.context()?;
            py.allow_threads(|| context.reader_for(&groups)?.open(&admitted.inner, &groups))
                .map(|inner| PyOpened { inner })
                .map_err(to_py)
        })
    }
    fn __repr__(&self) -> PyResult<String> {
        if self.closed()? {
            Ok("Session(closed=True)".to_owned())
        } else {
            Ok(format!("Session(did={:?})", self.did()?))
        }
    }
}
