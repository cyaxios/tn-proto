use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tn_core::governed::{GovernedDraft, GovernedReader};
use tn_core::runtime::{Objects, Session};

use super::dataset::PyDatasetSelection;
use super::objects::{PyDraft, PyGovernance, PyObject};
use super::reader::{PyAdmitted, PyGovernanceView, PyOpened, PyReader};
use super::use_context::PyUseContext;
use super::{codec, guard, to_py, GovernedError, SessionClosed};

/// Optional per-session signed metadata registers.
#[pyclass(frozen, module = "tn.governed", name = "ObjectRegisters")]
pub(super) struct PyRegisters {
    pub(super) inner: tn_core::runtime::ObjectRegisters,
}
#[pymethods]
impl PyRegisters {
    #[new]
    #[pyo3(signature = (*, creation=None, release=None))]
    fn new(creation: Option<PathBuf>, release: Option<PathBuf>) -> Self {
        Self {
            inner: tn_core::runtime::ObjectRegisters::new(creation, release),
        }
    }
}

/// Independent governed session. Construction creates in-memory BTN material;
/// from_config loads an existing object context. Each instance closes separately.
#[pyclass(frozen, module = "tn.governed", name = "Session")]
pub(super) struct PySession {
    pub(super) context: Arc<Mutex<Option<Arc<Session<'static>>>>>,
    reader: Mutex<Option<Arc<GovernedReader>>>,
}

impl PySession {
    fn ensure_live(state: &std::sync::Weak<Mutex<Option<Arc<Session<'static>>>>>) -> PyResult<()> {
        let state = state
            .upgrade()
            .ok_or_else(|| SessionClosed::new_err("session is closed"))?;
        if state
            .lock()
            .map_err(|_| GovernedError::new_err("session lock poisoned"))?
            .is_none()
        {
            return Err(SessionClosed::new_err("session is closed"));
        }
        Ok(())
    }
    fn from_context(context: Objects<'static>) -> tn_core::Result<Self> {
        Self::from_session(Session::new(context))
    }
    pub(super) fn from_session(context: Session<'static>) -> tn_core::Result<Self> {
        let reader = context.reader()?;
        Ok(Self {
            context: Arc::new(Mutex::new(Some(Arc::new(context)))),
            reader: Mutex::new(Some(Arc::new(reader))),
        })
    }
    pub(super) fn context(&self) -> PyResult<Arc<Session<'static>>> {
        self.context
            .lock()
            .map_err(|_| GovernedError::new_err("session lock poisoned"))?
            .clone()
            .ok_or_else(|| SessionClosed::new_err("this governed session is closed"))
    }
    fn cached_reader(&self) -> PyResult<Arc<GovernedReader>> {
        self.context()?;
        self.reader
            .lock()
            .map_err(|_| GovernedError::new_err("session reader lock poisoned"))?
            .clone()
            .ok_or_else(|| SessionClosed::new_err("this governed session is closed"))
    }
}

#[pymethods]
impl PySession {
    #[new]
    #[pyo3(signature = (policy, *, groups=None, policy_id="agents.md", registers=None))]
    fn new(
        py: Python<'_>,
        policy: &str,
        groups: Option<Vec<String>>,
        policy_id: &str,
        registers: Option<&PyRegisters>,
    ) -> PyResult<Self> {
        guard(|| {
            let groups = groups.unwrap_or_else(|| vec!["default".to_owned()]);
            let names: Vec<_> = groups.iter().map(String::as_str).collect();
            let registers = registers.map(|r| r.inner.clone());
            py.allow_threads(|| {
                Objects::ephemeral(policy, policy_id, &names).map(|objects| match registers {
                    Some(r) => objects.with_registers(r),
                    None => objects,
                })
            })
            .and_then(Self::from_context)
            .map_err(to_py)
        })
    }
    #[staticmethod]
    #[pyo3(signature = (path, *, registers=None))]
    fn from_config(
        py: Python<'_>,
        path: PathBuf,
        registers: Option<&PyRegisters>,
    ) -> PyResult<Self> {
        guard(|| {
            let registers = registers.map(|r| r.inner.clone());
            py.allow_threads(|| {
                Objects::open(&path).map(|objects| match registers {
                    Some(r) => objects.with_registers(r),
                    None => objects,
                })
            })
            .and_then(Self::from_context)
            .map_err(to_py)
        })
    }
    #[pyo3(signature=(*, r#use, decide, groups=None, object_type=None))]
    fn configure_receive(
        &self,
        py: Python<'_>,
        r#use: &PyUseContext,
        decide: &Bound<'_, PyAny>,
        groups: Option<Vec<String>>,
        object_type: Option<&str>,
    ) -> PyResult<()> {
        guard(|| {
            if !decide.is_callable() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "decide must be callable",
                ));
            }
            let callback = decide.clone().unbind();
            let state = Arc::downgrade(&self.context);
            let context = self.context()?;
            let use_context = r#use.inner.clone();
            py.allow_threads(|| {
                context.configure_receive_for(
                    object_type,
                    use_context,
                    groups.unwrap_or_else(|| vec!["default".into()]),
                    move |native| {
                        Python::with_gil(|py| {
                            let allow = super::data::decision(
                                callback.bind(py),
                                Py::new(py, super::data::PyAdmission::from_native(native))?
                                    .into_any(),
                            )?;
                            Self::ensure_live(&state)?;
                            Ok(allow)
                        })
                        .map_err(|error: PyErr| {
                            tn_core::Error::InvalidConfig(format!(
                                "configured admission evaluator failed: {error}"
                            ))
                        })
                    },
                )
            })
            .map_err(to_py)
        })
    }
    #[pyo3(signature=(*, r#use, to, object_type, decide))]
    fn configure_release(
        &self,
        py: Python<'_>,
        r#use: &PyUseContext,
        to: &str,
        object_type: &str,
        decide: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        guard(|| {
            if !decide.is_callable() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "decide must be callable",
                ));
            }
            let callback = decide.clone().unbind();
            let state = Arc::downgrade(&self.context);
            let context = self.context()?;
            let use_context = r#use.inner.clone();
            py.allow_threads(|| {
                context.configure_release(use_context, to, object_type, move |native| {
                    Python::with_gil(|py| {
                        let allow = super::data::decision(
                            callback.bind(py),
                            Py::new(py, super::data::PyRelease::from_native(native))?.into_any(),
                        )?;
                        Self::ensure_live(&state)?;
                        Ok(allow)
                    })
                    .map_err(|error: PyErr| {
                        tn_core::Error::InvalidConfig(format!(
                            "configured release evaluator failed: {error}"
                        ))
                    })
                })
            })
            .map_err(to_py)
        })
    }
    #[pyo3(signature=(*, decide))]
    fn configure_attach(&self, py: Python<'_>, decide: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            if !decide.is_callable() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "decide must be callable",
                ));
            }
            let callback = decide.clone().unbind();
            let state = Arc::downgrade(&self.context);
            let context = self.context()?;
            py.allow_threads(|| {
                context.configure_attach(move |native| {
                    Python::with_gil(|py| {
                        let allow = super::data::decision(
                            callback.bind(py),
                            Py::new(py, super::data::PyAttachment::from_native(native))?.into_any(),
                        )?;
                        Self::ensure_live(&state)?;
                        Ok(allow)
                    })
                    .map_err(|error: PyErr| {
                        tn_core::Error::InvalidConfig(format!(
                            "configured attachment evaluator failed: {error}"
                        ))
                    })
                })
            })
            .map_err(to_py)
        })
    }
    #[pyo3(signature=(fields, policy, *, object_type=None, group="default"))]
    fn create(
        &self,
        py: Python<'_>,
        fields: &Bound<'_, pyo3::types::PyDict>,
        policy: &PyGovernance,
        object_type: Option<&str>,
        group: &str,
    ) -> PyResult<super::data::PyData> {
        super::data::create(self, py, fields, policy, object_type, group)
    }
    #[pyo3(signature=(fields, policy, *, object_type=None, group="default"))]
    fn create_obj(
        &self,
        py: Python<'_>,
        fields: &Bound<'_, pyo3::types::PyDict>,
        policy: &PyGovernance,
        object_type: Option<&str>,
        group: &str,
    ) -> PyResult<super::data::PyData> {
        super::data::create(self, py, fields, policy, object_type, group)
    }
    #[pyo3(signature=(groups, policy, *, object_type=None, primary_group="default"))]
    fn create_obj_with_groups(
        &self,
        py: Python<'_>,
        groups: &Bound<'_, pyo3::types::PyDict>,
        policy: &PyGovernance,
        object_type: Option<&str>,
        primary_group: &str,
    ) -> PyResult<super::data::PyData> {
        super::data::create_with_groups(self, py, groups, policy, object_type, primary_group)
    }
    #[pyo3(signature=(sealed, *, decide=None, purpose=None, r#use=None, groups=None, selection=None))]
    #[pyo3(text_signature="($self, sealed, *, decide=None, purpose=None, use=None, groups=None, selection=None)")]
    fn receive(
        &self,
        py: Python<'_>,
        sealed: &Bound<'_, PyAny>,
        decide: Option<&Bound<'_, PyAny>>,
        purpose: Option<&str>,
        r#use: Option<&PyUseContext>,
        groups: Option<Vec<String>>,
        selection: Option<&PyDatasetSelection>,
    ) -> PyResult<super::data::PyData> {
        if decide.is_none() {
            if r#use.is_some() || groups.is_some() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "configured receipt takes purpose; explicit use/groups requires decide",
                ));
            }
            return super::data::receive_configured(
                self,
                py,
                sealed,
                purpose.ok_or_else(|| {
                    pyo3::exceptions::PyTypeError::new_err("receive requires purpose")
                })?,
                selection,
            );
        }
        super::data::receive(
            self,
            py,
            sealed,
            purpose,
            r#use,
            groups.unwrap_or_else(|| vec!["default".to_owned()]),
            selection,
            decide.expect("explicit decision"),
        )
    }
    #[pyo3(signature=(data, *, r#use=None, purpose=None, to=None, decide=None, object_type=None))]
    #[pyo3(text_signature="($self, data, *, use=None, purpose=None, to=None, decide=None, object_type=None)")]
    fn release(
        &self,
        py: Python<'_>,
        data: &super::data::PyData,
        r#use: Option<&PyUseContext>,
        purpose: Option<&str>,
        to: Option<&str>,
        decide: Option<&Bound<'_, PyAny>>,
        object_type: Option<&str>,
    ) -> PyResult<PyObject> {
        super::data::release(self, data, py, r#use, purpose, to, decide, object_type)
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
        self.reader
            .lock()
            .map_err(|_| GovernedError::new_err("session reader lock poisoned"))?
            .take();
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
    #[pyo3(signature = (*, receive, release))]
    fn workflow(&self, receive: &str, release: &str) -> PyResult<super::data::PyWorkflow> {
        guard(|| super::data::PyWorkflow::bind(self, receive, release))
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
            let context = self.context()?;
            let wire = codec::wire(wire)?;
            py.allow_threads(|| context.verify(&wire))
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
            let reader = self.cached_reader()?;
            py.allow_threads(|| reader.governance(&object.inner))
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
            let reader = self.cached_reader()?;
            py.allow_threads(|| reader.open(&admitted.inner, &groups))
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
