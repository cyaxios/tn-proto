//! Mutable governed values. Python callbacks run against detached state snapshots.
use super::dataset::{PyDatasetBinding, PyDatasetSelection};
use super::objects::{PyGovernance, PyObject};
use super::session::PySession;
use super::use_context::PyUseContext;
use super::{codec, guard, to_py, GovernedError, SessionClosed};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tn_core::governed::{
    DataObject, Governance, OwnedAdmissionContext, PublicationReport, SourceReference, UseContext,
};
use tn_core::runtime::Objects;

type SessionState = Arc<Mutex<Option<Arc<Objects<'static>>>>>;

fn session(state: &SessionState) -> PyResult<Arc<Objects<'static>>> {
    state
        .lock()
        .map_err(|_| GovernedError::new_err("session lock poisoned"))?
        .clone()
        .ok_or_else(|| SessionClosed::new_err("this governed session is closed"))
}
pub(super) fn decision(callback: &Bound<'_, PyAny>, context: Py<PyAny>) -> PyResult<bool> {
    let answer = callback.call1((context,))?;
    if !answer.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err("governance decision must return bool"));
    }
    answer.extract()
}
pub(super) fn native_decision(
    error: &mut Option<PyErr>,
    callback: impl FnOnce() -> PyResult<bool>,
) -> tn_core::Result<bool> {
    callback().map_err(|failure| {
        *error = Some(failure);
        tn_core::Error::InvalidConfig("Python governance decision failed".to_owned())
    })
}
fn requested_use(
    purpose: Option<&str>,
    use_context: Option<&PyUseContext>,
) -> PyResult<Option<UseContext>> {
    match (purpose, use_context) {
        (Some(_), Some(_)) => Err(PyTypeError::new_err(
            "specify use or legacy purpose, not both",
        )),
        (None, None) => Err(PyTypeError::new_err(
            "receive and release require use or legacy purpose",
        )),
        (_, Some(context)) => Ok(Some(context.inner.clone())),
        (Some(_), None) => Ok(None),
    }
}
fn path(value: &Bound<'_, PyAny>) -> PyResult<Vec<Value>> {
    codec::to_json(value, 0)?
        .as_array()
        .cloned()
        .ok_or_else(|| PyTypeError::new_err("data path requires a list or tuple"))
}
fn policies(data: &DataObject) -> PyResult<Vec<PyGovernance>> {
    data.policies()
        .map(|items| {
            items
                .into_iter()
                .map(|inner| PyGovernance { inner })
                .collect()
        })
        .map_err(to_py)
}
fn sources(data: &DataObject) -> Vec<PySource> {
    data.sources()
        .iter()
        .cloned()
        .map(|inner| PySource { inner })
        .collect()
}

#[pyclass(frozen, module = "tn.governed", name = "SourceReference")]
pub(super) struct PySource {
    pub inner: SourceReference,
}
#[pymethods]
impl PySource {
    #[getter]
    fn revision_id(&self) -> Option<&str> {
        self.inner.revision_id()
    }
    #[getter]
    fn object_id(&self) -> &str {
        self.inner.object_id()
    }
    #[getter]
    fn object_type(&self) -> &str {
        self.inner.object_type()
    }
    #[getter]
    fn writer(&self) -> &str {
        self.inner.writer()
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
    fn groups(&self) -> Vec<String> {
        self.inner.groups().to_vec()
    }
    #[getter]
    fn operation(&self) -> &str {
        self.inner.operation()
    }
    fn references(&self, object: &PyObject) -> bool {
        self.inner.references(&object.inner)
    }
    fn references_with_policy(&self, object: &PyObject, accepted_policy: &PyGovernance) -> bool {
        self.inner
            .references_with_policy(&object.inner, &accepted_policy.inner)
    }
}

/// Frozen owned view: dictionaries returned here are detached copies.
#[pyclass(frozen, module = "tn.governed", name = "DataState")]
pub(super) struct PyDataState {
    inner: DataObject,
}
#[pymethods]
impl PyDataState {
    #[getter]
    fn dataset_bindings(&self) -> PyResult<Vec<PyDatasetBinding>> {
        self.inner
            .dataset_bindings()
            .map(|items| {
                items
                    .into_iter()
                    .map(|inner| PyDatasetBinding { inner })
                    .collect()
            })
            .map_err(to_py)
    }
    #[getter]
    fn hidden_groups(&self) -> Vec<String> {
        self.inner
            .hidden_groups()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }
    #[getter]
    fn object_type(&self) -> &str {
        self.inner.object_type()
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.governance().clone(),
        }
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(&self.inner)
    }
    #[getter]
    fn sources(&self) -> Vec<PySource> {
        sources(&self.inner)
    }
    #[getter]
    fn revision(&self) -> u64 {
        self.inner.revision()
    }
    #[getter]
    fn has_unreleased_changes(&self) -> bool {
        self.inner.has_unreleased_changes()
    }
    #[getter]
    fn groups<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        codec::to_python(py, &self.inner.get_path(&[]).map_err(to_py)?)
    }
    #[getter]
    fn snapshot(&self) -> Option<PyObject> {
        self.inner
            .snapshot()
            .cloned()
            .map(|inner| PyObject { inner })
    }
}

#[pyclass(frozen, module = "tn.governed", name = "AdmissionContext")]
pub(super) struct PyAdmission {
    pub inner: OwnedAdmissionContext,
}
impl PyAdmission {
    pub(super) fn from_native(context: &tn_core::governed::AdmissionContext<'_>) -> Self {
        Self {
            inner: context.to_owned(),
        }
    }
}
#[pymethods]
impl PyAdmission {
    #[getter]
    fn object(&self) -> PyObject {
        PyObject {
            inner: self.inner.context().object().clone(),
        }
    }
    #[getter]
    fn writer(&self) -> String {
        self.inner.context().object().writer().to_owned()
    }
    #[getter]
    fn object_type(&self) -> String {
        self.inner.context().object().object_type().to_owned()
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.context().governance().clone(),
        }
    }
    #[getter]
    fn operation(&self) -> String {
        self.inner.context().operation().to_owned()
    }
    #[getter]
    fn purpose(&self) -> String {
        let context = self.inner.context();
        context
            .use_context()
            .map(UseContext::purpose)
            .unwrap_or(context.operation())
            .to_owned()
    }
    #[getter]
    fn use_context(&self) -> Option<PyUseContext> {
        self.inner
            .context()
            .use_context()
            .cloned()
            .map(|inner| PyUseContext { inner })
    }
    #[getter]
    fn groups(&self) -> Option<Vec<String>> {
        self.inner.context().groups().map(<[String]>::to_vec)
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        self.inner
            .context()
            .policies()
            .map(|items| {
                items
                    .into_iter()
                    .map(|inner| PyGovernance { inner })
                    .collect()
            })
            .map_err(to_py)
    }
    #[getter]
    fn sources(&self) -> PyResult<Vec<PySource>> {
        self.inner
            .context()
            .sources()
            .map(|items| items.into_iter().map(|inner| PySource { inner }).collect())
            .map_err(to_py)
    }
}

#[pyclass(frozen, module = "tn.governed", name = "AttachmentContext")]
pub(super) struct PyAttachment {
    authority: String,
    data: DataObject,
    policy: Governance,
}
#[pymethods]
impl PyAttachment {
    #[getter]
    fn authority(&self) -> &str {
        &self.authority
    }
    #[getter]
    fn data(&self) -> PyDataState {
        PyDataState {
            inner: self.data.clone(),
        }
    }
    #[getter]
    fn policy(&self) -> PyGovernance {
        PyGovernance {
            inner: self.policy.clone(),
        }
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(&self.data)
    }
}

#[pyclass(frozen, module = "tn.governed", name = "ReleaseContext")]
pub(super) struct PyRelease {
    writer: String,
    data: DataObject,
    object_type: String,
    purpose: String,
    destination: String,
    use_context: Option<UseContext>,
}
impl PyRelease {
    fn from_native(context: &tn_core::governed::ReleaseContext<'_>) -> Self {
        Self {
            writer: context.writer().to_owned(),
            data: context.data().clone(),
            object_type: context.object_type().to_owned(),
            purpose: context.purpose().to_owned(),
            destination: context.destination().to_owned(),
            use_context: context.use_context().cloned(),
        }
    }
}
#[pymethods]
impl PyRelease {
    #[getter]
    fn use_context(&self) -> Option<PyUseContext> {
        self.use_context.clone().map(|inner| PyUseContext { inner })
    }
    #[getter]
    fn writer(&self) -> &str {
        &self.writer
    }
    #[getter]
    fn data(&self) -> PyDataState {
        PyDataState {
            inner: self.data.clone(),
        }
    }
    #[getter]
    fn object_type(&self) -> &str {
        &self.object_type
    }
    #[getter]
    fn purpose(&self) -> &str {
        &self.purpose
    }
    #[getter]
    fn destination(&self) -> &str {
        &self.destination
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(&self.data)
    }
    #[getter]
    fn sources(&self) -> Vec<PySource> {
        sources(&self.data)
    }
}

#[pyclass(frozen, module = "tn.governed", name = "PublicationReport")]
pub(super) struct PyPublication {
    pub inner: PublicationReport,
}
#[pymethods]
impl PyPublication {
    #[getter]
    fn required_groups(&self) -> Vec<String> {
        self.inner.required_groups().to_vec()
    }
    #[getter]
    fn supported_groups(&self) -> Vec<String> {
        self.inner.supported_groups().to_vec()
    }
    #[getter]
    fn missing_groups(&self) -> Vec<String> {
        self.inner.missing_groups().to_vec()
    }
    #[getter]
    fn unavailable_groups(&self) -> Vec<String> {
        self.inner.unavailable_groups().to_vec()
    }
    #[getter]
    fn unknown_groups(&self) -> Vec<String> {
        self.inner.unknown_groups().to_vec()
    }
    #[getter]
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}

#[pyclass(frozen, module = "tn.governed", name = "DataObject")]
pub(super) struct PyData {
    inner: Arc<Mutex<DataObject>>,
    session: SessionState,
    default_group: String,
}
impl PyData {
    fn new(inner: DataObject, session: SessionState, default_group: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            session,
            default_group,
        }
    }
    fn read(&self) -> PyResult<DataObject> {
        self.inner
            .lock()
            .map(|v| v.clone())
            .map_err(|_| GovernedError::new_err("data lock poisoned"))
    }
    fn mutate<T>(&self, f: impl FnOnce(&mut DataObject) -> tn_core::Result<T>) -> PyResult<T> {
        let mut data = self
            .inner
            .lock()
            .map_err(|_| GovernedError::new_err("data lock poisoned"))?;
        f(&mut data).map_err(to_py)
    }
    fn checked<T>(
        &self,
        revision: u64,
        f: impl FnOnce(&mut DataObject) -> tn_core::Result<T>,
    ) -> PyResult<T> {
        let mut data = self
            .inner
            .lock()
            .map_err(|_| GovernedError::new_err("data lock poisoned"))?;
        if data.revision() != revision {
            return Err(GovernedError::new_err(
                "object changed during governance decision; evaluate its current state again",
            ));
        }
        f(&mut data).map_err(to_py)
    }

    fn release_with_session(
        &self,
        py: Python<'_>,
        publisher: &SessionState,
        use_context: Option<UseContext>,
        purpose: Option<&str>,
        to: &str,
        decide: &Bound<'_, PyAny>,
        object_type: Option<&str>,
    ) -> PyResult<PyObject> {
        let context = session(publisher)?;
        let mut candidate = self.read()?;
        let revision = candidate.revision();
        let object_type = object_type.unwrap_or(candidate.object_type()).to_owned();
        let callback = decide.clone().unbind();
        let mut callback_error = None;
        let result = py.allow_threads(|| {
            // Hold no object lock during application code. Once its decision is
            // current, keep the original locked through sealing and installation.
            let mut accepted_data = None;
            let decide_native = |native: &tn_core::governed::ReleaseContext<'_>| {
                native_decision(&mut callback_error, || {
                    let allow = Python::with_gil(|py| {
                        let allow = decision(
                            callback.bind(py),
                            Py::new(py, PyRelease::from_native(native))?.into_any(),
                        )?;
                        session(publisher)?;
                        Ok::<_, PyErr>(allow)
                    })?;
                    if allow {
                        let data = self
                            .inner
                            .lock()
                            .map_err(|_| GovernedError::new_err("data lock poisoned"))?;
                        if data.revision() != revision {
                            return Err(GovernedError::new_err(
                                "object changed during governance decision; evaluate its current state again",
                            ));
                        }
                        accepted_data = Some(data);
                    }
                    Ok(allow)
                })
            };
            let result = match use_context.as_ref() {
                Some(use_context) => context.release_for(
                    &mut candidate,
                    &object_type,
                    use_context,
                    to,
                    decide_native,
                ),
                None => context.release(
                    &mut candidate,
                    &object_type,
                    purpose.unwrap_or_default(),
                    to,
                    decide_native,
                ),
            };
            if result.is_ok() {
                if let Some(mut data) = accepted_data {
                    *data = candidate;
                }
            }
            result
        });
        if let Some(error) = callback_error {
            return Err(error);
        }
        result.map(|inner| PyObject { inner }).map_err(to_py)
    }
}
#[pymethods]
impl PyData {
    fn copy(&self) -> PyResult<Self> {
        guard(|| {
            Ok(Self::new(
                self.read()?,
                self.session.clone(),
                self.default_group.clone(),
            ))
        })
    }
    #[getter]
    fn dataset_bindings(&self) -> PyResult<Vec<PyDatasetBinding>> {
        self.read()?
            .dataset_bindings()
            .map(|items| {
                items
                    .into_iter()
                    .map(|inner| PyDatasetBinding { inner })
                    .collect()
            })
            .map_err(to_py)
    }
    fn retain_groups(&self, groups: Vec<String>) -> PyResult<()> {
        guard(|| self.mutate(|data| data.retain_groups(groups)))
    }
    #[getter]
    fn object_type(&self) -> PyResult<String> {
        Ok(self.read()?.object_type().to_owned())
    }
    #[getter]
    fn governance(&self) -> PyResult<PyGovernance> {
        Ok(PyGovernance {
            inner: self.read()?.governance().clone(),
        })
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(&self.read()?)
    }
    #[getter]
    fn sources(&self) -> PyResult<Vec<PySource>> {
        Ok(sources(&self.read()?))
    }
    #[getter]
    fn history(&self) -> PyResult<Vec<PyObject>> {
        Ok(self
            .read()?
            .history()
            .iter()
            .cloned()
            .map(|inner| PyObject { inner })
            .collect())
    }
    #[getter]
    fn snapshot(&self) -> PyResult<PyObject> {
        self.read()?
            .snapshot()
            .cloned()
            .map(|inner| PyObject { inner })
            .ok_or_else(|| {
                GovernedError::new_err("created or received object requires its signed snapshot")
            })
    }
    #[getter]
    fn hidden_groups(&self) -> PyResult<Vec<String>> {
        Ok(self
            .read()?
            .hidden_groups()
            .into_iter()
            .map(str::to_owned)
            .collect())
    }
    #[getter]
    fn register_error(&self) -> PyResult<Option<String>> {
        Ok(self.read()?.register_error().map(str::to_owned))
    }
    #[getter]
    fn revision(&self) -> PyResult<u64> {
        Ok(self.read()?.revision())
    }
    #[getter]
    fn has_unreleased_changes(&self) -> PyResult<bool> {
        Ok(self.read()?.has_unreleased_changes())
    }
    #[getter]
    fn state(&self) -> PyResult<PyDataState> {
        Ok(PyDataState {
            inner: self.read()?,
        })
    }
    #[getter]
    fn groups(slf: PyRef<'_, Self>) -> PyResult<Bound<'_, PyAny>> {
        slf.py()
            .import("tn.governed._views")?
            .getattr("view")?
            .call1((slf, Vec::<String>::new()))
    }
    #[getter]
    fn data(slf: PyRef<'_, Self>) -> PyResult<Bound<'_, PyAny>> {
        let name = slf.default_group.clone();
        slf.py()
            .import("tn.governed._views")?
            .getattr("view")?
            .call1((slf, vec![name]))
    }
    fn _get<'py>(&self, py: Python<'py>, keys: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| codec::to_python(py, &self.read()?.get_path(&path(keys)?).map_err(to_py)?))
    }
    fn _set(&self, keys: &Bound<'_, PyAny>, value: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let value = codec::to_json(value, 0)?;
            self.mutate(|data| data.set_path(&keys, value))
        })
    }
    fn _delete(&self, keys: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            self.mutate(|data| data.delete_path(&keys))
        })
    }
    fn _append(&self, keys: &Bound<'_, PyAny>, value: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let value = codec::to_json(value, 0)?;
            self.mutate(|data| data.append_path(&keys, value))
        })
    }
    fn _insert(
        &self,
        keys: &Bound<'_, PyAny>,
        index: isize,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let value = codec::to_json(value, 0)?;
            self.mutate(|data| {
                let mut list = data.get_path(&keys)?;
                let items = list.as_array_mut().ok_or_else(|| {
                    tn_core::Error::InvalidConfig("insert requires a list".to_owned())
                })?;
                let length = items.len() as isize;
                let index = if index < 0 {
                    (length + index).max(0)
                } else {
                    index.min(length)
                } as usize;
                items.insert(index, value);
                data.set_path(&keys, list)
            })
        })
    }
    fn _take<'py>(&self, py: Python<'py>, keys: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| {
            let keys = path(keys)?;
            let value = self.mutate(|data| {
                let value = data.get_path(&keys)?;
                data.delete_path(&keys)?;
                Ok(value)
            })?;
            codec::to_python(py, &value)
        })
    }
    fn _reverse(&self, keys: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            self.mutate(|data| {
                let mut value = data.get_path(&keys)?;
                value
                    .as_array_mut()
                    .ok_or_else(|| {
                        tn_core::Error::InvalidConfig("reverse requires a list".to_owned())
                    })?
                    .reverse();
                data.set_path(&keys, value)
            })
        })
    }
    fn _extend(&self, keys: &Bound<'_, PyAny>, values: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let values = codec::to_json(values, 0)?
                .as_array()
                .cloned()
                .ok_or_else(|| PyTypeError::new_err("extend requires an array"))?;
            self.mutate(|data| {
                let mut value = data.get_path(&keys)?;
                value
                    .as_array_mut()
                    .ok_or_else(|| {
                        tn_core::Error::InvalidConfig("extend requires a list".to_owned())
                    })?
                    .extend(values);
                data.set_path(&keys, value)
            })
        })
    }
    #[pyo3(signature=(keys, start, stop, step, values, delete))]
    fn _slice(
        &self,
        keys: &Bound<'_, PyAny>,
        start: Option<isize>,
        stop: Option<isize>,
        step: isize,
        values: &Bound<'_, PyAny>,
        delete: bool,
    ) -> PyResult<()> {
        guard(|| {
            if step == 0 {
                return Err(PyValueError::new_err("slice step cannot be zero"));
            }
            let keys = path(keys)?;
            let values = codec::to_json(values, 0)?
                .as_array()
                .cloned()
                .ok_or_else(|| PyTypeError::new_err("slice assignment requires an array"))?;
            self.mutate(|data| {
                let mut value = data.get_path(&keys)?;
                let items = value.as_array_mut().ok_or_else(|| {
                    tn_core::Error::InvalidConfig("slice requires a list".to_owned())
                })?;
                let n = items.len() as isize;
                let bound = |value: Option<isize>, default: isize| {
                    value
                        .map(|v| if v < 0 { n.saturating_add(v) } else { v })
                        .unwrap_or(default)
                        .clamp(
                            if step > 0 { 0 } else { -1 },
                            if step > 0 { n } else { n - 1 },
                        )
                };
                let start = bound(start, if step > 0 { 0 } else { n - 1 });
                let stop = bound(stop, if step > 0 { n } else { -1 });
                if step == 1 {
                    items.splice(
                        start as usize..stop.max(start) as usize,
                        if delete { Vec::new() } else { values },
                    );
                } else {
                    let mut indices = Vec::new();
                    let mut i = start;
                    while if step > 0 { i < stop } else { i > stop } {
                        indices.push(i as usize);
                        match i.checked_add(step) {
                            Some(next) => i = next,
                            None => break,
                        }
                    }
                    if delete {
                        indices.sort_unstable_by(|a, b| b.cmp(a));
                        for i in indices {
                            items.remove(i);
                        }
                    } else {
                        if indices.len() != values.len() {
                            return Err(tn_core::Error::InvalidConfig(
                                "extended slice assignment requires matching lengths".to_owned(),
                            ));
                        }
                        for (i, value) in indices.into_iter().zip(values) {
                            items[i] = value;
                        }
                    }
                }
                data.set_path(&keys, value)
            })
        })
    }
    fn include(&self, other: &Self) -> PyResult<()> {
        guard(|| {
            let other = other.read()?;
            self.mutate(|data| data.include(&other))
        })
    }
    #[pyo3(signature=(policy, *, decide))]
    fn attach(
        &self,
        py: Python<'_>,
        policy: &PyGovernance,
        decide: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        guard(|| {
            let context = session(&self.session)?;
            let before = self.read()?;
            let revision = before.revision();
            let policy = policy.inner.clone();
            let allow = decision(
                decide,
                Py::new(
                    py,
                    PyAttachment {
                        authority: context.did().to_owned(),
                        data: before,
                        policy: policy.clone(),
                    },
                )?
                .into_any(),
            )?;
            session(&self.session)?;
            py.allow_threads(|| {
                self.checked(revision, |data| context.attach(data, policy, |_| Ok(allow)))
            })
        })
    }
    #[pyo3(signature=(*, to, decide, purpose=None, r#use=None, object_type=None))]
    fn release(
        &self,
        py: Python<'_>,
        to: &str,
        decide: &Bound<'_, PyAny>,
        purpose: Option<&str>,
        r#use: Option<&PyUseContext>,
        object_type: Option<&str>,
    ) -> PyResult<PyObject> {
        guard(|| {
            let use_context = requested_use(purpose, r#use)?;
            self.release_with_session(
                py,
                &self.session,
                use_context,
                purpose,
                to,
                decide,
                object_type,
            )
        })
    }
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "DataObject(type={:?}, revision={})",
            self.object_type()?,
            self.revision()?
        ))
    }
}

pub(super) fn release(
    publisher: &PySession,
    data: &PyData,
    py: Python<'_>,
    use_context: &PyUseContext,
    to: &str,
    decide: &Bound<'_, PyAny>,
    object_type: Option<&str>,
) -> PyResult<PyObject> {
    guard(|| {
        data.release_with_session(
            py,
            &publisher.context,
            Some(use_context.inner.clone()),
            None,
            to,
            decide,
            object_type,
        )
    })
}

pub(super) fn create(
    session: &PySession,
    py: Python<'_>,
    fields: &Bound<'_, PyDict>,
    policy: &PyGovernance,
    object_type: &str,
    group: &str,
) -> PyResult<PyData> {
    guard(|| {
        let context = session.context()?;
        let fields = codec::fields(fields)?;
        let policy = policy.inner.clone();
        let inner = py
            .allow_threads(|| context.create_obj(object_type, policy, group, fields))
            .map_err(to_py)?;
        Ok(PyData::new(
            inner,
            session.context.clone(),
            group.to_owned(),
        ))
    })
}
pub(super) fn create_with_groups(
    session: &PySession,
    py: Python<'_>,
    groups: &Bound<'_, PyDict>,
    policy: &PyGovernance,
    object_type: &str,
    primary_group: &str,
) -> PyResult<PyData> {
    guard(|| {
        let context = session.context()?;
        let groups = codec::fields(groups)?;
        if !groups.contains_key(primary_group) {
            return Err(PyValueError::new_err(
                "primary_group must name a supplied business group",
            ));
        }
        let policy = policy.inner.clone();
        let inner = py
            .allow_threads(|| context.create_obj_with_groups(object_type, policy, groups))
            .map_err(to_py)?;
        Ok(PyData::new(
            inner,
            session.context.clone(),
            primary_group.to_owned(),
        ))
    })
}
pub(super) fn receive(
    session: &PySession,
    py: Python<'_>,
    wire: &Bound<'_, PyAny>,
    purpose: Option<&str>,
    use_context: Option<&PyUseContext>,
    groups: Vec<String>,
    selection: Option<&PyDatasetSelection>,
    decide: &Bound<'_, PyAny>,
) -> PyResult<PyData> {
    guard(|| {
        let use_context = requested_use(purpose, use_context)?;
        if selection.is_some() && use_context.is_none() {
            return Err(PyTypeError::new_err(
                "dataset selection requires a complete use",
            ));
        }
        let context = session.context()?;
        let wire = if let Ok(object) = wire.extract::<PyRef<'_, PyObject>>() {
            object.inner.wire().to_owned()
        } else {
            codec::wire(wire)?
        };
        let default_group = groups
            .first()
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        let callback = decide.clone().unbind();
        let selection = selection.map(|selection| selection.inner.clone());
        let mut callback_error = None;
        let result = py.allow_threads(|| {
            let decide_native = |native: &tn_core::governed::AdmissionContext<'_>| {
                native_decision(&mut callback_error, || {
                    Python::with_gil(|py| {
                        let allow = decision(
                            callback.bind(py),
                            Py::new(py, PyAdmission::from_native(native))?.into_any(),
                        )?;
                        session.context()?;
                        Ok(allow)
                    })
                })
            };
            match use_context.as_ref() {
                Some(use_context) => context.receive_for(
                    &wire,
                    use_context,
                    &groups,
                    selection.as_ref(),
                    decide_native,
                ),
                None => context.receive(&wire, purpose.unwrap_or_default(), &groups, decide_native),
            }
        });
        if let Some(error) = callback_error {
            return Err(error);
        }
        let inner = result.map_err(to_py)?;
        Ok(PyData::new(inner, session.context.clone(), default_group))
    })
}
pub(super) fn populate(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyData>()?;
    m.add_class::<PyDataState>()?;
    m.add_class::<PySource>()?;
    m.add_class::<PyAdmission>()?;
    m.add_class::<PyAttachment>()?;
    m.add_class::<PyRelease>()?;
    m.add_class::<PyPublication>()?;
    Ok(())
}
