//! Mutable governed values. Python callbacks run against detached state snapshots.
use super::objects::{PyGovernance, PyObject};
use super::session::PySession;
use super::{codec, guard, to_py, GovernedError, SessionClosed};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tn_core::governed::{DataObject, Governance, PublicationReport, SourceReference};
use tn_core::runtime::Objects;

type SessionState = Arc<Mutex<Option<Arc<Objects<'static>>>>>;

fn session(state: &SessionState) -> PyResult<Arc<Objects<'static>>> {
    state
        .lock()
        .map_err(|_| GovernedError::new_err("session lock poisoned"))?
        .clone()
        .ok_or_else(|| SessionClosed::new_err("this governed session is closed"))
}
fn decision(callback: &Bound<'_, PyAny>, context: Py<PyAny>) -> PyResult<bool> {
    let answer = callback.call1((context,))?;
    if !answer.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err("governance decision must return bool"));
    }
    answer.extract()
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
}

/// Frozen owned view: dictionaries returned here are detached copies.
#[pyclass(frozen, module = "tn.governed", name = "DataState")]
pub(super) struct PyDataState {
    inner: DataObject,
}
#[pymethods]
impl PyDataState {
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
    object: tn_core::governed::GovernedObject,
    governance: Governance,
    operation: String,
}
#[pymethods]
impl PyAdmission {
    #[getter]
    fn object(&self) -> PyObject {
        PyObject {
            inner: self.object.clone(),
        }
    }
    #[getter]
    fn writer(&self) -> &str {
        self.object.writer()
    }
    #[getter]
    fn object_type(&self) -> &str {
        self.object.object_type()
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.governance.clone(),
        }
    }
    #[getter]
    fn operation(&self) -> &str {
        &self.operation
    }
    #[getter]
    fn purpose(&self) -> &str {
        &self.operation
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        self.governance
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
        self.governance
            .source_references()
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
}
#[pymethods]
impl PyRelease {
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
}
#[pymethods]
impl PyData {
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
    #[pyo3(signature=(*, to, purpose, decide, object_type=None))]
    fn release(
        &self,
        py: Python<'_>,
        to: &str,
        purpose: &str,
        decide: &Bound<'_, PyAny>,
        object_type: Option<&str>,
    ) -> PyResult<PyObject> {
        guard(|| {
            if to.trim().is_empty() || purpose.trim().is_empty() {
                return Err(PyValueError::new_err(
                    "release requires purpose and destination",
                ));
            }
            let context = session(&self.session)?;
            let before = self.read()?;
            let revision = before.revision();
            let object_type = object_type.unwrap_or(before.object_type()).to_owned();
            let allow = decision(
                decide,
                Py::new(
                    py,
                    PyRelease {
                        writer: context.did().to_owned(),
                        data: before,
                        object_type: object_type.clone(),
                        purpose: purpose.to_owned(),
                        destination: to.to_owned(),
                    },
                )?
                .into_any(),
            )?;
            session(&self.session)?;
            py.allow_threads(|| {
                self.checked(revision, |data| {
                    context.release(data, &object_type, purpose, to, |_| Ok(allow))
                })
            })
            .map(|inner| PyObject { inner })
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
pub(super) fn receive(
    session: &PySession,
    py: Python<'_>,
    wire: &Bound<'_, PyAny>,
    purpose: &str,
    groups: Vec<String>,
    decide: &Bound<'_, PyAny>,
) -> PyResult<PyData> {
    guard(|| {
        if purpose.trim().is_empty() {
            return Err(PyValueError::new_err("purpose must be nonempty"));
        }
        let context = session.context()?;
        let wire = if let Ok(object) = wire.extract::<PyRef<'_, PyObject>>() {
            object.inner.wire().to_owned()
        } else {
            codec::wire(wire)?
        };
        let (reader, view) = py
            .allow_threads(|| {
                let object = tn_core::governed::GovernedObject::parse(&wire)?;
                let reader = context.reader()?;
                let view = reader.governance(&object)?;
                Ok::<_, tn_core::Error>((reader, view))
            })
            .map_err(to_py)?;
        let allow = decision(
            decide,
            Py::new(
                py,
                PyAdmission {
                    object: view.object().clone(),
                    governance: view.governance().clone(),
                    operation: purpose.to_owned(),
                },
            )?
            .into_any(),
        )?;
        session.context()?;
        let default_group = groups
            .first()
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        let inner = py
            .allow_threads(|| {
                let admitted = view.authorize_with(purpose, |_| Ok(allow))?;
                DataObject::from_opened(reader.open(&admitted, &groups)?)
            })
            .map_err(to_py)?;
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
