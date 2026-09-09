//! Signed revision records and authority callbacks over the canonical Rust DAG.

use std::sync::{Mutex, MutexGuard};

use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::PyBool;
use tn_core::governed::{
    PolicyDag, PolicyParent, PolicyRelation, PolicyRevision, PolicyRevisionDraft,
};

use super::objects::{PyDraft, PyGovernance, PyObject};
use super::reader::PyOpened;
use super::{guard, to_py, GovernedError};

/// The signed relationship declared by a revision to its accepted parent.
#[pyclass(frozen, eq, module = "tn.governed", name = "PolicyRelation")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PyPolicyRelation {
    Revise,
    Extend,
    Combine,
}

impl From<PyPolicyRelation> for PolicyRelation {
    fn from(value: PyPolicyRelation) -> Self {
        match value {
            PyPolicyRelation::Revise => Self::Revise,
            PyPolicyRelation::Extend => Self::Extend,
            PyPolicyRelation::Combine => Self::Combine,
        }
    }
}

impl From<PolicyRelation> for PyPolicyRelation {
    fn from(value: PolicyRelation) -> Self {
        match value {
            PolicyRelation::Revise => Self::Revise,
            PolicyRelation::Extend => Self::Extend,
            PolicyRelation::Combine => Self::Combine,
        }
    }
}

/// Read-only authenticated parent identity and declared relationship.
#[pyclass(frozen, module = "tn.governed", name = "PolicyParent")]
pub(super) struct PyPolicyParent {
    inner: PolicyParent,
}

#[pymethods]
impl PyPolicyParent {
    #[getter]
    fn revision_id(&self) -> &str {
        self.inner.revision_id()
    }

    #[getter]
    fn relation(&self) -> PyPolicyRelation {
        self.inner.relation().into()
    }
}

/// Immutable normalized policy record before ordinary governed signing.
#[pyclass(frozen, module = "tn.governed", name = "PolicyRevisionDraft")]
pub(super) struct PyPolicyRevisionDraft {
    inner: PolicyRevisionDraft,
}

#[pymethods]
impl PyPolicyRevisionDraft {
    #[staticmethod]
    fn from_markdown(
        authority: &str,
        markdown: &str,
        policy_id: &str,
        event_type: &str,
        scope: &str,
    ) -> PyResult<Self> {
        guard(|| {
            PolicyRevisionDraft::from_markdown(authority, markdown, policy_id, event_type, scope)
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }

    /// Return a new draft with one additional signed parent relationship.
    fn parent(&self, revision_id: &str, relation: &PyPolicyRelation) -> PyResult<Self> {
        guard(|| {
            self.inner
                .clone()
                .parent(revision_id, (*relation).into())
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }

    /// Build the governed draft for Session.seal under its administration contract.
    fn into_draft(&self, administration_contract: &PyGovernance) -> PyResult<PyDraft> {
        guard(|| {
            self.inner
                .clone()
                .into_draft(administration_contract.inner.clone())
                .map(|inner| PyDraft { inner })
                .map_err(to_py)
        })
    }
}

/// A structurally valid revision decoded from an admitted and opened TN object.
#[pyclass(frozen, module = "tn.governed", name = "PolicyRevision")]
pub(super) struct PyPolicyRevision {
    inner: PolicyRevision,
}

#[pymethods]
impl PyPolicyRevision {
    #[staticmethod]
    fn from_opened(opened: &PyOpened) -> PyResult<Self> {
        guard(|| {
            PolicyRevision::from_opened(&opened.inner)
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
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
    fn scope(&self) -> &str {
        self.inner.scope()
    }

    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.governance().clone(),
        }
    }

    #[getter]
    fn parents(&self) -> Vec<PyPolicyParent> {
        self.inner
            .parents()
            .iter()
            .cloned()
            .map(|inner| PyPolicyParent { inner })
            .collect()
    }

    #[getter]
    fn object(&self) -> PyObject {
        PyObject {
            inner: self.inner.object().clone(),
        }
    }
}

#[derive(Clone, Default)]
struct DagState {
    dag: PolicyDag,
    version: u64,
}

/// Append-only accepted policy history with explicit application decisions.
#[pyclass(frozen, module = "tn.governed", name = "PolicyDag")]
pub(super) struct PyPolicyDag {
    state: Mutex<DagState>,
}

impl PyPolicyDag {
    pub(super) fn snapshot(&self) -> PyResult<PolicyDag> {
        Ok(self.lock()?.dag.clone())
    }

    fn lock(&self) -> PyResult<MutexGuard<'_, DagState>> {
        self.state
            .lock()
            .map_err(|_| GovernedError::new_err("policy history lock poisoned"))
    }

    fn unchanged(current: &DagState, version: u64) -> PyResult<()> {
        if current.version != version {
            return Err(PyRuntimeError::new_err(
                "policy history changed during governance decision; evaluate its current state again",
            ));
        }
        Ok(())
    }
}

// Core callbacks use tn_core::Error. Retain the original Python exception and
// short-circuit the native operation; the sentinel is never exposed in Python.
fn callback_answer(
    result: PyResult<Bound<'_, PyAny>>,
    failure: &mut Option<PyErr>,
    operation: &str,
) -> tn_core::Result<bool> {
    let result = result.and_then(|answer| {
        if !answer.is_instance_of::<PyBool>() {
            return Err(PyTypeError::new_err("policy decision must return bool"));
        }
        answer.extract()
    });
    result.map_err(|error| {
        *failure = Some(error);
        tn_core::Error::UseDenied {
            operation: operation.to_owned(),
        }
    })
}

#[pymethods]
impl PyPolicyDag {
    #[new]
    fn new() -> Self {
        Self {
            state: Mutex::new(DagState::default()),
        }
    }

    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.lock()?.dag.len()))
    }

    fn get(&self, revision_id: &str) -> PyResult<Option<PyPolicyRevision>> {
        guard(|| {
            Ok(self
                .lock()?
                .dag
                .get(revision_id)
                .cloned()
                .map(|inner| PyPolicyRevision { inner }))
        })
    }

    /// Admit only when authorize(revision, parent) approves every root or edge.
    /// parent is None for roots, otherwise (PolicyParent, accepted PolicyRevision).
    /// Callback errors propagate; concurrent or reentrant changes require retry.
    fn admit(&self, revision: &PyPolicyRevision, authorize: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let mut candidate = self.lock()?.clone();
            let mut failure = None;
            let result = candidate
                .dag
                .admit(revision.inner.clone(), |revision, parent| {
                    callback_answer(
                        authorize.call1((
                            PyPolicyRevision {
                                inner: revision.clone(),
                            },
                            parent.map(|(edge, accepted)| {
                                (
                                    PyPolicyParent {
                                        inner: edge.clone(),
                                    },
                                    PyPolicyRevision {
                                        inner: accepted.clone(),
                                    },
                                )
                            }),
                        )),
                        &mut failure,
                        "policy.update",
                    )
                });
            if let Some(error) = failure {
                return Err(error);
            }
            result.map_err(to_py)?;
            let mut current = self.lock()?;
            Self::unchanged(&current, candidate.version)?;
            candidate.version = candidate
                .version
                .checked_add(1)
                .ok_or_else(|| PyRuntimeError::new_err("policy history version exhausted"))?;
            *current = candidate;
            Ok(())
        })
    }

    /// Select one exact accepted revision and scope after applicable(revision).
    fn select(
        &self,
        revision_id: &str,
        scope: &str,
        applicable: &Bound<'_, PyAny>,
    ) -> PyResult<PyGovernance> {
        guard(|| {
            let snapshot = self.lock()?.clone();
            let mut failure = None;
            let result = snapshot.dag.select(revision_id, scope, |revision| {
                callback_answer(
                    applicable.call1((PyPolicyRevision {
                        inner: revision.clone(),
                    },)),
                    &mut failure,
                    "policy.select",
                )
            });
            if let Some(error) = failure {
                return Err(error);
            }
            let inner = result.map_err(to_py)?;
            Self::unchanged(&*self.lock()?, snapshot.version)?;
            Ok(PyGovernance { inner })
        })
    }

    /// Resolve the carried binding and exact contract against accepted history.
    fn resolve(&self, governance: &PyGovernance, scope: &str) -> PyResult<PyPolicyRevision> {
        guard(|| {
            self.lock()?
                .dag
                .resolve(&governance.inner, scope)
                .cloned()
                .map(|inner| PyPolicyRevision { inner })
                .map_err(to_py)
        })
    }
}
