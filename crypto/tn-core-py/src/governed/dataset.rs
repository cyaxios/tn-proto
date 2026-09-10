//! Thin Python views over canonical Rust dataset records and accepted selections.

use std::sync::{Mutex, MutexGuard};

use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::PyBool;
use tn_core::governed::{
    ContractBinding, DatasetBinding, DatasetCatalog, DatasetEdition, DatasetEditionDraft,
    DatasetSelection, EvaluatorArtifactSet,
};

use super::objects::{PyDraft, PyGovernance, PyObject};
use super::reader::{PyGovernanceView, PyOpened};
use super::revision::PyPolicyDag;
use super::use_context::PyUseContext;
use super::{codec, guard, to_py, GovernedError};

#[pyclass(frozen, eq, module = "tn.governed", name = "ContractBinding")]
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PyContractBinding {
    pub inner: ContractBinding,
}

#[pymethods]
impl PyContractBinding {
    #[new]
    fn new(revision_id: &str, scope: &str) -> PyResult<Self> {
        guard(|| {
            ContractBinding::new(revision_id, scope)
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }
    #[getter]
    fn revision_id(&self) -> &str {
        self.inner.revision_id()
    }
    #[getter]
    fn scope(&self) -> &str {
        self.inner.scope()
    }
}

#[pyclass(frozen, eq, module = "tn.governed", name = "EvaluatorArtifactSet")]
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PyEvaluatorArtifactSet {
    pub inner: EvaluatorArtifactSet,
}

#[pymethods]
impl PyEvaluatorArtifactSet {
    #[new]
    fn new(
        policy_revision: &str,
        compiled_policy_sha256: &str,
        profile_sha256: &str,
        wasm_sha256: &str,
        data_sha256: &str,
    ) -> PyResult<Self> {
        guard(|| {
            EvaluatorArtifactSet::new(
                policy_revision,
                compiled_policy_sha256,
                profile_sha256,
                wasm_sha256,
                data_sha256,
            )
            .map(|inner| Self { inner })
            .map_err(to_py)
        })
    }
    #[getter]
    fn policy_revision(&self) -> &str {
        self.inner.policy_revision()
    }
    #[getter]
    fn compiled_policy_sha256(&self) -> &str {
        self.inner.compiled_policy_sha256()
    }
    #[getter]
    fn profile_sha256(&self) -> &str {
        self.inner.profile_sha256()
    }
    #[getter]
    fn wasm_sha256(&self) -> &str {
        self.inner.wasm_sha256()
    }
    #[getter]
    fn data_sha256(&self) -> &str {
        self.inner.data_sha256()
    }
}

/// Read-only origin declaration. It has no arbitrary Python constructor.
#[pyclass(frozen, eq, module = "tn.governed", name = "DatasetBinding")]
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PyDatasetBinding {
    pub inner: DatasetBinding,
}

#[pymethods]
impl PyDatasetBinding {
    #[getter]
    fn dataset(&self) -> &str {
        self.inner.dataset()
    }
    #[getter]
    fn edition(&self) -> &str {
        self.inner.edition()
    }
    #[getter]
    fn source_object_id(&self) -> &str {
        self.inner.source_object_id()
    }
    #[getter]
    fn edition_record_id(&self) -> &str {
        self.inner.edition_record_id()
    }
    #[getter]
    fn contracts(&self) -> Vec<PyContractBinding> {
        self.inner
            .contracts()
            .iter()
            .cloned()
            .map(|inner| PyContractBinding { inner })
            .collect()
    }
    #[getter]
    fn fields<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| {
            codec::to_python(
                py,
                &serde_json::to_value(&self.inner).map_err(|e| to_py(e.into()))?,
            )
        })
    }
}

#[pyclass(frozen, module = "tn.governed", name = "DatasetEditionDraft")]
pub(super) struct PyDatasetEditionDraft {
    inner: DatasetEditionDraft,
}

#[pymethods]
impl PyDatasetEditionDraft {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        dataset: &str,
        edition: &str,
        source: &PyObject,
        source_groups: Vec<String>,
        contracts: Vec<PyRef<'_, PyContractBinding>>,
        eligible_uses: Vec<PyRef<'_, PyUseContext>>,
        grant_ref: &str,
        evaluator_artifacts: Vec<PyRef<'_, PyEvaluatorArtifactSet>>,
    ) -> PyResult<Self> {
        guard(|| {
            DatasetEditionDraft::new(
                dataset,
                edition,
                &source.inner,
                source_groups,
                contracts.iter().map(|item| item.inner.clone()).collect(),
                eligible_uses
                    .iter()
                    .map(|item| item.inner.clone())
                    .collect(),
                grant_ref,
                evaluator_artifacts
                    .iter()
                    .map(|item| item.inner.clone())
                    .collect(),
            )
            .map(|inner| Self { inner })
            .map_err(to_py)
        })
    }
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

#[pyclass(frozen, module = "tn.governed", name = "DatasetEdition")]
pub(super) struct PyDatasetEdition {
    pub inner: DatasetEdition,
}

#[pymethods]
impl PyDatasetEdition {
    #[staticmethod]
    fn from_opened(opened: &PyOpened) -> PyResult<Self> {
        guard(|| {
            DatasetEdition::from_opened(&opened.inner)
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
    fn dataset(&self) -> &str {
        self.inner.dataset()
    }
    #[getter]
    fn edition(&self) -> &str {
        self.inner.edition()
    }
    #[getter]
    fn source_object_id(&self) -> &str {
        self.inner.source_object_id()
    }
    #[getter]
    fn source_writer(&self) -> &str {
        self.inner.source_writer()
    }
    #[getter]
    fn source_type(&self) -> &str {
        self.inner.source_type()
    }
    #[getter]
    fn source_groups(&self) -> Vec<String> {
        self.inner.source_groups().to_vec()
    }
    #[getter]
    fn contracts(&self) -> Vec<PyContractBinding> {
        self.inner
            .contracts()
            .iter()
            .cloned()
            .map(|inner| PyContractBinding { inner })
            .collect()
    }
    #[getter]
    fn eligible_uses(&self) -> Vec<PyUseContext> {
        self.inner
            .eligible_uses()
            .iter()
            .cloned()
            .map(|inner| PyUseContext { inner })
            .collect()
    }
    #[getter]
    fn grant_ref(&self) -> &str {
        self.inner.grant_ref()
    }
    #[getter]
    fn evaluator_artifacts(&self) -> Vec<PyEvaluatorArtifactSet> {
        self.inner
            .evaluator_artifacts()
            .iter()
            .cloned()
            .map(|inner| PyEvaluatorArtifactSet { inner })
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
struct CatalogState {
    catalog: DatasetCatalog,
    version: u64,
}

#[pyclass(frozen, module = "tn.governed", name = "DatasetCatalog")]
pub(super) struct PyDatasetCatalog {
    state: Mutex<CatalogState>,
}

impl PyDatasetCatalog {
    fn lock(&self) -> PyResult<MutexGuard<'_, CatalogState>> {
        self.state
            .lock()
            .map_err(|_| GovernedError::new_err("dataset catalog lock poisoned"))
    }
    pub(super) fn snapshot(&self) -> PyResult<DatasetCatalog> {
        Ok(self.lock()?.catalog.clone())
    }
}

#[pymethods]
impl PyDatasetCatalog {
    #[new]
    fn new() -> Self {
        Self {
            state: Mutex::new(CatalogState::default()),
        }
    }
    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.lock()?.catalog.len()))
    }
    fn get(&self, record_id: &str) -> PyResult<Option<PyDatasetEdition>> {
        guard(|| {
            Ok(self
                .lock()?
                .catalog
                .get(record_id)
                .cloned()
                .map(|inner| PyDatasetEdition { inner }))
        })
    }
    /// Run application authority against a detached record; commit only unchanged catalog state.
    fn admit(
        &self,
        edition: &PyDatasetEdition,
        dag: &PyPolicyDag,
        authorize: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        guard(|| {
            let mut candidate = self.lock()?.clone();
            let dag = dag.snapshot()?;
            let mut failure = None;
            let result = candidate
                .catalog
                .admit(edition.inner.clone(), &dag, |record| {
                    authorize
                        .call1((PyDatasetEdition {
                            inner: record.clone(),
                        },))
                        .and_then(|answer| {
                            if !answer.is_instance_of::<PyBool>() {
                                return Err(PyTypeError::new_err(
                                    "catalog decision must return bool",
                                ));
                            }
                            answer.extract::<bool>()
                        })
                        .map_err(|error| {
                            failure = Some(error);
                            tn_core::Error::UseDenied {
                                operation: "dataset.admit".to_owned(),
                            }
                        })
                });
            if let Some(error) = failure {
                return Err(error);
            }
            result.map_err(to_py)?;
            let mut current = self.lock()?;
            if current.version != candidate.version {
                return Err(PyRuntimeError::new_err("dataset catalog changed during authority decision; evaluate its current state again"));
            }
            candidate.version = candidate
                .version
                .checked_add(1)
                .ok_or_else(|| PyRuntimeError::new_err("dataset catalog version exhausted"))?;
            *current = candidate;
            Ok(())
        })
    }
    fn select(
        &self,
        dataset: &str,
        edition: &str,
        record_id: &str,
        use_context: &PyUseContext,
    ) -> PyResult<PyDatasetSelection> {
        guard(|| {
            self.lock()?
                .catalog
                .select(dataset, edition, record_id, &use_context.inner)
                .map(|inner| PyDatasetSelection { inner })
                .map_err(to_py)
        })
    }
    fn verify_binding(&self, binding: &PyDatasetBinding, dag: &PyPolicyDag) -> PyResult<()> {
        guard(|| {
            self.snapshot()?
                .verify_binding(&binding.inner, &dag.snapshot()?)
                .map_err(to_py)
        })
    }
    fn accepts(&self, context: &super::data::PyAdmission, dag: &PyPolicyDag) -> PyResult<bool> {
        guard(|| {
            let catalog = self.snapshot()?;
            let dag = dag.snapshot()?;
            catalog
                .accepts(&context.inner.context(), &dag)
                .map_err(to_py)
        })
    }
}

/// Only a native catalog can produce this immutable accepted selection.
#[pyclass(frozen, module = "tn.governed", name = "DatasetSelection")]
pub(super) struct PyDatasetSelection {
    pub inner: DatasetSelection,
}

#[pymethods]
impl PyDatasetSelection {
    #[getter]
    fn record(&self) -> PyDatasetEdition {
        PyDatasetEdition {
            inner: self.inner.record().clone(),
        }
    }
    #[getter]
    fn use_context(&self) -> PyUseContext {
        PyUseContext {
            inner: self.inner.use_context().clone(),
        }
    }
    #[getter]
    fn binding(&self) -> PyDatasetBinding {
        PyDatasetBinding {
            inner: self.inner.binding(),
        }
    }
    #[getter]
    fn dataset(&self) -> &str {
        self.inner.record().dataset()
    }
    #[getter]
    fn edition(&self) -> &str {
        self.inner.record().edition()
    }
    #[getter]
    fn source_object_id(&self) -> &str {
        self.inner.source_object_id()
    }
    #[getter]
    fn edition_record_id(&self) -> &str {
        self.inner.edition_record_id()
    }
    fn verify_source(
        &self,
        view: &PyGovernanceView,
        use_context: &PyUseContext,
        groups: Vec<String>,
    ) -> PyResult<()> {
        guard(|| {
            self.inner
                .verify_source(&view.inner, &use_context.inner, &groups)
                .map_err(to_py)
        })
    }
}
