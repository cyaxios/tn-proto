//! Python invokes the native bounded source-graph verifier.
use pyo3::prelude::*;
use tn_core::governed::{LineageVerifier, VerifiedLineage};

use super::dataset::PyDatasetCatalog;
use super::reader::PyGovernanceView;
use super::revision::PyPolicyDag;
use super::{guard, to_py};

#[pyclass(frozen, module = "tn.governed", name = "VerifiedLineage")]
pub(super) struct PyVerifiedLineage {
    inner: VerifiedLineage,
}

#[pymethods]
impl PyVerifiedLineage {
    #[getter]
    fn object_ids(&self) -> Vec<String> {
        self.inner.object_ids().to_vec()
    }

    #[getter]
    fn source_object_ids(&self) -> Vec<String> {
        self.inner.source_object_ids().to_vec()
    }
}

#[pyclass(frozen, module = "tn.governed", name = "LineageVerifier")]
pub(super) struct PyLineageVerifier {
    inner: LineageVerifier,
}

#[pymethods]
impl PyLineageVerifier {
    #[new]
    #[pyo3(signature = (*, max_objects=1024, max_depth=64))]
    fn new(max_objects: usize, max_depth: usize) -> PyResult<Self> {
        guard(|| {
            LineageVerifier::new(max_objects, max_depth)
                .map(|inner| Self { inner })
                .map_err(to_py)
        })
    }

    fn verify(
        &self,
        view: &PyGovernanceView,
        catalog: &PyDatasetCatalog,
        dag: &PyPolicyDag,
        resolve: &Bound<'_, PyAny>,
    ) -> PyResult<PyVerifiedLineage> {
        guard(|| {
            let catalog = catalog.snapshot()?;
            let dag = dag.snapshot()?;
            let mut python_error = None;
            let result = self.inner.verify(&view.inner, &catalog, &dag, |id| {
                let answer = resolve.call1((id,)).and_then(|value| {
                    value
                        .extract::<PyRef<'_, PyGovernanceView>>()
                        .map(|view| view.inner.clone())
                });
                match answer {
                    Ok(view) => Ok(view),
                    Err(error) => {
                        python_error = Some(error);
                        Err(tn_core::Error::InvalidConfig(
                            "lineage resolver failed".into(),
                        ))
                    }
                }
            });
            if let Some(error) = python_error {
                return Err(error);
            }
            result
                .map(|inner| PyVerifiedLineage { inner })
                .map_err(to_py)
        })
    }
}
