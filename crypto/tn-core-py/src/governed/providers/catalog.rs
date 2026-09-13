use super::*;

#[pyclass(frozen, module = "tn.providers", name = "CatalogRequest")]
#[derive(Clone)]
pub struct PyCatalogRequest {
    pub inner: CatalogRequest,
}
#[pymethods]
impl PyCatalogRequest {
    #[new]
    fn new(dataset: String, edition: String, use_context: &PyUseContext) -> PyResult<Self> {
        CatalogRequest::new(dataset, edition, use_context.inner.clone())
            .map(|inner| Self { inner })
            .map_err(to_py)
    }
    #[getter]
    fn dataset(&self) -> &str {
        &self.inner.dataset
    }
    #[getter]
    fn edition(&self) -> &str {
        &self.inner.edition
    }
    #[getter]
    fn use_context(&self) -> PyUseContext {
        PyUseContext {
            inner: self.inner.use_context.clone(),
        }
    }
}
#[pyclass(frozen, module = "tn.providers", name = "CatalogEntry")]
#[derive(Clone)]
pub struct PyCatalogEntry {
    pub inner: CatalogEntry,
}
#[pymethods]
impl PyCatalogEntry {
    #[new]
    fn new(publication: &PyObject, selection: &super::super::dataset::PyDatasetSelection) -> Self {
        Self {
            inner: CatalogEntry {
                publication: publication.inner.clone(),
                selection: selection.inner.clone(),
            },
        }
    }
    #[getter]
    fn publication(&self) -> PyObject {
        PyObject {
            inner: self.inner.publication.clone(),
        }
    }
    #[getter]
    fn selection(&self) -> super::super::dataset::PyDatasetSelection {
        super::super::dataset::PyDatasetSelection {
            inner: self.inner.selection.clone(),
        }
    }
}
#[pyclass(frozen, module = "tn.providers", name = "EditionCatalog")]
pub struct PyEditionCatalog {
    pub inner: Arc<EditionCatalog>,
}
#[pymethods]
impl PyEditionCatalog {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(EditionCatalog::new()),
        }
    }
    fn insert(&self, entry: &PyCatalogEntry) -> PyResult<()> {
        self.inner.insert(entry.inner.clone()).map_err(to_py)
    }
    fn resolve(&self, request: &PyCatalogRequest) -> PyResult<PyCatalogEntry> {
        Ok(PyCatalogEntry {
            inner: self.inner.resolve(&request.inner).map_err(to_py)?,
        })
    }
}
pub struct CatalogBridge(pub Py<PyAny>);
impl CatalogProvider for CatalogBridge {
    fn resolve(&self, request: &CatalogRequest) -> tn_core::Result<CatalogEntry> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    "resolve",
                    (PyCatalogRequest {
                        inner: request.clone(),
                    },),
                )?
                .extract::<PyRef<PyCatalogEntry>>(py)
                .map(|v| v.inner.clone())
        })
        .map_err(provider_error)
    }
}
