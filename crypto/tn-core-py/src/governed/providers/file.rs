use super::*;
use std::path::PathBuf;

#[pyclass(frozen, module = "tn.providers", name = "FileKeyStore")]
pub struct PyFileKeyStore {
    pub inner: Arc<FileKeyStore>,
}
#[pymethods]
impl PyFileKeyStore {
    #[staticmethod]
    #[pyo3(signature=(path, application, groups, *, cipher="btn"))]
    fn create(
        py: Python<'_>,
        path: PathBuf,
        application: &str,
        groups: Vec<String>,
        cipher: &str,
    ) -> PyResult<Self> {
        let names: Vec<_> = groups.iter().map(String::as_str).collect();
        py.allow_threads(|| FileKeyStore::create(&path, application, &names, cipher))
            .map(|inner| Self {
                inner: Arc::new(inner),
            })
            .map_err(to_py)
    }
    #[staticmethod]
    fn open(py: Python<'_>, path: PathBuf) -> PyResult<Self> {
        py.allow_threads(|| FileKeyStore::open(&path))
            .map(|inner| Self {
                inner: Arc::new(inner),
            })
            .map_err(to_py)
    }
    fn resolve(&self, py: Python<'_>, request: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        if let Ok(application) = request.extract::<String>() {
            let inner =
                IdentityProvider::resolve(self.inner.as_ref(), &application).map_err(to_py)?;
            Ok(Py::new(py, PyIdentity { inner })?.into_any())
        } else {
            let identity: PyRef<PyIdentity> = request.extract()?;
            let inner =
                KeyProvider::resolve(self.inner.as_ref(), &identity.inner).map_err(to_py)?;
            Ok(Py::new(py, PyKeySet { inner })?.into_any())
        }
    }
    #[getter]
    fn application(&self) -> &str {
        self.inner.application()
    }
    #[getter]
    fn cipher(&self) -> &str {
        self.inner.cipher()
    }
    #[getter]
    fn path(&self) -> PathBuf {
        self.inner.path().to_owned()
    }
    #[getter]
    fn groups(&self) -> Vec<String> {
        self.inner.groups().into_iter().map(str::to_owned).collect()
    }
}
