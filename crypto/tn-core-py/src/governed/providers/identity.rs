use super::*;

#[pyclass(frozen, module = "tn.providers", name = "ApplicationIdentity")]
#[derive(Clone)]
pub struct PyIdentity {
    pub inner: ApplicationIdentity,
}
#[pymethods]
impl PyIdentity {
    #[getter]
    fn application(&self) -> &str {
        self.inner.application()
    }
    #[getter]
    fn did(&self) -> &str {
        self.inner.did()
    }
}

#[pyclass(frozen, module = "tn.providers", name = "LocalIdentity")]
pub struct PyLocalIdentity {
    pub inner: Arc<LocalIdentity>,
}
#[pymethods]
impl PyLocalIdentity {
    #[staticmethod]
    fn from_private_bytes(application: &str, seed: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Arc::new(LocalIdentity::from_private_bytes(application, seed).map_err(to_py)?),
        })
    }
    #[new]
    fn new(application: &str) -> PyResult<Self> {
        Ok(Self {
            inner: Arc::new(LocalIdentity::generate(application).map_err(to_py)?),
        })
    }
    fn resolve(&self, application: &str) -> PyResult<PyIdentity> {
        Ok(PyIdentity {
            inner: self.inner.resolve(application).map_err(to_py)?,
        })
    }
}
pub struct IdentityBridge(pub Py<PyAny>);
impl IdentityProvider for IdentityBridge {
    fn resolve(&self, application: &str) -> tn_core::Result<ApplicationIdentity> {
        Python::with_gil(|py| {
            self.0
                .call_method1(py, "resolve", (application,))?
                .extract::<PyRef<PyIdentity>>(py)
                .map(|v| v.inner.clone())
        })
        .map_err(provider_error)
    }
}
