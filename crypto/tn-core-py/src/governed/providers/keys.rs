use super::*;

#[pyclass(frozen, module = "tn.providers", name = "GroupCapability")]
#[derive(Clone)]
pub struct PyGroupCapability {
    pub inner: GroupCapability,
}
#[pymethods]
impl PyGroupCapability {
    #[staticmethod]
    fn hibe(
        group: &str,
        public: &[u8],
        path: &str,
        readers: Vec<Vec<u8>>,
        index: [u8; 32],
    ) -> PyResult<Self> {
        GroupCapability::hibe(group, public, path, &readers, index)
            .map(|inner| Self { inner })
            .map_err(to_py)
    }
    #[staticmethod]
    fn jwe(
        group: &str,
        recipients: Vec<[u8; 32]>,
        readers: Vec<[u8; 32]>,
        index: [u8; 32],
    ) -> PyResult<Self> {
        GroupCapability::jwe(group, &recipients, &readers, index)
            .map(|inner| Self { inner })
            .map_err(to_py)
    }
    #[staticmethod]
    fn btn_reader(group: &str, kits: Vec<Vec<u8>>, index: [u8; 32]) -> PyResult<Self> {
        Ok(Self {
            inner: GroupCapability::btn_reader(group, &kits, index).map_err(to_py)?,
        })
    }
    #[staticmethod]
    fn btn_publisher(
        group: &str,
        state: &[u8],
        kits: Vec<Vec<u8>>,
        index: [u8; 32],
    ) -> PyResult<Self> {
        Ok(Self {
            inner: GroupCapability::btn_publisher(group, state, &kits, index).map_err(to_py)?,
        })
    }
    #[getter]
    fn group(&self) -> &str {
        self.inner.group()
    }
}

#[pyclass(frozen, module = "tn.providers", name = "KeySet")]
#[derive(Clone)]
pub struct PyKeySet {
    pub inner: KeySet,
}
#[pymethods]
impl PyKeySet {
    #[new]
    fn new(identity: &PyIdentity, groups: Vec<PyRef<PyGroupCapability>>) -> PyResult<Self> {
        Ok(Self {
            inner: KeySet::new(
                &identity.inner,
                groups.iter().map(|g| g.inner.clone()).collect(),
            )
            .map_err(to_py)?,
        })
    }
    #[getter]
    fn owner(&self) -> &str {
        self.inner.owner()
    }
    #[getter]
    fn groups(&self) -> Vec<String> {
        self.inner.groups().into_iter().map(str::to_owned).collect()
    }
}
#[pyclass(frozen, module = "tn.providers", name = "LocalKeys")]
pub struct PyLocalKeys {
    pub inner: Arc<LocalKeys>,
}
#[pymethods]
impl PyLocalKeys {
    #[new]
    fn new(groups: Vec<String>) -> PyResult<Self> {
        Ok(Self {
            inner: Arc::new(
                LocalKeys::generate(&groups.iter().map(String::as_str).collect::<Vec<_>>())
                    .map_err(to_py)?,
            ),
        })
    }
    #[pyo3(signature=(identity, *, read, publish))]
    fn assign(
        &self,
        identity: &PyIdentity,
        read: Vec<String>,
        publish: Vec<String>,
    ) -> PyResult<()> {
        self.inner
            .assign(
                &identity.inner,
                &read.iter().map(String::as_str).collect::<Vec<_>>(),
                &publish.iter().map(String::as_str).collect::<Vec<_>>(),
            )
            .map_err(to_py)
    }
    fn resolve(&self, identity: &PyIdentity) -> PyResult<PyKeySet> {
        Ok(PyKeySet {
            inner: self.inner.resolve(&identity.inner).map_err(to_py)?,
        })
    }
}
pub struct KeysBridge(pub Py<PyAny>);
impl KeyProvider for KeysBridge {
    fn resolve(&self, identity: &ApplicationIdentity) -> tn_core::Result<KeySet> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    "resolve",
                    (PyIdentity {
                        inner: identity.clone(),
                    },),
                )?
                .extract::<PyRef<PyKeySet>>(py)
                .map(|v| v.inner.clone())
        })
        .map_err(provider_error)
    }
}
