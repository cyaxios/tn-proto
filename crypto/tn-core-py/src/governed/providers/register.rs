use super::*;

#[pyclass(frozen, module = "tn.providers", name = "RegisterEvent")]
#[derive(Clone)]
pub struct PyRegisterEvent {
    pub inner: RegisterEvent,
}
#[pymethods]
impl PyRegisterEvent {
    #[getter]
    fn action(&self) -> &str {
        &self.inner.action
    }
    #[getter]
    fn publication(&self) -> PyObject {
        PyObject {
            inner: self.inner.publication.clone(),
        }
    }
    #[getter]
    fn purpose(&self) -> &str {
        &self.inner.purpose
    }
    #[getter]
    fn destination(&self) -> &str {
        &self.inner.destination
    }
    #[getter]
    fn policy_refs(&self) -> Vec<String> {
        self.inner.policy_refs.clone()
    }
}
#[pyclass(frozen, module = "tn.providers", name = "FileRegisters")]
pub struct PyFileRegisters {
    pub inner: Arc<FileRegisters>,
}
#[pymethods]
impl PyFileRegisters {
    #[new]
    fn new(registers: &super::super::session::PyRegisters) -> Self {
        Self {
            inner: Arc::new(FileRegisters::new(registers.inner.clone())),
        }
    }
}
pub struct RegisterBridge(pub Py<PyAny>);
impl RegisterProvider for RegisterBridge {
    fn record(&self, _signer: &tn_core::DeviceKey, event: &RegisterEvent) -> tn_core::Result<()> {
        Python::with_gil(|py| {
            let value = self.0.call_method1(
                py,
                "record",
                (PyRegisterEvent {
                    inner: event.clone(),
                },),
            )?;
            if !value.is_none(py) {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "register.record must return None",
                ));
            }
            Ok(())
        })
        .map_err(provider_error)
    }
}
