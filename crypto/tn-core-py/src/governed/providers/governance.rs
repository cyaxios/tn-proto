use super::*;

#[pyclass(frozen, module = "tn.providers", name = "PolicyRequest")]
#[derive(Clone)]
pub struct PyPolicyRequest {
    pub inner: PolicyRequest,
}
#[pymethods]
impl PyPolicyRequest {
    #[new]
    fn new(object_type: String, use_context: &PyUseContext) -> PyResult<Self> {
        PolicyRequest::new(object_type, use_context.inner.clone())
            .map(|inner| Self { inner })
            .map_err(to_py)
    }
    #[getter]
    fn object_type(&self) -> &str {
        &self.inner.object_type
    }
    #[getter]
    fn use_context(&self) -> PyUseContext {
        PyUseContext {
            inner: self.inner.use_context.clone(),
        }
    }
}
#[pyclass(frozen, module = "tn.providers", name = "WorkflowRequest")]
#[derive(Clone)]
pub struct PyWorkflowRequest {
    pub inner: WorkflowRequest,
}
#[pymethods]
impl PyWorkflowRequest {
    #[new]
    fn new(input: &PyUseContext, output: &PyUseContext) -> PyResult<Self> {
        WorkflowRequest::new(input.inner.clone(), output.inner.clone())
            .map(|inner| Self { inner })
            .map_err(to_py)
    }
    #[getter]
    fn input(&self) -> PyUseContext {
        PyUseContext {
            inner: self.inner.input.clone(),
        }
    }
    #[getter]
    fn output(&self) -> PyUseContext {
        PyUseContext {
            inner: self.inner.output.clone(),
        }
    }
}
#[pyclass(frozen, module = "tn.providers", name = "InputRule")]
#[derive(Clone)]
pub struct PyInputRule {
    pub inner: InputRule,
}
#[pymethods]
impl PyInputRule {
    #[new]
    #[pyo3(signature=(groups, *, object_type=None))]
    fn new(groups: Vec<String>, object_type: Option<String>) -> PyResult<Self> {
        InputRule::new(groups, object_type)
            .map(|inner| Self { inner })
            .map_err(to_py)
    }
    #[getter]
    fn groups(&self) -> Vec<String> {
        self.inner.groups.clone()
    }
    #[getter]
    fn object_type(&self) -> Option<String> {
        self.inner.object_type.clone()
    }
}
#[pyclass(frozen, module = "tn.providers", name = "WorkflowPolicy")]
#[derive(Clone)]
pub struct PyWorkflowPolicy {
    pub inner: WorkflowPolicy,
}
#[pymethods]
impl PyWorkflowPolicy {
    #[new]
    fn new(
        inputs: Vec<PyRef<PyInputRule>>,
        output_type: String,
        destination: String,
    ) -> PyResult<Self> {
        WorkflowPolicy::new(
            inputs.iter().map(|v| v.inner.clone()).collect(),
            output_type,
            destination,
        )
        .map(|inner| Self { inner })
        .map_err(to_py)
    }
    #[getter]
    fn inputs(&self) -> Vec<PyInputRule> {
        self.inner
            .inputs
            .iter()
            .map(|v| PyInputRule { inner: v.clone() })
            .collect()
    }
    #[getter]
    fn output_type(&self) -> &str {
        &self.inner.output_type
    }
    #[getter]
    fn destination(&self) -> &str {
        &self.inner.destination
    }
}
#[pyclass(frozen, module = "tn.providers", name = "PolicyDirectory")]
pub struct PyPolicyDirectory {
    pub inner: Arc<PolicyDirectory>,
}
#[pymethods]
impl PyPolicyDirectory {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(PolicyDirectory::new()),
        }
    }
    fn trust(&self, identity: &PyIdentity) -> PyResult<()> {
        self.inner.trust(&identity.inner).map_err(to_py)
    }
    fn add_policy(&self, request: &PyPolicyRequest, policy: &PyGovernance) -> PyResult<()> {
        self.inner
            .add_policy(&request.inner, policy.inner.clone())
            .map_err(to_py)
    }
    fn approve_contract(&self, request: &PyPolicyRequest, policy: &PyGovernance) -> PyResult<()> {
        self.inner
            .approve_contract(&request.inner, policy.inner.clone())
            .map_err(to_py)
    }
    fn add_workflow(&self, request: &PyWorkflowRequest, policy: &PyWorkflowPolicy) -> PyResult<()> {
        self.inner
            .add_workflow(&request.inner, policy.inner.clone())
            .map_err(to_py)
    }
    fn policy(&self, request: &PyPolicyRequest) -> PyResult<PyGovernance> {
        Ok(PyGovernance {
            inner: self.inner.policy(&request.inner).map_err(to_py)?,
        })
    }
    fn workflow(&self, request: &PyWorkflowRequest) -> PyResult<PyWorkflowPolicy> {
        Ok(PyWorkflowPolicy {
            inner: self.inner.workflow(&request.inner).map_err(to_py)?,
        })
    }
    fn attach(&self, context: &super::super::data::PyAttachment) -> PyResult<bool> {
        self.inner.attach(&context.inner.context()).map_err(to_py)
    }
    fn release(&self, context: &super::super::data::PyRelease) -> PyResult<bool> {
        self.inner.release(&context.inner.context()).map_err(to_py)
    }
    fn accept(&self, context: &super::super::data::PyAdmission) -> PyResult<bool> {
        self.inner.accept(&context.inner.context()).map_err(to_py)
    }
}
pub struct GovernanceBridge(pub Py<PyAny>);
impl GovernanceProvider for GovernanceBridge {
    fn policy(&self, request: &PolicyRequest) -> tn_core::Result<tn_core::governed::Governance> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    "policy",
                    (PyPolicyRequest {
                        inner: request.clone(),
                    },),
                )?
                .extract::<PyRef<PyGovernance>>(py)
                .map(|v| v.inner.clone())
        })
        .map_err(provider_error)
    }
    fn workflow(&self, request: &WorkflowRequest) -> tn_core::Result<WorkflowPolicy> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    "workflow",
                    (PyWorkflowRequest {
                        inner: request.clone(),
                    },),
                )?
                .extract::<PyRef<PyWorkflowPolicy>>(py)
                .map(|v| v.inner.clone())
        })
        .map_err(provider_error)
    }
    fn accept(&self, context: &tn_core::governed::AdmissionContext<'_>) -> tn_core::Result<bool> {
        Python::with_gil(|py| {
            super::super::data::decision(
                &self.0.bind(py).getattr("accept")?,
                Py::new(py, super::super::data::PyAdmission::from_native(context))?.into_any(),
            )
        })
        .map_err(provider_error)
    }
    fn attach(&self, context: &tn_core::governed::AttachmentContext<'_>) -> tn_core::Result<bool> {
        Python::with_gil(|py| {
            super::super::data::decision(
                &self.0.bind(py).getattr("attach")?,
                Py::new(py, super::super::data::PyAttachment::from_native(context))?.into_any(),
            )
        })
        .map_err(provider_error)
    }
    fn release(&self, context: &tn_core::governed::ReleaseContext<'_>) -> tn_core::Result<bool> {
        Python::with_gil(|py| {
            super::super::data::decision(
                &self.0.bind(py).getattr("release")?,
                Py::new(py, super::super::data::PyRelease::from_native(context))?.into_any(),
            )
        })
        .map_err(provider_error)
    }
}
