//! Typed adapters into canonical Rust provider contracts.
mod catalog;
mod file;
mod governance;
mod identity;
mod keys;
mod register;
use super::{
    objects::{PyGovernance, PyObject},
    to_py,
    use_context::PyUseContext,
};
use catalog::*;
use file::*;
use governance::*;
use identity::*;
use keys::*;
use pyo3::prelude::*;
use register::*;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock, Weak};
use tn_core::providers::*;

fn provider_error(error: PyErr) -> tn_core::Error {
    tn_core::Error::InvalidConfig(format!("provider callback failed: {error}"))
}

type SessionLife = Weak<Mutex<Option<Arc<tn_core::runtime::Session<'static>>>>>;

// Each session gets its own weak lifecycle guard, even when providers are shared.
struct LiveGovernance {
    provider: Arc<dyn GovernanceProvider>,
    session: Arc<OnceLock<SessionLife>>,
}
impl LiveGovernance {
    fn check(&self) -> tn_core::Result<()> {
        let state =
            self.session.get().and_then(Weak::upgrade).ok_or_else(|| {
                tn_core::Error::InvalidConfig("provider session is closed".into())
            })?;
        let active = state
            .lock()
            .map_err(|_| tn_core::Error::InvalidConfig("session lock poisoned".into()))?;
        if active.is_none() {
            return Err(tn_core::Error::InvalidConfig(
                "provider session is closed".into(),
            ));
        }
        Ok(())
    }
}
impl GovernanceProvider for LiveGovernance {
    fn policy(&self, request: &PolicyRequest) -> tn_core::Result<tn_core::governed::Governance> {
        self.provider.policy(request)
    }
    fn workflow(&self, request: &WorkflowRequest) -> tn_core::Result<WorkflowPolicy> {
        self.provider.workflow(request)
    }
    fn accept(&self, context: &tn_core::governed::AdmissionContext<'_>) -> tn_core::Result<bool> {
        self.check()?;
        let answer = self.provider.accept(context)?;
        self.check()?;
        Ok(answer)
    }
    fn attach(&self, context: &tn_core::governed::AttachmentContext<'_>) -> tn_core::Result<bool> {
        self.check()?;
        let answer = self.provider.attach(context)?;
        self.check()?;
        Ok(answer)
    }
    fn release(&self, context: &tn_core::governed::ReleaseContext<'_>) -> tn_core::Result<bool> {
        self.check()?;
        let answer = self.provider.release(context)?;
        self.check()?;
        Ok(answer)
    }
}

#[pyclass(frozen, module = "tn.providers", name = "Providers")]
pub struct PyProviders {
    inner: Providers,
}
#[pymethods]
impl PyProviders {
    #[new]
    #[pyo3(signature=(identity, keys, governance, *, catalog=None, registers=None))]
    fn new(
        identity: Bound<'_, PyAny>,
        keys: Bound<'_, PyAny>,
        governance: Bound<'_, PyAny>,
        catalog: Option<Bound<'_, PyAny>>,
        registers: Option<Bound<'_, PyAny>>,
    ) -> Self {
        let identity: Arc<dyn IdentityProvider> = match identity.extract::<PyRef<PyLocalIdentity>>()
        {
            Ok(v) => v.inner.clone(),
            Err(_) => match identity.extract::<PyRef<PyFileKeyStore>>() {
                Ok(v) => v.inner.clone(),
                Err(_) => Arc::new(IdentityBridge(identity.unbind())),
            },
        };
        let keys: Arc<dyn KeyProvider> = match keys.extract::<PyRef<PyLocalKeys>>() {
            Ok(v) => v.inner.clone(),
            Err(_) => match keys.extract::<PyRef<PyFileKeyStore>>() {
                Ok(v) => v.inner.clone(),
                Err(_) => Arc::new(KeysBridge(keys.unbind())),
            },
        };
        let governance: Arc<dyn GovernanceProvider> =
            match governance.extract::<PyRef<PyPolicyDirectory>>() {
                Ok(v) => v.inner.clone(),
                Err(_) => Arc::new(GovernanceBridge(governance.unbind())),
            };
        let catalog = catalog.map(|v| -> Arc<dyn CatalogProvider> {
            match v.extract::<PyRef<PyEditionCatalog>>() {
                Ok(c) => c.inner.clone(),
                Err(_) => Arc::new(CatalogBridge(v.unbind())),
            }
        });
        let registers = registers.map(|v| -> Arc<dyn RegisterProvider> {
            match v.extract::<PyRef<PyFileRegisters>>() {
                Ok(c) => c.inner.clone(),
                Err(_) => Arc::new(RegisterBridge(v.unbind())),
            }
        });
        Self {
            inner: Providers {
                identity,
                keys,
                governance,
                catalog,
                registers,
            },
        }
    }
    #[pyo3(signature=(application, *, workflows))]
    fn session(
        &self,
        py: Python<'_>,
        application: &str,
        workflows: Vec<PyRef<PyWorkflowRequest>>,
    ) -> PyResult<super::session::PySession> {
        let requests: Vec<_> = workflows.iter().map(|v| v.inner.clone()).collect();
        let life = Arc::new(OnceLock::new());
        let providers = Providers {
            identity: self.inner.identity.clone(),
            keys: self.inner.keys.clone(),
            governance: Arc::new(LiveGovernance {
                provider: self.inner.governance.clone(),
                session: life.clone(),
            }),
            catalog: self.inner.catalog.clone(),
            registers: self.inner.registers.clone(),
        };
        let session = py
            .allow_threads(|| providers.session(application, &requests))
            .and_then(super::session::PySession::from_session)
            .map_err(to_py)?;
        life.set(Arc::downgrade(&session.context)).map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("provider session already initialized")
        })?;
        Ok(session)
    }
    fn policy(&self, py: Python<'_>, request: &PyPolicyRequest) -> PyResult<PyGovernance> {
        py.allow_threads(|| self.inner.policy(&request.inner))
            .map(|inner| PyGovernance { inner })
            .map_err(to_py)
    }
    fn resolve(&self, py: Python<'_>, request: &PyCatalogRequest) -> PyResult<PyCatalogEntry> {
        py.allow_threads(|| self.inner.resolve(&request.inner))
            .map(|inner| PyCatalogEntry { inner })
            .map_err(to_py)
    }
}
pub(super) fn populate(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyProviders>()?;
    m.add_class::<PyFileKeyStore>()?;
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyLocalIdentity>()?;
    m.add_class::<PyKeySet>()?;
    m.add_class::<PyGroupCapability>()?;
    m.add_class::<PyLocalKeys>()?;
    m.add_class::<PyPolicyRequest>()?;
    m.add_class::<PyWorkflowRequest>()?;
    m.add_class::<PyInputRule>()?;
    m.add_class::<PyWorkflowPolicy>()?;
    m.add_class::<PyPolicyDirectory>()?;
    m.add_class::<PyCatalogRequest>()?;
    m.add_class::<PyCatalogEntry>()?;
    m.add_class::<PyEditionCatalog>()?;
    m.add_class::<PyRegisterEvent>()?;
    m.add_class::<PyFileRegisters>()?;
    Ok(())
}
