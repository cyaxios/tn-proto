//! Typed provider boundaries for application setup. Protocol operations remain native.
mod catalog;
#[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
mod file;
mod governance;
mod identity;
mod keys;
mod register;
use crate::governed::Governance;
use crate::runtime::{Objects, Session};
use crate::{Error, Result};
pub use catalog::*;
#[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
pub use file::FileKeyStore;
pub use governance::*;
pub use identity::*;
pub use keys::*;
pub use register::*;
use std::sync::Arc;
pub(crate) fn label(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "provider identifier must be nonblank without control characters".into(),
        ));
    }
    Ok(())
}
pub(crate) fn lock_error() -> Error {
    Error::InvalidConfig("provider lock poisoned".into())
}

/// Provider bundle used to construct independent governed sessions.
pub struct Providers {
    /// Application identity resolver.
    pub identity: Arc<dyn IdentityProvider>,
    /// Assigned group capability resolver.
    pub keys: Arc<dyn KeyProvider>,
    /// Contract resolver and live boundary decisions.
    pub governance: Arc<dyn GovernanceProvider>,
    /// Optional accepted dataset edition resolver.
    pub catalog: Option<Arc<dyn CatalogProvider>>,
    /// Optional publication recorder; absent uses environment-configured registers.
    pub registers: Option<Arc<dyn RegisterProvider>>,
}
impl Providers {
    /// Construct an independent session and install live provider decisions for its workflows.
    pub fn session(
        &self,
        application: &str,
        workflows: &[WorkflowRequest],
    ) -> Result<Session<'static>> {
        label(application)?;
        let identity = self.identity.resolve(application)?;
        if identity.application() != application {
            return Err(Error::InvalidConfig(
                "identity provider returned another application".into(),
            ));
        }
        let keys = self.keys.resolve(&identity)?;
        if keys.owner() != identity.did() {
            return Err(Error::InvalidConfig(
                "key provider returned another identity's capabilities".into(),
            ));
        }
        let objects = Objects::from_capabilities(identity, keys, self.registers.clone())?;
        let session = Session::new(objects);
        for request in workflows {
            request.validate()?;
            if request.input.application() != application
                || request.output.application() != application
            {
                return Err(Error::InvalidConfig(
                    "workflow use belongs to another application".into(),
                ));
            }
            let policy = self.governance.workflow(request)?;
            policy.validate()?;
            for input in policy.inputs {
                let provider = self.governance.clone();
                session.configure_receive_for(
                    input.object_type.as_deref(),
                    request.input.clone(),
                    input.groups,
                    move |ctx| provider.accept(ctx),
                )?;
            }
            let provider = self.governance.clone();
            session.configure_release(
                request.output.clone(),
                &policy.destination,
                &policy.output_type,
                move |ctx| provider.release(ctx),
            )?;
        }
        let provider = self.governance.clone();
        session.configure_attach(move |ctx| provider.attach(ctx))?;
        Ok(session)
    }
    /// Resolve the default origination contract for the exact requested use and type.
    pub fn policy(&self, request: &PolicyRequest) -> Result<Governance> {
        request.validate()?;
        let policy = self.governance.policy(request)?;
        if policy.selected_object_type() != Some(request.object_type.as_str()) {
            return Err(Error::InvalidConfig(
                "provider policy does not select the requested object type".into(),
            ));
        }
        Ok(policy)
    }
    /// Resolve the typed request; return an error when no matching assignment exists.
    pub fn resolve(&self, request: &CatalogRequest) -> Result<CatalogEntry> {
        request.validate()?;
        let entry = self
            .catalog
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("no catalog provider configured".into()))?
            .resolve(request)?;
        entry.validate(request)?;
        Ok(entry)
    }
}
