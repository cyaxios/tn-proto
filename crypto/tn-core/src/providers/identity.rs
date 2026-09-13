use crate::{DeviceKey, Error, Result};
use std::sync::Arc;

/// Resolved local signing capability. Private material is never a debug value.
#[derive(Clone)]
pub struct ApplicationIdentity {
    application: String,
    pub(crate) signer: Arc<DeviceKey>,
}
impl ApplicationIdentity {
    /// Construct this typed provider value from explicit native configuration.
    pub fn new(application: &str, signer: Arc<DeviceKey>) -> Result<Self> {
        super::label(application)?;
        Ok(Self {
            application: application.into(),
            signer,
        })
    }
    /// Return the configured application name.
    pub fn application(&self) -> &str {
        &self.application
    }
    /// Return the signing identity DID.
    pub fn did(&self) -> &str {
        self.signer.did()
    }
}
/// Resolve a native application identity from application configuration.
pub trait IdentityProvider: Send + Sync {
    /// Resolve the typed request; return an error when no matching assignment exists.
    fn resolve(&self, application: &str) -> Result<ApplicationIdentity>;
}
/// First adapter: one generated or provisioned local identity.
pub struct LocalIdentity {
    identity: ApplicationIdentity,
}
impl LocalIdentity {
    /// Load an existing signing seed supplied by a credential provider.
    pub fn from_private_bytes(application: &str, seed: &[u8]) -> Result<Self> {
        Self::new(application, DeviceKey::from_private_bytes(seed)?)
    }
    /// Generate fresh local capability material for this adapter instance.
    pub fn generate(application: &str) -> Result<Self> {
        Self::new(application, DeviceKey::generate())
    }
    /// Construct this typed provider value from explicit native configuration.
    pub fn new(application: &str, signer: DeviceKey) -> Result<Self> {
        Ok(Self {
            identity: ApplicationIdentity::new(application, Arc::new(signer))?,
        })
    }
}
impl IdentityProvider for LocalIdentity {
    /// Resolve the typed request; return an error when no matching assignment exists.
    fn resolve(&self, application: &str) -> Result<ApplicationIdentity> {
        if application != self.identity.application() {
            return Err(Error::InvalidConfig(
                "identity provider does not serve this application".into(),
            ));
        }
        Ok(self.identity.clone())
    }
}
