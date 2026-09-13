use crate::governed::GovernedObject;
use crate::runtime::ObjectRegisters;
use crate::{DeviceKey, Result};

#[derive(Clone)]
/// Detached metadata and exact signed publication available to a register.
pub struct RegisterEvent {
    /// Publication action: create or release.
    pub action: String,
    /// Exact signed publication, including its original wire bytes.
    pub publication: GovernedObject,
    /// Operation recorded for this publication.
    pub purpose: String,
    /// Resolved destination or audience for release.
    pub destination: String,
    /// Content references of every carried contract.
    pub policy_refs: Vec<String>,
}
/// Record a completed signed publication; failures remain on the working object.
pub trait RegisterProvider: Send + Sync {
    /// Record the exact completed publication with its action and contract references.
    fn record(&self, signer: &DeviceKey, event: &RegisterEvent) -> Result<()>;
}
/// First adapter: existing signed, chained creation/release metadata registers.
pub struct FileRegisters {
    registers: ObjectRegisters,
}
impl FileRegisters {
    /// Construct this typed provider value from explicit native configuration.
    pub fn new(registers: ObjectRegisters) -> Self {
        Self { registers }
    }
}
impl RegisterProvider for FileRegisters {
    /// Record the exact completed publication with its action and contract references.
    fn record(&self, signer: &DeviceKey, event: &RegisterEvent) -> Result<()> {
        self.registers.record(
            signer,
            &event.action,
            &event.publication,
            &event.purpose,
            &event.destination,
            &event.policy_refs,
        )?;
        Ok(())
    }
}
