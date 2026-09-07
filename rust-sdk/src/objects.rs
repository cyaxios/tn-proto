//! Governed data objects: contract, signing, selected opening, and derivation.

use std::path::Path;

pub use tn_core::governed::{
    AdmittedObject, Governance, GovernanceView, GovernedDraft, GovernedObject, GovernedReader,
    GovernedWriter, OpenedObject, GOVERNANCE_GROUP,
};
pub use tn_core::runtime::Objects;

use crate::{Result, Tn};

impl Tn {
    /// Open the configured governed-object interface without event handlers,
    /// log files, lifecycle emissions, or chain initialization.
    pub fn open_objects(yaml_path: impl AsRef<Path>) -> Result<Objects<'static>> {
        Ok(Objects::open(yaml_path.as_ref())?)
    }

    /// Create governed objects with this handle's existing identity and groups.
    pub fn objects(&self) -> Objects<'_> {
        self.runtime().objects()
    }
}
