//! Mutable governed data, retained policies, and signed releases.

#[cfg(feature = "fs")]
use std::path::Path;

pub use tn_core::governed::{
    AdmissionContext, AdmittedObject, AttachmentContext, ContractBinding, DataObject,
    DatasetBinding, DatasetCatalog, DatasetEdition, DatasetEditionDraft, DatasetSelection,
    EvaluatorArtifactSet, Governance, GovernanceView, GovernedDraft, GovernedObject,
    GovernedReader, GovernedWriter, LineageVerifier, OpenedObject, OwnedAdmissionContext,
    OwnedAttachmentContext, OwnedReleaseContext, PolicyDag, PolicyParent, PolicyRelation,
    PolicyRevision, PolicyRevisionDraft, PublicationReport, ReleaseContext, SourceReference,
    UseContext, VerifiedLineage, DATASET_EDITION_GROUP, DATASET_EDITION_TYPE, GOVERNANCE_GROUP,
    POLICY_REVISION_GROUP, POLICY_REVISION_TYPE,
};
#[cfg(feature = "fs")]
pub use tn_core::runtime::{ObjectRegisters, Objects, Publication, ReleasePlan, Session, Workflow};

#[cfg(feature = "fs")]
use crate::{Result, Tn};

#[cfg(feature = "fs")]
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
