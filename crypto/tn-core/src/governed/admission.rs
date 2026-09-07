//! Application decisions receive the verified source and the current output.
use super::{DataObject, Governance, GovernedObject, SourceReference};
use crate::Result;

/// All authenticated source context for one requested operation.
pub struct AdmissionContext<'a> {
    pub(crate) object: &'a GovernedObject,
    pub(crate) governance: &'a Governance,
    pub(crate) operation: &'a str,
}
impl AdmissionContext<'_> {
    /// Verified signed input.
    pub fn object(&self) -> &GovernedObject {
        self.object
    }
    /// Primary contract, including carried extensions.
    pub fn governance(&self) -> &Governance {
        self.governance
    }
    /// Requested application operation.
    pub fn operation(&self) -> &str {
        self.operation
    }
    /// Every attached contract, with the primary contract first.
    pub fn policies(&self) -> Result<Vec<Governance>> {
        self.governance.policies()
    }
    /// Validated causal data inputs.
    pub fn sources(&self) -> Result<Vec<SourceReference>> {
        self.governance.source_references()
    }
}

/// Authority decision for an additional contract on a mutable object.
pub struct AttachmentContext<'a> {
    pub(crate) authority: &'a str,
    pub(crate) data: &'a DataObject,
    pub(crate) policy: &'a Governance,
}
impl AttachmentContext<'_> {
    /// Session identity requesting the attachment; the application checks delegation.
    pub fn authority(&self) -> &str {
        self.authority
    }
    /// Existing object and policy set.
    pub fn data(&self) -> &DataObject {
        self.data
    }
    /// Additional policy and its declared governing authority.
    pub fn policy(&self) -> &Governance {
        self.policy
    }
}

/// Current result, destination and purpose at a release boundary.
pub struct ReleaseContext<'a> {
    pub(crate) writer: &'a str,
    pub(crate) data: &'a DataObject,
    pub(crate) object_type: &'a str,
    pub(crate) purpose: &'a str,
    pub(crate) destination: &'a str,
}
impl ReleaseContext<'_> {
    /// Identity that will sign the released version.
    pub fn writer(&self) -> &str {
        self.writer
    }
    /// Current data, attached policies and causal sources.
    pub fn data(&self) -> &DataObject {
        self.data
    }
    /// Type assigned to the released version.
    pub fn object_type(&self) -> &str {
        self.object_type
    }
    /// Intended use.
    pub fn purpose(&self) -> &str {
        self.purpose
    }
    /// Application-resolved destination or audience.
    pub fn destination(&self) -> &str {
        self.destination
    }
}
