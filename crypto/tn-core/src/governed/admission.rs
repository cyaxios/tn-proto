//! Application decisions receive the verified source and the current output.
use super::{DataObject, Governance, GovernedObject, SourceReference, UseContext};
use crate::Result;

/// Authenticated source context and the requested use at admission.
pub struct AdmissionContext<'a> {
    pub(crate) object: &'a GovernedObject,
    pub(crate) governance: &'a Governance,
    pub(crate) operation: &'a str,
    pub(crate) use_context: Option<&'a UseContext>,
    pub(crate) groups: Option<&'a [String]>,
}
impl AdmissionContext<'_> {
    /// Preserve this authenticated read-only context beyond the callback lifetime.
    pub fn to_owned(&self) -> OwnedAdmissionContext {
        OwnedAdmissionContext {
            object: self.object.clone(),
            governance: self.governance.clone(),
            operation: self.operation.to_owned(),
            use_context: self.use_context.cloned(),
            groups: self.groups.map(<[String]>::to_vec),
        }
    }
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
    /// Complete requested use on the strict path; absent on legacy admission.
    pub fn use_context(&self) -> Option<&UseContext> {
        self.use_context
    }
    /// Selected business groups on the strict path, sorted and unique.
    pub fn groups(&self) -> Option<&[String]> {
        self.groups
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

/// An owned snapshot created only from an authenticated admission callback.
/// This retains context for later evaluation; it does not grant data access.
#[derive(Clone)]
pub struct OwnedAdmissionContext {
    object: GovernedObject,
    governance: Governance,
    operation: String,
    use_context: Option<UseContext>,
    groups: Option<Vec<String>>,
}
impl OwnedAdmissionContext {
    /// Borrow the same verified source, complete use and selected group set.
    pub fn context(&self) -> AdmissionContext<'_> {
        AdmissionContext {
            object: &self.object,
            governance: &self.governance,
            operation: &self.operation,
            use_context: self.use_context.as_ref(),
            groups: self.groups.as_deref(),
        }
    }
}

/// Authority decision for an additional contract on a mutable object.
pub struct AttachmentContext<'a> {
    pub(crate) authority: &'a str,
    pub(crate) data: &'a DataObject,
    pub(crate) policy: &'a Governance,
}
/// Owned snapshot of a policy attachment decision.
#[derive(Clone)]
pub struct OwnedAttachmentContext {
    authority: String,
    data: DataObject,
    policy: Governance,
}
impl OwnedAttachmentContext {
    /// Borrow the original authority, data and proposed additional contract.
    pub fn context(&self) -> AttachmentContext<'_> {
        AttachmentContext {
            authority: &self.authority,
            data: &self.data,
            policy: &self.policy,
        }
    }
}
impl AttachmentContext<'_> {
    /// Retain this decision context independently of the callback lifetime.
    pub fn to_owned(&self) -> OwnedAttachmentContext {
        OwnedAttachmentContext {
            authority: self.authority.into(),
            data: self.data.clone(),
            policy: self.policy.clone(),
        }
    }

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

/// Current result, destination and requested use at a release boundary.
pub struct ReleaseContext<'a> {
    pub(crate) writer: &'a str,
    pub(crate) data: &'a DataObject,
    pub(crate) object_type: &'a str,
    pub(crate) purpose: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) use_context: Option<&'a UseContext>,
}
/// Owned snapshot of a publication decision.
#[derive(Clone)]
pub struct OwnedReleaseContext {
    writer: String,
    data: DataObject,
    object_type: String,
    purpose: String,
    destination: String,
    use_context: Option<UseContext>,
}
impl OwnedReleaseContext {
    /// Borrow the original result, destination and requested use.
    pub fn context(&self) -> ReleaseContext<'_> {
        ReleaseContext {
            writer: &self.writer,
            data: &self.data,
            object_type: &self.object_type,
            purpose: &self.purpose,
            destination: &self.destination,
            use_context: self.use_context.as_ref(),
        }
    }
}
impl ReleaseContext<'_> {
    /// Retain this decision context independently of the callback lifetime.
    pub fn to_owned(&self) -> OwnedReleaseContext {
        OwnedReleaseContext {
            writer: self.writer.into(),
            data: self.data.clone(),
            object_type: self.object_type.into(),
            purpose: self.purpose.into(),
            destination: self.destination.into(),
            use_context: self.use_context.cloned(),
        }
    }

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
    /// Complete release use; absent for legacy purpose-only releases.
    pub fn use_context(&self) -> Option<&UseContext> {
        self.use_context
    }
    /// Application-resolved destination or audience.
    pub fn destination(&self) -> &str {
        self.destination
    }
}
