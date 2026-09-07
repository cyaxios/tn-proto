//! Governed data objects: signed envelopes carrying encrypted data and rules.
//!
//! [`Governance`] selects a contract and [`DataObject`] retains it through
//! mutation. [`GovernedWriter`] signs each release as a [`GovernedObject`]. The
//! object retains its exact wire representation for transport and exhaust.
//! These operations use no logger, receipt sink, ceremony, or filesystem.

mod admission;
mod data;
mod object;
mod policy;
mod policy_dag;
mod reader;
mod revision;
mod source;
mod writer;

pub use admission::{AdmissionContext, AttachmentContext, ReleaseContext};
pub use data::DataObject;
pub use object::GovernedObject;
pub use policy::Governance;
pub use policy_dag::PolicyDag;
pub use reader::{AdmittedObject, GovernanceView, GovernedReader, OpenedObject};
pub use revision::{
    PolicyParent, PolicyRelation, PolicyRevision, PolicyRevisionDraft, POLICY_REVISION_GROUP,
    POLICY_REVISION_TYPE,
};
pub use source::SourceReference;
pub use writer::{GovernedDraft, GovernedWriter, PublicationReport};

/// Reserved encrypted group carrying the use contract.
pub const GOVERNANCE_GROUP: &str = "tn.agents";

pub(crate) fn invalid(reason: impl Into<String>) -> crate::Error {
    crate::Error::Malformed {
        kind: "governed object",
        reason: reason.into(),
    }
}

pub(crate) fn validate_name(name: &str) -> crate::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(invalid(
            "object and group names require letters, digits, '.', '_' or '-'",
        ));
    }
    Ok(())
}

pub(crate) fn validate_group(name: &str) -> crate::Result<()> {
    validate_name(name)?;
    if crate::sealed_object::ENVELOPE_RESERVED.contains(&name)
        || matches!(name, "tn_aad" | "tn_sealed")
        || (name.starts_with("tn.") && name != GOVERNANCE_GROUP)
    {
        return Err(invalid(format!("reserved envelope/group name {name:?}")));
    }
    Ok(())
}

fn validate_field(name: &str) -> crate::Result<()> {
    if name.is_empty() || name.contains(['\0', '=']) {
        return Err(invalid(
            "field names must be nonempty and exclude NUL and '=' delimiters",
        ));
    }
    Ok(())
}
