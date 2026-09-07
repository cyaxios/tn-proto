//! Typed causal references carried in encrypted governance.
use super::{invalid, validate_group, validate_name, Governance, GovernedObject, OpenedObject};
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An admitted input, including the groups used and its governing contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReference {
    object_id: String,
    object_type: String,
    writer: String,
    governed_by: String,
    policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_revision: Option<String>,
    groups: Vec<String>,
    operation: String,
}

impl SourceReference {
    pub(crate) fn new(
        object: &GovernedObject,
        policy: &Governance,
        groups: Vec<String>,
        operation: &str,
    ) -> Result<Self> {
        let result = Self {
            object_id: object.id().to_owned(),
            object_type: object.object_type().to_owned(),
            writer: object.writer().to_owned(),
            governed_by: policy.governed_by().to_owned(),
            policy: policy.policy_ref().to_owned(),
            policy_revision: policy.revision_id().map(str::to_owned),
            groups,
            operation: operation.to_owned(),
        };
        result.validate()?;
        Ok(result)
    }
    /// Construct from an input whose selected groups have actually opened.
    pub fn from_opened(opened: &OpenedObject) -> Result<Self> {
        Self::new(
            opened.object(),
            opened.governance(),
            opened.groups().keys().cloned().collect(),
            opened.operation(),
        )
    }
    /// Signed source identity.
    pub fn object_id(&self) -> &str {
        &self.object_id
    }
    /// Source object's declared type.
    pub fn object_type(&self) -> &str {
        &self.object_type
    }
    /// Source signer.
    pub fn writer(&self) -> &str {
        &self.writer
    }
    /// Source governing authority.
    pub fn governed_by(&self) -> &str {
        &self.governed_by
    }
    /// Source policy reference.
    pub fn policy_ref(&self) -> &str {
        &self.policy
    }
    /// Exact source policy revision when one was selected.
    pub fn revision_id(&self) -> Option<&str> {
        self.policy_revision.as_deref()
    }
    /// Selected source groups.
    pub fn groups(&self) -> &[String] {
        &self.groups
    }
    /// Admitted source operation.
    pub fn operation(&self) -> &str {
        &self.operation
    }
    /// Match a pending source without assembling lineage JSON by hand.
    pub fn references(&self, object: &GovernedObject) -> bool {
        self.object_id == object.id()
            && self.object_type == object.object_type()
            && self.writer == object.writer()
            && object.marker.get("governed_by").and_then(Value::as_str) == Some(&self.governed_by)
            && object.marker.get("policy").and_then(Value::as_str) == Some(&self.policy)
    }
    fn validate(&self) -> Result<()> {
        super::revision::validate_revision_id(&self.object_id)?;
        validate_name(&self.object_type)?;
        crate::trust::parse_ed25519_did_key(&self.writer)
            .map_err(|_| invalid("source writer requires a DID"))?;
        super::policy::validate_marker(&self.governed_by, &self.policy)?;
        if let Some(id) = &self.policy_revision {
            super::revision::validate_revision_id(id)?;
        }
        if self.operation.trim().is_empty() {
            return Err(invalid("source operation must be nonempty"));
        }
        let mut names = std::collections::BTreeSet::new();
        for group in &self.groups {
            validate_group(group)?;
            if group == super::GOVERNANCE_GROUP || !names.insert(group) {
                return Err(invalid("source groups must be distinct business groups"));
            }
        }
        Ok(())
    }
}

impl Governance {
    /// Inspect validated immediate causal inputs; policy DAG parents remain separate.
    pub fn source_references(&self) -> Result<Vec<SourceReference>> {
        let Some(value) = self.get("source_lineage") else {
            return Ok(Vec::new());
        };
        let references: Vec<SourceReference> = serde_json::from_value(value.clone())
            .map_err(|e| invalid(format!("source lineage: {e}")))?;
        for reference in &references {
            reference.validate()?;
        }
        Ok(references)
    }
}
