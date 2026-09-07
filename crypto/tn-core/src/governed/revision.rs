//! Signed policy revision records using the existing governed envelope.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::agents_policy::{parse_policy_text, PolicyDocument, PolicyTemplate, REQUIRED_FIELDS};
use crate::{Error, Result};

use super::{validate_name, Governance, GovernedDraft, GovernedObject, OpenedObject};

/// Object type for a signed policy revision.
pub const POLICY_REVISION_TYPE: &str = "tn.policy.revision";
/// Encrypted business group containing the typed policy revision record.
pub const POLICY_REVISION_GROUP: &str = "policy_revision";
const REVISION_SCHEMA: &str = "tn-policy-revision@v1";

pub(super) fn invalid_revision(reason: impl Into<String>) -> Error {
    Error::Malformed {
        kind: "policy revision",
        reason: reason.into(),
    }
}

pub(super) fn validate_revision_id(id: &str) -> Result<()> {
    let digest = id.strip_prefix("sha256:").unwrap_or_default();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_revision(
            "revision identity requires a lowercase TN row hash",
        ));
    }
    Ok(())
}

/// Declared relationship to a parent. Applications evaluate its policy meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRelation {
    /// Succeed one earlier revision within an application-authorized scope.
    Revise,
    /// Carry a parent's applicable obligations and add requirements.
    Extend,
    /// Incorporate multiple parents into an explicit effective contract.
    Combine,
}

/// Authenticated reference to an earlier signed revision object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyParent {
    revision_id: String,
    relation: PolicyRelation,
}

impl PolicyParent {
    /// Row hash identifying the entire parent revision record.
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }
    /// Application-declared relationship to the parent.
    pub fn relation(&self) -> PolicyRelation {
        self.relation
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalizedPolicy {
    events: BTreeMap<String, BTreeMap<String, String>>,
    schema: String,
    version: String,
}

impl NormalizedPolicy {
    fn from_document(document: &PolicyDocument) -> Self {
        let events = document
            .templates
            .iter()
            .map(|(event, template)| {
                let fields = BTreeMap::from([
                    ("instruction".into(), template.instruction.clone()),
                    ("use_for".into(), template.use_for.clone()),
                    ("do_not_use_for".into(), template.do_not_use_for.clone()),
                    ("consequences".into(), template.consequences.clone()),
                    (
                        "on_violation_or_error".into(),
                        template.on_violation_or_error.clone(),
                    ),
                ]);
                (event.clone(), fields)
            })
            .collect();
        Self {
            events,
            schema: document.schema.clone(),
            version: document.version.clone(),
        }
    }

    fn governance(&self, authority: &str, policy_id: &str, event_type: &str) -> Result<Governance> {
        validate_name(event_type)?;
        if self.schema != "tn-agents-policy@v1"
            || self.version.trim().is_empty()
            || policy_id.trim().is_empty()
            || policy_id.contains('\0')
            || self.events.is_empty()
        {
            return Err(invalid_revision(
                "required policy schema, version, label, and events",
            ));
        }
        for (event, fields) in &self.events {
            if event.trim().is_empty()
                || fields.len() != REQUIRED_FIELDS.len()
                || REQUIRED_FIELDS
                    .iter()
                    .any(|name| fields.get(*name).is_none_or(|v| v.trim().is_empty()))
            {
                return Err(invalid_revision(
                    "each policy event requires exactly five nonempty contract fields",
                ));
            }
        }
        if !self.events.contains_key(event_type) {
            return Err(invalid_revision(
                "selected policy event must occur in the normalized document",
            ));
        }
        let template = PolicyTemplate::from_normalized_document(
            event_type,
            &self.version,
            &self.schema,
            self.events.clone(),
            policy_id,
        )?;
        Governance::from_template(authority, &template)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionBody {
    schema: String,
    scope: String,
    governed_by: String,
    policy_id: String,
    event_type: String,
    document: NormalizedPolicy,
    policy: String,
    parents: Vec<PolicyParent>,
}

impl RevisionBody {
    fn validate(&self) -> Result<Governance> {
        if self.schema != REVISION_SCHEMA {
            return Err(invalid_revision("required tn-policy-revision@v1 schema"));
        }
        validate_name(&self.scope)?;
        let mut parents = BTreeSet::new();
        for parent in &self.parents {
            validate_revision_id(parent.revision_id())?;
            if !parents.insert(parent.revision_id()) {
                return Err(invalid_revision("each parent revision must occur once"));
            }
        }
        match self.parents.as_slice() {
            [] => {}
            [parent] if parent.relation != PolicyRelation::Combine => {}
            multiple
                if multiple.len() >= 2
                    && multiple
                        .iter()
                        .all(|p| p.relation == PolicyRelation::Combine) => {}
            _ => {
                return Err(invalid_revision(
                    "revise/extend requires one parent; combine requires at least two parents",
                ))
            }
        }
        let governance =
            self.document
                .governance(&self.governed_by, &self.policy_id, &self.event_type)?;
        if governance.policy_ref() != self.policy {
            return Err(invalid_revision(
                "policy reference must match the normalized document and selected event",
            ));
        }
        Ok(governance)
    }
}

/// A policy revision before signing, containing its normalized document and parents.
#[derive(Debug, Clone)]
pub struct PolicyRevisionDraft {
    body: RevisionBody,
}

impl PolicyRevisionDraft {
    /// Parse a policy document and select the effective contract for this scope.
    /// Starts a root revision; use `parent` for a revision, extension, or merge.
    pub fn from_markdown(
        authority: &str,
        markdown: &str,
        policy_id: &str,
        event_type: &str,
        scope: &str,
    ) -> Result<Self> {
        let document = NormalizedPolicy::from_document(&parse_policy_text(markdown, policy_id)?);
        let governance = document.governance(authority, policy_id, event_type)?;
        let body = RevisionBody {
            schema: REVISION_SCHEMA.to_owned(),
            scope: scope.to_owned(),
            governed_by: authority.to_owned(),
            policy_id: policy_id.to_owned(),
            event_type: event_type.to_owned(),
            document,
            policy: governance.policy_ref().to_owned(),
            parents: Vec::new(),
        };
        body.validate()?;
        Ok(Self { body })
    }

    /// Add an earlier revision identity and its declared relationship.
    /// The complete parent cardinality is validated by `into_draft`.
    pub fn parent(mut self, revision_id: &str, relation: PolicyRelation) -> Result<Self> {
        validate_revision_id(revision_id)?;
        if self
            .body
            .parents
            .iter()
            .any(|p| p.revision_id == revision_id)
        {
            return Err(invalid_revision("each parent revision must occur once"));
        }
        self.body.parents.push(PolicyParent {
            revision_id: revision_id.to_owned(),
            relation,
        });
        Ok(self)
    }

    /// Build a governed draft under the contract for administering this revision.
    /// The administration contract governs this publication; the encrypted record
    /// contains the effective contract being published. The writer supplies keys
    /// for `tn.agents` and `policy_revision` and seals the returned draft normally.
    pub fn into_draft(self, administration_contract: Governance) -> Result<GovernedDraft> {
        self.body.validate()?;
        GovernedDraft::new(POLICY_REVISION_TYPE, administration_contract)?
            .group(POLICY_REVISION_GROUP, self.body)
    }
}

/// A decoded policy revision and its original integrity-verified TN object.
/// `PolicyDag::admit` applies update authority after this structural validation.
#[derive(Debug, Clone)]
pub struct PolicyRevision {
    object: GovernedObject,
    governance: Governance,
    body: RevisionBody,
}

impl PolicyRevision {
    /// Decode a revision after ordinary governance admission and selected opening.
    /// Recompute the policy reference from the complete normalized document.
    pub fn from_opened(opened: &OpenedObject) -> Result<Self> {
        if opened.object().object_type() != POLICY_REVISION_TYPE {
            return Err(invalid_revision("required tn.policy.revision object type"));
        }
        let payload = opened.groups().get(POLICY_REVISION_GROUP).ok_or_else(|| {
            invalid_revision("open the policy_revision group before decoding its record")
        })?;
        let body: RevisionBody = serde_json::from_value(payload.clone())
            .map_err(|e| invalid_revision(format!("invalid revision record: {e}")))?;
        let governance = body.validate()?;
        if body
            .parents
            .iter()
            .any(|parent| parent.revision_id == opened.object().id())
        {
            return Err(invalid_revision(
                "a revision must reference earlier objects, not itself",
            ));
        }
        Ok(Self {
            object: opened.object().clone(),
            governance,
            body,
        })
    }

    /// Identity covering this revision's signed content and parent relationships.
    pub fn id(&self) -> &str {
        self.object.id()
    }
    /// Writer authenticated by the TN object's signature.
    pub fn writer(&self) -> &str {
        self.object.writer()
    }
    /// Exact application scope of this revision.
    pub fn scope(&self) -> &str {
        &self.body.scope
    }
    /// Effective contract reconstructed from the normalized policy document.
    pub fn governance(&self) -> &Governance {
        &self.governance
    }
    /// Signed parent identities and declared relationships, in recorded order.
    pub fn parents(&self) -> &[PolicyParent] {
        &self.body.parents
    }
    /// Original signed envelope for forwarding, persistence, and exhaust.
    pub fn object(&self) -> &GovernedObject {
        &self.object
    }
}
