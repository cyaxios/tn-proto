use serde_json::{json, Map, Value};

use crate::agents_policy::{parse_policy_text, PolicyTemplate, REQUIRED_FIELDS};
use crate::Result;

use super::invalid;

/// A use contract and its governing authority, ready for encrypted carriage.
///
/// The writer inserts these fields into `tn.agents` and derives every group's
/// AAD from the same contract. Accessors borrow the original values.
#[derive(Debug, Clone, PartialEq)]
pub struct Governance {
    governed_by: String,
    pub(super) fields: Map<String, Value>,
}

impl Governance {
    /// Parse policy Markdown and select the named object's event section.
    /// `policy_id` is the portable label used in the policy reference.
    pub fn from_markdown(
        governed_by: &str,
        markdown: &str,
        policy_id: &str,
        object_type: &str,
    ) -> Result<Self> {
        let document = parse_policy_text(markdown, policy_id)?;
        let template = document
            .templates
            .get(object_type)
            .ok_or_else(|| invalid(format!("policy has no section for {object_type:?}")))?;
        Self::from_template(governed_by, template)
    }

    /// Use a selected policy template, including its normalized-document hash.
    pub fn from_template(governed_by: &str, template: &PolicyTemplate) -> Result<Self> {
        let fields = json!({
            "instruction": template.instruction,
            "use_for": template.use_for,
            "do_not_use_for": template.do_not_use_for,
            "consequences": template.consequences,
            "on_violation_or_error": template.on_violation_or_error,
            "policy": format!("{}#{}@{}#{}", template.path, template.event_type, template.version, template.content_hash),
        });
        let fields: Map<String, Value> = serde_json::from_value(fields)?;
        Self::from_body(governed_by, fields)
    }

    pub(super) fn from_body(governed_by: &str, fields: Map<String, Value>) -> Result<Self> {
        validate_marker(governed_by, string_field(&fields, "policy")?)?;
        for name in REQUIRED_FIELDS {
            string_field(&fields, name)?;
        }
        Ok(Self {
            governed_by: governed_by.to_owned(),
            fields,
        })
    }

    /// Governing authority declared by this contract.
    pub fn governed_by(&self) -> &str {
        &self.governed_by
    }

    /// Reference identifying the applicable normalized policy content.
    ///
    /// # Panics
    /// The private constructor establishes this string and all public access
    /// is immutable, so a constructed contract always has this field.
    pub fn policy_ref(&self) -> &str {
        self.fields["policy"]
            .as_str()
            .expect("validated policy string")
    }

    /// Contract fields as carried in the encrypted governance group.
    pub fn fields(&self) -> &Map<String, Value> {
        &self.fields
    }

    /// A policy field or carried extension, such as source lineage.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.get(name)
    }

    pub(super) fn marker(&self) -> Value {
        json!({"governed_by": self.governed_by, "policy": self.policy_ref()})
    }
}

pub(super) fn string_field<'a>(fields: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid(format!("required nonempty string {name:?}")))
}

pub(super) fn validate_marker(governed_by: &str, policy: &str) -> Result<()> {
    crate::trust::parse_ed25519_did_key(governed_by)
        .map_err(|_| invalid("governed_by requires an Ed25519 did:key"))?;
    let (identity, digest) = policy
        .rsplit_once("#sha256:")
        .ok_or_else(|| invalid("policy requires a content-addressed reference"))?;
    if identity.trim().is_empty()
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            "policy requires an identity and lowercase SHA-256 digest",
        ));
    }
    Ok(())
}
