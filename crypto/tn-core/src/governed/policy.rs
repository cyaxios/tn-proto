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
    /// Rejects public fields changed since parsing or validated reconstruction.
    pub fn from_template(governed_by: &str, template: &PolicyTemplate) -> Result<Self> {
        template.validate_binding()?;
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
        if fields.contains_key("policy_revision") {
            super::revision::validate_revision_id(string_field(&fields, "policy_revision")?)?;
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

    /// Exact signed policy revision selected by an application, when supplied.
    /// `PolicyDag::resolve` checks this binding against accepted revision content.
    pub fn revision_id(&self) -> Option<&str> {
        self.fields.get("policy_revision").and_then(Value::as_str)
    }

    /// Compare authority, policy reference, selected revision, and all five
    /// effective rules. Carried extensions such as source lineage are ignored.
    /// Applications evaluate source context and any attached policies separately.
    pub fn matches_contract(&self, expected: &Governance) -> bool {
        self.governed_by == expected.governed_by
            && self.policy_ref() == expected.policy_ref()
            && self.revision_id() == expected.revision_id()
            && REQUIRED_FIELDS
                .iter()
                .all(|name| self.fields.get(*name) == expected.fields.get(*name))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> Governance {
        Governance::from_markdown(
            crate::DeviceKey::generate().did(),
            "## sample\n### instruction\nCompute the aggregate.\n### use_for\nResearch.\n### do_not_use_for\nDisclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n",
            "agents.md",
            "sample",
        )
        .unwrap()
    }

    #[test]
    fn contract_match_checks_each_effective_rule_even_with_the_same_reference() {
        let expected = contract();
        for name in REQUIRED_FIELDS {
            let mut carried = expected.fields().clone();
            carried.insert(name.into(), json!("A different rule."));
            let received = Governance::from_body(expected.governed_by(), carried).unwrap();
            assert_eq!(received.policy_ref(), expected.policy_ref());
            assert!(!received.matches_contract(&expected), "changed {name}");
            assert!(!expected.matches_contract(&received), "changed {name}");
        }
    }

    #[test]
    fn contract_match_requires_the_same_authority_and_reference() {
        let expected = contract();
        let other_authority = Governance::from_body(
            crate::DeviceKey::generate().did(),
            expected.fields().clone(),
        )
        .unwrap();
        assert!(!other_authority.matches_contract(&expected));

        let mut fields = expected.fields().clone();
        fields.insert(
            "policy".into(),
            json!(expected.policy_ref().replace("agents.md", "different.md")),
        );
        let other_reference = Governance::from_body(expected.governed_by(), fields).unwrap();
        assert!(!other_reference.matches_contract(&expected));
    }

    #[test]
    fn contract_match_distinguishes_missing_equal_and_different_revisions() {
        let unversioned = contract();
        let revised = |digit: &str| {
            let mut fields = unversioned.fields().clone();
            fields.insert(
                "policy_revision".into(),
                json!(format!("sha256:{}", digit.repeat(64))),
            );
            Governance::from_body(unversioned.governed_by(), fields).unwrap()
        };
        let first = revised("1");
        assert!(!first.matches_contract(&unversioned));
        assert!(!unversioned.matches_contract(&first));
        assert!(first.matches_contract(&revised("1")));
        assert!(!first.matches_contract(&revised("2")));
    }

    #[test]
    fn contract_match_ignores_carried_lineage_extensions() {
        let expected = contract();
        let mut fields = expected.fields().clone();
        fields.insert(
            "derived_from".into(),
            json!(format!("sha256:{}", "3".repeat(64))),
        );
        fields.insert("operation".into(), json!("approved aggregate"));
        let received = Governance::from_body(expected.governed_by(), fields).unwrap();
        assert_ne!(received, expected);
        assert!(received.matches_contract(&expected));
        assert!(expected.matches_contract(&received));
    }
}
