use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::canonical::canonical_bytes;
use crate::cipher::GroupCipher;
use crate::{Error, Result};

use super::object::parse_json;
use super::policy::string_field;
use super::{invalid, validate_group, Governance, GovernedDraft, GovernedObject, GOVERNANCE_GROUP};

/// Reader material indexed by group. Multiple candidates support retained
/// historical keys and objects from different publishers.
#[derive(Default)]
pub struct GovernedReader {
    groups: BTreeMap<String, Vec<Arc<dyn GroupCipher>>>,
}

impl GovernedReader {
    /// Verify a source, admit its full contract and identity, then open selected data.
    pub fn receive<I, S, F>(
        &self,
        wire: &str,
        operation: &str,
        groups: I,
        decide: F,
    ) -> Result<super::DataObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnOnce(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        let object = GovernedObject::parse(wire)?;
        let admitted = self
            .governance(&object)?
            .authorize_with(operation, decide)?;
        super::DataObject::from_opened(self.open(&admitted, groups)?)
    }

    /// Start a reader with no group material.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cipher capable of opening the named group.
    pub fn with_group(mut self, name: &str, cipher: Arc<dyn GroupCipher>) -> Result<Self> {
        validate_group(name)?;
        self.groups.entry(name.to_owned()).or_default().push(cipher);
        Ok(self)
    }

    /// Open only the contract, retaining every business group as ciphertext.
    pub fn governance(&self, object: &GovernedObject) -> Result<GovernanceView> {
        let body = self.open_group(object, GOVERNANCE_GROUP)?;
        let governance = Governance::from_body(string_field(&object.marker, "governed_by")?, body)?;
        governance.policies()?;
        governance.source_references()?;
        if governance.policy_ref() != string_field(&object.marker, "policy")? {
            return Err(invalid(
                "opened policy must match its authenticated AAD reference",
            ));
        }
        Ok(GovernanceView {
            object: object.clone(),
            governance,
        })
    }

    /// Open precisely the named business groups after application admission.
    /// Every requested group must open; other ciphertext is retained unchanged.
    pub fn open<I, S>(&self, admitted: &AdmittedObject, groups: I) -> Result<OpenedObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut selected = BTreeSet::new();
        for name in groups {
            let name = name.as_ref();
            if name == GOVERNANCE_GROUP
                || !admitted.view.object.groups.contains_key(name)
                || !selected.insert(name.to_owned())
            {
                return Err(invalid(format!(
                    "select each present business group once: {name:?}"
                )));
            }
        }
        let mut plaintext = BTreeMap::new();
        for name in selected {
            plaintext.insert(
                name.clone(),
                Value::Object(self.open_group(&admitted.view.object, &name)?),
            );
        }
        Ok(OpenedObject {
            admitted: admitted.clone(),
            groups: plaintext,
        })
    }

    fn open_group(&self, object: &GovernedObject, name: &str) -> Result<Map<String, Value>> {
        let block = object
            .groups
            .get(name)
            .ok_or_else(|| invalid(format!("object has no group {name:?}")))?;
        let aad = canonical_bytes(&Value::Object(object.marker.clone()))?;
        let mut cipher_error = None;
        for cipher in self.groups.get(name).into_iter().flatten() {
            let bytes = match cipher.decrypt_with_aad(&block.ciphertext, &aad) {
                Ok(bytes) => bytes,
                Err(Error::NotEntitled { .. } | Error::NotAPublisher { .. }) => continue,
                Err(error) => {
                    cipher_error = Some(error);
                    continue;
                }
            };
            let source = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("opened group must be UTF-8 JSON"))?;
            let value = parse_json(source)?;
            let fields = value
                .as_object()
                .ok_or_else(|| invalid("opened group must be a JSON object"))?;
            if fields.len() != block.field_hashes.len()
                || !fields.keys().all(|f| block.field_hashes.contains_key(f))
            {
                return Err(invalid(
                    "opened fields must match the group's signed field names",
                ));
            }
            return Ok(fields.clone());
        }
        Err(cipher_error.unwrap_or_else(|| Error::NotEntitled {
            group: name.to_owned(),
        }))
    }
}

/// The opened contract and its verified source, before business-data admission.
#[derive(Clone)]
pub struct GovernanceView {
    object: GovernedObject,
    governance: Governance,
}

impl GovernanceView {
    /// Admit use with verified writer, object type, contract and source context together.
    pub fn authorize_with<F>(self, operation: &str, decide: F) -> Result<AdmittedObject>
    where
        F: FnOnce(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        if operation.trim().is_empty() {
            return Err(invalid("operation must be nonempty"));
        }
        let context = super::AdmissionContext {
            object: &self.object,
            governance: &self.governance,
            operation,
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: operation.to_owned(),
            });
        }
        Ok(AdmittedObject {
            view: self,
            operation: operation.to_owned(),
        })
    }
    /// The authenticated contract the application is to evaluate.
    pub fn governance(&self) -> &Governance {
        &self.governance
    }
    /// Complete verified source, ready for unchanged forwarding.
    pub fn object(&self) -> &GovernedObject {
        &self.object
    }

    /// Apply the application's permitted-use decision for a named operation.
    /// The callback returns `true` for approval; its errors propagate. Reader
    /// keys remain the separate requirement for opening the admitted groups.
    pub fn authorize<F>(self, operation: &str, decide: F) -> Result<AdmittedObject>
    where
        F: FnOnce(&Governance, &str) -> Result<bool>,
    {
        if operation.trim().is_empty() {
            return Err(invalid("operation must be nonempty"));
        }
        if !decide(&self.governance, operation)? {
            return Err(Error::UseDenied {
                operation: operation.to_owned(),
            });
        }
        Ok(AdmittedObject {
            view: self,
            operation: operation.to_owned(),
        })
    }
}

/// An object admitted by the application for a particular operation.
#[derive(Clone)]
pub struct AdmittedObject {
    view: GovernanceView,
    operation: String,
}

impl AdmittedObject {
    /// Operation accepted by the application callback.
    pub fn operation(&self) -> &str {
        &self.operation
    }
    /// Accepted contract.
    pub fn governance(&self) -> &Governance {
        &self.view.governance
    }
    /// Verified object to which the decision applies.
    pub fn object(&self) -> &GovernedObject {
        &self.view.object
    }
}

/// Selected plaintext with its accepted contract and original signed source.
#[derive(Clone)]
pub struct OpenedObject {
    admitted: AdmittedObject,
    groups: BTreeMap<String, Value>,
}

impl OpenedObject {
    /// Application operation for which these source groups were opened.
    pub fn operation(&self) -> &str {
        self.admitted.operation()
    }
    /// Typed causal reference for this admitted input.
    pub fn source_reference(&self) -> Result<super::SourceReference> {
        super::SourceReference::from_opened(self)
    }
    /// Selected business plaintext, separated by group.
    pub fn groups(&self) -> &BTreeMap<String, Value> {
        &self.groups
    }
    /// Accepted contract carried with the plaintext.
    pub fn governance(&self) -> &Governance {
        self.admitted.governance()
    }
    /// Complete original signed object, including unselected ciphertext.
    pub fn object(&self) -> &GovernedObject {
        self.admitted.object()
    }
    /// Business groups remaining encrypted in this view.
    pub fn hidden_groups(&self) -> Vec<&str> {
        self.object()
            .group_names()
            .into_iter()
            .filter(|name| *name != GOVERNANCE_GROUP && !self.groups.contains_key(*name))
            .collect()
    }

    /// Start a derivative with the continuing source contract and lineage.
    pub fn derive(&self, object_type: &str) -> Result<GovernedDraft> {
        self.derive_under(object_type, self.governance().clone())
    }

    /// Start a derivative under an explicitly selected output contract.
    /// The source reference retains the input's own policy and authority.
    pub fn derive_under(
        &self,
        object_type: &str,
        mut governance: Governance,
    ) -> Result<GovernedDraft> {
        let source = self.source_reference()?;
        governance
            .fields
            .insert("source_lineage".to_owned(), json!([source]));
        GovernedDraft::new(object_type, governance)
    }
}
