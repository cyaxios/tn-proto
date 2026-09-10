use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::canonical::canonical_bytes;
use crate::cipher::GroupCipher;
use crate::{Error, Result};

use super::object::parse_json;
use super::policy::string_field;
use super::{
    invalid, validate_group, DatasetSelection, Governance, GovernedDraft, GovernedObject,
    UseContext, GOVERNANCE_GROUP,
};

/// Reader material indexed by group. Multiple candidates support retained
/// historical keys and objects from different publishers.
#[derive(Default)]
pub struct GovernedReader {
    groups: BTreeMap<String, Vec<Arc<dyn GroupCipher>>>,
    identity: Arc<()>,
}

impl GovernedReader {
    /// Legacy operation-only receipt. Use [`Self::receive_for`] to bind the
    /// complete use, reader context and selected groups before opening data.
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

    /// Verify the exact source and optional edition selection, admit its complete
    /// use and selected groups, then open business data under this reader.
    pub fn receive_for<I, S, F>(
        &self,
        wire: &str,
        use_context: &UseContext,
        groups: I,
        selection: Option<&DatasetSelection>,
        decide: F,
    ) -> Result<super::DataObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnOnce(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        let object = GovernedObject::parse(wire)?;
        let view = self.governance(&object)?;
        let selected = selected_groups(&object, groups)?;
        if selected.is_empty() {
            return Err(invalid(
                "strict admission requires at least one business group",
            ));
        }
        if let Some(selection) = selection {
            selection.verify_source(&view, use_context, &selected)?;
        }
        let admitted = view.accept(use_context.clone(), &selected, decide)?;
        let mut data = super::DataObject::from_opened(self.open(&admitted, &selected)?)?;
        if let Some(selection) = selection {
            data.bind_selection(selection)?;
        }
        Ok(data)
    }

    /// Start a reader with no group material.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cipher capable of opening the named group.
    pub fn with_group(mut self, name: &str, cipher: Arc<dyn GroupCipher>) -> Result<Self> {
        validate_group(name)?;
        self.groups.entry(name.to_owned()).or_default().push(cipher);
        // A changed capability snapshot must obtain a new strict acceptance.
        self.identity = Arc::new(());
        Ok(self)
    }

    /// Open only the contract, retaining every business group as ciphertext.
    pub fn governance(&self, object: &GovernedObject) -> Result<GovernanceView> {
        let body = self.open_group(object, GOVERNANCE_GROUP)?;
        let governance = Governance::from_body(string_field(&object.marker, "governed_by")?, body)?;
        governance.policies()?;
        governance.source_references()?;
        governance.dataset_bindings()?;
        if governance.policy_ref() != string_field(&object.marker, "policy")? {
            return Err(invalid(
                "opened policy must match its authenticated AAD reference",
            ));
        }
        Ok(GovernanceView {
            object: object.clone(),
            governance,
            reader_identity: Arc::clone(&self.identity),
        })
    }

    /// Open precisely the named business groups after application admission.
    /// Every requested group must open; other ciphertext is retained unchanged.
    pub fn open<I, S>(&self, admitted: &AdmittedObject, groups: I) -> Result<OpenedObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let selected = selected_groups(&admitted.view.object, groups)?;
        if let Some(accepted) = &admitted.strict {
            if !Arc::ptr_eq(&self.identity, &admitted.view.reader_identity) {
                return Err(invalid(
                    "strict acceptance belongs to a different reader context",
                ));
            }
            if selected
                .iter()
                .any(|name| accepted.groups.binary_search(name).is_err())
            {
                return Err(invalid(
                    "opening cannot expand the strictly accepted business groups",
                ));
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
    reader_identity: Arc<()>,
}

impl GovernanceView {
    /// Accept a complete use and immutable group set under this reader context.
    /// All structural checks precede the application decision; no business group
    /// is opened until the resulting admission is passed to the same reader.
    pub fn accept<I, S, F>(
        self,
        use_context: UseContext,
        groups: I,
        decide: F,
    ) -> Result<AdmittedObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnOnce(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        let groups = selected_groups(&self.object, groups)?;
        if groups.is_empty() {
            return Err(invalid(
                "strict admission requires at least one business group",
            ));
        }
        let context = super::AdmissionContext {
            object: &self.object,
            governance: &self.governance,
            operation: use_context.operation(),
            use_context: Some(&use_context),
            groups: Some(&groups),
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: use_context.operation().to_owned(),
            });
        }
        Ok(AdmittedObject {
            view: self,
            operation: use_context.operation().to_owned(),
            strict: Some(AcceptedUse {
                use_context,
                groups,
            }),
        })
    }

    /// Legacy operation-only admission with verified source context. Use
    /// [`Self::accept`] for complete use and immutable selected-group admission.
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
            use_context: None,
            groups: None,
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: operation.to_owned(),
            });
        }
        Ok(AdmittedObject {
            view: self,
            operation: operation.to_owned(),
            strict: None,
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

    /// Legacy contract-and-operation decision. Use [`Self::accept`] to bind
    /// complete use and selected groups under this reader context.
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
            strict: None,
        })
    }
}

/// An object admitted for a complete use, or a legacy operation-only decision.
#[derive(Clone)]
pub struct AdmittedObject {
    view: GovernanceView,
    operation: String,
    strict: Option<AcceptedUse>,
}

#[derive(Clone)]
struct AcceptedUse {
    use_context: UseContext,
    groups: Vec<String>,
}

impl AdmittedObject {
    /// Complete accepted use, absent only for the legacy operation-only path.
    pub fn use_context(&self) -> Option<&UseContext> {
        self.strict.as_ref().map(|accepted| &accepted.use_context)
    }
    /// Maximum business group set accepted on the strict path.
    pub fn selected_groups(&self) -> Option<&[String]> {
        self.strict
            .as_ref()
            .map(|accepted| accepted.groups.as_slice())
    }
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
    /// Complete use accepted before opening these groups, when the strict path was used.
    pub fn use_context(&self) -> Option<&UseContext> {
        self.admitted.use_context()
    }
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

fn selected_groups<I, S>(object: &GovernedObject, groups: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut selected = BTreeSet::new();
    for name in groups {
        let name = name.as_ref();
        if name == GOVERNANCE_GROUP
            || !object.groups.contains_key(name)
            || !selected.insert(name.to_owned())
        {
            return Err(invalid(format!(
                "select each present business group once: {name:?}"
            )));
        }
    }
    Ok(selected.into_iter().collect())
}
