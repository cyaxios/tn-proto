//! Mutable data with retained contracts and immutable signed versions.
use super::{
    invalid, validate_group, validate_name, AttachmentContext, DatasetBinding, DatasetSelection,
    Governance, GovernedDraft, GovernedObject, GovernedWriter, OpenedObject, ReleaseContext,
    SourceReference, UseContext, GOVERNANCE_GROUP,
};
use crate::sealed_object::GroupBlock;
use crate::{Error, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// A mutable working object. Policy attachment is append-only; releases retain snapshots.
#[derive(Clone)]
pub struct DataObject {
    object_type: String,
    governance: Governance,
    groups: BTreeMap<String, Map<String, Value>>,
    opaque: BTreeMap<String, GroupBlock>,
    sources: Vec<SourceReference>,
    history: Vec<GovernedObject>,
    revision: u64,
    unreleased_changes: bool,
    register_error: Option<String>,
}

impl DataObject {
    /// Exact selected dataset origins retained through mutation and inclusion.
    pub fn dataset_bindings(&self) -> Result<Vec<DatasetBinding>> {
        self.governance.dataset_bindings()
    }

    /// Receipt has already verified this private accepted selection against the source.
    pub(crate) fn bind_selection(&mut self, selection: &DatasetSelection) -> Result<()> {
        let mut candidate = self.governance.clone();
        merge_bindings(&mut candidate, [selection.binding()])?;
        self.governance = candidate;
        self.changed();
        Ok(())
    }

    /// Originate a mutable object with its required contract and first business group.
    pub fn new(
        object_type: &str,
        policy: Governance,
        group: &str,
        fields: impl Serialize,
    ) -> Result<Self> {
        Self::new_with_groups(object_type, policy, [(group, fields)])
    }
    /// Originate all business groups together before creating a signed snapshot.
    /// An empty collection, duplicate names, or reserved governance group is refused.
    pub fn new_with_groups<I, S, V>(
        object_type: &str,
        policy: Governance,
        groups: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (S, V)>,
        S: AsRef<str>,
        V: Serialize,
    {
        validate_name(object_type)?;
        policy.policies()?;
        policy.dataset_bindings()?;
        let sources = policy.source_references()?;
        let mut data = Self {
            object_type: object_type.to_owned(),
            governance: policy,
            groups: BTreeMap::new(),
            opaque: BTreeMap::new(),
            sources,
            history: Vec::new(),
            revision: 0,
            unreleased_changes: true,
            register_error: None,
        };
        for (name, fields) in groups {
            let name = name.as_ref();
            if data.groups.contains_key(name) {
                return Err(invalid(format!("duplicate business group {name:?}")));
            }
            data.set_group(name, fields)?;
        }
        if data.groups.is_empty() {
            return Err(invalid("creation requires at least one business group"));
        }
        Ok(data)
    }
    /// Use admitted selected plaintext while retaining every unopened source group.
    pub fn from_opened(opened: OpenedObject) -> Result<Self> {
        let source = SourceReference::from_opened(&opened)?;
        let groups = opened
            .groups()
            .iter()
            .map(|(name, value)| {
                value
                    .as_object()
                    .cloned()
                    .map(|fields| (name.clone(), fields))
                    .ok_or_else(|| invalid("business group must be an object"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let opaque = opened
            .object()
            .groups
            .iter()
            .filter(|(name, _)| name.as_str() != GOVERNANCE_GROUP && !groups.contains_key(*name))
            .map(|(name, block)| (name.clone(), block.clone()))
            .collect();
        Ok(Self {
            object_type: opened.object().object_type().to_owned(),
            governance: opened.governance().clone(),
            groups,
            opaque,
            sources: vec![source],
            history: vec![opened.object().clone()],
            revision: 0,
            unreleased_changes: false,
            register_error: None,
        })
    }
    /// Current object type.
    pub fn object_type(&self) -> &str {
        &self.object_type
    }
    /// Primary governance; callers cannot replace or remove it.
    pub fn governance(&self) -> &Governance {
        &self.governance
    }
    /// Primary and additional policy contracts.
    pub fn policies(&self) -> Result<Vec<Governance>> {
        self.governance.policies()
    }
    /// Current selected plaintext groups.
    pub fn groups(&self) -> &BTreeMap<String, Map<String, Value>> {
        &self.groups
    }
    /// Selected plaintext for one group.
    pub fn group(&self, name: &str) -> Option<&Map<String, Value>> {
        self.groups.get(name)
    }
    /// Groups retained as original ciphertext.
    pub fn hidden_groups(&self) -> Vec<&str> {
        self.opaque.keys().map(String::as_str).collect()
    }
    /// Causal inputs of the next release.
    pub fn sources(&self) -> &[SourceReference] {
        &self.sources
    }
    /// Latest sealed snapshot, suitable for exact-byte retry.
    pub fn snapshot(&self) -> Option<&GovernedObject> {
        self.history.last()
    }
    /// Retained signed versions, in local observation/release order.
    pub fn history(&self) -> &[GovernedObject] {
        &self.history
    }
    /// Working-state generation for callback/concurrency checks.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Whether a successful mutation occurred since the latest signed snapshot.
    /// A newly constructed unsaved object is also pending. Refused operations
    /// preserve this state; successful release records the current state.
    /// This describes local working data, independently of delivery or database commit.
    pub fn has_unreleased_changes(&self) -> bool {
        self.unreleased_changes
    }
    /// Most recent optional register I/O error; the sealed snapshot remains available.
    pub fn register_error(&self) -> Option<&str> {
        self.register_error.as_deref()
    }
    #[cfg(feature = "fs")]
    pub(crate) fn set_register_error(&mut self, error: Option<String>) {
        self.register_error = error;
    }
    fn changed(&mut self) {
        self.revision = self.revision.wrapping_add(1);
        self.unreleased_changes = true;
    }

    /// Inspect a detached snapshot of the current working state.
    pub fn inspect(&self) -> Self {
        self.clone()
    }
    /// Read a business field, or the complete opened group when field is None.
    pub fn get(&self, group: &str, field: Option<&str>) -> Result<Value> {
        business_group(group)?;
        let fields = self
            .groups
            .get(group)
            .ok_or_else(|| invalid(format!("no opened group {group:?}")))?;
        match field {
            Some(name) => fields
                .get(name)
                .cloned()
                .ok_or_else(|| invalid(format!("no field {name:?} in {group:?}"))),
            None => Ok(Value::Object(fields.clone())),
        }
    }
    /// Change a business field or replace a group; contracts remain attached.
    pub fn set(&mut self, group: &str, field: Option<&str>, value: Value) -> Result<()> {
        match field {
            Some(name) => self.set_field(group, name, value),
            None => self.set_group(group, value),
        }
    }
    /// Select retained groups and optionally fields within opened groups, atomically.
    /// A field projection must name a retained, opened group and existing fields.
    pub fn select<I, S>(
        &mut self,
        groups: I,
        fields: Option<&BTreeMap<String, Vec<String>>>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut candidate = self.clone();
        candidate.retain_groups(groups)?;
        if let Some(projections) = fields {
            for (group, names) in projections {
                business_group(group)?;
                let original = candidate.groups.get(group).ok_or_else(|| {
                    invalid(format!(
                        "field selection requires retained opened group {group:?}"
                    ))
                })?;
                let mut selected = Map::new();
                for name in names {
                    let value = original
                        .get(name)
                        .ok_or_else(|| invalid(format!("no field {name:?} in {group:?}")))?;
                    if selected.insert(name.clone(), value.clone()).is_some() {
                        return Err(invalid(format!("duplicate selected field {name:?}")));
                    }
                }
                candidate.set_group(group, selected)?;
            }
        }
        *self = candidate;
        Ok(())
    }
    /// Forward only a current signed publication, never stale working data.
    pub fn forward(&self) -> Result<&[u8]> {
        if self.has_unreleased_changes() {
            return Err(invalid("release working changes before forwarding"));
        }
        Ok(self
            .snapshot()
            .ok_or_else(|| invalid("object has no signed publication"))?
            .forward())
    }
    /// Write the current signed publication; pending edits must be released first.
    pub fn write(&self, mut destination: impl std::io::Write) -> Result<()> {
        destination.write_all(self.forward()?)?;
        Ok(())
    }
    /// Set a complete plaintext group. Governance names are reserved.
    pub fn set_group(&mut self, name: &str, fields: impl Serialize) -> Result<()> {
        business_group(name)?;
        let value = serde_json::to_value(fields)?;
        let fields = value
            .as_object()
            .ok_or_else(|| invalid("group fields must be a JSON object"))?;
        for field in fields.keys() {
            super::validate_field(field)?;
        }
        self.groups.insert(name.to_owned(), fields.clone());
        self.opaque.remove(name);
        self.changed();
        Ok(())
    }
    /// Update one field in an opened group.
    pub fn set_field(&mut self, group: &str, field: &str, value: Value) -> Result<()> {
        self.set_path(&[json!(group), json!(field)], value)
    }
    /// Remove a business group from the next version; prior snapshots remain intact.
    pub fn remove_group(&mut self, name: &str) -> Result<()> {
        business_group(name)?;
        if self.groups.remove(name).is_none() && self.opaque.remove(name).is_none() {
            return Err(invalid(format!("no group {name:?}")));
        }
        self.changed();
        Ok(())
    }
    /// Keep only the named business groups in the next output, including any
    /// explicitly selected opaque groups. Policies and signed history remain.
    /// Every name must exist; all validation precedes any mutation. An empty
    /// selection removes every business group. Repeating a name is harmless.
    pub fn retain_groups<I, S>(&mut self, names: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut selected = BTreeSet::new();
        for name in names {
            let name = name.as_ref();
            business_group(name)?;
            if !self.groups.contains_key(name) && !self.opaque.contains_key(name) {
                return Err(invalid(format!("no group {name:?}")));
            }
            selected.insert(name.to_owned());
        }
        let before = self.groups.len() + self.opaque.len();
        self.groups.retain(|name, _| selected.contains(name));
        self.opaque.retain(|name, _| selected.contains(name));
        if before != self.groups.len() + self.opaque.len() {
            self.changed();
        }
        Ok(())
    }
    /// Copy a selected JSON value. Path elements are dictionary keys or list indices.
    pub fn get_path(&self, path: &[Value]) -> Result<Value> {
        let tree = self.tree();
        let mut node = &tree;
        for key in path {
            node = child(node, key)?;
        }
        Ok(node.clone())
    }
    /// Atomically replace a nested value, retaining policies and unopened groups.
    pub fn set_path(&mut self, path: &[Value], value: Value) -> Result<()> {
        if path.is_empty() {
            return Err(invalid("assign a group or a field"));
        }
        let mut tree = self.tree();
        let (last, parents) = path.split_last().expect("nonempty path");
        let parent = descend(&mut tree, parents)?;
        match (parent, last) {
            (Value::Object(map), Value::String(name)) => {
                map.insert(name.clone(), value);
            }
            (Value::Array(items), Value::Number(index)) => {
                let i = index
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or_else(|| invalid("list index must be nonnegative"))?;
                *items
                    .get_mut(i)
                    .ok_or_else(|| invalid("list index out of range"))? = value;
            }
            _ => {
                return Err(invalid(
                    "path does not address a dictionary key or list index",
                ))
            }
        }
        self.replace_tree(tree)
    }
    /// Atomically append to a selected nested list.
    pub fn append_path(&mut self, path: &[Value], value: Value) -> Result<()> {
        let mut tree = self.tree();
        descend(&mut tree, path)?
            .as_array_mut()
            .ok_or_else(|| invalid("append requires a list"))?
            .push(value);
        self.replace_tree(tree)
    }
    /// Atomically delete a selected dictionary field or list item.
    pub fn delete_path(&mut self, path: &[Value]) -> Result<()> {
        if path.len() == 1 {
            return self.remove_group(
                path[0]
                    .as_str()
                    .ok_or_else(|| invalid("group requires a string"))?,
            );
        }
        let (last, parents) = path
            .split_last()
            .ok_or_else(|| invalid("delete requires a path"))?;
        let mut tree = self.tree();
        match (descend(&mut tree, parents)?, last) {
            (Value::Object(map), Value::String(name)) => {
                map.remove(name).ok_or_else(|| invalid("field not found"))?;
            }
            (Value::Array(items), Value::Number(index)) => {
                let i = index
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|i| *i < items.len())
                    .ok_or_else(|| invalid("list index out of range"))?;
                items.remove(i);
            }
            _ => return Err(invalid("invalid deletion path")),
        }
        self.replace_tree(tree)
    }
    fn tree(&self) -> Value {
        Value::Object(
            self.groups
                .iter()
                .map(|(name, fields)| (name.clone(), Value::Object(fields.clone())))
                .collect(),
        )
    }
    fn replace_tree(&mut self, tree: Value) -> Result<()> {
        let root = tree
            .as_object()
            .ok_or_else(|| invalid("data groups require an object"))?;
        let mut groups = BTreeMap::new();
        for (name, value) in root {
            business_group(name)?;
            let fields = value
                .as_object()
                .ok_or_else(|| invalid("group fields require an object"))?;
            for field in fields.keys() {
                super::validate_field(field)?;
            }
            groups.insert(name.clone(), fields.clone());
        }
        self.opaque.retain(|name, _| !groups.contains_key(name));
        self.groups = groups;
        self.changed();
        Ok(())
    }
    /// Add an authority-approved policy without replacing any existing contract.
    pub fn attach<F>(&mut self, authority: &str, policy: Governance, decide: F) -> Result<()>
    where
        F: FnOnce(&AttachmentContext<'_>) -> Result<bool>,
    {
        crate::trust::parse_ed25519_did_key(authority)
            .map_err(|_| invalid("attachment authority requires a DID"))?;
        policy.policies()?;
        let context = AttachmentContext {
            authority,
            data: self,
            policy: &policy,
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: "policy.attach".to_owned(),
            });
        }
        let mut candidate = self.governance.clone();
        for policy in policy.policies()? {
            append_policy(&mut candidate, &policy)?;
        }
        self.governance = candidate;
        self.changed();
        Ok(())
    }
    /// Include another admitted input's causal references and every attached policy.
    /// Data assignment stays explicit; the additional source object remains available to its owner.
    pub fn include(&mut self, other: &Self) -> Result<()> {
        let mut candidate = self.governance.clone();
        for policy in other.policies()? {
            append_policy(&mut candidate, &policy)?;
        }
        merge_bindings(&mut candidate, other.dataset_bindings()?)?;
        let mut sources = self.sources.clone();
        for source in &other.sources {
            if !sources.contains(source) {
                sources.push(source.clone());
            }
        }
        self.governance = candidate;
        self.sources = sources;
        self.changed();
        Ok(())
    }
    pub(crate) fn draft(
        &self,
        object_type: &str,
        purpose: &str,
        destination: &str,
    ) -> Result<GovernedDraft> {
        let mut policy = self.governance.clone();
        policy.fields.insert(
            "source_lineage".to_owned(),
            serde_json::to_value(&self.sources)?,
        );
        policy.fields.insert(
            "release_context".to_owned(),
            json!({"purpose":purpose,"destination":destination}),
        );
        let mut draft = GovernedDraft::new(object_type, policy)?;
        for (name, fields) in &self.groups {
            draft = draft.group(name, fields)?;
        }
        draft.retained = self.opaque.clone();
        Ok(draft)
    }
    pub(crate) fn record_snapshot(
        &mut self,
        snapshot: GovernedObject,
        operation: &str,
    ) -> Result<()> {
        let reference = SourceReference::new(
            &snapshot,
            &self.governance,
            self.groups.keys().cloned().collect(),
            operation,
        )?;
        self.object_type = snapshot.object_type().to_owned();
        self.history.push(snapshot);
        self.sources = vec![reference];
        self.changed();
        self.unreleased_changes = false;
        Ok(())
    }
}

fn business_group(name: &str) -> Result<()> {
    validate_group(name)?;
    if name == GOVERNANCE_GROUP {
        return Err(invalid(
            "policy is retained by the governed object; attach additional policy explicitly",
        ));
    }
    Ok(())
}
fn child<'a>(node: &'a Value, key: &Value) -> Result<&'a Value> {
    match (node, key) {
        (Value::Object(map), Value::String(name)) => map.get(name),
        (Value::Array(items), Value::Number(index)) => index
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|i| items.get(i)),
        _ => None,
    }
    .ok_or_else(|| invalid("data path not found"))
}
fn descend<'a>(mut node: &'a mut Value, path: &[Value]) -> Result<&'a mut Value> {
    for key in path {
        node = match (node, key) {
            (Value::Object(map), Value::String(name)) => map.get_mut(name),
            (Value::Array(items), Value::Number(index)) => index
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|i| items.get_mut(i)),
            _ => None,
        }
        .ok_or_else(|| invalid("data path not found"))?;
    }
    Ok(node)
}
pub(super) fn base_contract(policy: &Governance) -> Governance {
    let mut policy = policy.clone();
    for name in [
        "attached_policies",
        "source_lineage",
        "release_context",
        "dataset_bindings",
    ] {
        policy.fields.remove(name);
    }
    policy
}
fn append_policy(target: &mut Governance, additional: &Governance) -> Result<()> {
    let policies = target.policies()?;
    let additional = base_contract(additional);
    if policies.contains(&additional) {
        return Ok(());
    }
    if policies.len() >= 64 {
        return Err(invalid("object supports at most 64 attached contracts"));
    }
    let value = json!({"governed_by":additional.governed_by(),"fields":additional.fields()});
    target
        .fields
        .entry("attached_policies")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid("attached policies require an array"))?
        .push(value);
    Ok(())
}
impl Governance {
    /// Validated selected origins. These are carried facts; the catalog admits their use.
    pub fn dataset_bindings(&self) -> Result<Vec<DatasetBinding>> {
        let Some(value) = self.get("dataset_bindings") else {
            return Ok(Vec::new());
        };
        let values = value
            .as_array()
            .ok_or_else(|| invalid("dataset bindings require an array"))?;
        if values.len() > 1024 {
            return Err(invalid("object supports at most 1024 dataset bindings"));
        }
        let bindings: Vec<DatasetBinding> = serde_json::from_value(value.clone())
            .map_err(|error| invalid(format!("dataset bindings: {error}")))?;
        for (index, binding) in bindings.iter().enumerate() {
            binding.validate()?;
            if bindings[..index]
                .iter()
                .any(|existing| existing.edition_record_id() == binding.edition_record_id())
            {
                return Err(invalid(
                    "each edition record must have exactly one dataset binding",
                ));
            }
        }
        Ok(bindings)
    }

    /// Primary and appended contracts, each retaining its own authority and revision.
    pub fn policies(&self) -> Result<Vec<Governance>> {
        let mut policies = vec![base_contract(self)];
        if let Some(value) = self.get("attached_policies") {
            let values = value
                .as_array()
                .ok_or_else(|| invalid("attached policies require an array"))?;
            if values.len() >= 64 {
                return Err(invalid("object supports at most 64 attached contracts"));
            }
            for value in values {
                let record = value
                    .as_object()
                    .filter(|record| record.len() == 2)
                    .ok_or_else(|| invalid("attached policy requires authority and fields"))?;
                let authority = record
                    .get("governed_by")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("attached policy requires authority"))?;
                let fields = record
                    .get("fields")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("attached policy requires fields"))?;
                if fields.contains_key("attached_policies") {
                    return Err(invalid("attached policy list must be flat"));
                }
                let policy = Governance::from_body(authority, fields.clone())?;
                if policies.contains(&policy) {
                    return Err(invalid("attached policies must be distinct"));
                }
                policies.push(policy);
            }
        }
        Ok(policies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additional_machine_rules_are_retained_even_with_the_same_base_contract() {
        let device = crate::DeviceKey::generate();
        let policy=Governance::from_markdown(device.did(),
            "## data\n### instruction\nAnalyze.\n### use_for\nResearch.\n### do_not_use_for\nDisclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n",
            "unity/data", "data").unwrap();
        let mut first = policy.clone();
        first.fields.insert("region".into(), json!("eu"));
        let mut second = policy;
        second.fields.insert("region".into(), json!("us"));
        assert!(first.matches_contract(&second));
        let mut data = DataObject::new("data", first, "data", json!({})).unwrap();
        let other = DataObject::new("data", second.clone(), "data", json!({})).unwrap();
        data.include(&other).unwrap();
        data.attach(device.did(), second, |_| Ok(true)).unwrap();
        let policies = data.policies().unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].get("region"), Some(&json!("eu")));
        assert_eq!(policies[1].get("region"), Some(&json!("us")));
    }
}

impl GovernedWriter<'_> {
    /// Originate data with its required contract and retain the initial signed version.
    pub fn create_obj(
        &self,
        object_type: &str,
        policy: Governance,
        group: &str,
        fields: impl Serialize,
    ) -> Result<DataObject> {
        self.create_obj_with_groups(object_type, policy, [(group, fields)])
    }

    /// Originate a complete group collection in one signed initial version.
    /// Group routing remains explicit; `tn.agents` comes from the required policy.
    pub fn create_obj_with_groups<I, S, V>(
        &self,
        object_type: &str,
        policy: Governance,
        groups: I,
    ) -> Result<DataObject>
    where
        I: IntoIterator<Item = (S, V)>,
        S: AsRef<str>,
        V: Serialize,
    {
        let mut data = DataObject::new_with_groups(object_type, policy, groups)?;
        let sealed = self.seal(data.draft(object_type, "create", "origin")?)?;
        data.record_snapshot(sealed, "create")?;
        Ok(data)
    }

    /// Add policy after the application accepts this writer's attachment authority.
    pub fn attach<F>(&self, data: &mut DataObject, policy: Governance, decide: F) -> Result<()>
    where
        F: FnOnce(&AttachmentContext<'_>) -> Result<bool>,
    {
        data.attach(self.did(), policy, decide)
    }

    /// Admit the current data for its destination and purpose, then retain a signed version.
    pub fn release<F>(
        &self,
        data: &mut DataObject,
        object_type: &str,
        purpose: &str,
        destination: &str,
        decide: F,
    ) -> Result<GovernedObject>
    where
        F: FnOnce(&ReleaseContext<'_>) -> Result<bool>,
    {
        validate_name(object_type)?;
        if purpose.trim().is_empty() || destination.trim().is_empty() {
            return Err(invalid("release requires purpose and destination"));
        }
        let context = ReleaseContext {
            writer: self.did(),
            data,
            object_type,
            purpose,
            destination,
            use_context: None,
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: format!("release:{purpose}"),
            });
        }
        let sealed = self.seal(data.draft(object_type, purpose, destination)?)?;
        data.record_snapshot(sealed.clone(), purpose)?;
        Ok(sealed)
    }

    /// Release under an explicit application, purpose and operation.
    pub fn release_for<F>(
        &self,
        data: &mut DataObject,
        object_type: &str,
        use_context: &UseContext,
        destination: &str,
        decide: F,
    ) -> Result<GovernedObject>
    where
        F: FnOnce(&ReleaseContext<'_>) -> Result<bool>,
    {
        validate_name(object_type)?;
        if destination.trim().is_empty() {
            return Err(invalid("release requires a destination"));
        }
        let context = ReleaseContext {
            writer: self.did(),
            data,
            object_type,
            purpose: use_context.purpose(),
            destination,
            use_context: Some(use_context),
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: use_context.operation().to_owned(),
            });
        }
        let mut draft = data.draft(object_type, use_context.purpose(), destination)?;
        draft.governance.fields.insert(
            "release_context".into(),
            json!({
                "application": use_context.application(), "purpose": use_context.purpose(),
                "operation": use_context.operation(), "destination": destination,
            }),
        );
        let sealed = self.seal(draft)?;
        data.record_snapshot(sealed.clone(), use_context.operation())?;
        Ok(sealed)
    }
}

fn merge_bindings(
    governance: &mut Governance,
    additions: impl IntoIterator<Item = DatasetBinding>,
) -> Result<()> {
    let mut bindings = governance.dataset_bindings()?;
    for binding in additions {
        binding.validate()?;
        if bindings.iter().any(|existing| {
            existing.edition_record_id() == binding.edition_record_id() && existing != &binding
        }) {
            return Err(invalid(
                "a selected edition record cannot acquire a different binding",
            ));
        }
        if !bindings.contains(&binding) {
            if bindings.len() >= 1024 {
                return Err(invalid("object supports at most 1024 dataset bindings"));
            }
            bindings.push(binding);
        }
    }
    if !bindings.is_empty() {
        governance
            .fields
            .insert("dataset_bindings".into(), serde_json::to_value(bindings)?);
    }
    Ok(())
}
