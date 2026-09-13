//! Configured governed objects using the shared protocol primitives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::agents_policy::PolicyDocument;
use crate::governed::{Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter};
use crate::{DeviceKey, Error, Result};

use super::material::Material;
use super::{GroupState, ObjectRegisters, Runtime};
use crate::governed::{
    AdmissionContext, AttachmentContext, DataObject, DatasetSelection, ReleaseContext, UseContext,
};

enum Identity<'a> {
    Owned(Box<DeviceKey>),
    Shared(Arc<DeviceKey>),
    Borrowed(&'a DeviceKey),
}

/// Create, seal, and read governed objects with configured group material.
///
/// [`Objects::open`] owns its identity and opens only configuration, policies,
/// and key material. [`Runtime::objects`] borrows the active runtime identity
/// and shares its group states, including subsequent in-process rotations.
/// [`Objects::ephemeral`] creates an independent in-memory identity and groups.
/// Every path signs governed objects and returns their wire bytes.
pub struct Objects<'a> {
    identity: Identity<'a>,
    groups: BTreeMap<String, Arc<RwLock<GroupState>>>,
    private_groups: BTreeSet<String>,
    policies: Option<PolicyDocument>,
    registers: ObjectRegisters,
    register_provider: Option<Arc<dyn crate::providers::RegisterProvider>>,
}

impl Objects<'static> {
    /// Construct an independent object context from assigned native capabilities.
    pub fn from_capabilities(
        identity: crate::providers::ApplicationIdentity,
        keys: crate::providers::KeySet,
        register_provider: Option<Arc<dyn crate::providers::RegisterProvider>>,
    ) -> Result<Self> {
        if keys.owner() != identity.did() {
            return Err(Error::InvalidConfig(
                "capabilities belong to another identity".into(),
            ));
        }
        let mut groups = BTreeMap::new();
        for capability in keys.groups {
            groups.insert(
                capability.group,
                Arc::new(RwLock::new(GroupState {
                    cipher: capability.cipher,
                    hmac_template: crate::indexing::build_hmac_template(&capability.index)?,
                    aad_default: serde_json::Map::new(),
                })),
            );
        }
        Ok(Self {
            identity: Identity::Shared(identity.signer),
            private_groups: groups.keys().cloned().collect(),
            groups,
            policies: None,
            registers: if register_provider.is_some() {
                ObjectRegisters::default()
            } else {
                ObjectRegisters::from_env()?
            },
            register_provider,
        })
    }

    /// Create an independent in-memory identity, policy, and BTN group context.
    /// The governance group is supplied automatically. No files are created.
    pub fn ephemeral(policy: &str, policy_id: &str, business_groups: &[&str]) -> Result<Self> {
        use crate::cipher::btn::BtnPublisherCipher;
        use crate::governed::{validate_group, GOVERNANCE_GROUP};
        use rand_core::RngCore as _;

        let policies = crate::agents_policy::parse_policy_text(policy, policy_id)?;
        let mut names = BTreeSet::from([GOVERNANCE_GROUP.to_owned()]);
        for name in business_groups {
            validate_group(name)?;
            if !names.insert((*name).to_owned()) {
                return Err(Error::InvalidConfig(format!(
                    "duplicate or reserved group {name:?}"
                )));
            }
        }
        let device = DeviceKey::generate();
        let namespace = uuid::Uuid::new_v4().to_string();
        let mut master = zeroize::Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(master.as_mut());
        let mut groups = BTreeMap::new();
        for name in &names {
            let mut state = tn_btn::PublisherState::setup(tn_btn::Config)?;
            let kit = state.mint()?;
            let cipher = BtnPublisherCipher::from_state(state).with_reader_kit(&kit.to_bytes())?;
            let index = crate::indexing::derive_group_index_key(&master[..], &namespace, name, 0)?;
            groups.insert(
                name.clone(),
                Arc::new(RwLock::new(GroupState {
                    cipher: Arc::new(cipher),
                    hmac_template: crate::indexing::build_hmac_template(&index)?,
                    aad_default: serde_json::Map::new(),
                })),
            );
        }
        Ok(Self {
            identity: Identity::Owned(Box::new(device)),
            groups,
            private_groups: names,
            policies: Some(policies),
            registers: ObjectRegisters::from_env()?,
            register_provider: None,
        })
    }

    /// Load object configuration without initializing event handlers or logs.
    /// Reopen this context to load external changes to configuration or keys.
    pub fn open(yaml_path: &Path) -> Result<Self> {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::FsStorage::new());
        let Material {
            cfg,
            device,
            master_index_key,
            yaml_dir,
            keystore,
        } = Material::load(yaml_path, &storage)?;
        let (groups, _, _) = super::cipher_build::build_group_states(
            &cfg,
            &master_index_key,
            &keystore,
            &storage,
            &device,
        )?;
        let policies = crate::agents_policy::load_policy_file_with_storage(&yaml_dir, &storage)?;
        let private_groups = cfg
            .groups
            .iter()
            .filter(|(_, spec)| spec.policy != "public")
            .map(|(name, _)| name.clone())
            .collect();
        Ok(Self {
            identity: Identity::Owned(Box::new(device)),
            groups,
            private_groups,
            policies,
            registers: ObjectRegisters::from_env()?,
            register_provider: None,
        })
    }
}

impl Objects<'_> {
    /// Resolve the type chosen by a policy loader or a matching local template.
    pub fn selected_type(&self, policy: &Governance) -> Result<String> {
        if let Some(name) = policy.selected_object_type() {
            return Ok(name.to_owned());
        }
        if let Some(document) = &self.policies {
            for (name, template) in &document.templates {
                if &Governance::from_template(self.did(), template)? == policy {
                    return Ok(name.clone());
                }
            }
        }
        Err(Error::InvalidConfig(
            "object_type is required for a contract without a selected type".into(),
        ))
    }
    /// Create signed data using the policy loader's selected object type.
    pub fn create_selected(
        &self,
        fields: impl serde::Serialize,
        policy: Governance,
        group: &str,
    ) -> Result<DataObject> {
        let name = self.selected_type(&policy)?;
        self.create_obj(&name, policy, group, fields)
    }
    /// Create all initial groups in one signed object using a selected policy.
    pub fn create_selected_groups<I, S, V>(
        &self,
        groups: I,
        policy: Governance,
    ) -> Result<DataObject>
    where
        I: IntoIterator<Item = (S, V)>,
        S: AsRef<str>,
        V: serde::Serialize,
    {
        let name = self.selected_type(&policy)?;
        self.create_obj_with_groups(&name, policy, groups)
    }
    /// Originate governed data and its initial signed snapshot from a required policy.
    pub fn create_obj(
        &self,
        object_type: &str,
        policy: Governance,
        group: &str,
        fields: impl serde::Serialize,
    ) -> Result<DataObject> {
        self.create_obj_with_groups(object_type, policy, [(group, fields)])
    }
    /// Originate every business group in one snapshot and one optional creation entry.
    pub fn create_obj_with_groups<I, S, V>(
        &self,
        object_type: &str,
        policy: Governance,
        groups: I,
    ) -> Result<DataObject>
    where
        I: IntoIterator<Item = (S, V)>,
        S: AsRef<str>,
        V: serde::Serialize,
    {
        let mut data = self
            .writer()?
            .create_obj_with_groups(object_type, policy, groups)?;
        self.record(&mut data, "create", "create", "origin");
        Ok(data)
    }
    /// Legacy operation-only receipt into a mutable governed object. Use
    /// [`Self::receive_for`] for complete use and selected-group admission.
    pub fn receive<I, S, F>(
        &self,
        wire: &str,
        operation: &str,
        groups: I,
        decide: F,
    ) -> Result<DataObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnOnce(&AdmissionContext<'_>) -> Result<bool>,
    {
        self.reader()?.receive(wire, operation, groups, decide)
    }
    /// Admit a complete use and optional exact edition before opening selected data.
    pub fn receive_for<I, S, F>(
        &self,
        wire: &str,
        use_context: &UseContext,
        groups: I,
        selection: Option<&DatasetSelection>,
        decide: F,
    ) -> Result<DataObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnOnce(&AdmissionContext<'_>) -> Result<bool>,
    {
        self.reader()?
            .receive_for(wire, use_context, groups, selection, decide)
    }
    /// Add an authority-approved policy while retaining the existing policy set.
    pub fn attach<F>(&self, data: &mut DataObject, policy: Governance, decide: F) -> Result<()>
    where
        F: FnOnce(&AttachmentContext<'_>) -> Result<bool>,
    {
        data.attach(self.did(), policy, decide)
    }
    /// Check the current output for its purpose/destination, then seal a signed version.
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
        let sealed = self
            .writer()?
            .release(data, object_type, purpose, destination, decide)?;
        self.record(data, "release", purpose, destination);
        Ok(sealed)
    }
    /// Decide and sign a release carrying the complete application use.
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
        let sealed =
            self.writer()?
                .release_for(data, object_type, use_context, destination, decide)?;
        self.record(data, "release", use_context.operation(), destination);
        Ok(sealed)
    }
    /// Choose this service's optional creation and release registers explicitly.
    pub fn with_registers(mut self, registers: ObjectRegisters) -> Self {
        self.registers = registers;
        self.register_provider = None;
        self
    }
    fn record(&self, data: &mut DataObject, action: &str, purpose: &str, destination: &str) {
        let result = data.policies().and_then(|policies| {
            let refs = policies
                .iter()
                .map(|policy| policy.policy_ref().to_owned())
                .collect::<Vec<_>>();
            match (data.snapshot(), self.register_provider.as_ref()) {
                (Some(object), Some(provider)) => provider
                    .record(
                        self.device(),
                        &crate::providers::RegisterEvent {
                            action: action.into(),
                            publication: object.clone(),
                            purpose: purpose.into(),
                            destination: destination.into(),
                            policy_refs: refs,
                        },
                    )
                    .map(|_| true),
                (Some(object), None) => self.registers.record(
                    self.device(),
                    action,
                    object,
                    purpose,
                    destination,
                    &refs,
                ),
                (None, _) => Err(Error::InvalidConfig(
                    "registration requires a sealed snapshot".into(),
                )),
            }
        });
        data.set_register_error(result.err().map(|error| error.to_string()));
    }
    /// Check configured publication material for every declared output group.
    pub fn check_groups<I, S>(&self, groups: I) -> Result<crate::governed::PublicationReport>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.writer()?.check_groups(groups)
    }
    /// Require declared groups to have known publication capability before work begins.
    pub fn require_groups<I, S>(&self, groups: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.writer()?.require_groups(groups)
    }
    fn device(&self) -> &DeviceKey {
        match &self.identity {
            Identity::Owned(key) => key,
            Identity::Shared(key) => key,
            Identity::Borrowed(key) => key,
        }
    }

    /// Signing identity for objects created by this context.
    pub fn did(&self) -> &str {
        self.device().did()
    }

    /// Select the named object's contract from the loaded agents.md tree.
    /// Use [`GovernedDraft::new`] to supply an explicit contract instead.
    pub fn draft(&self, object_type: &str) -> Result<GovernedDraft> {
        let template = self
            .policies
            .as_ref()
            .and_then(|p| p.templates.get(object_type))
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "governed object requires a policy for {object_type:?}"
                ))
            })?;
        GovernedDraft::new(
            object_type,
            Governance::from_template(self.did(), template)?,
        )
    }

    /// Encrypt the explicitly assigned groups, bind their contract, and sign.
    /// Configured event profiles and receipt settings do not change this flow.
    pub fn seal(&self, draft: GovernedDraft) -> Result<GovernedObject> {
        self.writer()?.seal(draft)
    }

    fn writer(&self) -> Result<GovernedWriter<'_>> {
        let mut writer = GovernedWriter::new(self.device());
        for name in &self.private_groups {
            if let Some(group) = self.groups.get(name) {
                let state = group
                    .read()
                    .map_err(|_| Error::InvalidConfig("group state lock poisoned".into()))?;
                writer = writer.with_material(
                    name,
                    Arc::clone(&state.cipher),
                    state.hmac_template.clone(),
                )?;
            }
        }
        Ok(writer)
    }

    /// Build a reader from current and retained material in configured groups. It opens only
    /// governance until an application admits use and selects business groups.
    pub fn reader(&self) -> Result<GovernedReader> {
        self.reader_for(&self.private_groups)
    }

    /// Create a reader containing only the named configured groups.
    /// The returned reader owns its cipher snapshot independently of this context.
    pub fn reader_for<I, S>(&self, names: I) -> Result<GovernedReader>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut reader = GovernedReader::new();
        let mut selected = BTreeSet::new();
        for name in names {
            let name = name.as_ref();
            if !self.private_groups.contains(name) || !selected.insert(name.to_owned()) {
                return Err(Error::InvalidConfig(format!(
                    "select each configured private group once: {name:?}"
                )));
            }
            if let Some(group) = self.groups.get(name) {
                let state = group
                    .read()
                    .map_err(|_| Error::InvalidConfig("group state lock poisoned".into()))?;
                reader = reader.with_group(name, Arc::clone(&state.cipher))?;
            }
        }
        Ok(reader)
    }
}

impl Runtime {
    /// Use this runtime's configured identity and groups for governed objects.
    pub fn objects(&self) -> Objects<'_> {
        Objects {
            identity: Identity::Borrowed(&self.device),
            groups: self.groups.clone(),
            private_groups: self
                .cfg
                .groups
                .iter()
                .filter(|(_, spec)| spec.policy != "public")
                .map(|(name, _)| name.clone())
                .collect(),
            policies: self.agent_policies.clone(),
            registers: ObjectRegisters::from_env().unwrap_or_default(),
            register_provider: None,
        }
    }
}
