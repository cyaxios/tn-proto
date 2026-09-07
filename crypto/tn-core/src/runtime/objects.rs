//! Configured governed objects using the shared protocol primitives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::agents_policy::PolicyDocument;
use crate::governed::{Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter};
use crate::{DeviceKey, Error, Result};

use super::material::Material;
use super::{GroupState, Runtime};

enum Identity<'a> {
    Owned(Box<DeviceKey>),
    Borrowed(&'a DeviceKey),
}

/// Create, seal, and read governed objects with configured group material.
///
/// [`Objects::open`] owns its identity and opens only configuration, policies,
/// and key material. [`Runtime::objects`] borrows the active runtime identity
/// and shares its group states, including subsequent in-process rotations.
/// Both paths always sign governed objects and return their wire bytes.
pub struct Objects<'a> {
    identity: Identity<'a>,
    groups: BTreeMap<String, Arc<RwLock<GroupState>>>,
    private_groups: BTreeSet<String>,
    policies: Option<PolicyDocument>,
}

impl Objects<'static> {
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
        })
    }
}

impl Objects<'_> {
    fn device(&self) -> &DeviceKey {
        match &self.identity {
            Identity::Owned(key) => key,
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
        writer.seal(draft)
    }

    /// Build a reader from current and retained material in configured groups. It opens only
    /// governance until an application admits use and selects business groups.
    pub fn reader(&self) -> Result<GovernedReader> {
        let mut reader = GovernedReader::new();
        for name in &self.private_groups {
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
        }
    }
}
