use super::ApplicationIdentity;
use crate::cipher::{
    btn::{BtnPublisherCipher, BtnReaderCipher},
    GroupCipher,
};
use crate::{Error, Result};
use rand_core::RngCore;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
/// Native cipher and index capability for one encrypted group.
pub struct GroupCapability {
    pub(crate) group: String,
    pub(crate) cipher: Arc<dyn GroupCipher>,
    pub(crate) index: [u8; 32],
}
impl GroupCapability {
    /// Load HIBE public parameters and assigned reader keys for an identity path.
    #[cfg(feature = "hibe")]
    pub fn hibe(
        group: &str,
        public: &[u8],
        path: &str,
        readers: &[Vec<u8>],
        index: [u8; 32],
    ) -> Result<Self> {
        Self::new(
            group,
            Arc::new(crate::cipher::hibe::HibeCipher::new(
                public,
                path,
                None,
                None,
                vec![],
                readers.to_vec(),
            )?),
            index,
        )
    }
    /// Load real General JSON JWE capabilities using raw X25519 recipient keys.
    #[cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
    pub fn jwe(
        group: &str,
        recipients: &[[u8; 32]],
        readers: &[[u8; 32]],
        index: [u8; 32],
    ) -> Result<Self> {
        Self::new(
            group,
            Arc::new(crate::cipher::jwe::JweCipher::new(
                group, recipients, readers,
            )?),
            index,
        )
    }
    /// Load assigned reader kits, including retained generations, from a key service.
    pub fn btn_reader(group: &str, kits: &[impl AsRef<[u8]>], index: [u8; 32]) -> Result<Self> {
        Self::new(
            group,
            Arc::new(BtnReaderCipher::from_multi_kit_bytes(kits)?),
            index,
        )
    }
    /// Load a publisher state and its assigned reader kits from a key service.
    pub fn btn_publisher(
        group: &str,
        state: &[u8],
        kits: &[impl AsRef<[u8]>],
        index: [u8; 32],
    ) -> Result<Self> {
        let cipher = BtnPublisherCipher::from_state_bytes(state)?.with_reader_kits(kits)?;
        Self::new(group, Arc::new(cipher), index)
    }
    /// Construct this typed provider value from explicit native configuration.
    pub fn new(group: &str, cipher: Arc<dyn GroupCipher>, index: [u8; 32]) -> Result<Self> {
        crate::governed::validate_group(group)?;
        Ok(Self {
            group: group.into(),
            cipher,
            index,
        })
    }
    /// Return the encrypted group name.
    pub fn group(&self) -> &str {
        &self.group
    }
}
#[derive(Clone)]
/// Assigned native group capabilities bound to one signing identity.
pub struct KeySet {
    pub(crate) owner: String,
    pub(crate) groups: Vec<GroupCapability>,
}
impl KeySet {
    /// Construct this typed provider value from explicit native configuration.
    pub fn new(identity: &ApplicationIdentity, groups: Vec<GroupCapability>) -> Result<Self> {
        let names: BTreeSet<_> = groups.iter().map(|g| g.group.as_str()).collect();
        if names.len() != groups.len() || !names.contains("tn.agents") {
            return Err(Error::InvalidConfig(
                "key set requires unique groups including tn.agents".into(),
            ));
        }
        Ok(Self {
            owner: identity.did().into(),
            groups,
        })
    }
    /// Return the identity DID assigned these capabilities.
    pub fn owner(&self) -> &str {
        &self.owner
    }
    /// Return the assigned encrypted group names.
    pub fn groups(&self) -> Vec<&str> {
        self.groups.iter().map(|g| g.group()).collect()
    }
}
/// Resolve capabilities assigned to the resolved identity.
pub trait KeyProvider: Send + Sync {
    /// Resolve the typed request; return an error when no matching assignment exists.
    fn resolve(&self, identity: &ApplicationIdentity) -> Result<KeySet>;
}
/// First adapter: explicit assignments of generated BTN group capabilities.
pub struct LocalKeys {
    material: BTreeMap<String, (GroupCapability, GroupCapability)>,
    assigned: RwLock<BTreeMap<String, KeySet>>,
}
impl LocalKeys {
    /// Generate fresh local capability material for this adapter instance.
    pub fn generate(groups: &[&str]) -> Result<Self> {
        let mut names = BTreeSet::from(["tn.agents"]);
        for name in groups {
            crate::governed::validate_group(name)?;
            if !names.insert(name) {
                return Err(Error::InvalidConfig(
                    "duplicate or reserved generated group".into(),
                ));
            }
        }
        let mut material = BTreeMap::new();
        for name in names {
            let mut state = tn_btn::PublisherState::setup(tn_btn::Config)?;
            let kit = state.mint()?.to_bytes();
            let mut index = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut index);
            let publisher = Arc::new(BtnPublisherCipher::from_state(state).with_reader_kit(&kit)?);
            let reader = Arc::new(BtnReaderCipher::from_kit_bytes(&kit)?);
            material.insert(
                name.into(),
                (
                    GroupCapability::new(name, reader, index)?,
                    GroupCapability::new(name, publisher, index)?,
                ),
            );
        }
        Ok(Self {
            material,
            assigned: RwLock::new(BTreeMap::new()),
        })
    }
    /// Assign named capabilities. Governance read is automatic; publication must be explicit.
    pub fn assign(
        &self,
        identity: &ApplicationIdentity,
        read: &[&str],
        publish: &[&str],
    ) -> Result<()> {
        let readers: BTreeSet<_> = read.iter().copied().chain(["tn.agents"]).collect();
        let publishers: BTreeSet<_> = publish.iter().copied().collect();
        let names: BTreeSet<_> = readers.union(&publishers).copied().collect();
        let mut selected = Vec::new();
        for name in names {
            let pair = self
                .material
                .get(name)
                .ok_or_else(|| Error::InvalidConfig(format!("unknown group {name:?}")))?;
            selected.push(if publishers.contains(name) {
                pair.1.clone()
            } else {
                pair.0.clone()
            });
        }
        let keys = KeySet::new(identity, selected)?;
        self.assigned
            .write()
            .map_err(|_| super::lock_error())?
            .insert(identity.did().into(), keys);
        Ok(())
    }
}
impl KeyProvider for LocalKeys {
    /// Resolve the typed request; return an error when no matching assignment exists.
    fn resolve(&self, identity: &ApplicationIdentity) -> Result<KeySet> {
        self.assigned
            .read()
            .map_err(|_| super::lock_error())?
            .get(identity.did())
            .cloned()
            .ok_or_else(|| Error::InvalidConfig("no keys assigned to this identity".into()))
    }
}
