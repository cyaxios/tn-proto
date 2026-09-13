//! Persistent, single-application identity and encrypted-group capabilities.
use super::{ApplicationIdentity, GroupCapability, IdentityProvider, KeyProvider, KeySet};
use crate::{DeviceKey, Error, Result};
use curve25519_dalek::montgomery::MontgomeryPoint;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const MAX_STORE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredGroup {
    name: String,
    index: [u8; 32],
    material: Material,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "cipher", rename_all = "lowercase", deny_unknown_fields)]
enum Material {
    #[cfg(feature = "hibe")]
    Hibe {
        public: Vec<u8>,
        reader: Vec<u8>,
        path: String,
    },
    Btn {
        publisher: Vec<u8>,
        reader: Vec<u8>,
    },
    Jwe {
        private: [u8; 32],
        public: [u8; 32],
    },
}
impl Drop for StoredGroup {
    fn drop(&mut self) {
        self.index.zeroize();
        match &mut self.material {
            #[cfg(feature = "hibe")]
            Material::Hibe { reader, .. } => reader.zeroize(),
            Material::Btn { publisher, reader } => {
                publisher.zeroize();
                reader.zeroize();
            }
            Material::Jwe { private, .. } => private.zeroize(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreDocument {
    version: u32,
    application: String,
    signing_seed: [u8; 32],
    groups: Vec<StoredGroup>,
}
impl Drop for StoreDocument {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
    }
}

/// File-backed provider for one application's signing identity and group grants.
/// Creation enrolls this application as a publisher and reader of every group.
/// The secret bundle is separate from publications and is never replaced by open.
pub struct FileKeyStore {
    path: PathBuf,
    identity: ApplicationIdentity,
    keys: KeySet,
    cipher: String,
}
impl FileKeyStore {
    /// Generate fresh material and atomically create a new secret bundle.
    /// Existing files are never overwritten. Supports BTN, JWE and feature-enabled HIBE.
    pub fn create(path: &Path, application: &str, groups: &[&str], cipher: &str) -> Result<Self> {
        super::label(application)?;
        if !matches!(cipher, "btn" | "jwe") && !(cipher == "hibe" && cfg!(feature = "hibe")) {
            return Err(Error::InvalidConfig(
                "keystore cipher must be btn, jwe, or feature-enabled hibe".into(),
            ));
        }
        let mut names = BTreeSet::from([crate::governed::GOVERNANCE_GROUP]);
        for group in groups {
            crate::governed::validate_group(group)?;
            if !names.insert(*group) {
                return Err(Error::InvalidConfig(
                    "duplicate or reserved keystore group".into(),
                ));
            }
        }
        let device = DeviceKey::generate();
        let mut stored = Vec::new();
        for name in names {
            let mut index = [0; 32];
            rand_core::OsRng.fill_bytes(&mut index);
            let material = if cipher == "btn" {
                let mut publisher = tn_btn::PublisherState::setup(tn_btn::Config)?;
                let reader = publisher.mint()?.to_bytes();
                Material::Btn {
                    publisher: publisher.to_bytes(),
                    reader,
                }
            } else if cipher == "hibe" {
                #[cfg(feature = "hibe")]
                {
                    let (public, master) = tn_hibe::setup(1, rand_core::OsRng)
                        .map_err(|e| Error::Cipher(e.to_string()))?;
                    let target = tn_hibe::Identity::try_from_str_path(name)
                        .map_err(|e| Error::Cipher(e.to_string()))?;
                    let reader = tn_hibe::keygen(&public, &master, &target, rand_core::OsRng)
                        .map_err(|e| Error::Cipher(e.to_string()))?;
                    Material::Hibe {
                        public: public.to_bytes(),
                        reader: reader.to_bytes(),
                        path: name.into(),
                    }
                }
                #[cfg(not(feature = "hibe"))]
                return Err(Error::InvalidConfig("HIBE support is disabled".into()));
            } else {
                let mut private = [0; 32];
                rand_core::OsRng.fill_bytes(&mut private);
                let public = *MontgomeryPoint::mul_base_clamped(private).as_bytes();
                Material::Jwe { private, public }
            };
            stored.push(StoredGroup {
                name: name.into(),
                index,
                material,
            });
        }
        let document = StoreDocument {
            version: 1,
            application: application.into(),
            signing_seed: device.private_bytes(),
            groups: stored,
        };
        let store = Self::from_document(path, &document)?;
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(&document)?);
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(Error::InvalidConfig("keystore exceeds size limit".into()));
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut pending = tempfile::NamedTempFile::new_in(parent)?;
        pending.write_all(&bytes)?;
        pending.as_file().sync_all()?;
        // tempfile creates mode 0600 on Unix; Windows uses the containing directory ACL.
        pending
            .persist_noclobber(path)
            .map_err(|error| Error::Io(error.error))?;
        Ok(store)
    }
    /// Load the exact saved identity and grants. Missing or invalid files fail.
    pub fn open(path: &Path) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(path)?
            .take(MAX_STORE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(Error::InvalidConfig("keystore exceeds size limit".into()));
        }
        let document: StoreDocument = serde_json::from_slice(&bytes)?;
        Self::from_document(path, &document)
    }
    fn from_document(path: &Path, document: &StoreDocument) -> Result<Self> {
        if document.version != 1 {
            return Err(Error::InvalidConfig("unsupported keystore version".into()));
        }
        let identity = ApplicationIdentity::new(
            &document.application,
            Arc::new(DeviceKey::from_private_bytes(&document.signing_seed)?),
        )?;
        let mut capabilities = Vec::new();
        let mut cipher = None;
        for group in &document.groups {
            let (kind, capability) = match &group.material {
                #[cfg(feature = "hibe")]
                Material::Hibe {
                    public,
                    reader,
                    path,
                } => (
                    "hibe",
                    GroupCapability::hibe(
                        &group.name,
                        public,
                        path,
                        &[reader.clone()],
                        group.index,
                    )?,
                ),
                Material::Btn { publisher, reader } => (
                    "btn",
                    GroupCapability::btn_publisher(&group.name, publisher, &[reader], group.index)?,
                ),
                Material::Jwe { private, public } => {
                    if MontgomeryPoint::mul_base_clamped(*private).as_bytes() != public {
                        return Err(Error::InvalidConfig(
                            "JWE public and private keys do not match".into(),
                        ));
                    }
                    (
                        "jwe",
                        GroupCapability::jwe(&group.name, &[*public], &[*private], group.index)?,
                    )
                }
            };
            if cipher.is_some_and(|previous| previous != kind) {
                return Err(Error::InvalidConfig(
                    "file keystore must use one cipher consistently".into(),
                ));
            }
            cipher = Some(kind);
            capabilities.push(capability);
        }
        let keys = KeySet::new(&identity, capabilities)?;
        Ok(Self {
            path: path.to_owned(),
            identity,
            keys,
            cipher: cipher
                .ok_or_else(|| Error::InvalidConfig("empty keystore".into()))?
                .into(),
        })
    }
    /// Path to the saved secret bundle.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Configured application name.
    pub fn application(&self) -> &str {
        self.identity.application()
    }
    /// Native group cipher selected at creation.
    pub fn cipher(&self) -> &str {
        &self.cipher
    }
    /// All persisted group names, including governance.
    pub fn groups(&self) -> Vec<&str> {
        self.keys.groups()
    }
}
impl IdentityProvider for FileKeyStore {
    fn resolve(&self, application: &str) -> Result<ApplicationIdentity> {
        if application != self.application() {
            return Err(Error::InvalidConfig(
                "keystore belongs to another application".into(),
            ));
        }
        Ok(self.identity.clone())
    }
}
impl KeyProvider for FileKeyStore {
    fn resolve(&self, identity: &ApplicationIdentity) -> Result<KeySet> {
        if identity.did() != self.identity.did() || identity.application() != self.application() {
            return Err(Error::InvalidConfig(
                "keystore has no grants for this identity".into(),
            ));
        }
        Ok(self.keys.clone())
    }
}
