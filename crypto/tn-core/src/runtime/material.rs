//! Configuration and identity loading shared by objects and event runtimes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{config::Config, storage::Storage, DeviceKey, Error, Result};

pub(super) struct Material {
    pub cfg: Config,
    pub device: DeviceKey,
    pub master_index_key: [u8; 32],
    pub yaml_dir: PathBuf,
    pub keystore: PathBuf,
}

impl Material {
    pub fn load(yaml_path: &Path, storage: &Arc<dyn Storage>) -> Result<Self> {
        let yaml_bytes = storage.read_bytes(yaml_path).map_err(Error::Io)?;
        let yaml_str = std::str::from_utf8(&yaml_bytes)
            .map_err(|e| Error::InvalidConfig(format!("yaml is not valid UTF-8: {e}")))?;
        let expanded = crate::config::substitute_env_vars(yaml_str, yaml_path)?;
        let cfg = crate::config::parse_with_extends(&expanded, yaml_path, storage.as_ref())?;
        let yaml_dir = yaml_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let keystore = super::util::resolve(&yaml_dir, Path::new(&cfg.keystore.path));
        let seed_bytes = storage
            .read_bytes(&keystore.join(crate::identity::DEVICE_SEED_FILENAME))
            .map_err(Error::Io)?;
        let device = DeviceKey::from_private_bytes(&seed_bytes)?;
        if device.did() != cfg.device.device_identity {
            return Err(Error::InvalidConfig(format!(
                "keystore DID {} does not match yaml device.device_identity {}",
                device.did(),
                cfg.device.device_identity
            )));
        }
        let master_index_key = storage
            .read_bytes(&keystore.join("index_master.key"))
            .map_err(Error::Io)?
            .try_into()
            .map_err(|_| Error::InvalidConfig("index_master.key must be 32 bytes".into()))?;
        Ok(Self {
            cfg,
            device,
            master_index_key,
            yaml_dir,
            keystore,
        })
    }
}
