//! DeviceKey keystore I/O.
//!
//! Matches the Python layout at `tn/config.py`: the 32-byte Ed25519 seed is
//! persisted at `<keystore>/local.private` as raw bytes.

use std::path::Path;

use crate::{DeviceKey, Error, Result};

/// Filename inside the keystore directory that holds the raw 32-byte Ed25519 seed.
pub const DEVICE_SEED_FILENAME: &str = "local.private";

/// Load a DeviceKey from the keystore, creating one if the seed file does not yet exist.
///
/// Creates `keystore` if it does not exist.
pub fn load_or_create_device(keystore: &Path) -> Result<DeviceKey> {
    let seed_path = keystore.join(DEVICE_SEED_FILENAME);
    if seed_path.exists() {
        let seed = std::fs::read(&seed_path)?;
        DeviceKey::from_private_bytes(&seed)
    } else {
        std::fs::create_dir_all(keystore)?;
        let dk = DeviceKey::generate();
        std::fs::write(&seed_path, dk.private_bytes())?;
        Ok(dk)
    }
}

/// Load a DeviceKey from `<keystore>/local.private`. Errors if absent.
pub fn load_device(keystore: &Path) -> Result<DeviceKey> {
    let seed_path = keystore.join(DEVICE_SEED_FILENAME);
    let seed = std::fs::read(&seed_path).map_err(Error::Io)?;
    DeviceKey::from_private_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_is_idempotent() {
        let td = tempfile::tempdir().unwrap();
        let d1 = load_or_create_device(td.path()).unwrap();
        let d2 = load_or_create_device(td.path()).unwrap();
        assert_eq!(d1.public_bytes(), d2.public_bytes());
        assert_eq!(d1.did(), d2.did());
    }

    #[test]
    fn load_device_errors_when_absent() {
        let td = tempfile::tempdir().unwrap();
        assert!(load_device(td.path()).is_err());
    }
}
