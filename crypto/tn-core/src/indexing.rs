//! HKDF-SHA256 per-group index key + HMAC-SHA256 field tokens.
//!
//! Mirrors `tn/indexing.py` exactly:
//! - HKDF-SHA256, info = `b"tn-index:v1:" + ceremony + b":" + group + b":" + decimal(epoch)`
//! - HMAC-SHA256 over `field_name || 0x00 || canonical_bytes(value)`
//! - Token format: `"hmac-sha256:v1:" + lowercase-hex(tag)`

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::canonical::canonical_bytes;
use crate::{Error, Result};

/// Size of the per-ceremony master index secret.
pub const MASTER_KEY_BYTES: usize = 32;
/// Size of the per-group derived index key.
pub const GROUP_KEY_BYTES: usize = 32;
/// Prefix literal present on every emitted token.
pub const INDEX_TOKEN_PREFIX: &str = "hmac-sha256:v1:";

/// Derive the per-group index key via HKDF-SHA256.
///
/// Info string binds the key to the `(ceremony_id, group_name, epoch)` tuple.
pub fn derive_group_index_key(
    master: &[u8],
    ceremony_id: &str,
    group_name: &str,
    epoch: u64,
) -> Result<[u8; GROUP_KEY_BYTES]> {
    if master.len() != MASTER_KEY_BYTES {
        return Err(Error::InvalidConfig(format!(
            "master index key must be {MASTER_KEY_BYTES} bytes, got {}",
            master.len()
        )));
    }
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"tn-index:v1:");
    info.extend_from_slice(ceremony_id.as_bytes());
    info.push(b':');
    info.extend_from_slice(group_name.as_bytes());
    info.push(b':');
    info.extend_from_slice(epoch.to_string().as_bytes());

    let hk = Hkdf::<Sha256>::new(None, master);
    let mut okm = [0u8; GROUP_KEY_BYTES];
    hk.expand(&info, &mut okm)
        .map_err(|e| Error::Internal(format!("hkdf: {e}")))?;
    Ok(okm)
}

/// Compute the keyed equality token `"hmac-sha256:v1:<hex>"` for a field.
pub fn index_token(group_index_key: &[u8], field_name: &str, value: &Value) -> Result<String> {
    if group_index_key.len() != GROUP_KEY_BYTES {
        return Err(Error::InvalidConfig(format!(
            "group index key must be {GROUP_KEY_BYTES} bytes, got {}",
            group_index_key.len()
        )));
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(group_index_key)
        .map_err(|e| Error::Internal(format!("hmac: {e}")))?;
    mac.update(field_name.as_bytes());
    mac.update(&[0u8]);
    mac.update(&canonical_bytes(value)?);
    Ok(format!(
        "{INDEX_TOKEN_PREFIX}{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}
