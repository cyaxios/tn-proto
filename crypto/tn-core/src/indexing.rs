//! HKDF-SHA256 per-group index keys and HMAC-SHA256 equality-search field
//! tokens. Internal primitive: most readers want the high-level API instead
//! — see [`crate::Runtime`] (events and queryable fields, behind `tn.info()`
//! / `tn read`). Reach here directly only when computing or matching raw
//! index tokens.
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
///
/// Allocates a fresh HMAC state per call. Hot-path callers should use
/// [`build_hmac_template`] once at init and [`index_token_with_template`]
/// per emit — that path skips the per-call key-XOR-into-pads work
/// (saves ~2-3 µs per field on every emit).
pub fn index_token(group_index_key: &[u8], field_name: &str, value: &Value) -> Result<String> {
    if group_index_key.len() != GROUP_KEY_BYTES {
        return Err(Error::InvalidConfig(format!(
            "group index key must be {GROUP_KEY_BYTES} bytes, got {}",
            group_index_key.len()
        )));
    }
    let mac = <Hmac<Sha256> as Mac>::new_from_slice(group_index_key)
        .map_err(|e| Error::Internal(format!("hmac: {e}")))?;
    index_token_with_template(&mac, field_name, value)
}

/// Build a reusable HMAC-SHA256 template keyed by `group_index_key`.
/// Cache the result on the per-group state and pass it to
/// [`index_token_with_template`] on every emit to skip the ipad/opad
/// XOR-into-key initialization that `Mac::new_from_slice` does.
pub fn build_hmac_template(group_index_key: &[u8]) -> Result<Hmac<Sha256>> {
    if group_index_key.len() != GROUP_KEY_BYTES {
        return Err(Error::InvalidConfig(format!(
            "group index key must be {GROUP_KEY_BYTES} bytes, got {}",
            group_index_key.len()
        )));
    }
    <Hmac<Sha256> as Mac>::new_from_slice(group_index_key)
        .map_err(|e| Error::Internal(format!("hmac: {e}")))
}

/// Hot-path index token compute: clones the pre-initialized HMAC
/// state, feeds the field bytes, finalizes. Save ~2-3 µs per field
/// per emit vs. [`index_token`] (which allocates a fresh HMAC each
/// time). Use [`build_hmac_template`] once at runtime construction
/// to build the template.
pub fn index_token_with_template(
    template: &Hmac<Sha256>,
    field_name: &str,
    value: &Value,
) -> Result<String> {
    let mut mac = template.clone();
    mac.update(field_name.as_bytes());
    mac.update(&[0u8]);
    mac.update(&canonical_bytes(value)?);
    // One-allocation build (avoids `format!` + `hex::encode` double
    // alloc). Prefix length is `INDEX_TOKEN_PREFIX.len()`; hex is 64
    // chars (32-byte HMAC digest).
    let tag = mac.finalize().into_bytes();
    let mut out = String::with_capacity(INDEX_TOKEN_PREFIX.len() + 64);
    out.push_str(INDEX_TOKEN_PREFIX);
    let mut hex_buf = [0u8; 64];
    hex::encode_to_slice(tag.as_slice(), &mut hex_buf)
        .expect("32-byte digest into 64-char buffer is infallible");
    out.push_str(std::str::from_utf8(&hex_buf).expect("hex::encode_to_slice emits ASCII"));
    Ok(out)
}
