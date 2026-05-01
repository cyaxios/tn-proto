//! JWE cipher — Python-owned in this plan.
//!
//! JWE is standard crypto (X25519 + HKDF + AES-KW + AES-GCM). The btn-first
//! plan keeps JWE groups running through `tn/cipher.py::JWEGroupCipher`; this
//! Rust-side stub exists only so the cipher-dispatch code compiles, and so a
//! JWE group configured in a yaml yields a clear `NotImplemented` error from
//! the Rust runtime with a pointer to run that ceremony from Python instead.

use crate::{Error, Result};

/// Sentinel JWE cipher that signals "not implemented in Rust — use Python".
pub struct JwePlaceholder;

impl super::GroupCipher for JwePlaceholder {
    fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "JWE encrypt is Python-owned in this plan; run this ceremony from Python or migrate the group to btn",
        ))
    }
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "JWE decrypt is Python-owned in this plan; run this ceremony from Python or migrate the group to btn",
        ))
    }
    fn kind(&self) -> &'static str {
        "jwe"
    }
}
