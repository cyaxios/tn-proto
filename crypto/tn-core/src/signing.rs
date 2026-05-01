//! Ed25519 device key + did:key encoding.
//!
//! Matches `tn/signing.py` for Ed25519 (the curve TN signs with). The Python
//! verify path additionally accepts secp256k1 DIDs for ATProto interop; this
//! Rust port defers that branch — secp256k1 DIDs return `Ok(false)` from
//! `verify_did` without erroring. Will be added when a fixture requires it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::{Error, Result};

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// An Ed25519 device identity: signing key + verifying key + cached did:key.
pub struct DeviceKey {
    signing: SigningKey,
    verifying: VerifyingKey,
    did: String,
}

impl DeviceKey {
    /// Load a DeviceKey from its 32-byte Ed25519 seed.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidConfig` if `seed` is not exactly 32 bytes.
    ///
    /// # Panics
    ///
    /// Never — the `try_into` is guarded by the length check above it.
    pub fn from_private_bytes(seed: &[u8]) -> Result<Self> {
        if seed.len() != 32 {
            return Err(Error::InvalidConfig(
                "Ed25519 private key seed must be 32 bytes".into(),
            ));
        }
        let arr: [u8; 32] = seed
            .try_into()
            .expect("32-byte seed fits [u8; 32]: length validated above");
        let signing = SigningKey::from_bytes(&arr);
        let verifying = signing.verifying_key();
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        buf.extend_from_slice(verifying.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(buf).into_string());
        Ok(Self {
            signing,
            verifying,
            did,
        })
    }

    /// Generate a fresh DeviceKey from OS RNG.
    ///
    /// # Panics
    ///
    /// Never — Ed25519 signing key is always 32 bytes.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_private_bytes(&seed)
            .expect("from_private_bytes accepts 32-byte seeds: seed has fixed [u8; 32] type")
    }

    /// 32-byte Ed25519 seed (private key material).
    pub fn private_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// Cached `did:key:z…` encoding of the public key.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Produce a 64-byte Ed25519 signature over `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Verify a signature against an Ed25519 `did:key:z…` identity.
    ///
    /// Returns `Ok(false)` for non-Ed25519 DIDs (secp256k1 verify deferred).
    pub fn verify_did(did: &str, message: &[u8], signature: &[u8]) -> Result<bool> {
        let Some(rest) = did.strip_prefix("did:key:z") else {
            return Ok(false);
        };
        let multi = bs58::decode(rest)
            .into_vec()
            .map_err(|e| Error::Malformed {
                kind: "did:key",
                reason: e.to_string(),
            })?;
        if multi.len() < 2 || multi[..2] != ED25519_MULTICODEC {
            return Ok(false);
        }
        let pub_bytes: &[u8; 32] = multi[2..].try_into().map_err(|_| Error::Malformed {
            kind: "did:key",
            reason: "pubkey length".into(),
        })?;
        let vk = VerifyingKey::from_bytes(pub_bytes).map_err(|e| Error::Malformed {
            kind: "ed25519 pubkey",
            reason: e.to_string(),
        })?;
        let sig_arr: &[u8; 64] = signature.try_into().map_err(|_| Error::Malformed {
            kind: "ed25519 sig",
            reason: "length".into(),
        })?;
        let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
        Ok(vk.verify(message, &sig).is_ok())
    }
}

/// Encode a signature as URL-safe base64 with no padding.
pub fn signature_b64(sig: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(sig)
}

/// Decode a URL-safe-no-padding base64 signature.
pub fn signature_from_b64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| Error::Malformed {
        kind: "signature base64url",
        reason: e.to_string(),
    })
}
