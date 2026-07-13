//! Ed25519 device identity — signing key, verifying key, and `did:key` encoding.
//!
//! [`DeviceKey`] is the device identity TN mints behind `tn init`: an Ed25519
//! keypair whose public half is encoded as a `did:key:z…` string. Every
//! attested event a runtime writes is signed by this key; every reader verifies
//! against the publisher's `did:key`. The two free functions
//! ([`signature_b64`] / [`signature_from_b64`]) are the wire codec for the
//! signature bytes (URL-safe base64, no padding).
//!
//! Matches `tn/signing.py` for Ed25519 (the curve TN signs with). The Python
//! verify path additionally accepts secp256k1 DIDs for ATProto interop; this
//! Rust port defers that branch — secp256k1 DIDs return `Ok(false)` from
//! [`DeviceKey::verify_did`] without erroring. Will be added when a fixture
//! requires it.
//!
//! This module deliberately keeps its legacy multi-curve, boolean verify API.
//! Trust-boundary code (enrollment ceremonies, package signer checks) uses
//! the strict [`crate::trust`] module instead: only canonical Ed25519
//! `did:key` identifiers are accepted there, and every rejection carries a
//! stable machine-readable reason.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::{Error, Result};

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// An Ed25519 device identity: signing key + verifying key + cached `did:key`.
///
/// This is the cryptographic half of a TN device — the keypair that signs the
/// events a runtime writes and the `did:key:z…` other parties verify against.
/// Construct one from a stored 32-byte seed with [`DeviceKey::from_private_bytes`]
/// (the `tn init` round-trip) or mint a fresh identity with [`DeviceKey::generate`].
/// The `did` is derived once at construction and cached, so [`DeviceKey::did`]
/// is a cheap borrow.
///
/// # Examples
///
/// ```
/// use tn_core::DeviceKey;
///
/// // Deterministic identity from a fixed seed (fixtures pin keys this way).
/// let dk = DeviceKey::from_private_bytes(&[7u8; 32]).unwrap();
/// assert!(dk.did().starts_with("did:key:z"));
///
/// // Round-trips: the seed in is the seed back out.
/// assert_eq!(dk.private_bytes(), [7u8; 32]);
/// ```
pub struct DeviceKey {
    signing: SigningKey,
    verifying: VerifyingKey,
    did: String,
}

impl DeviceKey {
    /// Load a `DeviceKey` from its 32-byte Ed25519 seed.
    ///
    /// `seed` is the raw private scalar (the `local.private` keystore blob),
    /// not a base64 or DID encoding. Deriving the verifying key and `did:key`
    /// happens here, once.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidConfig`] if `seed` is not exactly 32 bytes.
    ///
    /// # Panics
    ///
    /// Never — the `try_into` is guarded by the length check above it.
    ///
    /// # Examples
    ///
    /// ```
    /// use tn_core::DeviceKey;
    ///
    /// assert!(DeviceKey::from_private_bytes(&[0u8; 32]).is_ok());
    /// // Wrong length is rejected rather than silently truncated.
    /// assert!(DeviceKey::from_private_bytes(b"too short").is_err());
    /// ```
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

    /// Generate a fresh `DeviceKey` from the OS RNG.
    ///
    /// Draws 32 random bytes from the OS RNG (`rand_core::OsRng`) and derives
    /// the identity from them. This is the new-identity path behind `tn init`
    /// when no seed is being restored. Persist
    /// [`private_bytes`](Self::private_bytes) afterwards or the identity is lost.
    ///
    /// # Panics
    ///
    /// Never — an Ed25519 signing key is always 32 bytes, so the internal
    /// [`from_private_bytes`](Self::from_private_bytes) call cannot fail.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_private_bytes(&seed)
            .expect("from_private_bytes accepts 32-byte seeds: seed has fixed [u8; 32] type")
    }

    /// Return the 32-byte Ed25519 seed (private key material).
    ///
    /// This is the secret to persist (the `local.private` blob). Treat it as
    /// sensitive: anyone holding it can sign as this device.
    pub fn private_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Return the 32-byte Ed25519 public key.
    ///
    /// The raw point bytes, without the multicodec prefix or base58 encoding
    /// that [`did`](Self::did) carries.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// Borrow the cached `did:key:z…` encoding of the public key.
    ///
    /// This is the device's public identifier — the `device_identity` /
    /// `publisher_identity` field other parties verify signatures against.
    /// Computed once at construction; this is a cheap borrow.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Produce a 64-byte Ed25519 signature over `message`.
    ///
    /// Signs the bytes exactly as given — callers pass the canonical bytes they
    /// intend to bind (a `row_hash`, a manifest's signing bytes, etc.). Pure
    /// and deterministic for a fixed key and message.
    ///
    /// # Examples
    ///
    /// ```
    /// use tn_core::DeviceKey;
    ///
    /// let dk = DeviceKey::from_private_bytes(&[3u8; 32]).unwrap();
    /// let sig = dk.sign(b"attested row bytes");
    /// // Verifies against the device's own did:key.
    /// assert!(DeviceKey::verify_did(dk.did(), b"attested row bytes", &sig).unwrap());
    /// ```
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Verify `signature` over `message` against an Ed25519 `did:key:z…`.
    ///
    /// Associated (not a method): the caller supplies the DID directly, since
    /// verification needs only the public identifier, not a live `DeviceKey`.
    /// Decodes the DID's multicodec-prefixed Ed25519 public key, then checks the
    /// signature. Returns `Ok(true)` on a valid signature and `Ok(false)` on a
    /// cryptographic mismatch.
    ///
    /// Non-Ed25519 DIDs are not an error: a DID that is not `did:key:z…`, or one
    /// whose multicodec is not Ed25519 (e.g. a secp256k1 ATProto DID, whose
    /// verify path is deferred), returns `Ok(false)`.
    ///
    /// This is the legacy compatibility verifier. Trust decisions (enrollment
    /// statements, package signer identity) go through the strict
    /// [`crate::trust::verify_ed25519_did_signature`] instead, which accepts
    /// only canonical Ed25519 `did:key` identifiers and reports stable
    /// [`crate::trust::TrustReason`] rejections.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Malformed`] when the DID is shaped like a
    /// `did:key:z…` but its payload is corrupt: invalid base58, a non-32-byte
    /// public key, or a `signature` that is not exactly 64 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use tn_core::DeviceKey;
    ///
    /// let dk = DeviceKey::from_private_bytes(&[9u8; 32]).unwrap();
    /// let sig = dk.sign(b"hello");
    ///
    /// // Right message verifies; a tampered message does not.
    /// assert!(DeviceKey::verify_did(dk.did(), b"hello", &sig).unwrap());
    /// assert!(!DeviceKey::verify_did(dk.did(), b"HELLO", &sig).unwrap());
    ///
    /// // A non-did:key identifier is a clean `Ok(false)`, not an error.
    /// assert!(!DeviceKey::verify_did("did:web:example.com", b"hello", &sig).unwrap());
    /// ```
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
///
/// The on-the-wire string form of the `signature` envelope field. Inverse of
/// [`signature_from_b64`]. Pure.
///
/// # Examples
///
/// ```
/// use tn_core::signing::{signature_b64, signature_from_b64};
///
/// let raw = [0xABu8; 64];
/// let encoded = signature_b64(&raw);
/// assert!(!encoded.contains('=')); // no padding
/// assert_eq!(signature_from_b64(&encoded).unwrap(), raw);
/// ```
pub fn signature_b64(sig: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(sig)
}

/// Decode a URL-safe-no-padding base64 signature back into raw bytes.
///
/// Inverse of [`signature_b64`]; the decode the reader runs on the `signature`
/// envelope field before handing the bytes to [`DeviceKey::verify_did`].
///
/// # Errors
///
/// Returns [`crate::Error::Malformed`] if `s` is not valid URL-safe-no-padding
/// base64.
pub fn signature_from_b64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| Error::Malformed {
        kind: "signature base64url",
        reason: e.to_string(),
    })
}
