//! Byte-oriented RFC 7516 JWE encryption primitives.
//!
//! This facade accepts raw X25519 key material and delegates cryptographic
//! operations to the native [`tn_core`] JWE engine. It does not authenticate
//! identities or bind keys to DIDs; use the enrollment APIs for that boundary.

use std::borrow::Borrow;

use rand_core::RngCore as _;
use tn_core::cipher::{jwe::JweCipher, GroupCipher as _};

use crate::{Error, Result};

const PRIMITIVE_GROUP: &str = "jwe-primitive";
const MAX_AAD_BYTES: usize = 64 * 1_024;
const MAX_KEYS: usize = 1_024;

/// A raw X25519 public/private key pair.
///
/// This type deliberately does not implement [`Debug`](std::fmt::Debug), so
/// formatting it cannot accidentally expose `private_key`.
pub struct KeyPair {
    /// Raw 32-byte X25519 public key.
    pub public_key: [u8; 32],
    /// Raw 32-byte X25519 private scalar.
    pub private_key: [u8; 32],
}

/// Generate a fresh raw X25519 key pair.
///
/// # Errors
///
/// Returns [`Error::Core`] if the operating system cannot provide secure
/// randomness.
pub fn keygen() -> Result<KeyPair> {
    let mut private_key = [0_u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut private_key)
        .map_err(|error| {
            Error::Core(tn_core::Error::Internal(format!(
                "X25519 key generation failed: {error}"
            )))
        })?;
    let public_key = tn_core::trusted_enrollment::x25519_public_key(&private_key);
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

/// Encrypt bytes for one or more raw X25519 recipient public keys.
///
/// The returned bytes are UTF-8 RFC 7516 General JSON Serialization.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] when `recipients` is empty, or forwards
/// an error from the native JWE engine.
pub fn encrypt<I, K>(plaintext: &[u8], recipients: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = K>,
    K: Borrow<[u8; 32]>,
{
    encrypt_with_aad(plaintext, recipients, &[])
}

/// Encrypt bytes with RFC 7516 additional authenticated data for one or more
/// raw X25519 recipient public keys.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] when `recipients` is empty, or forwards
/// an error from the native JWE engine.
pub fn encrypt_with_aad<I, K>(plaintext: &[u8], recipients: I, aad: &[u8]) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = K>,
    K: Borrow<[u8; 32]>,
{
    let recipients = collect_keys(recipients, "recipients")?;
    require_keys(
        &recipients,
        "JWE encryption requires at least one recipient",
    )?;
    require_aad_within_limit(aad)?;
    let cipher = map_jwe(JweCipher::new(PRIMITIVE_GROUP, &recipients, &[]))?;
    map_jwe(cipher.encrypt_with_aad(plaintext, aad))
}

/// Construct a JWE subscriber from one or more raw X25519 private keys.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] when `private_keys` is empty, or forwards
/// an error from the native JWE engine.
pub fn subscribe<I, K>(private_keys: I) -> Result<Subscriber>
where
    I: IntoIterator<Item = K>,
    K: Borrow<[u8; 32]>,
{
    let private_keys = collect_keys(private_keys, "private keys")?;
    require_keys(
        &private_keys,
        "JWE subscription requires at least one private key",
    )?;
    let cipher = map_jwe(JweCipher::new(PRIMITIVE_GROUP, &[], &private_keys))?;
    Ok(Subscriber { cipher })
}

/// A reader holding one or more raw X25519 private keys.
pub struct Subscriber {
    cipher: JweCipher,
}

impl Subscriber {
    /// Decrypt an RFC 7516 General JSON JWE without additional authenticated
    /// data.
    ///
    /// # Errors
    ///
    /// Forwards malformed-input, entitlement, and authentication errors from
    /// the native JWE engine.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        map_jwe(self.cipher.decrypt(ciphertext))
    }

    /// Decrypt an RFC 7516 General JSON JWE using byte-identical additional
    /// authenticated data.
    ///
    /// # Errors
    ///
    /// Forwards malformed-input, entitlement, and authentication errors from
    /// the native JWE engine.
    pub fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        require_aad_within_limit(aad)?;
        map_jwe(self.cipher.decrypt_with_aad(ciphertext, aad))
    }
}

fn collect_keys<I, K>(keys: I, kind: &str) -> Result<Vec<[u8; 32]>>
where
    I: IntoIterator<Item = K>,
    K: Borrow<[u8; 32]>,
{
    let keys = keys
        .into_iter()
        .take(MAX_KEYS + 1)
        .map(|key| *key.borrow())
        .collect::<Vec<_>>();
    if keys.len() > MAX_KEYS {
        Err(Error::LimitExceeded(format!(
            "JWE {kind} exceed the {MAX_KEYS}-key limit"
        )))
    } else {
        Ok(keys)
    }
}

fn require_keys(keys: &[[u8; 32]], message: &str) -> Result<()> {
    if keys.is_empty() {
        Err(Error::InvalidArgument(message.to_owned()))
    } else {
        Ok(())
    }
}

fn require_aad_within_limit(aad: &[u8]) -> Result<()> {
    if aad.len() > MAX_AAD_BYTES {
        Err(Error::LimitExceeded(format!(
            "JWE AAD exceeds {MAX_AAD_BYTES} bytes"
        )))
    } else {
        Ok(())
    }
}

fn map_jwe<T>(result: tn_core::Result<T>) -> Result<T> {
    result.map_err(map_jwe_error)
}

fn map_jwe_error(error: tn_core::Error) -> Error {
    match error {
        tn_core::Error::NotEntitled { group } => {
            Error::NotEntitled(format!("no supplied private key opens JWE group {group:?}"))
        }
        tn_core::Error::Malformed { kind, reason } => Error::Malformed(format!("{kind}: {reason}")),
        tn_core::Error::Json(error) => Error::Malformed(format!("JWE JSON: {error}")),
        tn_core::Error::InvalidConfig(message) if is_key_count_limit(&message) => {
            Error::LimitExceeded(message)
        }
        tn_core::Error::Cipher(message) if is_size_limit(&message) => Error::LimitExceeded(message),
        tn_core::Error::Cipher(message) if is_authentication_failure(&message) => {
            Error::AuthenticationFailed(message)
        }
        tn_core::Error::Cipher(message)
            if message == "JWE X25519 produced an all-zero shared secret" =>
        {
            Error::Malformed(message)
        }
        other => Error::Core(other),
    }
}

fn is_key_count_limit(message: &str) -> bool {
    message.starts_with("JWE has ") && message.contains("; maximum is ")
}

fn is_size_limit(message: &str) -> bool {
    message.starts_with("JWE plaintext exceeds ") || message.starts_with("JWE AAD exceeds ")
}

fn is_authentication_failure(message: &str) -> bool {
    matches!(
        message,
        "JWE AAD does not match the envelope" | "JWE content authentication failed"
    )
}
