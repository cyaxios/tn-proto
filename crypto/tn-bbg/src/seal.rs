//! The full hibe-group ciphertext blob: what a `cipher: hibe` group stores as
//! its `ciphertext`. Byte-identical layout to tn-hibe's `seal.rs`.
//!
//! Blob layout:
//! `version(1) | wrapped_CEK(205, see kem.rs) | body_nonce(12) | AES-256-GCM(body)`.
//! The wrapped-CEK bytes are the body's AEAD associated data.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::error::{BbgError, Result};
use crate::identity::Identity;
use crate::kem::{kem_unwrap, kem_wrap, WRAPPED_CEK_LEN};
use crate::key::PrivateKey;
use crate::params::PublicParams;

const BLOB_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_BLOB_LEN: usize = 1 + WRAPPED_CEK_LEN + NONCE_LEN + TAG_LEN;

/// Seals `plaintext` to `id`: fresh CEK, KEM-wrapped to the identity path, body
/// under AES-256-GCM. No caller AAD.
pub fn seal(
    pp: &PublicParams,
    id: &Identity,
    plaintext: &[u8],
    rng: impl RngCore + CryptoRng,
) -> Result<Vec<u8>> {
    seal_with_aad(pp, id, plaintext, &[], rng)
}

/// Like [`seal`], but binds `aad` into the body's AEAD tag. An empty `aad`
/// uses the same wire construction as [`seal`]; individual blobs are still
/// randomized by the CEK and nonce.
pub fn seal_with_aad(
    pp: &PublicParams,
    id: &Identity,
    plaintext: &[u8],
    aad: &[u8],
    mut rng: impl RngCore + CryptoRng,
) -> Result<Vec<u8>> {
    let mut cek = [0u8; 32];
    rng.fill_bytes(&mut cek);
    let wrapped = kem_wrap(pp, id, &cek, &mut rng)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new((&cek).into());
    cek.zeroize();
    let body = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &body_aad(&wrapped, aad),
            },
        )
        .map_err(|_| BbgError::Unwrap)?;

    let mut out = Vec::with_capacity(1 + wrapped.len() + NONCE_LEN + body.len());
    out.push(BLOB_VERSION);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a sealed blob with a key on the identity path it was sealed to. No
/// caller AAD.
pub fn open(pp: &PublicParams, sk: &PrivateKey, blob: &[u8]) -> Result<Vec<u8>> {
    open_with_aad(pp, sk, blob, &[])
}

/// Like [`open`], but requires the same `aad` bound at seal time.
pub fn open_with_aad(
    pp: &PublicParams,
    sk: &PrivateKey,
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    const WHAT: &str = "sealed blob";
    if blob.len() < MIN_BLOB_LEN || blob[0] != BLOB_VERSION {
        return Err(BbgError::Malformed(WHAT));
    }
    let wrapped = &blob[1..1 + WRAPPED_CEK_LEN];
    let nonce = &blob[1 + WRAPPED_CEK_LEN..1 + WRAPPED_CEK_LEN + NONCE_LEN];
    let body = &blob[1 + WRAPPED_CEK_LEN + NONCE_LEN..];

    let mut cek = kem_unwrap(pp, sk, wrapped)?;
    let cipher = Aes256Gcm::new((&cek).into());
    cek.zeroize();
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: &body_aad(wrapped, aad),
            },
        )
        .map_err(|_| BbgError::Unwrap)
}

/// The body AEAD's associated data: the KEM header, then the caller's AAD.
fn body_aad(wrapped: &[u8], aad: &[u8]) -> Vec<u8> {
    if aad.is_empty() {
        return wrapped.to_vec();
    }
    let mut combined = Vec::with_capacity(wrapped.len() + aad.len());
    combined.extend_from_slice(wrapped);
    combined.extend_from_slice(aad);
    combined
}
