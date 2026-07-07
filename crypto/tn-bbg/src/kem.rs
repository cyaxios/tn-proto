//! The CEK KEM: what goes inside a hibe group's `ciphertext` blob.
//!
//! `kem_wrap` runs BBG key encapsulation to the identity path, derives an
//! AES-256-GCM key from the shared GT element with HKDF-SHA256, and seals the
//! caller's 32-byte CEK under it. KEM-not-direct: the wire bytes are compressed
//! group points plus canonical AEAD output — the GT element only ever exists in
//! memory as a KDF input.
//!
//! Wire layout (fixed 237 bytes), byte-identical to tn-hibe:
//! `version(1) | B(48, G1) | C(96, G2) | nonce(12) | AES-256-GCM(CEK)(32+16)`.
//! `version | B | C` doubles as the AEAD associated data.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::codec::{gt_bytes, read_g1, read_g2, Reader, G1_LEN, G2_LEN, VERSION};
use crate::encrypt::{decapsulate, encapsulate};
use crate::error::{BbgError, Result};
use crate::identity::Identity;
use crate::key::PrivateKey;
use crate::params::PublicParams;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const CEK_LEN: usize = 32;
const KDF_INFO: &[u8] = b"tn-hibe/kem/v1";

/// Total size of a wrapped CEK: `1 + 48 + 96 + 12 + 32 + 16`.
pub const WRAPPED_CEK_LEN: usize = 1 + G1_LEN + G2_LEN + NONCE_LEN + CEK_LEN + TAG_LEN;

/// Wraps a 32-byte CEK to `id` under the authority's public params.
pub fn kem_wrap(
    pp: &PublicParams,
    id: &Identity,
    cek: &[u8; CEK_LEN],
    mut rng: impl RngCore,
) -> Result<Vec<u8>> {
    if id.depth() > pp.max_depth() {
        return Err(BbgError::IdentityTooDeep);
    }
    let (shared, b, c) = encapsulate(pp, id.scalars(), &mut rng);

    let mut key = derive_key(&gt_bytes(&shared));
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(1 + G1_LEN + G2_LEN);
    header.push(VERSION);
    header.extend_from_slice(&b.to_compressed());
    header.extend_from_slice(&c.to_compressed());

    let cipher = Aes256Gcm::new((&key).into());
    key.zeroize();
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: cek,
                aad: &header,
            },
        )
        .map_err(|_| BbgError::Unwrap)?;

    let mut out = header;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    debug_assert_eq!(out.len(), WRAPPED_CEK_LEN);
    Ok(out)
}

/// Unwraps a CEK with a key on the identity path it was wrapped to. Fails with
/// [`BbgError::Unwrap`] on a wrong-path key or any tampered byte.
pub fn kem_unwrap(pp: &PublicParams, sk: &PrivateKey, wrapped: &[u8]) -> Result<[u8; CEK_LEN]> {
    // `pp` is unused by decapsulation (the key carries everything needed) but
    // kept in the signature to match tn-hibe's API for a mechanical swap.
    let _ = pp;
    const WHAT: &str = "wrapped CEK";
    if wrapped.len() != WRAPPED_CEK_LEN {
        return Err(BbgError::Malformed(WHAT));
    }
    let header = &wrapped[..1 + G1_LEN + G2_LEN];
    let mut r = Reader::new(wrapped, WHAT);
    r.expect_version(WHAT)?;
    let b = read_g1(r.take(G1_LEN)?, WHAT)?;
    let c = read_g2(r.take(G2_LEN)?, WHAT)?;
    let nonce = r.take(NONCE_LEN)?;
    let sealed = r.take(CEK_LEN + TAG_LEN)?;
    r.finish()?;

    let shared = decapsulate(sk, &b, &c);

    let mut key = derive_key(&gt_bytes(&shared));
    let cipher = Aes256Gcm::new((&key).into());
    key.zeroize();
    let mut opened = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: header,
            },
        )
        .map_err(|_| BbgError::Unwrap)?;

    let cek: [u8; CEK_LEN] = opened
        .as_slice()
        .try_into()
        .map_err(|_| BbgError::Malformed(WHAT))?;
    opened.zeroize();
    Ok(cek)
}

/// `HKDF-SHA256(ikm = GT bytes, salt = none, info = "tn-hibe/kem/v1") -> 32B`.
fn derive_key(gt: &[u8]) -> [u8; CEK_LEN] {
    let hk = Hkdf::<Sha256>::new(None, gt);
    let mut okm = [0u8; CEK_LEN];
    hk.expand(KDF_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}
