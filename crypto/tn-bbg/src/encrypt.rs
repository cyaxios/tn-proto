//! Raw BBG encrypt/decrypt over GT, and the encapsulate/decapsulate KEM core.
//!
//! Wire code never uses `encrypt`/`decrypt` directly — the on-wire form is the
//! KEM in [`crate::kem`] (KEM-not-direct). They exist for the scheme's own
//! tests and the golden vectors.
//!
//! Equations (id depth k), our G1/G2 placement (B in G1, C in G2):
//! ```text
//! s   <- random Zp
//! A   = e(g1, g2)^s * m            (GT)   [Encrypt only; KEM has no m]
//! B   = g^s                        (G1)
//! C   = (g3 * prod hs[i]^{I_i})^s  (G2)
//! ```
//! Decrypt: `m = A * e(B, a0)^{-1} * e(a1, C)`, using `e: G1 x G2 -> GT`.
//! The pairing arguments are `(B:G1, a0:G2)` and `(a1:G1, C:G2)`.
//!
//! Correctness (why the masking cancels):
//! ```text
//! e(B, a0)  = e(g,g2)^{s.alpha} * e(g, base)^{s.r}
//! e(a1, C)  = e(g, base)^{r.s}
//! => e(B,a0)^{-1} * e(a1,C) = e(g,g2)^{-s.alpha}
//! and A = e(g1,g2)^s * m = e(g,g2)^{s.alpha} * m  => product = m.
//! ```

use bls12_381_plus::ff::Field;
use bls12_381_plus::{pairing, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use rand_core::RngCore;

use crate::codec::{gt_bytes, read_g1, read_g2, read_gt, Reader, G1_LEN, G2_LEN, VERSION};
use crate::error::{BbgError, Result};
use crate::identity::Identity;
use crate::key::PrivateKey;
use crate::params::PublicParams;

/// A BBG ciphertext: always exactly three elements, whatever the identity
/// depth (BBG's constant-size property).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    pub(crate) a: Gt,
    pub(crate) b: G1Affine,
    pub(crate) c: G2Affine,
}

/// The randomized BBG head shared by Encrypt and Encapsulate:
/// `(mask = e(g1,g2)^s, B = g^s, C = base^s)`.
fn encaps_head(pp: &PublicParams, id_scalars: &[Scalar], rng: &mut impl RngCore) -> (Gt, G1Affine, G2Affine) {
    let s = Scalar::random(rng);
    let mask = pairing(&pp.g1, &pp.g2) * s;
    let b = G1Affine::from(G1Projective::from(pp.g) * s);
    let c = G2Affine::from(pp.identity_base(id_scalars) * s);
    (mask, b, c)
}

/// Recovers the BBG masking element `e(g1,g2)^s` from a key on the ciphertext's
/// identity path: `mask = e(B, a0) * e(a1, C)^{-1}`.
fn recover_mask(sk: &PrivateKey, b: &G1Affine, c: &G2Affine) -> Gt {
    let left = pairing(b, &sk.a0);
    let right = pairing(&sk.a1, c);
    left * right.invert().expect("pairing of curve points is never the GT identity")
}

/// Encrypts a GT element to `id` under the authority's public params.
pub fn encrypt(pp: &PublicParams, id: &Identity, m: &Gt, mut rng: impl RngCore) -> Result<Ciphertext> {
    if id.depth() > pp.max_depth() {
        return Err(BbgError::IdentityTooDeep);
    }
    let (mask, b, c) = encaps_head(pp, id.scalars(), &mut rng);
    Ok(Ciphertext { a: mask * m, b, c })
}

/// Decrypts with a key whose identity path matches the one encrypted to.
///
/// BBG decryption never fails structurally — a wrong-path key just yields a
/// different GT element. Authenticity comes from the AEAD layer in the KEM.
pub fn decrypt(pp: &PublicParams, sk: &PrivateKey, ct: &Ciphertext) -> Result<Gt> {
    let _ = pp;
    let mask = recover_mask(sk, &ct.b, &ct.c);
    // m = A * mask^{-1}
    Ok(ct.a * mask.invert().expect("mask is a pairing of curve points, never GT identity"))
}

/// BBG key encapsulation: returns the shared masking element and the two
/// public ciphertext components. The KEM in [`crate::kem`] derives an AEAD key
/// from the shared element.
pub(crate) fn encapsulate(
    pp: &PublicParams,
    id_scalars: &[Scalar],
    mut rng: impl RngCore,
) -> (Gt, G1Affine, G2Affine) {
    encaps_head(pp, id_scalars, &mut rng)
}

/// Inverse of [`encapsulate`]: recovers the shared masking element.
pub(crate) fn decapsulate(sk: &PrivateKey, b: &G1Affine, c: &G2Affine) -> Gt {
    recover_mask(sk, b, c)
}

impl Ciphertext {
    /// Canonical encoding: `version(1) | a(GT, 576) | b(48) | c(96)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let a = gt_bytes(&self.a);
        let mut out = Vec::with_capacity(1 + a.len() + G1_LEN + G2_LEN);
        out.push(VERSION);
        out.extend_from_slice(&a);
        out.extend_from_slice(&self.b.to_compressed());
        out.extend_from_slice(&self.c.to_compressed());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const WHAT: &str = "Ciphertext";
        let mut r = Reader::new(bytes, WHAT);
        r.expect_version(WHAT)?;
        let gt_len = r
            .remaining()
            .checked_sub(G1_LEN + G2_LEN)
            .ok_or(BbgError::Malformed(WHAT))?;
        let a = read_gt(r.take(gt_len)?, WHAT)?;
        let b = read_g1(r.take(G1_LEN)?, WHAT)?;
        let c = read_g2(r.take(G2_LEN)?, WHAT)?;
        r.finish()?;
        Ok(Ciphertext { a, b, c })
    }
}
