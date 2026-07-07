//! BBG `KeyGen` (from master) and `Delegate` (parent to child, no master key).
//!
//! Equations, in our G1/G2 placement (a0, bs in G2; a1 in G1). For an identity
//! of depth `k` in a system of depth `l`:
//!
//! KeyGen from master:
//! ```text
//! r      <- random Zp
//! a0     = msk * (g3 * prod_{i<k} hs[i]^{I_i})^r      (G2)
//! a1     = g^r                                        (G1)
//! bs[j]  = hs[k+j]^r   for j in 0..l-k                (G2)
//! ```
//!
//! Delegate (parent depth k-1 -> child depth k, child scalar `I_k`):
//! ```text
//! t      <- random Zp
//! a0     = parent.a0 * parent.bs[0]^{I_k} * (g3 * prod_{i<k} hs[i]^{I_i})^t   (G2)
//! a1     = parent.a1 * g^t                                                    (G1)
//! bs[j]  = parent.bs[j+1] * hs[k+j]^t   for j in 0..l-k                       (G2)
//! ```
//! `parent.bs[0]` is `hs[k-1]^{r_parent}` — consumed to bind the new component
//! into a0, then dropped from the child's bs tail. This is BBG's key-derivation
//! trick that lets delegation happen with no master key.

use bls12_381_plus::ff::Field;
use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand_core::RngCore;

use crate::codec::{read_g1, read_g2, Reader, G1_LEN, G2_LEN, VERSION};
use crate::error::{BbgError, Result};
use crate::identity::Identity;
use crate::params::{MasterKey, PublicParams};

/// A delegated (or directly generated) secret key for one identity path.
///
/// BBG structure: `a0 ∈ G2`, `a1 ∈ G1`, and one `b ∈ G2` per remaining
/// delegatable level — a leaf at `max_depth` has an empty `bs`.
///
/// A private key is a permanent trapdoor for its path (no forward revocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    pub(crate) a0: G2Affine,
    pub(crate) a1: G1Affine,
    pub(crate) bs: Vec<G2Affine>,
    pub(crate) id: Identity,
}

/// Generates the key for `id` directly from the master secret. Only the
/// authority (msk holder) can do this.
pub fn keygen(
    pp: &PublicParams,
    msk: &MasterKey,
    id: &Identity,
    mut rng: impl RngCore,
) -> Result<PrivateKey> {
    let k = id.depth();
    if k > pp.max_depth {
        return Err(BbgError::IdentityTooDeep);
    }
    let r = Scalar::random(&mut rng);

    // a0 = msk * (g3 * prod hs[i]^{I_i})^r
    let a0 = G2Projective::from(msk.mk) + pp.identity_base(id.scalars()) * r;
    // a1 = g^r
    let a1 = G1Projective::from(pp.g) * r;
    // bs[j] = hs[k+j]^r
    let bs: Vec<G2Affine> = pp.hs[k..]
        .iter()
        .map(|h| G2Affine::from(G2Projective::from(*h) * r))
        .collect();

    Ok(PrivateKey {
        a0: G2Affine::from(a0),
        a1: G1Affine::from(a1),
        bs,
        id: id.clone(),
    })
}

/// Derives the key for `parent`'s child labelled `child_label` — parent to
/// child, no msk involved. This is HIBE's native `add_recipient`.
pub fn delegate(
    pp: &PublicParams,
    parent: &PrivateKey,
    child_label: &[u8],
    mut rng: impl RngCore,
) -> Result<PrivateKey> {
    let child_id = parent.id.child(child_label);
    let k = child_id.depth();
    if k > pp.max_depth {
        return Err(BbgError::IdentityTooDeep);
    }
    if parent.bs.is_empty() {
        // A leaf parent has no delegatable levels left.
        return Err(BbgError::IdentityTooDeep);
    }
    let child_scalar = child_id.scalars()[k - 1];
    let t = Scalar::random(&mut rng);

    // a0 = parent.a0 * parent.bs[0]^{I_k} * (g3 * prod_{i<k} hs[i]^{I_i})^t
    let a0 = G2Projective::from(parent.a0)
        + G2Projective::from(parent.bs[0]) * child_scalar
        + pp.identity_base(child_id.scalars()) * t;
    // a1 = parent.a1 * g^t
    let a1 = G1Projective::from(parent.a1) + G1Projective::from(pp.g) * t;
    // bs[j] = parent.bs[j+1] * hs[k+j]^t
    let bs: Vec<G2Affine> = (0..pp.max_depth - k)
        .map(|j| {
            let updated = G2Projective::from(parent.bs[j + 1]) + G2Projective::from(pp.hs[k + j]) * t;
            G2Affine::from(updated)
        })
        .collect();

    Ok(PrivateKey {
        a0: G2Affine::from(a0),
        a1: G1Affine::from(a1),
        bs,
        id: child_id,
    })
}

impl PrivateKey {
    /// The identity path this key opens (and can delegate below).
    pub fn identity(&self) -> &Identity {
        &self.id
    }

    /// Canonical encoding:
    /// `version(1) | depth(1) | [label_len(2 BE) | label]*depth | a0(96) | a1(48) | bs_count(1) | bs(96 * count)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(VERSION);
        out.push(self.id.depth() as u8);
        for label in self.id.labels() {
            out.extend_from_slice(&(label.len() as u16).to_be_bytes());
            out.extend_from_slice(label);
        }
        out.extend_from_slice(&self.a0.to_compressed());
        out.extend_from_slice(&self.a1.to_compressed());
        out.push(self.bs.len() as u8);
        for b in &self.bs {
            out.extend_from_slice(&b.to_compressed());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const WHAT: &str = "PrivateKey";
        let mut r = Reader::new(bytes, WHAT);
        r.expect_version(WHAT)?;
        let depth = r.u8()? as usize;
        let mut labels = Vec::with_capacity(depth);
        for _ in 0..depth {
            let len = r.u16()? as usize;
            labels.push(r.take(len)?.to_vec());
        }
        let a0 = read_g2(r.take(G2_LEN)?, WHAT)?;
        let a1 = read_g1(r.take(G1_LEN)?, WHAT)?;
        let bs_count = r.u8()? as usize;
        let mut bs = Vec::with_capacity(bs_count);
        for _ in 0..bs_count {
            bs.push(read_g2(r.take(G2_LEN)?, WHAT)?);
        }
        r.finish()?;
        Ok(PrivateKey {
            a0,
            a1,
            bs,
            id: Identity::from_labels(labels),
        })
    }
}
