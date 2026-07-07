//! BBG `Setup` and the public/secret system material.
//!
//! Element placement (from the tn-proto HIBE spec, matching what hohibe froze
//! into the golden vectors — NOT the samkumar/bn256 layout, which swaps G1/G2
//! because bn256's G2 is cheaper):
//!
//! - `g   : G1`  system generator
//! - `g1  : G1`  = g^alpha
//! - `g2  : G2`  random
//! - `g3  : G2`  random
//! - `hs  : [G2; max_depth]`  random, one per delegatable level
//! - `msk : G2`  = g2^alpha
//!
//! So `a0, g2, g3, hs, C` live in G2 and `g, g1, a1, B` live in G1; the single
//! decrypt/encapsulate pairing pattern is `e(G1, G2)`.

use bls12_381_plus::ff::Field;
use bls12_381_plus::group::Group;
use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand_core::RngCore;

use crate::codec::{read_g1, read_g2, Reader, G1_LEN, G2_LEN, VERSION};
use crate::error::{BbgError, Result};

/// The master public key ("MPK") of one authority's HIBE system, plus the
/// system depth. This is what an authority publishes (pinned by
/// [`mpk_fingerprint`][crate::mpk_fingerprint] in its signed manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicParams {
    pub(crate) max_depth: usize,
    pub(crate) g: G1Affine,
    pub(crate) g1: G1Affine,
    pub(crate) g2: G2Affine,
    pub(crate) g3: G2Affine,
    pub(crate) hs: Vec<G2Affine>,
}

/// The master secret key of one authority's HIBE system.
///
/// Custody rule (contract D2): this never leaves the authority. Whoever holds
/// it can derive a reader key for ANY identity path and open everything ever
/// sealed under the matching [`PublicParams`].
pub struct MasterKey {
    /// `g2^alpha`.
    pub(crate) mk: G2Affine,
}

/// Runs BBG `Setup` for one authority: a fresh system supporting identity
/// paths up to `max_depth` labels.
///
/// ```text
/// g      <- G1 generator
/// alpha  <- random Zp
/// g1     = g^alpha                 (G1)
/// g2, g3 <- random G2
/// hs[i]  <- random G2   for i in 0..max_depth
/// msk    = g2^alpha                (G2)
/// ```
pub fn setup(max_depth: usize, mut rng: impl RngCore) -> Result<(PublicParams, MasterKey)> {
    if max_depth == 0 || max_depth > 255 {
        return Err(BbgError::BadMaxDepth(max_depth));
    }
    let g = G1Affine::generator();
    let alpha = Scalar::random(&mut rng);
    let g1 = G1Affine::from(G1Projective::from(g) * alpha);
    let g2 = G2Affine::from(G2Projective::random(&mut rng));
    let g3 = G2Affine::from(G2Projective::random(&mut rng));
    let hs: Vec<G2Affine> = (0..max_depth)
        .map(|_| G2Affine::from(G2Projective::random(&mut rng)))
        .collect();
    let mk = G2Affine::from(G2Projective::from(g2) * alpha);
    Ok((
        PublicParams {
            max_depth,
            g,
            g1,
            g2,
            g3,
            hs,
        },
        MasterKey { mk },
    ))
}

impl PublicParams {
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// `g3 * prod(hs[i]^{I_i})` over the identity's scalars — the per-identity
    /// group element that appears (raised to r/s/t) in KeyGen, Delegate,
    /// Encrypt and Encapsulate. Lives in G2.
    pub(crate) fn identity_base(&self, id_scalars: &[Scalar]) -> G2Projective {
        let mut acc = G2Projective::from(self.g3);
        for (h, i) in self.hs.iter().zip(id_scalars.iter()) {
            acc += G2Projective::from(*h) * i;
        }
        acc
    }

    /// Canonical encoding:
    /// `version(1) | max_depth(1) | g(48) | g1(48) | g2(96) | g3(96) | hs(96 * max_depth)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 * G1_LEN + (2 + self.hs.len()) * G2_LEN);
        out.push(VERSION);
        out.push(self.max_depth as u8);
        out.extend_from_slice(&self.g.to_compressed());
        out.extend_from_slice(&self.g1.to_compressed());
        out.extend_from_slice(&self.g2.to_compressed());
        out.extend_from_slice(&self.g3.to_compressed());
        for h in &self.hs {
            out.extend_from_slice(&h.to_compressed());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const WHAT: &str = "PublicParams";
        let mut r = Reader::new(bytes, WHAT);
        r.expect_version(WHAT)?;
        let max_depth = r.u8()? as usize;
        if max_depth == 0 {
            return Err(BbgError::Malformed(WHAT));
        }
        let g = read_g1(r.take(G1_LEN)?, WHAT)?;
        let g1 = read_g1(r.take(G1_LEN)?, WHAT)?;
        let g2 = read_g2(r.take(G2_LEN)?, WHAT)?;
        let g3 = read_g2(r.take(G2_LEN)?, WHAT)?;
        let mut hs = Vec::with_capacity(max_depth);
        for _ in 0..max_depth {
            hs.push(read_g2(r.take(G2_LEN)?, WHAT)?);
        }
        r.finish()?;
        Ok(PublicParams {
            max_depth,
            g,
            g1,
            g2,
            g3,
            hs,
        })
    }
}

impl MasterKey {
    /// Canonical encoding: `version(1) | mk(96)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + G2_LEN);
        out.push(VERSION);
        out.extend_from_slice(&self.mk.to_compressed());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const WHAT: &str = "MasterKey";
        let mut r = Reader::new(bytes, WHAT);
        r.expect_version(WHAT)?;
        let mk = read_g2(r.take(G2_LEN)?, WHAT)?;
        r.finish()?;
        Ok(MasterKey { mk })
    }
}
