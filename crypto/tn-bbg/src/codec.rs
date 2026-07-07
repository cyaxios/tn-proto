//! Canonical byte encodings. Byte-for-byte identical to tn-hibe's `codec.rs`
//! so the two crates' `to_bytes`/`from_bytes` are interchangeable:
//! - G1: compressed, 48 bytes. G2: compressed, 96 bytes.
//! - GT: the `bls12_381_plus` `GroupEncoding` representation (576 bytes). GT
//!   bytes are only ever a local KDF input (KEM-not-direct) or a golden-vector
//!   fixture, never a wire field.
//! - Every multi-field encoding starts with a one-byte format version.

use bls12_381_plus::{G1Affine, G2Affine, Gt};
use sha2::{Digest, Sha256};

use crate::error::{BbgError, Result};
use crate::params::PublicParams;

pub(crate) const VERSION: u8 = 1;
pub(crate) const G1_LEN: usize = 48;
pub(crate) const G2_LEN: usize = 96;

pub(crate) fn read_g1(bytes: &[u8], what: &'static str) -> Result<G1Affine> {
    let arr: [u8; G1_LEN] = bytes.try_into().map_err(|_| BbgError::Malformed(what))?;
    Option::<G1Affine>::from(G1Affine::from_compressed(&arr)).ok_or(BbgError::Malformed(what))
}

pub(crate) fn read_g2(bytes: &[u8], what: &'static str) -> Result<G2Affine> {
    let arr: [u8; G2_LEN] = bytes.try_into().map_err(|_| BbgError::Malformed(what))?;
    Option::<G2Affine>::from(G2Affine::from_compressed(&arr)).ok_or(BbgError::Malformed(what))
}

/// The pinned GT encoding (`bls12_381_plus` representation, 576 bytes). Public
/// for golden-vector fixtures; GT bytes are never a wire field (KEM-not-direct)
/// — they are a KDF input and a test artifact only.
pub fn gt_to_bytes(gt: &Gt) -> Vec<u8> {
    gt.to_bytes().as_ref().to_vec()
}

/// Inverse of [`gt_to_bytes`].
pub fn gt_from_bytes(bytes: &[u8]) -> Result<Gt> {
    read_gt(bytes, "Gt")
}

pub(crate) fn gt_bytes(gt: &Gt) -> Vec<u8> {
    gt_to_bytes(gt)
}

pub(crate) fn read_gt(bytes: &[u8], what: &'static str) -> Result<Gt> {
    let arr: [u8; Gt::BYTES] = bytes.try_into().map_err(|_| BbgError::Malformed(what))?;
    Option::<Gt>::from(Gt::from_bytes(&arr)).ok_or(BbgError::Malformed(what))
}

/// Cursor-style reader so fixed-width parsers stay bounds-checked.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], what: &'static str) -> Self {
        Reader { bytes, what }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.bytes.len() < n {
            return Err(BbgError::Malformed(self.what));
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn expect_version(&mut self, what: &'static str) -> Result<()> {
        if self.u8()? != VERSION {
            return Err(BbgError::Malformed(what));
        }
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(BbgError::Malformed(self.what))
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len()
    }
}

/// SHA-256 over the canonical [`PublicParams`] encoding. This is the `mpk_fp`
/// that manifests publish so readers can pin an authority's MPK.
pub fn mpk_fingerprint(pp: &PublicParams) -> [u8; 32] {
    Sha256::digest(pp.to_bytes()).into()
}
