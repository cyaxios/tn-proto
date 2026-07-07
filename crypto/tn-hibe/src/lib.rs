//! BBG HIBE cipher core for tn-proto.
//!
//! This crate is the Rust core behind the `cipher: hibe` group option: a
//! hybrid KEM/DEM where BBG HIBE (Boneh-Boyen-Goh 2005, constant-size
//! ciphertext) wraps a 32-byte content-encryption key to an identity path
//! under an authority's master public key. AES-256-GCM seals the body.
//!
//! # Scheme provenance
//!
//! The scheme is provided by [`tn_bbg`] — our own **Apache-2.0 / MIT**
//! reimplementation of BBG on BLS12-381. It replaced the previously-vendored
//! LGPL `hohibe` crate, which has been removed; the on-wire bytes are
//! identical (the golden vectors, generated under hohibe, still open — see
//! `tests/golden.rs`). This crate is now a thin, stable re-export of
//! `tn_bbg` so its high-level consumers (tn-hibe-py, tn-wasm, tn-core) keep
//! importing `tn_hibe::*` unchanged.
//!
//! What the surface provides:
//! - [`Identity`]: identity paths and the pinned label→scalar mapping
//!   (`I_i = SHA-256(label) mod p`).
//! - [`setup`] / [`keygen`] / [`delegate`]: authority and delegation.
//! - [`kem_wrap`] / [`kem_unwrap`]: the CEK KEM. KEM-not-direct: the wire
//!   format is canonical AES-256-GCM output plus compressed group points —
//!   a raw GT element never leaves the process.
//! - [`seal`] / [`seal_with_aad`] / [`open`] / [`open_with_aad`]: the full
//!   group-ciphertext blob (with optional AAD marker binding).
//! - Canonical byte encodings for [`PublicParams`], [`MasterKey`],
//!   [`PrivateKey`] and [`mpk_fingerprint`].
//!
//! Direct BBG encryption over GT, [`Ciphertext`], and GT byte codecs live under
//! [`raw`] for golden-vector fixtures and advanced interop checks.
//!
//! # Security status
//!
//! `bls12_381_plus` and the `tn_bbg` scheme code are unaudited; external
//! review is required before production use. BBG delegated keys are
//! permanent: there is no forward revocation of an admitted reader — groups
//! that need that use btn.

pub use tn_bbg::{
    delegate, kem_unwrap, kem_wrap, keygen, mpk_fingerprint, open, open_with_aad, seal,
    seal_with_aad, setup, Identity, MasterKey, PrivateKey, PublicParams, WRAPPED_CEK_LEN,
};

/// The scheme error type. Re-exported from [`tn_bbg`] under the historical
/// `HibeError` name so existing `tn_hibe::HibeError` consumers are unchanged.
pub use tn_bbg::BbgError as HibeError;

/// Raw BBG primitives over GT.
///
/// The normal HIBE wire surface is [`kem_wrap`]/[`kem_unwrap`] and
/// [`seal`]/[`open`]. Direct GT encryption and GT byte codecs are kept here
/// for golden-vector fixtures and advanced interop checks.
pub mod raw {
    pub use tn_bbg::raw::{decrypt, encrypt, gt_from_bytes, gt_to_bytes, Ciphertext};
}
