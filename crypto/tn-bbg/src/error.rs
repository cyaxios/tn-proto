//! Error type. Mirrors `tn_hibe::HibeError` variant-for-variant so the
//! eventual swap behind tn-hibe is mechanical.

use thiserror::Error;

pub type Result<T> = core::result::Result<T, BbgError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BbgError {
    #[error("max_depth must be in 1..=255, got {0}")]
    BadMaxDepth(usize),

    #[error("identity is deeper than the system max_depth")]
    IdentityTooDeep,

    #[error("malformed {0} encoding")]
    Malformed(&'static str),

    #[error("KEM unwrap failed (wrong-path key or tampered ciphertext)")]
    Unwrap,
}
