//! Cryptographic primitives used by `btn`.
//!
//! All primitives here are textbook: HKDF-SHA256 for key derivation,
//! AES-GCM for authenticated encryption, AES-KW for key wrapping.
//! Nothing novel. Every choice is justified in the design spec.

pub mod aead;
pub mod kw;
pub mod prg;
