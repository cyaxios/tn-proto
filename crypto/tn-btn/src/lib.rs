//! # `btn` — Broadcast-Transaction Encryption
//!
//! NNL subset-difference broadcast encryption with selective revocation.
//!
//! ## Status
//!
//! Pre-1.0. The six-verb API (`setup`, `mint`, `revoke`, `encrypt`,
//! `decrypt`, `issued_count`/`revoked_count`) is implemented and
//! covered by integration tests. API shape may still change across
//! minor versions until 1.0.
//!
//! ## v0.1 constraints
//!
//! - **Tree height is hard-coded at 8** (256 leaves) — see
//!   [`config::TREE_HEIGHT`]. This simplifies v0.1 by keeping per-user
//!   storage around ~1.9 KB without Asano layered optimization. The
//!   hardcode is a configuration choice, not a wire-format limit;
//!   bumping it is a matter of changing a constant and re-running
//!   tests.
//!
//! ## Layout
//!
//! - [`tree`] — complete-binary-tree math: leaf/node indexing, LCA, paths.
//! - [`tree::kdt`] — key derivation tree: root key, node keys, self-labels.
//! - [`tree::cover`] — NNL subset-difference cover algorithm.
//! - [`crypto::prg`] — triple-PRG over HKDF-SHA256, the KDT's primitive.
//! - [`config`] — configuration struct + validation.
//! - [`error`] — public `Error` enum with friendly diagnostic messages.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
// Library code must not use `.unwrap()` — every fallible operation either
// returns a Result (via `?`) or uses `.expect("<documented invariant>")`.
// The `cfg_attr(not(test))` scope keeps the deny active for the production
// lib build but lets `#[cfg(test)] mod tests` blocks (and inline tests in
// example files) keep using `.unwrap()` for brevity.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod ciphertext;
pub mod config;
pub mod crypto;
pub mod error;
pub mod publisher;
pub mod reader;
pub mod rotate;
pub mod tree;
pub mod wire;

pub use ciphertext::{
    decrypt_with_keyset, decrypt_with_keyset_with_aad, encrypt_to_cover,
    encrypt_to_cover_with_aad, Ciphertext, CoverEntry,
};
pub use config::Config;
pub use error::{Error, Result};
pub use publisher::PublisherState;
pub use reader::ReaderKit;
pub use rotate::{RetiredPublisherState, RotationOutcome};
pub use tree::subset::{materialize_reader_keyset, subset_key, ReaderKeyset};
pub use tree::{LeafIndex, NodePos};
