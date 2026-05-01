//! # tn-core — TN protocol Rust runtime
//!
//! Re-implements the TN Python hot path with byte-for-byte wire compatibility.
//!
//! ## Feature flags
//!
//! - `fs` (default): enables filesystem-backed modules — `log_file`, `identity`,
//!   `FsStorage`, and the `Runtime` struct that composes them. Also builds the
//!   `tn-core-cli` binary.
//! - Without `fs`: only pure-compute modules compile — `canonical`, `chain`,
//!   `indexing`, `signing`, `envelope`, `cipher`, `config`, `classifier`.
//!   Useful for `wasm32-unknown-unknown` targets (browser / TS wrappers), which
//!   will provide their own storage-equivalent via the `Storage` trait.
//! - `bgw`: enables the (stubbed) BGW cipher FFI wrapper.
//!
//! See `docs/superpowers/specs/2026-04-21-tn-rust-core-rfc.md` for architecture.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
// Library code must not use `.unwrap()` — every fallible operation either
// returns a Result (via `?`) or uses `.expect("<documented invariant>")`.
// `cfg_attr(not(test))` keeps test modules (which freely use `.unwrap()`)
// out of scope.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod admin_catalog;
pub mod admin_reduce;
pub mod agents_policy;
pub mod canonical;
pub mod chain;
pub mod cipher;
pub mod classifier;
pub mod config;
pub mod envelope;
pub mod error;
pub mod indexing;
pub mod signing;
pub mod storage;
pub mod tnpkg;

#[cfg(feature = "fs")]
pub mod admin_cache;
#[cfg(feature = "fs")]
pub mod handlers;
#[cfg(feature = "fs")]
pub mod identity;
#[cfg(feature = "fs")]
pub mod log_file;
#[cfg(feature = "fs")]
pub mod read_as_recipient;
#[cfg(feature = "fs")]
pub mod runtime;
#[cfg(feature = "fs")]
pub mod runtime_export;

pub use error::{Error, Result};
pub use signing::DeviceKey;

#[cfg(feature = "fs")]
pub use admin_cache::{AdminStateCache, ChainConflict, LKV_VERSION};
#[cfg(feature = "fs")]
pub use runtime::{
    AdminCeremony, AdminCoupon, AdminEnrolment, AdminGroupRecord, AdminRecipientRecord,
    AdminRotation, AdminState, AdminVaultLink, FlatEntry, Instructions, OnInvalid,
    ReadEntry, RecipientEntry, Runtime, SecureEntry, SecureReadOptions, ValidFlags,
};
#[cfg(feature = "fs")]
pub use runtime_export::{AbsorbReceipt, AbsorbSource, ExportOptions};
pub use tnpkg::{Manifest, ManifestKind, VectorClock};
