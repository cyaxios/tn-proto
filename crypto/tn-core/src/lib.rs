//! # TN governed data protocol
//!
//! TN carries encrypted data and its use contract in one signed envelope.
//! The Rust core owns policy selection, group encryption, governance AAD,
//! row hashing, signing, verification, selected opening, and derivation.
//!
//! Start with [`governed`]: supply a [`DeviceKey`], group cipher material,
//! and a contract; receive a verified object ready for transport or retention.
//! The reader exposes governance before application admission and selected
//! business plaintext. Derivation binds a fresh object to its signed source.
//!
//! With `fs`, [`runtime::Objects`] loads configured object material directly.
//! [`Runtime`] supports event streams, administration, and packages; its
//! [`Runtime::objects`] method shares that runtime's groups with the governed
//! interface. Python and TypeScript use this same protocol substrate.
//!
//! ## Feature flags
//!
//! - Without `fs`: the governed object API and protocol primitives operate
//!   directly on supplied identity and cipher material.
//! - `fs` (default): configured objects, filesystem storage, event runtime,
//!   administration, and the `tn-core-cli` binary.
//! - `fs-locking` (default): advisory locking for native filesystem operations.
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
pub mod body_encryption;
pub mod canonical;
pub mod chain;
pub mod cipher;
pub mod classifier;
pub mod config;
pub mod envelope;
pub mod error;
pub mod governed;
pub mod indexing;
pub mod panic_guard;
pub mod path_template;
pub(crate) mod pathutil;
pub mod perf;
pub mod sealed_object;
pub mod signing;
pub mod storage;
pub mod tnpkg;
pub mod trust;
pub mod trusted_enrollment;
pub mod unsafe_operation;

#[cfg(feature = "fs")]
pub mod admin_cache;
#[cfg(feature = "fs")]
pub mod handlers;
#[cfg(feature = "fs")]
pub mod identity;
#[cfg(feature = "fs")]
pub mod keystore_backend;
#[cfg(feature = "fs")]
pub mod log_file;
#[cfg(feature = "fs")]
pub mod read_as_recipient;
#[cfg(feature = "fs")]
mod recipient_seal;
#[cfg(feature = "fs")]
pub mod runtime;
#[cfg(feature = "fs")]
pub mod runtime_export;

pub use error::{Error, Result};
pub use panic_guard::catch_panic;
pub use sealed_object::{GroupBlock, SealedObjectLine, SealedValid};
pub use signing::DeviceKey;

#[cfg(feature = "fs")]
pub use admin_cache::{AdminStateCache, ChainConflict, LKV_VERSION};
#[cfg(feature = "fs")]
pub use runtime::{
    unseal_as_recipient, AdminCeremony, AdminCoupon, AdminEnrolment, AdminGroupRecord,
    AdminRecipientRecord, AdminRotation, AdminState, AdminVaultLink, EnsureGroupResult, FlatEntry,
    GrantReaderResult, Instructions, OnInvalid, ReadEntry, RecipientEntry, RotateIdPathResult,
    Runtime, RuntimeInitOptions, SealOptions, SealedGroupInfo, SecureEntry, SecureReadOptions,
    UnsealOptions, UnsealOutcome, ValidFlags,
};
#[cfg(feature = "fs")]
pub use runtime_export::{AbsorbReceipt, AbsorbSource, ExportOptions};
pub use tnpkg::{Manifest, ManifestKind, VectorClock};
pub use trust::{AcceptedOffer, TrustError, TrustReason, VerifiedJweBinding, VerifiedPrincipal};
pub use unsafe_operation::{UnsafeOperation, UnsafeOperationNotice, UnsafeRelaxation};
