//! # tn-core — TN protocol Rust runtime
//!
//! Re-implements the TN Python hot path with byte-for-byte wire
//! compatibility. tn-core is the shared substrate the language SDKs wrap
//! (Python via PyO3, TS/browser via WASM); the user-facing surface is the
//! `tn.*` SDK verbs and the `tn` CLI, which call into the types below.
//!
//! ## Where to start (primary interfaces)
//!
//! Reach for these; most other modules are internal primitives these
//! compose.
//!
//! - [`Runtime`] — the front door: open a ceremony, write
//!   attested events (the write family, behind `tn.info()` / `tn log`),
//!   read them back (behind `tn.read()` / `tn read`), and run admin verbs
//!   (behind `tn.admin.*` / `tn rotate`). Configured by
//!   [`RuntimeInitOptions`]; reads yield [`ReadEntry`] / [`SecureEntry`] /
//!   [`FlatEntry`]; admin state is [`AdminState`].
//! - [`Manifest`] / [`ManifestKind`] — the `.tnpkg` package manifest
//!   (canonical bytes, sign/verify, kind catalog), behind `tn export` /
//!   `tn absorb`; see [`ExportOptions`] and [`AbsorbReceipt`].
//! - [`DeviceKey`] — the Ed25519 device identity (`did:key:z…`), behind
//!   `tn init`.
//! - [`Error`] / [`Result`] — the error taxonomy every fallible API returns.
//! - Pluggable extension points (traits): the [`cipher`], [`handlers`], and
//!   [`storage`] modules.
//!
//! Everything else (canonical bytes, chain hashing, indexing, envelope
//! assembly, log files, and so on) is an internal primitive. If you find
//! yourself reaching for one directly, first check whether [`Runtime`]
//! already does what you need.
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
pub mod indexing;
pub mod panic_guard;
pub mod path_template;
pub(crate) mod pathutil;
pub mod perf;
pub mod sealed_object;
pub mod signing;
pub mod storage;
pub mod tnpkg;
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
pub use unsafe_operation::{UnsafeOperation, UnsafeOperationNotice, UnsafeRelaxation};
