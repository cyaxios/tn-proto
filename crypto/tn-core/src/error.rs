//! Public error taxonomy.
//!
//! [`enum@Error`] is the single error type returned across the tn-core public
//! API — the [`crate::Runtime`] admin/emit/read verbs, [`crate::Manifest`]
//! parse/verify, and cipher/config loading all surface it — and [`Result`]
//! is the crate-wide `Result<T, Error>` alias they return. These map up to
//! the user-facing `tn.*` SDK verbs and the `tn` CLI: an error a user sees
//! (say a keystore conflict on `tn rotate`) is one of these variants
//! crossing the language boundary.
//!
//! Most variants are terminal. The one routinely worth catching is
//! [`Error::KeystoreConflict`] — recoverable by re-reading state and
//! retrying the admin verb:
//!
//! ```
//! use tn_core::Error;
//!
//! fn rotate_group() -> Result<(), Error> {
//!     // An admin verb that lost a compare-and-swap race on the keystore.
//!     Err(Error::KeystoreConflict { group: "default".into() })
//! }
//!
//! match rotate_group() {
//!     Ok(()) => {}
//!     Err(Error::KeystoreConflict { group }) => {
//!         // Stale in-memory state: re-read the keystore for `group`,
//!         // re-apply, and retry. Surfaced to users on `tn rotate` /
//!         // `tn.admin.rotate(...)`.
//!         assert_eq!(group, "default");
//!     }
//!     Err(_) => panic!("unexpected error variant"),
//! }
//! ```

use std::path::PathBuf;

use thiserror::Error;

/// The crate-wide result type: `Result<T, Error>`.
///
/// Returned by every fallible tn-core API so callers can `?`-propagate
/// against a single error type. See [`enum@Error`] for the variant taxonomy.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors produced by tn-core.
///
/// Returned (via [`Result`]) across the crate's public API — the
/// [`crate::Runtime`] admin/emit/read verbs, [`crate::Manifest`]
/// parse/verify, and cipher/config loading. Variants are grouped by
/// failure domain and each documents when it fires. The only routinely
/// recoverable variant is [`Error::KeystoreConflict`] (re-read state and
/// retry) — see the module docs for the pattern.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration value is missing or invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Incoming data is structurally malformed.
    #[error("malformed {kind} data: {reason}")]
    Malformed {
        /// What kind of data (e.g. "envelope", "row_hash").
        kind: &'static str,
        /// Human-readable reason.
        reason: String,
    },

    /// Caller lacks a CEK for this group.
    #[error("not entitled to decrypt this envelope for group {group:?}")]
    NotEntitled {
        /// Group name.
        group: String,
    },

    /// Caller is not a publisher for this group.
    #[error("not a publisher for group {group:?}: {reason}")]
    NotAPublisher {
        /// Group name.
        group: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse or serialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML parse or serialization failure.
    #[error("YAML error: {0}")]
    Yaml(String),

    /// `${VAR}` referenced in a yaml config but the env var is unset
    /// and no `${VAR:-default}` fallback was provided.
    #[error("{path}:{line}: required environment variable ${{{var}}} is not set (use ${{{var}:-default}} to provide a fallback)")]
    ConfigEnvVarMissing {
        /// Variable name that was missing.
        var: String,
        /// Source path of the yaml file.
        path: PathBuf,
        /// Line number (1-indexed) where the reference appears.
        line: usize,
    },

    /// A `${...}` token in a yaml config could not be parsed as a valid
    /// `${NAME}` or `${NAME:-default}` reference.
    #[error("{path}:{line}: malformed env-var reference {token:?} (expected ${{NAME}} or ${{NAME:-default}} where NAME matches [A-Za-z_][A-Za-z0-9_]*)")]
    ConfigEnvVarMalformed {
        /// The offending substring.
        token: String,
        /// Source path of the yaml file.
        path: PathBuf,
        /// Line number (1-indexed).
        line: usize,
    },

    /// Cipher operation failure.
    #[error("cipher error: {0}")]
    Cipher(String),

    /// Error propagated from the tn-btn crate.
    #[error("btn error: {0}")]
    Btn(#[from] tn_btn::Error),

    /// Feature exists in the plan but is not yet implemented.
    #[error("feature not implemented: {0}")]
    NotImplemented(&'static str),

    /// An internal invariant was violated (should never happen in correct code).
    #[error("internal invariant violated: {0}")]
    Internal(String),

    /// User yaml declared a group whose name starts with `tn.` other than
    /// the auto-injected `tn.agents`. The `tn.*` namespace is reserved
    /// for protocol-level conventions per the 2026-04-25 read-ergonomics
    /// spec §2.2.
    #[error("group name {name:?} is reserved (the `tn.*` namespace is for protocol-level conventions; only `tn.agents` is allowed). Rename your group.")]
    ReservedGroupName {
        /// The offending group name.
        name: String,
    },

    /// Publisher state file on disk has diverged from the caller's
    /// `prior` snapshot. Another writer (process or thread) committed
    /// a state mutation between the caller's read and the caller's
    /// CAS write attempt. The caller's in-memory state is stale; a
    /// re-read + re-apply + retry is required.
    ///
    /// Raised by `keystore_backend::LocalKeystore::write_state` and
    /// surfaced on the runtime admin verbs so the operator sees a
    /// recoverable, named failure rather than silent data loss.
    #[error(
        "keystore state for group {group:?} has diverged on disk; re-read and retry the admin verb"
    )]
    KeystoreConflict {
        /// Group whose state file diverged.
        group: String,
    },
}

impl From<serde_yml::Error> for Error {
    fn from(e: serde_yml::Error) -> Self {
        Error::Yaml(e.to_string())
    }
}

#[cfg(feature = "fs")]
impl From<crate::keystore_backend::KeystoreError> for Error {
    /// Bridge the keystore module's local error type onto the public
    /// `Error` enum so admin verbs can use `?` against
    /// `LocalKeystore::write_state(...)` without losing the
    /// conflict-vs-io distinction.
    fn from(e: crate::keystore_backend::KeystoreError) -> Self {
        match e {
            crate::keystore_backend::KeystoreError::Conflict { group } => {
                Error::KeystoreConflict { group }
            }
            crate::keystore_backend::KeystoreError::Io(io) => Error::Io(io),
        }
    }
}
