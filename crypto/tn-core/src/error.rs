//! Public error taxonomy.

use std::path::PathBuf;

use thiserror::Error;

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors produced by tn-core.
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
}

impl From<serde_yml::Error> for Error {
    fn from(e: serde_yml::Error) -> Self {
        Error::Yaml(e.to_string())
    }
}
