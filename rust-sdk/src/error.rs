//! SDK-wide error and result types.
//!
//! The Rust SDK keeps protocol errors in `tn-core` and uses this module for
//! ergonomic boundary errors that belong to the public SDK surface.

/// SDK-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for the public Rust SDK.
///
/// Most protocol and filesystem failures come from `tn-core`; this wrapper
/// leaves room for SDK-specific validation errors as the ergonomic surface
/// grows.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error returned by the underlying `tn-core` runtime.
    ///
    /// `tn_core::Error::SealedObjectVerify` is deliberately never wrapped
    /// here — the hand-written `From<tn_core::Error>` impl below routes it
    /// to [`Error::Verify`] instead, so callers can match a failed
    /// `Tn::unseal` check without reaching into `tn_core`. Every other
    /// `tn_core::Error` variant wraps as-is.
    #[error(transparent)]
    Core(tn_core::Error),

    /// Filesystem error surfaced by SDK-level helpers.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// YAML parse or render error surfaced by SDK-level config helpers.
    #[error(transparent)]
    Yaml(#[from] serde_yml::Error),

    /// JSON parse or render error surfaced by SDK-level helpers.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Zip archive error surfaced by invitation inbox helpers.
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),

    /// HTTP transport error surfaced by optional SDK HTTP clients.
    #[cfg(feature = "http")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// Native file watcher error surfaced by optional watch APIs.
    #[cfg(feature = "watch")]
    #[error(transparent)]
    Notify(#[from] notify::Error),

    /// Vault HTTP response or protocol error.
    #[error("vault http error: {0}")]
    VaultHttp(String),

    /// Invalid input caught at the SDK boundary before calling `tn-core`.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// A sealed object failed verification on [`crate::Tn::unseal`] with
    /// `options.verify` set (the default). First-class rust-sdk mirror of
    /// `tn_core::Error::SealedObjectVerify`; `failed_checks` values are
    /// `"signature"` / `"row_hash"`.
    ///
    /// Malformed unseal input is [`Error::Core`] (wrapping
    /// `tn_core::Error::Malformed`) instead, and holding no key that fits
    /// any block is not an error at all — see [`crate::Tn::unseal`].
    #[error("entry seq={sequence} event={event_type:?} failed: {}", failed_checks.join(", "))]
    Verify {
        /// Which integrity checks failed (`"signature"` / `"row_hash"`).
        failed_checks: Vec<String>,
        /// The envelope's `sequence` (always 0 for sealed objects).
        sequence: u64,
        /// The envelope's `event_type`.
        event_type: String,
    },
}

impl From<tn_core::Error> for Error {
    /// Route `tn_core::Error::SealedObjectVerify` to the first-class
    /// [`Error::Verify`] variant; every other `tn_core::Error` wraps as
    /// [`Error::Core`]. Hand-written (instead of `#[from]`) so this `?`
    /// conversion can special-case the one variant rust-sdk promotes.
    fn from(err: tn_core::Error) -> Self {
        match err {
            tn_core::Error::SealedObjectVerify {
                failed_checks,
                sequence,
                event_type,
            } => Error::Verify {
                failed_checks,
                sequence,
                event_type,
            },
            other => Error::Core(other),
        }
    }
}
