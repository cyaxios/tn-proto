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
    #[error(transparent)]
    Core(#[from] tn_core::Error),

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
}
