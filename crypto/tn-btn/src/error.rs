//! Error types.
//!
//! Every error here names the exact location, the specific problem, and
//! the next step. The audience is a novice programmer or an LLM agent
//! reading the error in a stack trace.

use thiserror::Error;

/// Crate-level `Result` alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by public `btn` operations.
#[derive(Debug, Error)]
pub enum Error {
    /// The configuration is outside supported ranges (height too large,
    /// zero, or similar). The message names the exact field and the
    /// valid range.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The publisher's tree is full and cannot mint another reader kit.
    /// The error message includes the current tree height and issued
    /// count, and tells the caller how to grow capacity.
    #[error(
        "tree exhausted: all {issued} leaves of a height-{tree_height} tree have \
         been issued. In v0.1 the tree height is hard-coded — raising the \
         cap requires changing TREE_HEIGHT and rebuilding. Or rotate the \
         epoch to start a fresh tree."
    )]
    TreeExhausted {
        /// Current tree height.
        tree_height: u8,
        /// Number of leaves already issued.
        issued: usize,
    },

    /// A reader kit or ciphertext has been tampered with, corrupted, or
    /// originates from an incompatible library version.
    #[error("malformed {kind} wire data: {reason}")]
    Malformed {
        /// Which wire type failed to parse (e.g. `"reader_kit"`, `"ciphertext"`).
        kind: &'static str,
        /// Human-readable reason the parse failed.
        reason: String,
    },

    /// Decryption failed because the reader kit is not entitled to this
    /// ciphertext. Either the reader was never minted, or was revoked
    /// before the ciphertext was written, or the ciphertext is from a
    /// different publisher / epoch.
    #[error(
        "reader kit is not entitled to decrypt this ciphertext. Possible causes: \
         (a) the reader was revoked before this ciphertext was produced; \
         (b) the ciphertext was produced by a different publisher \
         (check publisher_id match); \
         (c) the ciphertext was produced in a different epoch than the kit."
    )]
    NotEntitled,

    /// An internal invariant was violated. These should not happen in
    /// correct usage; if you see one, please file a bug with the steps
    /// that produced it.
    #[error("internal invariant violated: {0}")]
    Internal(String),
}
