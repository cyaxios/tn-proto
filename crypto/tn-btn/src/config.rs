//! Runtime configuration.
//!
//! v0.1 hard-codes tree height at 10 (1024 leaves). This keeps per-user
//! storage under 2 KB without Asano layered optimization, lets the
//! compiler potentially unroll tree walks, and makes every unit test
//! exhaustively verifiable. The hardcode will be lifted in a later
//! version; the wire format already accommodates variable heights, so
//! only the configuration layer changes.

use crate::error::{Error, Result};

/// Fixed tree height for v0.1.
///
/// 2^8 = 256 leaves. Per-user storage (naive NNL-SD) is
/// h(h+1)/2 = 36 path keys × 32 bytes = 1152 bytes, plus overhead —
/// reader kit wire size around 1.9 KB. Publisher-side cache is 255
/// internal nodes × 32 bytes = ~8 KB, trivial. The 256-leaf cap
/// covers realistic broadcast groups; deployments past that roll a
/// new ceremony (rotate the master seed).
pub const TREE_HEIGHT: u8 = 8;

/// Maximum number of leaves (2^TREE_HEIGHT).
pub const MAX_LEAVES: u64 = 1u64 << TREE_HEIGHT;

/// Per-user path-keys count (naive NNL-SD): h(h+1)/2.
/// Exposed for tests and callers sizing buffers.
pub const PATH_KEYS_PER_READER: usize = (TREE_HEIGHT as usize) * (TREE_HEIGHT as usize + 1) / 2;

/// Configuration for a `PublisherState`.
///
/// v0.1 has no runtime-tunable fields — the tree height is fixed and
/// the AEAD / PRG choices are fixed. The struct is reserved for
/// forward compatibility so callers' code continues to compile when
/// real options get added later.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Config;

impl Config {
    /// Validate the configuration. In v0.1 this always succeeds; it
    /// exists so callers' code is ready when real options get added.
    ///
    /// # Errors
    /// In v0.1, never. The return type is reserved for forward
    /// compatibility; it will return [`Error::InvalidConfig`] once
    /// runtime-tunable fields are re-introduced.
    #[inline]
    pub fn validate(self) -> Result<()> {
        let _unused: Error; // keep the error import live for the future
        Ok(())
    }

    /// Tree height. Always equal to [`TREE_HEIGHT`] in v0.1.
    #[inline]
    pub fn tree_height(self) -> u8 {
        TREE_HEIGHT
    }

    /// Maximum number of leaves. Always equal to [`MAX_LEAVES`] in v0.1.
    #[inline]
    pub fn max_leaves(self) -> u64 {
        MAX_LEAVES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_height_is_eight() {
        assert_eq!(TREE_HEIGHT, 8);
        assert_eq!(MAX_LEAVES, 256);
        assert_eq!(Config.tree_height(), 8);
        assert_eq!(Config.max_leaves(), 256);
        assert_eq!(PATH_KEYS_PER_READER, 36);
    }

    #[test]
    fn validate_always_ok_in_v0_1() {
        assert!(Config.validate().is_ok());
    }
}
