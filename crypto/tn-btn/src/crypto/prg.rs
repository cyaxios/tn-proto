//! Pseudorandom generators used by the key derivation tree.
//!
//! The KDT relies on a **triple-PRG**: given one 32-byte input key, it
//! produces three independent 32-byte outputs. These serve as the left-
//! child key, right-child key, and self-label key in the tree.
//!
//! Security property required: knowing any one output must not let an
//! adversary compute either of the other two (or the input). This is
//! guaranteed by HKDF-SHA256 with three distinct `info` strings under
//! the standard KDF security model.

use hkdf::Hkdf;
use sha2::Sha256;

/// Key size in bytes (256 bits). This is the unit everywhere in `btn`.
pub const KEY_LEN: usize = 32;

/// Info label for the left-child derivation.
const INFO_LEFT: &[u8] = b"btn.v1.kdt.L";
/// Info label for the right-child derivation.
const INFO_RIGHT: &[u8] = b"btn.v1.kdt.R";
/// Info label for the self-label derivation (used in subset-difference key assignment).
const INFO_MID: &[u8] = b"btn.v1.kdt.M";

/// Triple-PRG output: `(left, right, mid)`.
///
/// Each component is 32 bytes. They are computationally independent
/// assuming HKDF-SHA256 is a secure KDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triple {
    /// Left child key — used as the key of the left subtree's root.
    pub left: [u8; KEY_LEN],
    /// Right child key — used as the key of the right subtree's root.
    pub right: [u8; KEY_LEN],
    /// Self-label key — used as the KEK for subsets rooted at this node.
    pub mid: [u8; KEY_LEN],
}

/// Apply the triple-PRG to a key.
///
/// Internally uses HKDF-SHA256 with a fixed zero salt (per RFC 5869
/// §3.1 this is safe when the input key already has full entropy, which
/// it does everywhere in the KDT). Three expansions with distinct info
/// strings produce the three outputs.
///
/// # Panics
/// Cannot panic for any valid input. The underlying `hkdf::Hkdf::expand`
/// only fails for output lengths greater than `255 * HashLen`; we request
/// exactly 32 bytes.
#[inline]
pub fn triple_prg(key: &[u8; KEY_LEN]) -> Triple {
    // HKDF with Salt::None uses an all-zero salt of the hash-block size.
    // Extract is a no-op for our purposes since the input key is already
    // full-entropy; we're effectively using Expand in all three calls.
    let hk = Hkdf::<Sha256>::new(None, key);

    let mut left = [0u8; KEY_LEN];
    let mut right = [0u8; KEY_LEN];
    let mut mid = [0u8; KEY_LEN];

    // `expect` here is unreachable: the only failure path for expand is
    // an output length > 255 * HashLen, and we always ask for 32 bytes.
    hk.expand(INFO_LEFT, &mut left)
        .expect("hkdf expand left: unreachable");
    hk.expand(INFO_RIGHT, &mut right)
        .expect("hkdf expand right: unreachable");
    hk.expand(INFO_MID, &mut mid)
        .expect("hkdf expand mid: unreachable");

    Triple { left, right, mid }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_is_deterministic() {
        let key = [7u8; KEY_LEN];
        let a = triple_prg(&key);
        let b = triple_prg(&key);
        assert_eq!(a, b);
    }

    #[test]
    fn triple_outputs_are_distinct() {
        // For a random key, the three outputs must differ from each other
        // and from the input key. Collisions would indicate a copy-paste
        // bug in the info strings.
        let key = [42u8; KEY_LEN];
        let t = triple_prg(&key);
        assert_ne!(t.left, t.right);
        assert_ne!(t.left, t.mid);
        assert_ne!(t.right, t.mid);
        assert_ne!(t.left, key);
        assert_ne!(t.right, key);
        assert_ne!(t.mid, key);
    }

    #[test]
    fn different_keys_produce_different_triples() {
        let t1 = triple_prg(&[1u8; KEY_LEN]);
        let t2 = triple_prg(&[2u8; KEY_LEN]);
        assert_ne!(t1, t2);
    }

    #[test]
    fn triple_outputs_are_stable_within_process() {
        // Regression anchor: two calls with the same input within one
        // process must agree. Cross-implementation test vectors (pinned
        // hex outputs for documented inputs) live in
        // `tests/test_vectors.rs` once independently computed, per the
        // design spec §15. They are deliberately NOT generated from this
        // library's own output — doing so would defeat the point.
        let key = [0u8; KEY_LEN];
        let a = triple_prg(&key);
        let b = triple_prg(&key);
        assert_eq!(a, b);
    }
}
