//! Key derivation tree (KDT).
//!
//! Every node in the conceptual binary tree has a 32-byte **node key**.
//! The root's key is derived from the ceremony's master seed. For each
//! node, its two children's keys and its own self-label key are derived
//! from its key via the triple-PRG (see [`crate::crypto::prg`]).
//!
//! Key property: knowing a node's key lets you compute the keys of every
//! descendant and the node's own self-label. Knowing a node's key tells
//! you **nothing** about ancestors, siblings, or their self-labels — the
//! triple-PRG is one-way.
//!
//! This module is pure derivation. It does not store any keys; callers
//! derive on demand. The publisher's `master_seed` is the only persistent
//! secret on the publisher side.

use crate::crypto::prg::{triple_prg, Triple, KEY_LEN};
use crate::tree::NodePos;
use zeroize::Zeroizing;

/// A 32-byte node key. Always zeroized on drop.
pub type NodeKey = Zeroizing<[u8; KEY_LEN]>;

/// Info tag used when deriving the root key from the master seed.
///
/// Deriving the root via HKDF rather than using `master_seed` directly
/// lets us domain-separate "root key" from other uses of the same seed
/// (future rotation, epoch derivation, etc. — all gated by distinct
/// info labels).
const INFO_ROOT: &[u8] = b"btn.v1.root";

/// Derive the root node key from a master seed.
///
/// Uses HKDF-SHA256 with a fixed salt (None) and info `b"btn.v1.root"`.
///
/// # Panics
/// Cannot panic for any valid input; the underlying HKDF expansion is
/// only fallible for output lengths greater than `255 * HashLen`.
#[inline]
pub fn root_key(master_seed: &[u8; KEY_LEN]) -> NodeKey {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut out = [0u8; KEY_LEN];
    hk.expand(INFO_ROOT, &mut out)
        .expect("hkdf expand root: unreachable");
    Zeroizing::new(out)
}

/// Derive the key of an arbitrary node by walking from the root.
///
/// This allocates no extra state: each step overwrites the running key.
/// Cost is `O(depth)` HKDF calls.
///
/// # Panics
/// Does not panic. All index arithmetic is u64, depth fits in u8.
#[inline]
pub fn node_key(master_seed: &[u8; KEY_LEN], node: NodePos) -> NodeKey {
    let mut current = root_key(master_seed);
    // Walk from the root down to `node`, at each step choosing left or
    // right based on the appropriate bit of `node.index`.
    //
    // At depth `d`, the bit to consume is bit number `(node.depth - 1 - d)`
    // of `node.index`. Top-most bit first.
    for step in 0..node.depth {
        let bit_pos = node.depth - 1 - step;
        let go_right = (node.index >> bit_pos) & 1 == 1;
        let t: Triple = triple_prg(&current);
        let next = if go_right { t.right } else { t.left };
        current = Zeroizing::new(next);
    }
    current
}

/// Derive the self-label key ("mid" in the triple) for a node.
///
/// The mid key is what gets used as the KEK for the subset-difference
/// subsets whose *inner* ancestor is this node. See the NNL paper §4 for
/// the full derivation in context.
///
/// Implementation: compute the node's key, then expand its triple and
/// keep only the `mid` output.
#[inline]
pub fn node_label(master_seed: &[u8; KEY_LEN], node: NodePos) -> NodeKey {
    let nk = node_key(master_seed, node);
    let t = triple_prg(&nk);
    Zeroizing::new(t.mid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    #[test]
    fn root_key_deterministic() {
        let s = seed(3);
        let a = root_key(&s);
        let b = root_key(&s);
        assert_eq!(*a, *b);
    }

    #[test]
    fn root_differs_from_master_seed() {
        // The root key is derived, not equal to, the seed. This prevents
        // leaking the seed through any surface that exposes the root key.
        let s = seed(9);
        let r = root_key(&s);
        assert_ne!(*r, s);
    }

    #[test]
    fn different_seeds_different_roots() {
        assert_ne!(*root_key(&seed(1)), *root_key(&seed(2)));
    }

    #[test]
    fn node_key_of_root_matches_root_key() {
        let s = seed(5);
        assert_eq!(*node_key(&s, NodePos::ROOT), *root_key(&s));
    }

    #[test]
    fn node_key_path_consistency() {
        // Deriving the left child by walking from root should match
        // deriving it directly.
        let s = seed(11);
        let root_k = root_key(&s);
        let t = triple_prg(&root_k);

        let left_direct = t.left;
        let left_via_node_key = node_key(&s, NodePos { depth: 1, index: 0 });
        assert_eq!(*left_via_node_key, left_direct);

        let right_direct = t.right;
        let right_via_node_key = node_key(&s, NodePos { depth: 1, index: 1 });
        assert_eq!(*right_via_node_key, right_direct);
    }

    #[test]
    fn node_key_two_steps_deep() {
        // Derive (depth=2, index=0b10) = right-then-left from root.
        let s = seed(13);
        let root_k = root_key(&s);
        let t1 = triple_prg(&root_k);
        // Go right first: take t1.right as the depth-1 node at index 1.
        let t2 = triple_prg(&t1.right);
        let expected_left_of_right = t2.left; // depth-2, index = 0b10 = 2

        let got = node_key(
            &s,
            NodePos {
                depth: 2,
                index: 0b10,
            },
        );
        assert_eq!(*got, expected_left_of_right);
    }

    #[test]
    fn siblings_have_independent_keys() {
        let s = seed(17);
        let left = node_key(
            &s,
            NodePos {
                depth: 4,
                index: 0b0000,
            },
        );
        let right = node_key(
            &s,
            NodePos {
                depth: 4,
                index: 0b0001,
            },
        );
        assert_ne!(*left, *right);
    }

    #[test]
    fn deep_leaf_derivation_stable() {
        // Derive a deep leaf twice; must agree.
        let s = seed(23);
        let leaf = NodePos {
            depth: 30,
            index: 0xDEAD_BEEF,
        };
        let a = node_key(&s, leaf);
        let b = node_key(&s, leaf);
        assert_eq!(*a, *b);
    }

    #[test]
    fn node_label_differs_from_node_key() {
        // The mid/label value must differ from the node key. If they
        // were equal, a holder of the node's key could pass it off as a
        // subset-label key without the triple application — which would
        // break the intended separation.
        let s = seed(29);
        let n = NodePos { depth: 3, index: 5 };
        let nk = node_key(&s, n);
        let nl = node_label(&s, n);
        assert_ne!(*nk, *nl);
    }

    #[test]
    fn node_label_of_root_is_root_triple_mid() {
        let s = seed(31);
        let root_k = root_key(&s);
        let t = triple_prg(&root_k);
        let got = node_label(&s, NodePos::ROOT);
        assert_eq!(*got, t.mid);
    }
}
