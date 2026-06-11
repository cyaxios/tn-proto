//! Subset-difference key derivation and per-reader key materialization.
//!
//! In Naor-Naor-Lotspiech §4 Subset-Difference, every node `v` has its
//! own dedicated *sub-label scheme* rooted at `v`. Notation: `L_v(w)`
//! is the sub-label at node `w` within `v`'s sub-scheme. The subset key
//! for `S(v_i, v_j)` is `K(v_i, v_j) = G_M(L_{v_i}(v_j))`, where
//! `G_M` is the mid output of the triple-PRG.
//!
//! The sub-label tree rooted at `v_i` works identically to the primary
//! label tree (triple-PRG applied node-by-node), but with a different
//! starting seed. Specifically, `L_{v_i}(v_i) = G_M(L(v_i))`, where
//! `L(v)` is the primary label (what [`super::kdt::node_key`] computes).
//! From there, `L_{v_i}(left(w)) = G_L(L_{v_i}(w))` and so on.
//!
//! This nested structure is what distinguishes NNL-SD from simpler
//! broadcast schemes like Complete-Subtree. A key `K(v_i, v_j)`
//! depends on *both* `v_i` and `v_j`; the same inner node under two
//! different outers produces two different keys. That makes NNL-SD
//! strictly more restrictive than Complete-Subtree and is what
//! prevents readers from decrypting subsets they aren't entitled to.
//!
//! ## Reader storage
//!
//! For a reader at leaf `l`, the stored path keys are, for each
//! ancestor `v_i` of `l` and each step `k` in 1..=(h - depth(v_i)):
//!
//! - The sub-label `L_{v_i}(s)`, where `s` is the sibling of `l`'s
//!   path at depth `depth(v_i) + k` within `v_i`'s sub-scheme.
//!
//! Total labels: `h + (h-1) + ... + 1 = h(h+1)/2`. For h=7, that's 28
//! labels × 32 bytes = 896 bytes per reader. Plus a separately-derived
//! FullTree key.
//!
//! ## Reader decrypt
//!
//! For a subset `S(v_i, v_j)`, the reader looks up a path key with
//! matching `outer = v_i` and a `sibling` that is an ancestor of `v_j`.
//! If found, they walk from that sibling down to `v_j` within `v_i`'s
//! sub-scheme, then apply `G_M` to get `K(v_i, v_j)`. If no such path
//! key exists, the reader is not entitled (either `v_i` is not an
//! ancestor of them, or `v_j` is on their own path).

use crate::crypto::prg::{triple_prg, KEY_LEN};
use crate::tree::cover::SubsetLabel;
use crate::tree::kdt::node_key;
use crate::tree::{is_ancestor, LeafIndex, NodePos};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Info string for deriving the FullTree subset key.
///
/// FullTree is used only when the cover is the entire tree (no
/// revocations). Every reader holds a direct copy of this key in
/// their [`ReaderKeyset::fulltree_key`].
const INFO_FULLTREE: &[u8] = b"btn.v1.fulltree";

/// Compute the publisher-side subset key for a given label.
///
/// Operates from the master seed:
/// - `FullTree` → `HKDF(seed, info="btn.v1.fulltree")`. Every reader
///   holds this directly.
/// - `Difference { outer, inner }` → walk from `L_{outer}(outer)` down
///   to `L_{outer}(inner)` within `outer`'s sub-scheme, then apply
///   the mid-PRG.
#[must_use]
pub fn subset_key(master_seed: &[u8; KEY_LEN], label: &SubsetLabel) -> Zeroizing<[u8; KEY_LEN]> {
    match label {
        SubsetLabel::FullTree => derive_fulltree_key(master_seed),
        SubsetLabel::Difference { outer, inner } => {
            // subtree_seed_{outer} = L_{outer}(outer) = G_M(L(outer))
            let l_outer = node_key(master_seed, *outer);
            let t = triple_prg(&l_outer);
            let subtree_seed = Zeroizing::new(t.mid);
            // Walk from outer (within outer's sub-scheme) down to inner.
            derive_subset_key_walk(&subtree_seed, *outer, *inner)
        }
    }
}

/// HKDF-derived FullTree key. Publisher and every reader compute this
/// the same way from the master seed.
fn derive_fulltree_key(master_seed: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut out = [0u8; KEY_LEN];
    hk.expand(INFO_FULLTREE, &mut out)
        .expect("hkdf expand fulltree: unreachable");
    Zeroizing::new(out)
}

/// Walk from a known sub-label at `from` down to descendant `to`,
/// then apply the mid-PRG to produce the subset key K(_, to).
///
/// `label_at_from` is `L_{v}(from)` for some `v` that is an ancestor
/// of `from`. The walk uses the appropriate bit positions of
/// `to.index` to navigate left/right at each step.
///
/// Precondition: `from` must be an ancestor of `to` (reflexive
/// allowed).
fn derive_subset_key_walk(
    label_at_from: &[u8; KEY_LEN],
    from: NodePos,
    to: NodePos,
) -> Zeroizing<[u8; KEY_LEN]> {
    debug_assert!(
        is_ancestor(from, to),
        "derive_subset_key_walk called with non-ancestor pair: \
         from={from:?} to={to:?}"
    );
    let mut current = Zeroizing::new(*label_at_from);
    let depth_delta = to.depth - from.depth;
    // Walk `depth_delta` steps. At step `s`, consume bit
    // (depth_delta - 1 - s) of to.index.
    for step in 0..depth_delta {
        let bit_pos = depth_delta - 1 - step;
        let go_right = (to.index >> bit_pos) & 1 == 1;
        let t = triple_prg(&current);
        current = Zeroizing::new(if go_right { t.right } else { t.left });
    }
    // current is now L_{v}(to). Apply mid-PRG to get K(v, to).
    let t = triple_prg(&current);
    Zeroizing::new(t.mid)
}

/// One entry in a reader's keyset: a sub-label at a specific
/// `(outer, sibling)` pair.
///
/// Reader decrypts `S(v_i, v_j)` iff some `PathKey` satisfies:
/// - `outer == v_i`, AND
/// - `sibling` is an ancestor of `v_j`.
///
/// Then the reader walks from `label` (which equals `L_{outer}(sibling)`)
/// down to `v_j`, and applies mid-PRG for the subset key.
#[derive(Clone)]
pub struct PathKey {
    /// The outer ancestor `v_i` this key belongs to. Reader is under
    /// `outer` in the full tree.
    pub outer: NodePos,
    /// The hanging sibling `s` off the reader's path within `outer`'s
    /// sub-scheme. Reader is NOT under `sibling`.
    pub sibling: NodePos,
    /// `L_{outer}(sibling)`: the sub-label at `sibling` in `outer`'s
    /// sub-scheme. From this, reader can walk down to any descendant
    /// of `sibling` and derive a subset key.
    pub label: [u8; KEY_LEN],
}

impl Drop for PathKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.label.zeroize();
        // `outer` and `sibling` are public coordinates — not secret.
    }
}

impl core::fmt::Debug for PathKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PathKey")
            .field("outer", &self.outer)
            .field("sibling", &self.sibling)
            .field("label", &"[REDACTED]")
            .finish()
    }
}

/// The key material a single reader holds.
///
/// Derived once from the master seed + leaf index, then shipped to
/// the reader (typically inside a signed reader-kit package). After
/// derivation, the master seed is not needed — the reader derives any
/// subset key they are entitled to from these fields alone.
///
/// Size for tree height h: `h(h+1)/2` path keys × 32 bytes each, plus
/// one 32-byte FullTree key. For h=7 → 28×32 + 32 = 928 bytes.
#[derive(Clone)]
pub struct ReaderKeyset {
    /// The reader's leaf index.
    pub leaf: LeafIndex,
    /// One entry per `(outer, sibling)` pair the reader is entitled
    /// to use, ordered by (outer.depth, sibling.depth). Exactly
    /// `h(h+1)/2` entries for a fully-formed keyset.
    pub path_keys: Vec<PathKey>,
    /// The FullTree subset key, letting the reader decrypt any
    /// ciphertext whose cover is just `[FullTree]` (no revocations).
    pub fulltree_key: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for ReaderKeyset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReaderKeyset")
            .field("leaf", &self.leaf)
            .field("path_keys_count", &self.path_keys.len())
            .field("fulltree_key", &"[REDACTED]")
            .finish()
    }
}

/// Materialize a reader's keyset from the publisher's master seed.
///
/// For each ancestor `v_i` of `leaf` at depth `d_vi` in `0..h`, walks
/// `v_i`'s sub-scheme from `v_i` toward `leaf` and records the sub-
/// label at each hanging sibling.
#[must_use]
pub fn materialize_reader_keyset(
    master_seed: &[u8; KEY_LEN],
    leaf: LeafIndex,
    tree_height: u8,
) -> ReaderKeyset {
    let capacity = usize::from(tree_height) * (usize::from(tree_height) + 1) / 2;
    let mut path_keys: Vec<PathKey> = Vec::with_capacity(capacity);

    for d_vi in 0..tree_height {
        // v_i = ancestor of leaf at depth d_vi.
        let v_i = NodePos {
            depth: d_vi,
            index: leaf.0 >> (tree_height - d_vi),
        };
        // subtree_seed_{v_i} = L_{v_i}(v_i) = G_M(L(v_i))
        let l_vi = node_key(master_seed, v_i);
        let t = triple_prg(&l_vi);
        let mut current_sub_label = Zeroizing::new(t.mid);
        // current_sub_label = L_{v_i}(v_i). Walk toward leaf.

        for k in 1..=(tree_height - d_vi) {
            let full_depth_before = d_vi + k - 1;
            let bit_pos = tree_height - 1 - full_depth_before;
            let path_goes_right = (leaf.0 >> bit_pos) & 1 == 1;

            let triple = triple_prg(&current_sub_label);
            let (path_next, sibling_label) = if path_goes_right {
                (triple.right, triple.left)
            } else {
                (triple.left, triple.right)
            };

            let full_depth_after = d_vi + k;
            let path_index_after = leaf.0 >> (tree_height - full_depth_after);
            let sibling_index_after = path_index_after ^ 1;
            let sibling_node = NodePos {
                depth: full_depth_after,
                index: sibling_index_after,
            };

            path_keys.push(PathKey {
                outer: v_i,
                sibling: sibling_node,
                label: sibling_label,
            });

            current_sub_label = Zeroizing::new(path_next);
        }
    }

    let fulltree_key = derive_fulltree_key(master_seed);

    ReaderKeyset {
        leaf,
        path_keys,
        fulltree_key,
    }
}

impl ReaderKeyset {
    /// Attempt to derive the subset key for `label`.
    ///
    /// Returns `Some(key)` iff the reader is entitled to this subset.
    /// Returns `None` otherwise — no cryptographic operation is
    /// performed beyond the path-key lookup, so the cost of "I'm not
    /// entitled" is proportional to the keyset size (tiny for h=7).
    #[must_use]
    pub fn try_subset_key(&self, label: &SubsetLabel) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        match label {
            SubsetLabel::FullTree => Some(self.fulltree_key.clone()),
            SubsetLabel::Difference { outer, inner } => {
                for pk in &self.path_keys {
                    if pk.outer == *outer && is_ancestor(pk.sibling, *inner) {
                        return Some(derive_subset_key_walk(&pk.label, pk.sibling, *inner));
                    }
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TREE_HEIGHT;
    use crate::tree::cover::subset_difference_cover;
    use std::collections::BTreeSet;

    fn seed(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    #[test]
    fn fulltree_subset_key_matches_reader_fulltree_key() {
        let s = seed(11);
        let pub_k = subset_key(&s, &SubsetLabel::FullTree);
        for leaf_idx in [0u64, 1, 7, 15] {
            let ks = materialize_reader_keyset(&s, LeafIndex(leaf_idx), TREE_HEIGHT);
            assert_eq!(*pub_k, *ks.fulltree_key);
        }
    }

    #[test]
    fn reader_keyset_has_correct_size() {
        let s = seed(13);
        let ks = materialize_reader_keyset(&s, LeafIndex(42), TREE_HEIGHT);
        let expected = usize::from(TREE_HEIGHT) * (usize::from(TREE_HEIGHT) + 1) / 2;
        assert_eq!(
            ks.path_keys.len(),
            expected,
            "h={TREE_HEIGHT} → h(h+1)/2 labels"
        );
    }

    #[test]
    fn entitled_reader_derives_same_subset_key_as_publisher() {
        let s = seed(17);
        // Revoke a small set; every non-revoked reader must derive
        // each cover entry's key correctly.
        let revoked = [LeafIndex(3), LeafIndex(42)];
        let cover = subset_difference_cover(TREE_HEIGHT, &revoked);
        assert!(!cover.is_empty());
        let revoked_set: BTreeSet<u64> = revoked.iter().map(|l| l.0).collect();
        for leaf_idx in 0u64..crate::config::MAX_LEAVES {
            if revoked_set.contains(&leaf_idx) {
                continue;
            }
            let reader = materialize_reader_keyset(&s, LeafIndex(leaf_idx), TREE_HEIGHT);
            // Exactly one cover entry should yield a matching key.
            let mut matched = 0;
            for label in &cover {
                if let Some(rk) = reader.try_subset_key(label) {
                    assert_eq!(
                        *rk,
                        *subset_key(&s, label),
                        "reader key for leaf {leaf_idx} doesn't match publisher's for {label:?}"
                    );
                    matched += 1;
                }
            }
            assert_eq!(
                matched, 1,
                "non-revoked leaf {leaf_idx} should match exactly 1 cover entry; got {matched}"
            );
        }
    }

    #[test]
    fn revoked_reader_cannot_derive_any_cover_subset_key() {
        let s = seed(19);
        for revoked_leaf in 0u64..crate::config::MAX_LEAVES {
            let cover = subset_difference_cover(TREE_HEIGHT, &[LeafIndex(revoked_leaf)]);
            let reader = materialize_reader_keyset(&s, LeafIndex(revoked_leaf), TREE_HEIGHT);
            for label in &cover {
                assert!(
                    reader.try_subset_key(label).is_none(),
                    "revoked leaf {revoked_leaf} derived a key for {label:?} (bug!)"
                );
            }
        }
    }

    #[test]
    fn exhaustive_h3_entitlement() {
        // h=3: 8 leaves, 2^8 possible revocation patterns. For each
        // pattern, every reader must derive correct keys for (and only
        // for) the cover entries they're entitled to.
        let s = seed(23);
        let h = 3u8;
        for mask in 0u32..(1 << 8) {
            let revoked: BTreeSet<u64> = (0..8).filter(|i| mask & (1 << i) != 0).collect();
            let revoked_vec: Vec<LeafIndex> = revoked.iter().copied().map(LeafIndex).collect();
            let cover = subset_difference_cover(h, &revoked_vec);
            for leaf in 0u64..8 {
                let reader = materialize_reader_keyset(&s, LeafIndex(leaf), h);
                let is_revoked = revoked.contains(&leaf);
                let mut matched_count = 0;
                for label in &cover {
                    if let Some(rk) = reader.try_subset_key(label) {
                        assert_eq!(
                            *rk,
                            *subset_key(&s, label),
                            "reader key mismatch: leaf={leaf} mask={mask:08b} label={label:?}"
                        );
                        matched_count += 1;
                    }
                }
                if is_revoked {
                    assert_eq!(
                        matched_count, 0,
                        "revoked leaf {leaf} (mask={mask:08b}) derived {matched_count} keys"
                    );
                } else if !cover.is_empty() {
                    // Non-revoked reader must match EXACTLY ONE cover
                    // entry — since cover subsets are disjoint.
                    assert_eq!(
                        matched_count, 1,
                        "non-revoked leaf {leaf} (mask={mask:08b}) matched \
                         {matched_count} cover entries; expected exactly 1. \
                         cover={cover:?}"
                    );
                }
            }
        }
    }
}
