//! Subset-difference cover algorithm (Naor-Naor-Lotspiech 2001 §4).
//!
//! Given a set of revoked leaves `R` in a complete binary tree, produce
//! a disjoint set of subsets `S(v_i, v_j)` whose union equals
//! `leaves \ R`.
//!
//! A subset `S(v_i, v_j)` is defined as: "all leaves in the subtree
//! rooted at `v_i`, except those in the subtree rooted at `v_j`." The
//! node `v_j` must be a strict descendant of `v_i`.
//!
//! ## Algorithm outline
//!
//! 1. Build the **Steiner tree** `ST(R ∪ {root})`: every node on a
//!    root-to-revoked-leaf path, including nodes with only one child in `ST`.
//! 2. From an outer node, follow the sole child in `ST` until reaching a
//!    branch or revoked leaf. Emit one difference from the outer node to
//!    that inner node when the path is nonempty. This covers all surviving
//!    sibling subtrees along the maximal unary path.
//! 3. At a branch, recurse into both children. At a revoked leaf, stop.
//!
//! The emitted differences partition the surviving leaves. There are
//! `r - 1` branches for `r > 0` revoked leaves, hence at most `2r - 1`
//! chain starts (the root and two children per branch). Empty chains emit
//! nothing. The cover therefore has at most `min(2r - 1, 2^h - r)` labels.
//!
//! ## Edge cases handled explicitly
//!
//! - **Empty revocation set** — output a single "full tree" cover:
//!   `S(root, impossible_descendant)`. We encode this as
//!   [`SubsetLabel::FullTree`] so decoders can short-circuit.
//!
//! - **All leaves revoked** — output no subsets at all; any ciphertext
//!   encrypted with this cover has an empty header and is trivially
//!   undecryptable.
//!
//! - **Single leaf revoked** — emit one `S(root, revoked_leaf)` label.

use crate::tree::{is_ancestor, LeafIndex, NodePos};
use std::collections::BTreeSet;

/// A subset-difference label.
///
/// Identifies the conceptual subset `S(outer, inner) = leaves_under(outer) \\ leaves_under(inner)`.
///
/// Special variant: [`SubsetLabel::FullTree`] represents "all leaves"
/// when no revocations apply. Its wire encoding differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubsetLabel {
    /// Represents the entire tree (no revocations).
    ///
    /// A ciphertext with exactly this one cover entry is sealed to
    /// every leaf in the tree. Any reader can decrypt it.
    FullTree,
    /// `S(outer, inner)`: everyone in `outer`'s subtree except those in
    /// `inner`'s subtree. `inner` must be a strict descendant of `outer`
    /// (i.e. `outer.depth < inner.depth` and `outer` is an ancestor of
    /// `inner`).
    Difference {
        /// Outer subtree root. Its descendants are included.
        outer: NodePos,
        /// Inner subtree root. Its descendants are excluded.
        inner: NodePos,
    },
}

/// Compute the subset-difference cover of `leaves \\ revoked` in a tree
/// of the given height.
///
/// Returns a vector of subset labels. The union of the subsets is
/// exactly the set of non-revoked leaves.
///
/// # Panics
/// Does not panic for any valid input. All internal arithmetic uses
/// saturating / checked operations where needed.
#[must_use]
pub fn subset_difference_cover(tree_height: u8, revoked: &[LeafIndex]) -> Vec<SubsetLabel> {
    // Dedup revoked set; anything out-of-range is silently ignored
    // since it represents a leaf that doesn't exist.
    let max_leaf = 1u64 << tree_height;
    let revoked_set: BTreeSet<LeafIndex> =
        revoked.iter().copied().filter(|l| l.0 < max_leaf).collect();

    // Empty revocation set: entire tree is covered by a single
    // FullTree label.
    if revoked_set.is_empty() {
        return vec![SubsetLabel::FullTree];
    }

    // All leaves revoked: empty cover.
    if u64::try_from(revoked_set.len()).is_ok_and(|n| n == max_leaf) {
        return Vec::new();
    }

    // Build the Steiner tree: the set of NodePos that lie on some path
    // from the root to a revoked leaf. By construction this includes
    // the root and every revoked leaf.
    let steiner = build_steiner_tree(tree_height, &revoked_set);

    // Walk maximal unary paths. Upper bound: 2r - 1 subsets. Preallocate
    // to avoid repeated reallocation during recursion.
    let capacity = revoked_set.len().saturating_mul(2).saturating_sub(1);
    let mut cover = Vec::with_capacity(capacity);
    walk_steiner_node(NodePos::ROOT, tree_height, &steiner, &mut cover);
    cover
}

/// Build the set of `NodePos` that are on some root-to-revoked-leaf path.
fn build_steiner_tree(tree_height: u8, revoked: &BTreeSet<LeafIndex>) -> BTreeSet<NodePos> {
    let mut steiner = BTreeSet::new();
    for leaf in revoked {
        let mut cur = leaf.as_node(tree_height);
        loop {
            steiner.insert(cur);
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
    }
    steiner
}

/// Compress a maximal unary path, then recurse below its terminal branch.
/// The emitted difference is disjoint from both recursive covers because
/// those contain only leaves under `inner`, which the difference excludes.
fn walk_steiner_node(
    outer: NodePos,
    tree_height: u8,
    steiner: &BTreeSet<NodePos>,
    cover: &mut Vec<SubsetLabel>,
) {
    let mut inner = outer;
    while !inner.is_leaf(tree_height) {
        let left = inner.left_child();
        let right = inner.right_child();
        let left_in = steiner.contains(&left);
        let right_in = steiner.contains(&right);
        debug_assert!(left_in || right_in, "internal Steiner node has no child");
        if left_in && right_in {
            break;
        }
        inner = if left_in { left } else { right };
    }
    if inner != outer {
        emit_subtree_exclusion(outer, inner, cover);
    }
    if !inner.is_leaf(tree_height) {
        walk_steiner_node(inner.left_child(), tree_height, steiner, cover);
        walk_steiner_node(inner.right_child(), tree_height, steiner, cover);
    }
}

/// Emit the subset `S(outer, inner) = leaves_under(outer) \\ leaves_under(inner)`.
///
/// Asserts `inner` is a strict descendant of `outer`. Panics on misuse
/// (internal bug).
fn emit_subtree_exclusion(outer: NodePos, inner: NodePos, cover: &mut Vec<SubsetLabel>) {
    debug_assert!(
        outer.depth < inner.depth && is_ancestor(outer, inner),
        "emit_subtree_exclusion called with non-strict-ancestor pair: outer={outer:?} inner={inner:?}"
    );
    cover.push(SubsetLabel::Difference { outer, inner });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force: compute the set of leaves covered by a single
    /// subset label, in a tree of the given height.
    fn leaves_under(node: NodePos, tree_height: u8) -> Vec<LeafIndex> {
        if node.is_leaf(tree_height) {
            return vec![LeafIndex(node.index)];
        }
        let span = 1u64 << (tree_height - node.depth);
        let start = node.index << (tree_height - node.depth);
        (start..start + span).map(LeafIndex).collect()
    }

    fn leaves_in_subset(label: SubsetLabel, tree_height: u8) -> BTreeSet<LeafIndex> {
        match label {
            SubsetLabel::FullTree => (0..1u64 << tree_height).map(LeafIndex).collect(),
            SubsetLabel::Difference { outer, inner } => {
                let outer_set: BTreeSet<_> = leaves_under(outer, tree_height).into_iter().collect();
                let inner_set: BTreeSet<_> = leaves_under(inner, tree_height).into_iter().collect();
                outer_set.difference(&inner_set).copied().collect()
            }
        }
    }

    fn cover_as_set(cover: &[SubsetLabel], tree_height: u8) -> BTreeSet<LeafIndex> {
        let mut s = BTreeSet::new();
        for label in cover {
            s.extend(leaves_in_subset(*label, tree_height));
        }
        s
    }

    fn expected_non_revoked(tree_height: u8, revoked: &[LeafIndex]) -> BTreeSet<LeafIndex> {
        let all: BTreeSet<LeafIndex> = (0..1u64 << tree_height).map(LeafIndex).collect();
        let r: BTreeSet<LeafIndex> = revoked.iter().copied().collect();
        all.difference(&r).copied().collect()
    }

    fn check_cover_exactly_covers(tree_height: u8, revoked: &[LeafIndex]) {
        let cover = subset_difference_cover(tree_height, revoked);
        let got = cover_as_set(&cover, tree_height);
        let want = expected_non_revoked(tree_height, revoked);
        assert_eq!(
            got, want,
            "cover for h={tree_height} revoked={revoked:?} is wrong; \
             got={got:?} want={want:?} cover={cover:?}"
        );

        // Additionally: subsets must be disjoint. Any overlap is either
        // wasteful (extra key wraps) or a bug.
        let mut seen = BTreeSet::new();
        for label in &cover {
            let leaves = leaves_in_subset(*label, tree_height);
            for leaf in &leaves {
                assert!(
                    seen.insert(*leaf),
                    "cover subsets overlap at leaf {leaf:?} (label {label:?}); \
                     the NNL algorithm should produce disjoint subsets"
                );
            }
        }
        let n = 1usize << tree_height;
        let r = revoked
            .iter()
            .filter(|leaf| leaf.0 < n as u64)
            .collect::<BTreeSet<_>>()
            .len();
        if r > 0 {
            assert!(
                cover.len() <= (2 * r - 1).min(n - r),
                "NNL bound exceeded: h={tree_height}, r={r}, cover={cover:?}"
            );
        }
    }

    #[test]
    fn no_revocations_yields_full_tree() {
        let c = subset_difference_cover(3, &[]);
        assert_eq!(c, vec![SubsetLabel::FullTree]);
    }

    #[test]
    fn all_revoked_yields_empty_cover() {
        let all: Vec<_> = (0..8).map(LeafIndex).collect();
        let c = subset_difference_cover(3, &all);
        assert!(c.is_empty());
    }

    #[test]
    fn one_revoked_at_h3() {
        // A maximal unary path is one root-minus-leaf difference.
        let c = subset_difference_cover(3, &[LeafIndex(5)]);
        assert_eq!(
            c,
            vec![SubsetLabel::Difference {
                outer: NodePos::ROOT,
                inner: NodePos { depth: 3, index: 5 },
            }]
        );
        check_cover_exactly_covers(3, &[LeafIndex(5)]);
    }

    #[test]
    fn two_adjacent_revoked() {
        // Revoke leaves 0 and 1. Their parent (1,0) is fully revoked.
        // The cover needs to skip all of (1,0)'s subtree.
        check_cover_exactly_covers(3, &[LeafIndex(0), LeafIndex(1)]);
    }

    #[test]
    fn two_far_revoked() {
        // Revoke leaf 0 and leaf 7 (opposite corners of an h=3 tree).
        check_cover_exactly_covers(3, &[LeafIndex(0), LeafIndex(7)]);
    }

    #[test]
    fn every_other_revoked() {
        // Revoke 0, 2, 4, 6 in h=3. Remaining: 1, 3, 5, 7.
        check_cover_exactly_covers(3, &[LeafIndex(0), LeafIndex(2), LeafIndex(4), LeafIndex(6)]);
    }

    #[test]
    fn all_revoked_at_h3() {
        let all: Vec<_> = (0..8).map(LeafIndex).collect();
        check_cover_exactly_covers(3, &all);
    }

    #[test]
    fn all_but_one_revoked() {
        // Revoke everyone except leaf 3. The cover should be a single
        // subset covering exactly {leaf 3}.
        let mut revoked: Vec<_> = (0..8).map(LeafIndex).collect();
        revoked.retain(|l| l.0 != 3);
        check_cover_exactly_covers(3, &revoked);

        let cover = subset_difference_cover(3, &revoked);
        let got = cover_as_set(&cover, 3);
        assert_eq!(got, [LeafIndex(3)].into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn h7_sparse_revocations() {
        // The v0.1 bound is h=7. Spot-check a few patterns.
        check_cover_exactly_covers(7, &[]);
        check_cover_exactly_covers(7, &[LeafIndex(0)]);
        check_cover_exactly_covers(7, &[LeafIndex(127)]);
        check_cover_exactly_covers(
            7,
            &[LeafIndex(3), LeafIndex(17), LeafIndex(42), LeafIndex(99)],
        );
        let every_other: Vec<_> = (0..128).step_by(2).map(LeafIndex).collect();
        check_cover_exactly_covers(7, &every_other);
    }

    #[test]
    fn exhaustive_h0_through_h4_partition_and_nnl_bound() {
        let mut cases = 0;
        for height in 0..=4 {
            let leaves = 1u32 << height;
            for mask in 0u32..(1 << leaves) {
                let revoked: Vec<_> = (0..leaves)
                    .filter(|i| mask & (1u32 << i) != 0)
                    .map(|i| LeafIndex(u64::from(i)))
                    .collect();
                check_cover_exactly_covers(height, &revoked);
                cases += 1;
            }
        }
        assert_eq!(cases, 65814);
    }

    #[test]
    fn h8_single_leaves_and_aligned_subtrees_compress_to_one_label() {
        for depth in 1..=8 {
            for index in 0..1u64 << depth {
                let inner = NodePos { depth, index };
                let revoked = leaves_under(inner, 8);
                assert_eq!(
                    subset_difference_cover(8, &revoked),
                    vec![SubsetLabel::Difference {
                        outer: NodePos::ROOT,
                        inner
                    }]
                );
                check_cover_exactly_covers(8, &revoked);
            }
        }
    }

    #[test]
    fn h8_sampled_and_adversarial_sets_partition_within_nnl_bound() {
        check_cover_exactly_covers(8, &[]);
        check_cover_exactly_covers(8, &(0..256).map(LeafIndex).collect::<Vec<_>>());
        for survivor in [0, 1, 127, 128, 254, 255] {
            let revoked = (0..256)
                .filter(|i| *i != survivor)
                .map(LeafIndex)
                .collect::<Vec<_>>();
            check_cover_exactly_covers(8, &revoked);
        }
        for step in [2, 3, 7, 31, 127] {
            let revoked = (0..256).step_by(step).map(LeafIndex).collect::<Vec<_>>();
            check_cover_exactly_covers(8, &revoked);
        }
        // Seeded xorshift sampling is for reproducible geometry, never key generation.
        let mut state = 0x7c0a_5b19_238d_ef61u64;
        for sample in 0..1000 {
            let threshold = [1, 8, 32, 64, 128, 192, 224, 255][sample % 8];
            let revoked: Vec<_> = (0..256)
                .filter(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state & 255 < threshold
                })
                .map(LeafIndex)
                .collect();
            check_cover_exactly_covers(8, &revoked);
        }
    }

    #[test]
    fn duplicate_and_out_of_range_revocations_do_not_change_compressed_cover() {
        assert_eq!(
            subset_difference_cover(
                8,
                &[
                    LeafIndex(7),
                    LeafIndex(7),
                    LeafIndex(256),
                    LeafIndex(u64::MAX)
                ]
            ),
            subset_difference_cover(8, &[LeafIndex(7)])
        );
    }

    #[test]
    fn cover_subsets_are_well_formed() {
        // Every Difference label must have outer as a strict ancestor
        // of inner. Regression against the emit_subtree_exclusion
        // assertion being silently disabled in release builds.
        let c = subset_difference_cover(5, &[LeafIndex(10), LeafIndex(11)]);
        for label in &c {
            if let SubsetLabel::Difference { outer, inner } = label {
                assert!(
                    outer.depth < inner.depth,
                    "subset outer depth {} should be < inner depth {}",
                    outer.depth,
                    inner.depth,
                );
                assert!(
                    is_ancestor(*outer, *inner),
                    "subset outer {outer:?} should be an ancestor of inner {inner:?}"
                );
            }
        }
    }
}
