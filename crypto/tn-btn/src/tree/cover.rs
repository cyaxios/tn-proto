//! Subset-difference cover algorithm (Naor-Naor-Lotspiech 2001 §4).
//!
//! Given a set of revoked leaves `R` in a complete binary tree, produce
//! a minimal set of subsets `S(v_i, v_j)` whose union equals
//! `leaves \ R`.
//!
//! A subset `S(v_i, v_j)` is defined as: "all leaves in the subtree
//! rooted at `v_i`, except those in the subtree rooted at `v_j`." The
//! node `v_j` must be a strict descendant of `v_i`.
//!
//! ## Algorithm outline
//!
//! 1. Build the **Steiner tree** `ST(R ∪ {root})` — the minimal subtree
//!    of the full tree that contains the root and every revoked leaf.
//!    Nodes in `ST` are either (a) revoked leaves, (b) the root, or
//!    (c) internal nodes where `ST` branches (i.e., have two children
//!    in `ST`).
//!
//! 2. Repeatedly find two leaves `l_i`, `l_j` of `ST` such that their
//!    least common ancestor `v` in `ST` has no other `ST`-leaves
//!    on the paths from `v` to `l_i` or `v` to `l_j`. Emit subsets
//!    `S(u_i, l_i)` and `S(u_j, l_j)` where `u_i`, `u_j` are the
//!    children of `v` on the respective paths (in the **original
//!    tree**, not in `ST`). Then remove `l_i` and `l_j` from `ST` and
//!    replace them with `v` as a new `ST`-leaf.
//!
//! 3. When `ST` has only the root: if the root is revoked, output no
//!    subsets (empty cover, every leaf is revoked). If the root is not
//!    revoked and is the sole `ST`-leaf: emit one "full subtree" cover
//!    for the entire tree.
//!
//! 4. If `ST` has exactly one non-root leaf `l`: emit `S(root, l)`
//!    (all leaves except those below `l`).
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
//! - **Single leaf revoked** — walk up the path and emit one subset
//!   per level, peeling off the off-path subtree each time. For a tree
//!   of height `h`, this produces exactly `h` subsets.

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

    // Now walk the Steiner tree and emit cover subsets. Upper bound:
    // ~2r subsets for r revoked leaves (NNL §4 analysis). Preallocate
    // to avoid repeated reallocation during recursion.
    let capacity = revoked_set
        .len()
        .saturating_mul(2)
        .max(usize::from(tree_height));
    let mut cover = Vec::with_capacity(capacity);
    emit_cover(tree_height, &steiner, &revoked_set, &mut cover);
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

/// Recursively walk the Steiner tree and emit cover subsets for nodes
/// not on any revoked-leaf path.
///
/// Invariant: at each node `v` in the Steiner tree we examine whether
/// each child subtree is fully revoked (in Steiner tree), fully alive
/// (not in Steiner tree), or mixed (some leaves revoked, some alive).
/// For alive children, we emit a cover that includes that subtree.
/// For mixed children we recurse.
fn emit_cover(
    tree_height: u8,
    steiner: &BTreeSet<NodePos>,
    revoked: &BTreeSet<LeafIndex>,
    cover: &mut Vec<SubsetLabel>,
) {
    // Walk the Steiner tree top-down from root.
    walk_steiner_node(NodePos::ROOT, tree_height, steiner, revoked, cover);
}

/// Walk the Steiner tree rooted at `node`, emitting cover subsets for
/// alive children and recursing into mixed children.
fn walk_steiner_node(
    node: NodePos,
    tree_height: u8,
    steiner: &BTreeSet<NodePos>,
    revoked: &BTreeSet<LeafIndex>,
    cover: &mut Vec<SubsetLabel>,
) {
    if node.is_leaf(tree_height) {
        // Steiner-tree leaves are always revoked leaves. Emit nothing.
        debug_assert!(revoked.contains(&LeafIndex(node.index)));
        return;
    }

    let left = node.left_child();
    let right = node.right_child();
    let left_in = steiner.contains(&left);
    let right_in = steiner.contains(&right);

    match (left_in, right_in) {
        // Both children are in the Steiner tree: each contains at least
        // one revoked leaf. We need to cover alive-descendants inside
        // each. Recurse on both.
        (true, true) => {
            // For each child, emit a Difference subset that says
            // "everything under this child except the revoked portion".
            // If the child itself is a revoked leaf, nothing to emit.
            // Otherwise we find the "excluded inner" that fully covers
            // all revoked leaves under this child.
            emit_child_cover(left, tree_height, steiner, revoked, cover);
            emit_child_cover(right, tree_height, steiner, revoked, cover);
        }
        // Only one child is in the Steiner tree. The other child is
        // alive and requires one FullSubtree-style cover (encoded as
        // S(alive_child, impossible_descendant) — but we can be
        // cleverer: at the top level we'd emit S(root, steiner_child).
        // Recursively, we want S(node, steiner_child) if node is the
        // "outer" and we exclude the steiner_child's subtree. That
        // doesn't work either because the alive sibling then needs its
        // own cover.
        //
        // Correct treatment: emit S(node, steiner_child). This covers
        // leaves_under(node) \\ leaves_under(steiner_child) = the
        // alive child's full subtree + any alive portions of
        // steiner_child's subtree. Then we ALSO recurse into
        // steiner_child to cover anything alive under it.
        //
        // Wait — that double-covers. Let me think again.
        //
        // Actually: if only left is in steiner, then right's entire
        // subtree is alive. We want to cover it. The right subtree is
        // covered by S(right, none) = leaves_under(right). That's a
        // "full subtree" within `right`. Encode as S(node, left): this
        // covers node's subtree minus left's subtree = right's subtree.
        // Good — that covers all alive leaves in right's subtree.
        //
        // Then we must recurse into left to cover any alive leaves
        // there. Left alone may have alive leaves (if it's not a leaf
        // itself).
        (true, false) => {
            emit_subtree_exclusion(node, left, cover);
            walk_steiner_node(left, tree_height, steiner, revoked, cover);
        }
        (false, true) => {
            emit_subtree_exclusion(node, right, cover);
            walk_steiner_node(right, tree_height, steiner, revoked, cover);
        }
        // Neither child is in Steiner tree: this should never happen
        // for an internal Steiner-tree node (it's in the tree because
        // at least one revoked leaf is below it, which means at least
        // one child must also be in the Steiner tree).
        (false, false) => {
            debug_assert!(
                false,
                "Steiner-tree internal node {node:?} has no Steiner children; \
                 this is a bug in build_steiner_tree"
            );
        }
    }
}

/// Emit cover for the given child, which IS in the Steiner tree (so it
/// contains at least one revoked leaf). If the child is itself a
/// revoked leaf, emit nothing. Otherwise recurse.
fn emit_child_cover(
    child: NodePos,
    tree_height: u8,
    steiner: &BTreeSet<NodePos>,
    revoked: &BTreeSet<LeafIndex>,
    cover: &mut Vec<SubsetLabel>,
) {
    if child.is_leaf(tree_height) {
        // This IS a revoked leaf. Nothing to cover here.
        debug_assert!(revoked.contains(&LeafIndex(child.index)));
        return;
    }
    walk_steiner_node(child, tree_height, steiner, revoked, cover);
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
        // Revoke leaf 5 (binary 101) in a tree of height 3. The cover
        // should contain exactly h=3 subsets peeling off siblings of
        // nodes on the path from root to leaf 5.
        let c = subset_difference_cover(3, &[LeafIndex(5)]);
        assert_eq!(c.len(), 3);
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
    fn exhaustive_h4_covers_are_correct() {
        // For every subset of a height-4 tree's 16 leaves, verify the
        // cover is correct. 2^16 cases — cheap, ~64k iterations.
        for mask in 0u32..(1 << 16) {
            let revoked: Vec<_> = (0u32..16)
                .filter(|i| mask & (1u32 << i) != 0)
                .map(|i| LeafIndex(u64::from(i)))
                .collect();
            check_cover_exactly_covers(4, &revoked);
        }
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
