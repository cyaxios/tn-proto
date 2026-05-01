//! Complete binary tree math: leaf and node indexing, path operations.
//!
//! Tree layout (height `h`):
//!
//! - Leaves: indices `0..2^h`, type [`LeafIndex`].
//! - Internal nodes + leaves together: addressed by [`NodePos`],
//!   which is `(depth, index_at_depth)`. Root is `(0, 0)`.
//! - A leaf at index `l` has [`NodePos`] `(h, l)`.
//!
//! Conventions:
//!
//! - Depth 0 is the root. Depth `h` is the leaf level.
//! - At depth `d`, indices run `0..2^d`.
//! - Left child of `(d, i)` is `(d+1, 2*i)`. Right child is `(d+1, 2*i + 1)`.
//! - Parent of `(d, i)` is `(d-1, i/2)` (integer division).
//!
//! This module is pure integer arithmetic. No crypto, no I/O, no state.

#![allow(clippy::module_name_repetitions)]

pub mod cover;
pub mod kdt;
pub mod subset;

/// A leaf index in a tree of height `h`. Valid range: `0..2^h`.
///
/// Stored as `u64`, supporting trees up to height 64. Realistic use is
/// `h <= 40` or so; 64 is the hard limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafIndex(pub u64);

/// A position in the tree at some depth, addressed as `(depth, index_at_depth)`.
///
/// The root is `NodePos { depth: 0, index: 0 }`. Leaves are at depth `h`.
/// Within a depth `d`, the index ranges over `0..2^d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodePos {
    /// Depth from the root. 0 = root, `tree_height` = leaf level.
    pub depth: u8,
    /// Index among the nodes at this depth. Range: `0..2^depth`.
    pub index: u64,
}

impl NodePos {
    /// The root node at `(0, 0)`.
    pub const ROOT: NodePos = NodePos { depth: 0, index: 0 };

    /// Left child of this node.
    ///
    /// # Panics
    /// Panics if `depth == u8::MAX` (would overflow). Realistic trees
    /// never approach this; we panic rather than silently wrap so a
    /// misuse surfaces immediately.
    #[inline]
    #[must_use]
    pub fn left_child(self) -> NodePos {
        NodePos {
            depth: self.depth.checked_add(1).expect("tree depth overflow"),
            index: self.index * 2,
        }
    }

    /// Right child of this node.
    ///
    /// # Panics
    /// Panics if `depth == u8::MAX`, for the same reason as [`Self::left_child`].
    #[inline]
    #[must_use]
    pub fn right_child(self) -> NodePos {
        NodePos {
            depth: self.depth.checked_add(1).expect("tree depth overflow"),
            index: self.index * 2 + 1,
        }
    }

    /// Child on a given side (`false` = left, `true` = right).
    ///
    /// # Panics
    /// Panics under the same conditions as [`Self::left_child`] / [`Self::right_child`].
    #[inline]
    #[must_use]
    pub fn child(self, right: bool) -> NodePos {
        if right {
            self.right_child()
        } else {
            self.left_child()
        }
    }

    /// Parent of this node. `None` if `self == ROOT`.
    #[inline]
    #[must_use]
    pub fn parent(self) -> Option<NodePos> {
        if self.depth == 0 {
            None
        } else {
            Some(NodePos {
                depth: self.depth - 1,
                index: self.index / 2,
            })
        }
    }

    /// Is this node a leaf in a tree of the given height?
    #[inline]
    #[must_use]
    pub fn is_leaf(self, tree_height: u8) -> bool {
        self.depth == tree_height
    }

    /// Which side of its parent is this node? `false` = left, `true` = right.
    ///
    /// Returns `None` if this is the root (no parent).
    #[inline]
    #[must_use]
    pub fn side_of_parent(self) -> Option<bool> {
        if self.depth == 0 {
            None
        } else {
            Some(self.index & 1 == 1)
        }
    }
}

impl LeafIndex {
    /// The [`NodePos`] for this leaf in a tree of height `tree_height`.
    #[inline]
    #[must_use]
    pub fn as_node(self, tree_height: u8) -> NodePos {
        NodePos {
            depth: tree_height,
            index: self.0,
        }
    }
}

/// Is `ancestor` an ancestor of (or equal to) `descendant`?
///
/// A node is considered its own ancestor.
#[inline]
#[must_use]
pub fn is_ancestor(ancestor: NodePos, descendant: NodePos) -> bool {
    if ancestor.depth > descendant.depth {
        return false;
    }
    let shift = descendant.depth - ancestor.depth;
    if shift >= 64 {
        // Descendant too deep — can't be shifted into the ancestor's range.
        return false;
    }
    (descendant.index >> shift) == ancestor.index
}

/// The path from `root` down to `node`, inclusive of both, top-down order.
///
/// Returns `None` if `node` has depth greater than any sane tree height
/// or if internal arithmetic would overflow (shouldn't happen for
/// realistic inputs).
#[must_use]
pub fn path_from_root(node: NodePos) -> Vec<NodePos> {
    let mut path = Vec::with_capacity(node.depth as usize + 1);
    let mut cur = Some(node);
    while let Some(n) = cur {
        path.push(n);
        cur = n.parent();
    }
    path.reverse();
    path
}

/// Least common ancestor of two leaves in a tree of height `tree_height`.
///
/// Both inputs must be valid leaf indices (< `2^tree_height`). Returns the
/// deepest node that is an ancestor of both.
#[must_use]
pub fn lca(a: LeafIndex, b: LeafIndex, tree_height: u8) -> NodePos {
    let mut xor = a.0 ^ b.0;
    let mut shared_prefix_depth: u8 = tree_height;
    while xor != 0 && shared_prefix_depth > 0 {
        xor >>= 1;
        shared_prefix_depth -= 1;
    }
    // The LCA is at depth `shared_prefix_depth`, and its index is the
    // prefix of either leaf index shifted down by (tree_height - depth).
    let shift = tree_height - shared_prefix_depth;
    let index = if shift >= 64 { 0 } else { a.0 >> shift };
    NodePos {
        depth: shared_prefix_depth,
        index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_children() {
        let root = NodePos::ROOT;
        assert_eq!(root.depth, 0);
        assert_eq!(root.index, 0);
        assert_eq!(root.left_child(), NodePos { depth: 1, index: 0 });
        assert_eq!(root.right_child(), NodePos { depth: 1, index: 1 });
    }

    #[test]
    fn child_and_parent_invert() {
        for depth in 0..10 {
            for index in 0..(1u64 << depth) {
                let n = NodePos { depth, index };
                assert_eq!(n.left_child().parent(), Some(n));
                assert_eq!(n.right_child().parent(), Some(n));
            }
        }
    }

    #[test]
    fn side_of_parent() {
        assert_eq!(NodePos::ROOT.side_of_parent(), None);
        assert_eq!(NodePos::ROOT.left_child().side_of_parent(), Some(false));
        assert_eq!(NodePos::ROOT.right_child().side_of_parent(), Some(true));
        let deep_left = NodePos {
            depth: 5,
            index: 0b10110,
        };
        assert_eq!(deep_left.side_of_parent(), Some(false)); // last bit 0
        let deep_right = NodePos {
            depth: 5,
            index: 0b10111,
        };
        assert_eq!(deep_right.side_of_parent(), Some(true)); // last bit 1
    }

    #[test]
    fn is_ancestor_trivial() {
        assert!(is_ancestor(NodePos::ROOT, NodePos::ROOT));
        assert!(is_ancestor(NodePos::ROOT, NodePos { depth: 3, index: 5 }));
        assert!(!is_ancestor(NodePos { depth: 3, index: 5 }, NodePos::ROOT));
    }

    #[test]
    fn is_ancestor_cross_subtree() {
        // Two leaves in different halves at depth 3:
        let left = NodePos {
            depth: 3,
            index: 0b001,
        };
        let right = NodePos {
            depth: 3,
            index: 0b110,
        };
        let left_subtree = NodePos { depth: 1, index: 0 };
        let right_subtree = NodePos { depth: 1, index: 1 };
        assert!(is_ancestor(left_subtree, left));
        assert!(!is_ancestor(left_subtree, right));
        assert!(is_ancestor(right_subtree, right));
        assert!(!is_ancestor(right_subtree, left));
    }

    #[test]
    fn path_from_root_matches_depth() {
        let n = NodePos {
            depth: 4,
            index: 0b1011,
        };
        let p = path_from_root(n);
        assert_eq!(p.len(), 5);
        assert_eq!(p[0], NodePos::ROOT);
        assert_eq!(p[4], n);
        // Each consecutive pair should be parent -> child.
        for i in 0..p.len() - 1 {
            assert_eq!(p[i + 1].parent(), Some(p[i]));
        }
    }

    #[test]
    fn lca_of_siblings() {
        // Leaves 0 and 1 at height 3: share depth-2 parent at index 0.
        let got = lca(LeafIndex(0), LeafIndex(1), 3);
        assert_eq!(got, NodePos { depth: 2, index: 0 });
    }

    #[test]
    fn lca_of_distant_leaves() {
        // Leaves 0 (000) and 7 (111) at height 3: only share root.
        let got = lca(LeafIndex(0), LeafIndex(7), 3);
        assert_eq!(got, NodePos::ROOT);
    }

    #[test]
    fn lca_of_same_leaf() {
        // Same leaf: LCA is the leaf itself.
        let got = lca(LeafIndex(5), LeafIndex(5), 3);
        assert_eq!(got, NodePos { depth: 3, index: 5 });
    }

    #[test]
    fn lca_mid_tree() {
        // Leaves 4 (100) and 5 (101) at h=3: share depth-2 parent idx 2.
        let got = lca(LeafIndex(4), LeafIndex(5), 3);
        assert_eq!(got, NodePos { depth: 2, index: 2 });
        // Leaves 4 (100) and 6 (110) at h=3: share depth-1 parent idx 1.
        let got = lca(LeafIndex(4), LeafIndex(6), 3);
        assert_eq!(got, NodePos { depth: 1, index: 1 });
    }

    #[test]
    fn leaf_as_node() {
        let leaf = LeafIndex(13);
        assert_eq!(
            leaf.as_node(5),
            NodePos {
                depth: 5,
                index: 13
            }
        );
        assert!(leaf.as_node(5).is_leaf(5));
        assert!(!leaf.as_node(5).is_leaf(6));
    }
}
