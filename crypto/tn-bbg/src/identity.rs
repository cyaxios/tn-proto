//! Identity paths and the pinned label to scalar mapping.
//!
//! `I_i = SHA-256(label) mod p`, digest read as a big-endian integer. This
//! mapping is part of the wire contract: it must be byte-for-byte identical to
//! `tn_hibe::Identity` (crypto/tn-hibe/src/identity.rs) or every wrapped CEK
//! ever sealed stops opening. It is covered by the interop golden vectors.

use bls12_381_plus::Scalar;
use sha2::{Digest, Sha256};

/// A hierarchical identity path, e.g. `did:key:zReader/sha256:policy...`.
/// Labels are ordered root-first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    labels: Vec<Vec<u8>>,
    scalars: Vec<Scalar>,
}

impl Identity {
    /// Builds an identity from raw label bytes, root-first.
    pub fn from_path(labels: &[&[u8]]) -> Self {
        Self {
            labels: labels.iter().map(|l| l.to_vec()).collect(),
            scalars: labels.iter().map(|l| hash_to_scalar(l)).collect(),
        }
    }

    /// Builds an identity from a `/`-separated string path. Empty segments are
    /// dropped, so `"a//b/"` equals `"a/b"` and `""` is the root identity.
    pub fn from_str_path(path: &str) -> Self {
        let labels: Vec<&[u8]> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::as_bytes)
            .collect();
        Self::from_path(&labels)
    }

    /// Number of path elements. The root identity has depth 0.
    pub fn depth(&self) -> usize {
        self.labels.len()
    }

    /// True when `other` sits strictly below `self`: `self`'s labels are a
    /// proper prefix of `other`'s.
    pub fn is_parent_of(&self, other: &Identity) -> bool {
        self.depth() < other.depth() && other.labels[..self.depth()] == self.labels[..]
    }

    /// The identity one level down from `self` with `label` appended.
    pub fn child(&self, label: &[u8]) -> Identity {
        let mut labels = self.labels.clone();
        labels.push(label.to_vec());
        let mut scalars = self.scalars.clone();
        scalars.push(hash_to_scalar(label));
        Identity { labels, scalars }
    }

    /// The raw labels, root-first.
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    pub(crate) fn scalars(&self) -> &[Scalar] {
        &self.scalars
    }

    pub(crate) fn from_labels(labels: Vec<Vec<u8>>) -> Self {
        let scalars = labels.iter().map(|l| hash_to_scalar(l)).collect();
        Identity { labels, scalars }
    }
}

/// `I = SHA-256(label) mod p`, digest read as a big-endian integer.
///
/// `from_bytes_wide` takes a 512-bit little-endian integer; reversing the
/// big-endian digest into the low 32 bytes computes exactly `digest mod p`.
/// This is the exact byte recipe tn-hibe uses.
fn hash_to_scalar(label: &[u8]) -> Scalar {
    let digest = Sha256::digest(label);
    let mut wide = [0u8; 64];
    for (i, b) in digest.iter().rev().enumerate() {
        wide[i] = *b;
    }
    Scalar::from_bytes_wide(&wide)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn str_path_matches_raw_labels() {
        let a = Identity::from_str_path("reader/policy");
        let b = Identity::from_path(&[b"reader", b"policy"]);
        assert_eq!(a, b);
        assert_eq!(a.depth(), 2);
    }

    #[test]
    fn parenthood_is_strict_prefix() {
        let root = Identity::from_path(&[]);
        let a = Identity::from_str_path("a");
        let ab = Identity::from_str_path("a/b");
        let cb = Identity::from_str_path("c/b");
        assert!(root.is_parent_of(&a));
        assert!(a.is_parent_of(&ab));
        assert!(!a.is_parent_of(&a));
        assert!(!a.is_parent_of(&cb));
        assert!(!ab.is_parent_of(&a));
        assert_eq!(a.child(b"b"), ab);
    }
}
