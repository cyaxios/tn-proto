//! Identity paths and the pinned label to scalar mapping.
//!
//! `I_i = SHA-256(label) mod p`, digest read as a big-endian integer. This
//! mapping is part of the wire contract: it must be byte-for-byte identical to
//! `tn_hibe::Identity` (re-exported from crypto/tn-hibe/src/lib.rs) or every
//! wrapped CEK ever sealed stops opening. It is covered by the interop golden
//! vectors.

use bls12_381_plus::Scalar;
use sha2::{Digest, Sha256};

use crate::error::{BbgError, Result};

/// Maximum label size supported by the canonical private-key encoding.
pub const MAX_LABEL_LEN: usize = u16::MAX as usize;

/// A hierarchical identity path, e.g. `did:key:zReader/sha256:policy...`.
/// Labels are ordered root-first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    labels: Vec<Vec<u8>>,
    scalars: Vec<Scalar>,
}

impl Identity {
    /// Builds an identity from raw label bytes, root-first.
    ///
    /// Panics if any label is empty, contains a path separator or control
    /// delimiter, has traversal semantics, carries leading/trailing ASCII
    /// whitespace, is longer than [`MAX_LABEL_LEN`], or if the path has more
    /// than 255 labels. Prefer [`Identity::try_from_path`] at public
    /// boundaries.
    pub fn from_path(labels: &[&[u8]]) -> Self {
        Self::try_from_path(labels).expect("valid HIBE identity path")
    }

    /// Fallibly builds an identity from raw label bytes, root-first.
    pub fn try_from_path(labels: &[&[u8]]) -> Result<Self> {
        validate_depth(labels.len())?;
        for label in labels {
            validate_label(label)?;
        }
        Ok(Self {
            labels: labels.iter().map(|l| l.to_vec()).collect(),
            scalars: labels.iter().map(|l| hash_to_scalar(l)).collect(),
        })
    }

    /// Builds an identity from a `/`-separated string path.
    ///
    /// Panics if the path is empty, contains an empty segment such as
    /// `"a//b"` or `"a/"`, or contains an overlong segment. Prefer
    /// [`Identity::try_from_str_path`] at public string boundaries.
    pub fn from_str_path(path: &str) -> Self {
        Self::try_from_str_path(path).expect("valid HIBE identity string path")
    }

    /// Fallibly builds an identity from a `/`-separated string path.
    pub fn try_from_str_path(path: &str) -> Result<Self> {
        if path.is_empty() {
            return Err(BbgError::InvalidIdentityPath("empty path"));
        }
        let labels: Vec<&[u8]> = path
            .split('/')
            .map(|segment| {
                if segment.is_empty() {
                    Err(BbgError::InvalidIdentityPath("empty path segment"))
                } else {
                    Ok(segment.as_bytes())
                }
            })
            .collect::<Result<_>>()?;
        Self::try_from_path(&labels)
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
    ///
    /// Panics if `label` is empty, contains a path separator or control
    /// delimiter, has traversal semantics, carries leading/trailing ASCII
    /// whitespace, is overlong, or if the child would exceed 255 labels.
    /// Prefer [`Identity::try_child`] at public boundaries.
    pub fn child(&self, label: &[u8]) -> Identity {
        self.try_child(label)
            .expect("valid HIBE identity child label")
    }

    /// Fallibly appends one validated child label to this identity.
    pub fn try_child(&self, label: &[u8]) -> Result<Identity> {
        validate_label(label)?;
        validate_depth(self.labels.len() + 1)?;
        let mut labels = self.labels.clone();
        labels.push(label.to_vec());
        let mut scalars = self.scalars.clone();
        scalars.push(hash_to_scalar(label));
        Ok(Identity { labels, scalars })
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

fn validate_depth(depth: usize) -> Result<()> {
    if depth > u8::MAX as usize {
        return Err(BbgError::IdentityTooDeep);
    }
    Ok(())
}

fn validate_label(label: &[u8]) -> Result<()> {
    if label.is_empty() {
        return Err(BbgError::InvalidIdentityLabel("empty label"));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(BbgError::InvalidIdentityLabel("label too long"));
    }
    if label == b"." || label == b".." {
        return Err(BbgError::InvalidIdentityLabel("traversal label"));
    }
    if label.first().is_some_and(u8::is_ascii_whitespace)
        || label.last().is_some_and(u8::is_ascii_whitespace)
    {
        return Err(BbgError::InvalidIdentityLabel(
            "leading or trailing whitespace",
        ));
    }
    if label
        .iter()
        .any(|b| matches!(*b, b'/' | b'\\' | b'\0' | b'\r' | b'\n'))
    {
        return Err(BbgError::InvalidIdentityLabel(
            "label contains path or line delimiter",
        ));
    }
    Ok(())
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
