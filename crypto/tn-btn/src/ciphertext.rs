//! Ciphertext type, encrypt, and decrypt.
//!
//! This module ties cover computation, subset-key derivation, AES-KW
//! wrapping, and AES-GCM body encryption together. The result is a
//! self-contained [`Ciphertext`] that any entitled [`ReaderKeyset`]
//! can decrypt without consulting the publisher.
//!
//! v0.1 keeps the surface free-function: `encrypt_to_cover` and
//! `decrypt_with_keyset`. The higher-level `PublisherState` wrapper
//! will land in a later commit and just orchestrates calls into
//! these plus revocation bookkeeping.

use crate::crypto::aead::{open, random_nonce, seal, NONCE_LEN};
use crate::crypto::kw::{unwrap, wrap, WRAPPED_LEN};
use crate::crypto::prg::KEY_LEN;
use crate::error::{Error, Result};
use crate::tree::cover::{subset_difference_cover, SubsetLabel};
use crate::tree::subset::{subset_key, ReaderKeyset};
use crate::tree::LeafIndex;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// One entry in a ciphertext's cover list. Wraps the per-entry CEK
/// under the subset's derived key so entitled readers can unwrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverEntry {
    /// Which subset this entry corresponds to.
    pub label: SubsetLabel,
    /// AES-KW-wrapped CEK (40 bytes).
    pub wrapped_cek: [u8; WRAPPED_LEN],
}

/// A sealed broadcast message.
///
/// Self-contained: any reader with an entitled [`ReaderKeyset`] that
/// matches the `publisher_id` and `epoch` can decrypt without further
/// publisher state. Wire-format encoding is a follow-on commit; for
/// now this struct is in-memory only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    /// Opaque 256-bit publisher identifier. Readers check this matches
    /// their kit's publisher_id before attempting decrypt; a mismatch
    /// surfaces as `NotEntitled` without any cryptographic work.
    pub publisher_id: [u8; 32],
    /// Epoch counter. Bumped on key rotation; a ciphertext from a
    /// later epoch requires a fresh reader kit.
    pub epoch: u32,
    /// One entry per subset in the cover.
    pub cover: Vec<CoverEntry>,
    /// AEAD nonce for the body.
    pub body_nonce: [u8; NONCE_LEN],
    /// AEAD-sealed plaintext (includes 16-byte tag at end).
    pub body: Vec<u8>,
}

/// Encrypt `plaintext` for a broadcast with the given revocation set.
///
/// - Computes the subset-difference cover of `revoked_leaves`.
/// - Generates a fresh random 32-byte CEK and 12-byte nonce.
/// - For each subset in the cover, derives its subset key from the
///   master seed and AES-KW-wraps the CEK under it.
/// - AEAD-seals the plaintext under the CEK with the nonce.
///
/// `tree_height` should equal [`crate::config::TREE_HEIGHT`] in v0.1.
/// The argument is explicit so the function is easy to test against
/// smaller trees (h=3, h=4) in unit tests.
///
/// `publisher_id` and `epoch` are copied verbatim into the ciphertext
/// so readers can reject content from a different publisher or epoch
/// up-front without attempting decrypt.
///
/// # Errors
/// Returns [`Error::Internal`] only on unreachable failures in the
/// underlying primitives (e.g. allocation failure).
pub fn encrypt_to_cover(
    master_seed: &[u8; KEY_LEN],
    tree_height: u8,
    publisher_id: [u8; 32],
    epoch: u32,
    revoked_leaves: &[LeafIndex],
    plaintext: &[u8],
) -> Result<Ciphertext> {
    let cover_labels = subset_difference_cover(tree_height, revoked_leaves);

    // Fresh random CEK, zeroized on drop.
    let cek = {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Zeroizing::new(k)
    };

    // Wrap the CEK under each subset key.
    let mut cover: Vec<CoverEntry> = Vec::with_capacity(cover_labels.len());
    for label in cover_labels {
        let sk = subset_key(master_seed, &label);
        let wrapped_cek = wrap(&sk, &cek).map_err(|()| {
            Error::Internal(format!(
                "AES-KW wrap failed for subset {label:?} — should be unreachable \
                 with 32-byte KEK and 32-byte CEK inputs"
            ))
        })?;
        cover.push(CoverEntry { label, wrapped_cek });
    }

    let body_nonce = random_nonce();
    let body = seal(&cek, &body_nonce, plaintext, &[]).map_err(|()| {
        Error::Internal(
            "AES-GCM seal failed — should be unreachable with a fresh 32-byte CEK".into(),
        )
    })?;

    Ok(Ciphertext {
        publisher_id,
        epoch,
        cover,
        body_nonce,
        body,
    })
}

/// Attempt to decrypt a [`Ciphertext`] with a [`ReaderKeyset`].
///
/// Walks the cover, finds the one entry the reader is entitled to,
/// unwraps the CEK, and AEAD-opens the body.
///
/// # Errors
/// Returns [`Error::NotEntitled`] if no cover entry can be unwrapped
/// with this keyset. That means either the reader was revoked before
/// this ciphertext was produced, or the ciphertext was produced by a
/// different publisher (subset keys won't match).
pub fn decrypt_with_keyset(keyset: &ReaderKeyset, ct: &Ciphertext) -> Result<Vec<u8>> {
    for entry in &ct.cover {
        if let Some(sk) = keyset.try_subset_key(&entry.label) {
            // Reader is entitled (at least per path-key lookup). Try the
            // unwrap; if integrity fails here, it means the subset key
            // was for a different publisher's seed — treat as not entitled.
            let Ok(cek) = unwrap(&sk, &entry.wrapped_cek) else {
                continue;
            };
            let cek = Zeroizing::new(cek);
            // Open the body. If AEAD fails, same logic: wrong publisher.
            let Ok(pt) = open(&cek, &ct.body_nonce, &ct.body, &[]) else {
                continue;
            };
            return Ok(pt);
        }
    }
    Err(Error::NotEntitled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TREE_HEIGHT;
    use crate::tree::subset::materialize_reader_keyset;

    fn seed(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    #[test]
    fn roundtrip_no_revocations() {
        let s = seed(41);
        let ct = encrypt_to_cover(&s, TREE_HEIGHT, [0; 32], 0, &[], b"broadcast body").unwrap();
        // Every reader should decrypt.
        for leaf_idx in [0u64, 1, 7, 15] {
            let ks = materialize_reader_keyset(&s, LeafIndex(leaf_idx), TREE_HEIGHT);
            let pt = decrypt_with_keyset(&ks, &ct).unwrap();
            assert_eq!(pt, b"broadcast body");
        }
    }

    #[test]
    fn roundtrip_one_revoked() {
        let s = seed(43);
        let revoked = [LeafIndex(7)];
        let ct = encrypt_to_cover(&s, TREE_HEIGHT, [0; 32], 0, &revoked, b"not-for-42").unwrap();
        // Revoked reader fails.
        let ks_7 = materialize_reader_keyset(&s, LeafIndex(7), TREE_HEIGHT);
        assert!(matches!(
            decrypt_with_keyset(&ks_7, &ct),
            Err(Error::NotEntitled)
        ));
        // Every other reader succeeds (leaf 7 is revoked, skip it).
        for leaf_idx in [0u64, 1, 2, 3, 5, 8, 15] {
            let ks = materialize_reader_keyset(&s, LeafIndex(leaf_idx), TREE_HEIGHT);
            let pt = decrypt_with_keyset(&ks, &ct).unwrap();
            assert_eq!(pt, b"not-for-42");
        }
    }

    #[test]
    fn roundtrip_many_revoked() {
        let s = seed(47);
        let revoked: Vec<_> = [2u64, 5, 8, 13].into_iter().map(LeafIndex).collect();
        let ct = encrypt_to_cover(&s, TREE_HEIGHT, [0; 32], 0, &revoked, b"selective").unwrap();
        let revoked_set: std::collections::BTreeSet<u64> = revoked.iter().map(|l| l.0).collect();
        for leaf_idx in 0u64..crate::config::MAX_LEAVES {
            let ks = materialize_reader_keyset(&s, LeafIndex(leaf_idx), TREE_HEIGHT);
            let result = decrypt_with_keyset(&ks, &ct);
            if revoked_set.contains(&leaf_idx) {
                assert!(
                    matches!(result, Err(Error::NotEntitled)),
                    "revoked leaf {leaf_idx} should fail, got {result:?}"
                );
            } else {
                assert_eq!(result.unwrap(), b"selective");
            }
        }
    }

    #[test]
    fn different_publishers_cannot_cross_decrypt() {
        let alice_seed = seed(51);
        let mallory_seed = seed(52);
        let ct = encrypt_to_cover(
            &alice_seed,
            TREE_HEIGHT,
            [0; 32],
            0,
            &[],
            b"alice's message",
        )
        .unwrap();
        // Mallory has a reader minted from her own seed — same leaf
        // index as one of Alice's readers. Cannot decrypt Alice's ct.
        let mallory_ks = materialize_reader_keyset(&mallory_seed, LeafIndex(5), TREE_HEIGHT);
        assert!(matches!(
            decrypt_with_keyset(&mallory_ks, &ct),
            Err(Error::NotEntitled)
        ));
    }

    #[test]
    fn tampered_body_fails() {
        let s = seed(53);
        let mut ct = encrypt_to_cover(&s, TREE_HEIGHT, [0; 32], 0, &[], b"honest payload").unwrap();
        // Flip one byte of the body.
        ct.body[0] ^= 0x01;
        let ks = materialize_reader_keyset(&s, LeafIndex(0), TREE_HEIGHT);
        assert!(matches!(
            decrypt_with_keyset(&ks, &ct),
            Err(Error::NotEntitled)
        ));
    }

    #[test]
    fn tampered_wrapped_cek_fails() {
        let s = seed(59);
        let mut ct =
            encrypt_to_cover(&s, TREE_HEIGHT, [0; 32], 0, &[], b"another payload").unwrap();
        // Flip a byte inside a wrapped_cek.
        ct.cover[0].wrapped_cek[0] ^= 0x01;
        let ks = materialize_reader_keyset(&s, LeafIndex(0), TREE_HEIGHT);
        assert!(matches!(
            decrypt_with_keyset(&ks, &ct),
            Err(Error::NotEntitled)
        ));
    }

    #[test]
    fn empty_plaintext_works() {
        let s = seed(61);
        let ct = encrypt_to_cover(&s, TREE_HEIGHT, [0; 32], 0, &[], b"").unwrap();
        let ks = materialize_reader_keyset(&s, LeafIndex(0), TREE_HEIGHT);
        let pt = decrypt_with_keyset(&ks, &ct).unwrap();
        assert_eq!(pt, b"");
    }
}
