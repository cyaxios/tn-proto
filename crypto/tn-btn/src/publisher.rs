//! Publisher-side state: the six-verb public API.
//!
//! [`PublisherState`] owns the master seed, leaf assignment, revocation
//! set, and an eagerly-populated cache of every internal node's primary
//! key. Every [`PublisherState::encrypt`] call reuses the cache, so
//! repeated encrypts amortize the tree-walk cost over many ciphertexts.
//!
//! ## Leaf assignment policy
//!
//! v0.1 assigns leaves sequentially from 0 and never reuses. A revoked
//! leaf leaves a "hole" — [`PublisherState::mint`] does not fill it.
//! Once the tree is exhausted, mint returns [`Error::TreeExhausted`];
//! growing capacity requires rotating the epoch (shipping later).
//!
//! Why no reuse: the NNL label scheme is deterministic in
//! `(master_seed, leaf)`, so a newly-minted kit at a previously-revoked
//! leaf would derive identical keys to the revoked reader. Reusing
//! the leaf and then un-revoking would silently restore the old
//! reader's access. We sidestep the footgun entirely.

use crate::ciphertext::{Ciphertext, CoverEntry};
use crate::config::{Config, TREE_HEIGHT};
use crate::crypto::aead::{random_nonce, seal};
use crate::crypto::kw::wrap;
use crate::crypto::prg::{triple_prg, KEY_LEN};
use crate::error::{Error, Result};
use crate::reader::ReaderKit;
use crate::tree::cover::{subset_difference_cover, SubsetLabel};
use crate::tree::kdt::root_key;
use crate::tree::subset::materialize_reader_keyset;
use crate::tree::{LeafIndex, NodePos};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// HKDF info string for deriving a publisher's 256-bit id from the master seed.
const INFO_PUBLISHER_ID: &[u8] = b"btn.v1.publisher_id";

/// HKDF info string for deriving the FullTree subset key (re-declared here
/// to avoid a public dependency on the tree::subset internals).
const INFO_FULLTREE: &[u8] = b"btn.v1.fulltree";

/// Publisher's mutable state. Owns every secret.
///
/// Contains the master seed, leaf bookkeeping, revocation set, and a
/// cache of every internal node's primary key. Loss = cannot encrypt.
/// Leak = catastrophic (an attacker can mint arbitrary reader kits
/// and decrypt every ciphertext past, present, and future from this
/// publisher).
pub struct PublisherState {
    publisher_id: [u8; 32],
    epoch: u32,
    master_seed: Zeroizing<[u8; KEY_LEN]>,
    /// Primary node keys for every internal node, indexed by
    /// `(1 << depth) - 1 + index`. Populated eagerly at setup.
    /// Has `(1 << TREE_HEIGHT) - 1` entries (1023 at h=10).
    node_key_cache: Vec<Zeroizing<[u8; KEY_LEN]>>,
    /// Leaves that have been minted. Disjoint from `revoked` by
    /// construction (revocation moves an entry from issued to
    /// revoked).
    issued: BTreeSet<LeafIndex>,
    /// Leaves whose readers are currently revoked. Future ciphertexts
    /// seal over `leaves \ revoked`.
    revoked: BTreeSet<LeafIndex>,
    /// Next leaf to hand out. Monotonically increases; never reuses
    /// revoked leaves.
    next_leaf: u64,
}

impl PublisherState {
    /// Create a fresh publisher with a random master seed.
    ///
    /// # Errors
    /// Returns [`Error::InvalidConfig`] if `config` is invalid. In v0.1
    /// `Config` has no validatable fields, so this always succeeds.
    pub fn setup(config: Config) -> Result<Self> {
        config.validate()?;
        let mut seed = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut seed);
        Ok(Self::with_seed_inner(config, seed))
    }

    /// Create a publisher from a specific master seed. For testing and
    /// deterministic-ceremony scenarios.
    ///
    /// # Errors
    /// Same as [`Self::setup`].
    pub fn setup_with_seed(config: Config, seed: [u8; KEY_LEN]) -> Result<Self> {
        config.validate()?;
        Ok(Self::with_seed_inner(config, seed))
    }

    fn with_seed_inner(_config: Config, seed: [u8; KEY_LEN]) -> Self {
        let master_seed = Zeroizing::new(seed);
        let publisher_id = derive_publisher_id(&master_seed);
        let node_key_cache = populate_node_cache(&master_seed);
        Self {
            publisher_id,
            epoch: 0,
            master_seed,
            node_key_cache,
            issued: BTreeSet::new(),
            revoked: BTreeSet::new(),
            next_leaf: 0,
        }
    }

    /// 256-bit publisher identifier. Derived deterministically from
    /// the master seed; stable across restarts.
    #[inline]
    #[must_use]
    pub fn publisher_id(&self) -> [u8; 32] {
        self.publisher_id
    }

    /// Current epoch. Starts at 0; bumps on rotation (not yet implemented).
    #[inline]
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// How many reader kits have been minted.
    #[inline]
    #[must_use]
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }

    /// How many readers are currently revoked.
    #[inline]
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    /// Mint a fresh reader kit at the next unused leaf.
    ///
    /// # Errors
    /// Returns [`Error::TreeExhausted`] if the tree is full (every
    /// leaf index has been used at some point, whether currently
    /// issued or revoked).
    pub fn mint(&mut self) -> Result<ReaderKit> {
        if self.next_leaf >= (1u64 << TREE_HEIGHT) {
            return Err(Error::TreeExhausted {
                tree_height: TREE_HEIGHT,
                issued: self.issued.len() + self.revoked.len(),
            });
        }
        let leaf = LeafIndex(self.next_leaf);
        self.next_leaf += 1;
        self.issued.insert(leaf);
        let keyset = materialize_reader_keyset(&self.master_seed, leaf, TREE_HEIGHT);
        Ok(ReaderKit::new(self.publisher_id, self.epoch, keyset))
    }

    /// Revoke a reader by their kit. Idempotent: revoking twice is a
    /// no-op.
    ///
    /// # Errors
    /// Returns [`Error::Internal`] if the kit's `publisher_id` doesn't
    /// match this publisher. Revoking someone else's kit is nonsense
    /// and would silently do nothing if we didn't surface it.
    pub fn revoke(&mut self, kit: &ReaderKit) -> Result<()> {
        if kit.publisher_id() != self.publisher_id {
            return Err(Error::Internal(format!(
                "revoke: kit publisher_id {:?} does not match this publisher \
                 ({:?}); revocation has no effect across publishers.",
                hex::encode(kit.publisher_id()),
                hex::encode(self.publisher_id),
            )));
        }
        self.revoke_by_leaf(kit.leaf())
    }

    /// Revoke by leaf index directly. Idempotent.
    ///
    /// # Errors
    /// Returns [`Error::Internal`] if the leaf index is out of range
    /// for this tree height (should not happen when called through
    /// [`Self::revoke`], since minted kits always have valid leaves).
    pub fn revoke_by_leaf(&mut self, leaf: LeafIndex) -> Result<()> {
        if leaf.0 >= (1u64 << TREE_HEIGHT) {
            return Err(Error::Internal(format!(
                "revoke_by_leaf: leaf {leaf:?} is out of range for a \
                 height-{TREE_HEIGHT} tree (max leaf index is \
                 {}).",
                (1u64 << TREE_HEIGHT) - 1,
            )));
        }
        self.issued.remove(&leaf);
        self.revoked.insert(leaf);
        Ok(())
    }

    /// Encrypt `plaintext` for the current non-revoked recipient set.
    ///
    /// # Errors
    /// Returns [`Error::Internal`] only on unreachable failures in the
    /// underlying AEAD / KW primitives.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Ciphertext> {
        let revoked: Vec<LeafIndex> = self.revoked.iter().copied().collect();
        let cover_labels = subset_difference_cover(TREE_HEIGHT, &revoked);

        let cek = {
            let mut k = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut k);
            Zeroizing::new(k)
        };

        let mut cover: Vec<CoverEntry> = Vec::with_capacity(cover_labels.len());
        for label in cover_labels {
            let sk = self.subset_key_cached(&label);
            let wrapped_cek = wrap(&sk, &cek).map_err(|()| {
                Error::Internal(format!(
                    "AES-KW wrap failed for subset {label:?}; should be \
                     unreachable with 32-byte KEK/CEK inputs."
                ))
            })?;
            cover.push(CoverEntry { label, wrapped_cek });
        }

        let body_nonce = random_nonce();
        let body = seal(&cek, &body_nonce, plaintext, &[]).map_err(|()| {
            Error::Internal(
                "AES-GCM seal failed; should be unreachable with a fresh 32-byte CEK.".into(),
            )
        })?;

        Ok(Ciphertext {
            publisher_id: self.publisher_id,
            epoch: self.epoch,
            cover,
            body_nonce,
            body,
        })
    }

    /// Cache-aware subset key derivation. FullTree goes through HKDF;
    /// Difference uses the cached primary label of `outer` to skip the
    /// root→outer walk.
    fn subset_key_cached(&self, label: &SubsetLabel) -> Zeroizing<[u8; KEY_LEN]> {
        match label {
            SubsetLabel::FullTree => {
                let hk = Hkdf::<Sha256>::new(None, self.master_seed.as_ref());
                let mut out = [0u8; KEY_LEN];
                hk.expand(INFO_FULLTREE, &mut out)
                    .expect("hkdf expand fulltree: unreachable");
                Zeroizing::new(out)
            }
            SubsetLabel::Difference { outer, inner } => {
                // Cached primary label at outer (outer is always a non-leaf
                // internal node since it must have descendants).
                let l_outer = self.get_cached_node_key(*outer);
                // Subtree seed L_{outer}(outer) = G_M(L(outer)).
                let t = triple_prg(&l_outer);
                let mut current = Zeroizing::new(t.mid);
                // Walk from outer down to inner within outer's sub-scheme.
                let depth_delta = inner.depth - outer.depth;
                for step in 0..depth_delta {
                    let bit_pos = depth_delta - 1 - step;
                    let go_right = (inner.index >> bit_pos) & 1 == 1;
                    let triple = triple_prg(&current);
                    current = Zeroizing::new(if go_right { triple.right } else { triple.left });
                }
                // Apply mid-PRG at inner to get K(outer, inner).
                let t = triple_prg(&current);
                Zeroizing::new(t.mid)
            }
        }
    }

    /// Serialize this publisher state to bytes.
    ///
    /// Contains the master seed + bookkeeping (issued/revoked sets,
    /// next_leaf, epoch). The node-key cache is NOT serialized —
    /// it's rebuilt in ~500 µs from the master seed on [`Self::from_bytes`].
    ///
    /// **Treat the output as secret.** Anyone holding these bytes can
    /// mint arbitrary reader kits and decrypt every ciphertext this
    /// publisher has ever produced.
    ///
    /// # Panics
    /// Panics if `issued` or `revoked` contains more than `u32::MAX`
    /// leaves — impossible given `MAX_LEAVES <= 2^64` and the set is
    /// bounded by the tree, but the unwrap is documented for completeness.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::wire::{KIND_PUBLISHER_STATE, WIRE_MAGIC, WIRE_VERSION};
        let mut out: Vec<u8> = Vec::with_capacity(
            3 + 32 + 4 + 8 + 4 + self.issued.len() * 8 + 4 + self.revoked.len() * 8,
        );
        out.push(WIRE_MAGIC);
        out.push(WIRE_VERSION);
        out.push(KIND_PUBLISHER_STATE);
        out.extend_from_slice(self.master_seed.as_ref());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.next_leaf.to_be_bytes());
        let issued_len = u32::try_from(self.issued.len()).expect("issued count fits u32");
        out.extend_from_slice(&issued_len.to_be_bytes());
        for leaf in &self.issued {
            out.extend_from_slice(&leaf.0.to_be_bytes());
        }
        let revoked_len = u32::try_from(self.revoked.len()).expect("revoked count fits u32");
        out.extend_from_slice(&revoked_len.to_be_bytes());
        for leaf in &self.revoked {
            out.extend_from_slice(&leaf.0.to_be_bytes());
        }
        out
    }

    /// Deserialize a publisher state from bytes.
    ///
    /// Rebuilds the node-key cache from the master seed. Takes roughly
    /// the same time as a fresh `setup()`.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] on wrong magic/version/kind,
    /// truncated buffer, or trailing bytes.
    ///
    /// # Panics
    /// Does not panic for any valid input; the inner `try_into().expect(...)`
    /// calls are guaranteed to succeed after the preceding length
    /// checks via the `need()` helper.
    #[allow(clippy::too_many_lines)]
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        use crate::wire::{KIND_PUBLISHER_STATE, WIRE_MAGIC, WIRE_VERSION};
        if buf.len() < 3 {
            return Err(Error::Malformed {
                kind: "publisher_state",
                reason: format!("buffer too short: {} bytes", buf.len()),
            });
        }
        if buf[0] != WIRE_MAGIC {
            return Err(Error::Malformed {
                kind: "publisher_state",
                reason: format!("wrong magic byte {:#x}; expected {WIRE_MAGIC:#x}", buf[0]),
            });
        }
        if buf[1] != WIRE_VERSION {
            return Err(Error::Malformed {
                kind: "publisher_state",
                reason: format!(
                    "unsupported wire version {}; this build supports {WIRE_VERSION}",
                    buf[1]
                ),
            });
        }
        if buf[2] != KIND_PUBLISHER_STATE {
            return Err(Error::Malformed {
                kind: "publisher_state",
                reason: format!(
                    "wrong kind byte {:#x}; expected {KIND_PUBLISHER_STATE:#x} — \
                     is this a publisher-state blob?",
                    buf[2]
                ),
            });
        }
        let mut p = 3usize;
        let need = |p: usize, n: usize, buf: &[u8]| -> Result<()> {
            if p + n > buf.len() {
                return Err(Error::Malformed {
                    kind: "publisher_state",
                    reason: format!(
                        "short read at offset {p}: need {n} bytes, buffer len {}",
                        buf.len()
                    ),
                });
            }
            Ok(())
        };
        need(p, 32, buf)?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&buf[p..p + 32]);
        p += 32;
        need(p, 4, buf)?;
        let epoch = u32::from_be_bytes(
            buf[p..p + 4]
                .try_into()
                .expect("4-byte slice fits [u8; 4]: len checked by need(p, 4, buf)"),
        );
        p += 4;
        need(p, 8, buf)?;
        let next_leaf = u64::from_be_bytes(
            buf[p..p + 8]
                .try_into()
                .expect("8-byte slice fits [u8; 8]: len checked by need(p, 8, buf)"),
        );
        p += 8;
        need(p, 4, buf)?;
        let issued_count = u32::from_be_bytes(
            buf[p..p + 4]
                .try_into()
                .expect("4-byte slice fits [u8; 4]: len checked by need(p, 4, buf)"),
        ) as usize;
        p += 4;
        let mut issued = BTreeSet::new();
        for _ in 0..issued_count {
            need(p, 8, buf)?;
            let leaf = u64::from_be_bytes(
                buf[p..p + 8]
                    .try_into()
                    .expect("8-byte slice fits [u8; 8]: len checked by need(p, 8, buf)"),
            );
            p += 8;
            issued.insert(LeafIndex(leaf));
        }
        need(p, 4, buf)?;
        let revoked_count = u32::from_be_bytes(
            buf[p..p + 4]
                .try_into()
                .expect("4-byte slice fits [u8; 4]: len checked by need(p, 4, buf)"),
        ) as usize;
        p += 4;
        let mut revoked = BTreeSet::new();
        for _ in 0..revoked_count {
            need(p, 8, buf)?;
            let leaf = u64::from_be_bytes(
                buf[p..p + 8]
                    .try_into()
                    .expect("8-byte slice fits [u8; 8]: len checked by need(p, 8, buf)"),
            );
            p += 8;
            revoked.insert(LeafIndex(leaf));
        }
        if p != buf.len() {
            return Err(Error::Malformed {
                kind: "publisher_state",
                reason: format!("trailing bytes: parsed {p} of {} bytes", buf.len()),
            });
        }
        // Rebuild the cache + publisher_id from the master seed.
        let master_seed = Zeroizing::new(seed);
        let publisher_id = derive_publisher_id(&master_seed);
        let node_key_cache = populate_node_cache(&master_seed);
        Ok(Self {
            publisher_id,
            epoch,
            master_seed,
            node_key_cache,
            issued,
            revoked,
            next_leaf,
        })
    }

    /// Look up a cached primary label for an internal node.
    ///
    /// Panics in debug if called with a leaf (depth == TREE_HEIGHT) —
    /// leaves aren't cached. In release, returns zeros, but the caller
    /// should not be walking into that path; subset_key_cached only
    /// queries for `outer` nodes which are always strict ancestors.
    fn get_cached_node_key(&self, node: NodePos) -> [u8; KEY_LEN] {
        debug_assert!(
            node.depth < TREE_HEIGHT,
            "get_cached_node_key called on non-internal node {node:?}"
        );
        // Tree height is capped at 7, so (1<<depth)-1+index fits in usize
        // on every supported target. Using try_from here silences the
        // cast-truncation lint without adding runtime panic risk.
        let offset = usize::try_from((1u64 << node.depth) - 1 + node.index)
            .expect("cache offset fits in usize for h<=7");
        *self.node_key_cache[offset]
    }
}

impl std::fmt::Debug for PublisherState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublisherState")
            .field("publisher_id", &hex::encode(self.publisher_id))
            .field("epoch", &self.epoch)
            .field("issued_count", &self.issued.len())
            .field("revoked_count", &self.revoked.len())
            .field("next_leaf", &self.next_leaf)
            .field("master_seed", &"[REDACTED]")
            .field(
                "node_key_cache",
                &format!("[{} entries]", self.node_key_cache.len()),
            )
            .finish()
    }
}

/// Derive the 256-bit publisher_id from the master seed via HKDF.
fn derive_publisher_id(master_seed: &[u8; KEY_LEN]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut out = [0u8; 32];
    hk.expand(INFO_PUBLISHER_ID, &mut out)
        .expect("hkdf expand publisher_id: unreachable");
    out
}

/// Eagerly populate the primary-label cache for every internal node.
///
/// Cost: one root_key call + (2^TREE_HEIGHT - 2) triple_prg calls.
/// For h=7 that's ~126 HKDF calls, well under a millisecond.
fn populate_node_cache(master_seed: &[u8; KEY_LEN]) -> Vec<Zeroizing<[u8; KEY_LEN]>> {
    // Total internal nodes: sum_{d=0}^{h-1} 2^d = 2^h - 1.
    let total = (1usize << TREE_HEIGHT) - 1;
    let mut cache: Vec<Zeroizing<[u8; KEY_LEN]>> = Vec::with_capacity(total);
    cache.push(root_key(master_seed));
    for depth in 0..TREE_HEIGHT - 1 {
        let offset_this_depth = (1usize << depth) - 1;
        let offset_next_depth = (1usize << (depth + 1)) - 1;
        let count_this_depth = 1usize << depth;
        for idx in 0..count_this_depth {
            let parent = *cache[offset_this_depth + idx];
            let t = triple_prg(&parent);
            // Children at depth+1, indices 2*idx and 2*idx+1.
            // Use push since we're building in order.
            debug_assert_eq!(cache.len(), offset_next_depth + 2 * idx);
            cache.push(Zeroizing::new(t.left));
            cache.push(Zeroizing::new(t.right));
        }
    }
    debug_assert_eq!(cache.len(), total);
    cache
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::subset::subset_key;

    #[test]
    fn setup_is_deterministic_for_same_seed() {
        let s = [9u8; KEY_LEN];
        let a = PublisherState::setup_with_seed(Config, s).unwrap();
        let b = PublisherState::setup_with_seed(Config, s).unwrap();
        assert_eq!(a.publisher_id(), b.publisher_id());
    }

    #[test]
    fn different_seeds_different_publisher_ids() {
        let a = PublisherState::setup_with_seed(Config, [1u8; 32]).unwrap();
        let b = PublisherState::setup_with_seed(Config, [2u8; 32]).unwrap();
        assert_ne!(a.publisher_id(), b.publisher_id());
    }

    #[test]
    fn mint_advances_and_tracks_issued() {
        let mut s = PublisherState::setup_with_seed(Config, [5u8; 32]).unwrap();
        assert_eq!(s.issued_count(), 0);
        let k0 = s.mint().unwrap();
        assert_eq!(k0.leaf(), LeafIndex(0));
        assert_eq!(s.issued_count(), 1);
        let k1 = s.mint().unwrap();
        assert_eq!(k1.leaf(), LeafIndex(1));
        assert_eq!(s.issued_count(), 2);
    }

    #[test]
    fn mint_exhausts_tree_at_max_leaves() {
        use crate::config::{MAX_LEAVES, TREE_HEIGHT};
        let mut s = PublisherState::setup_with_seed(Config, [7u8; 32]).unwrap();
        for _ in 0..MAX_LEAVES {
            s.mint().unwrap();
        }
        let err = s.mint().unwrap_err();
        let expected_issued = usize::try_from(MAX_LEAVES).expect("MAX_LEAVES fits usize");
        let expected_height = TREE_HEIGHT;
        assert!(
            matches!(
                err,
                Error::TreeExhausted { tree_height, issued }
                if tree_height == expected_height && issued == expected_issued
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn revoke_moves_leaf_to_revoked_set() {
        let mut s = PublisherState::setup_with_seed(Config, [11u8; 32]).unwrap();
        let k = s.mint().unwrap();
        s.revoke(&k).unwrap();
        assert_eq!(s.issued_count(), 0);
        assert_eq!(s.revoked_count(), 1);
    }

    #[test]
    fn revoke_is_idempotent() {
        let mut s = PublisherState::setup_with_seed(Config, [13u8; 32]).unwrap();
        let k = s.mint().unwrap();
        s.revoke(&k).unwrap();
        s.revoke(&k).unwrap();
        assert_eq!(s.revoked_count(), 1);
    }

    #[test]
    fn revoke_rejects_foreign_kit() {
        let mut a = PublisherState::setup_with_seed(Config, [21u8; 32]).unwrap();
        let mut b = PublisherState::setup_with_seed(Config, [22u8; 32]).unwrap();
        let k_from_b = b.mint().unwrap();
        let err = a.revoke(&k_from_b).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("publisher_id"));
        assert!(msg.contains("does not match"));
    }

    #[test]
    fn cache_has_correct_size() {
        let s = PublisherState::setup_with_seed(Config, [33u8; 32]).unwrap();
        assert_eq!(s.node_key_cache.len(), (1 << TREE_HEIGHT) - 1);
    }

    #[test]
    fn cached_subset_key_matches_uncached() {
        // The cached derivation must produce byte-identical subset keys
        // to the free-function derivation. Regression against any
        // indexing bug in the cache.
        let s = PublisherState::setup_with_seed(Config, [41u8; 32]).unwrap();
        // All Difference samples below have valid ancestor relationships:
        // outer must be an ancestor of inner, meaning inner.index's top
        // outer.depth bits equal outer.index.
        let samples = [
            SubsetLabel::FullTree,
            SubsetLabel::Difference {
                outer: NodePos::ROOT,
                inner: NodePos { depth: 3, index: 5 },
            },
            SubsetLabel::Difference {
                // outer=(2, 1): top-2 bits of inner must be 01.
                // inner=(6, 20): 20 = 0b010100, top-2 bits = 01 ✓
                outer: NodePos { depth: 2, index: 1 },
                inner: NodePos {
                    depth: 6,
                    index: 20,
                },
            },
            SubsetLabel::Difference {
                outer: NodePos { depth: 1, index: 1 },
                inner: NodePos {
                    depth: 4,
                    index: 0b1010,
                },
            },
        ];
        for label in &samples {
            let cached = s.subset_key_cached(label);
            let free = subset_key(&s.master_seed, label);
            assert_eq!(*cached, *free, "cache mismatch for {label:?}");
        }
    }

    #[test]
    fn encrypt_roundtrip_through_publisher() {
        let mut s = PublisherState::setup_with_seed(Config, [43u8; 32]).unwrap();
        let alice = s.mint().unwrap();
        let bob = s.mint().unwrap();
        let ct = s.encrypt(b"hello kit holders").unwrap();
        assert_eq!(alice.decrypt(&ct).unwrap(), b"hello kit holders");
        assert_eq!(bob.decrypt(&ct).unwrap(), b"hello kit holders");
    }

    #[test]
    fn state_round_trip_preserves_everything() {
        let mut s = PublisherState::setup_with_seed(Config, [55u8; 32]).unwrap();
        let alice = s.mint().unwrap();
        let _bob = s.mint().unwrap();
        let carol = s.mint().unwrap();
        s.revoke(&carol).unwrap();
        let ct = s.encrypt(b"check me after round-trip").unwrap();

        let bytes = s.to_bytes();
        let restored = PublisherState::from_bytes(&bytes).unwrap();

        assert_eq!(restored.publisher_id(), s.publisher_id());
        assert_eq!(restored.epoch(), s.epoch());
        assert_eq!(restored.issued_count(), s.issued_count());
        assert_eq!(restored.revoked_count(), s.revoked_count());

        // Restored state can still decrypt old ciphertexts using alice's kit.
        let pt = alice.decrypt(&ct).unwrap();
        assert_eq!(pt, b"check me after round-trip");

        // And it can produce NEW ciphertexts that alice can decrypt.
        let ct2 = restored.encrypt(b"after reload").unwrap();
        assert_eq!(alice.decrypt(&ct2).unwrap(), b"after reload");
        assert!(matches!(carol.decrypt(&ct2), Err(Error::NotEntitled)));
    }

    #[test]
    fn state_deserialize_rejects_bad_magic() {
        let mut bogus = vec![0u8; 100];
        bogus[0] = 0x00;
        let err = PublisherState::from_bytes(&bogus).unwrap_err();
        assert!(format!("{err}").contains("magic"));
    }

    #[test]
    fn state_deserialize_rejects_wrong_kind() {
        let mut s = PublisherState::setup_with_seed(Config, [1u8; 32]).unwrap();
        let _k = s.mint().unwrap();
        let ct_bytes = s.encrypt(b"x").unwrap().to_bytes();
        let err = PublisherState::from_bytes(&ct_bytes).unwrap_err();
        assert!(format!("{err}").contains("kind"));
    }

    #[test]
    fn revocation_takes_effect_on_next_encrypt() {
        let mut s = PublisherState::setup_with_seed(Config, [47u8; 32]).unwrap();
        let alice = s.mint().unwrap();
        let bob = s.mint().unwrap();
        s.revoke(&bob).unwrap();
        let ct = s.encrypt(b"no more bob").unwrap();
        assert_eq!(alice.decrypt(&ct).unwrap(), b"no more bob");
        assert!(matches!(bob.decrypt(&ct), Err(Error::NotEntitled)));
    }
}
