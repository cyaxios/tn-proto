//! Rotation primitives: produces a fresh PublisherState and archives the prior one.

use crate::crypto::prg::KEY_LEN;
use crate::error::{Error, Result};
use crate::publisher::PublisherState;
use crate::wire::{KIND_RETIRED_PUBLISHER_STATE, WIRE_MAGIC, WIRE_VERSION};
use zeroize::Zeroizing;

/// A frozen snapshot of a previously-active publisher state. Carries
/// just enough material to decrypt ciphertexts produced under it — the
/// node-key cache is rebuilt on demand from the seed.
#[derive(Debug)]
pub struct RetiredPublisherState {
    pub(crate) master_seed: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) publisher_id: [u8; 32],
    pub(crate) epoch: u32,
    pub(crate) retired_at_unix_secs: u64,
}

impl RetiredPublisherState {
    /// 256-bit publisher_id this state served under.
    #[must_use]
    pub fn publisher_id(&self) -> [u8; 32] {
        self.publisher_id
    }

    /// Epoch this state was active under (0, 1, 2, ...).
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Wall-clock UTC seconds at which this state was retired.
    #[must_use]
    pub fn retired_at_unix_secs(&self) -> u64 {
        self.retired_at_unix_secs
    }

    /// Serialize to bytes. Treat as secret: the master_seed is in the
    /// clear (zeroized in memory on drop, but plain on disk).
    ///
    /// Wire layout:
    /// - magic (1), version (1), kind=0x04 (1)
    /// - master_seed (32)
    /// - publisher_id (32)
    /// - epoch (u32 BE)
    /// - retired_at_unix_secs (u64 BE)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + 32 + 32 + 4 + 8);
        out.push(WIRE_MAGIC);
        out.push(WIRE_VERSION);
        out.push(KIND_RETIRED_PUBLISHER_STATE);
        out.extend_from_slice(self.master_seed.as_ref());
        out.extend_from_slice(&self.publisher_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.retired_at_unix_secs.to_be_bytes());
        out
    }

    /// Deserialize from bytes produced by [`Self::to_bytes`].
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for wrong magic/version/kind, short
    /// read, or trailing bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        const EXPECTED_LEN: usize = 3 + 32 + 32 + 4 + 8;
        if buf.len() != EXPECTED_LEN {
            return Err(Error::Malformed {
                kind: "retired_publisher_state",
                reason: format!("buffer length {} != expected {EXPECTED_LEN}", buf.len()),
            });
        }
        if buf[0] != WIRE_MAGIC {
            return Err(Error::Malformed {
                kind: "retired_publisher_state",
                reason: format!("wrong magic byte {:#x}; expected {WIRE_MAGIC:#x}", buf[0]),
            });
        }
        if buf[1] != WIRE_VERSION {
            return Err(Error::Malformed {
                kind: "retired_publisher_state",
                reason: format!(
                    "unsupported wire version {}; this build supports {WIRE_VERSION}",
                    buf[1]
                ),
            });
        }
        if buf[2] != KIND_RETIRED_PUBLISHER_STATE {
            return Err(Error::Malformed {
                kind: "retired_publisher_state",
                reason: format!(
                    "wrong kind byte {:#x}; expected {KIND_RETIRED_PUBLISHER_STATE:#x} \
                     — did you pass a publisher_state blob?",
                    buf[2]
                ),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&buf[3..3 + 32]);
        let mut publisher_id = [0u8; 32];
        publisher_id.copy_from_slice(&buf[3 + 32..3 + 32 + 32]);
        let epoch = u32::from_be_bytes(
            buf[3 + 32 + 32..3 + 32 + 32 + 4]
                .try_into()
                .expect("4-byte slice; len checked above"),
        );
        let retired_at_unix_secs = u64::from_be_bytes(
            buf[3 + 32 + 32 + 4..]
                .try_into()
                .expect("8-byte slice; len checked above"),
        );
        Ok(Self {
            master_seed: Zeroizing::new(seed),
            publisher_id,
            epoch,
            retired_at_unix_secs,
        })
    }
}

/// Result of `PublisherState::rotate()`. `active` is the new
/// PublisherState the publisher uses for future emits; `retired` is the
/// just-deposed state, archived for keywalk on historical ciphertexts.
#[derive(Debug)]
pub struct RotationOutcome {
    /// Publisher state that becomes active for future emits.
    pub active: PublisherState,
    /// Previously active state, archived for historical decrypts.
    pub retired: RetiredPublisherState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, PublisherState};

    #[test]
    fn retired_state_carries_publisher_id_epoch_and_timestamp() {
        let r = RetiredPublisherState {
            master_seed: Zeroizing::new([7u8; KEY_LEN]),
            publisher_id: [9u8; 32],
            epoch: 3,
            retired_at_unix_secs: 1_700_000_000,
        };
        assert_eq!(r.publisher_id(), [9u8; 32]);
        assert_eq!(r.epoch(), 3);
        assert_eq!(r.retired_at_unix_secs(), 1_700_000_000);
    }

    #[test]
    fn retired_state_wire_round_trip() {
        let original = RetiredPublisherState {
            master_seed: Zeroizing::new([3u8; KEY_LEN]),
            publisher_id: [11u8; 32],
            epoch: 7,
            retired_at_unix_secs: 1_700_123_456,
        };
        let bytes = original.to_bytes();
        let decoded = RetiredPublisherState::from_bytes(&bytes).expect("valid bytes should decode");
        assert_eq!(decoded.publisher_id(), original.publisher_id());
        assert_eq!(decoded.epoch(), original.epoch());
        assert_eq!(
            decoded.retired_at_unix_secs(),
            original.retired_at_unix_secs()
        );
        assert_eq!(*decoded.master_seed, *original.master_seed);
    }

    #[test]
    fn retired_state_rejects_wrong_kind_or_length() {
        // A publisher-state blob has kind 0x03; retired has kind 0x04
        // AND a fixed length. The error surfaces whichever check fails
        // first; either way it's a Malformed.
        let mut s = PublisherState::setup_with_seed(Config, [5u8; 32]).unwrap();
        let _k = s.mint().unwrap();
        let pub_bytes = s.to_bytes();
        let err = RetiredPublisherState::from_bytes(&pub_bytes).unwrap_err();
        assert!(matches!(err, Error::Malformed { .. }));
    }

    #[test]
    fn rotate_produces_distinct_publisher_id_and_increments_epoch() {
        let mut s = PublisherState::setup_with_seed(Config, [42u8; 32]).unwrap();
        let _alice = s.mint().unwrap();
        let prior_publisher_id = s.publisher_id();
        let prior_epoch = s.epoch();
        assert_eq!(prior_epoch, 0);

        let outcome = s.rotate().expect("rotate should succeed");

        assert_eq!(outcome.retired.epoch(), prior_epoch);
        assert_eq!(outcome.retired.publisher_id(), prior_publisher_id);
        assert_eq!(outcome.active.epoch(), prior_epoch + 1);
        assert_ne!(outcome.active.publisher_id(), prior_publisher_id);
    }

    #[test]
    fn mint_after_rotate_uses_new_keytree() {
        let mut s = PublisherState::setup_with_seed(Config, [1u8; 32]).unwrap();
        let pre_kit = s.mint().unwrap();
        let outcome = s.rotate().unwrap();
        let mut active = outcome.active;
        let post_kit = active.mint().unwrap();
        assert_ne!(post_kit.publisher_id(), pre_kit.publisher_id());
        assert_eq!(post_kit.epoch(), 1);
    }

    #[test]
    fn rotate_resets_leaf_bookkeeping() {
        let mut s = PublisherState::setup_with_seed(Config, [13u8; 32]).unwrap();
        let _a = s.mint().unwrap();
        let _b = s.mint().unwrap();
        let c = s.mint().unwrap();
        s.revoke(&c).unwrap();
        assert_eq!(s.issued_count(), 2);
        assert_eq!(s.revoked_count(), 1);

        let outcome = s.rotate().unwrap();
        assert_eq!(outcome.active.issued_count(), 0);
        assert_eq!(outcome.active.revoked_count(), 0);

        let mut active = outcome.active;
        let first = active.mint().unwrap();
        assert_eq!(first.leaf().0, 0);
    }
}
