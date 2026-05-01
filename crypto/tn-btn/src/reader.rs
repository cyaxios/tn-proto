//! Reader-side kit: what the publisher hands out at mint time.
//!
//! A [`ReaderKit`] bundles:
//!
//! - `publisher_id` — so the reader can reject ciphertexts from a
//!   different publisher up-front.
//! - `epoch` — so the reader can reject ciphertexts from a different
//!   epoch (after a rotation).
//! - A [`ReaderKeyset`] — the actual decryption key material.
//!
//! In v0.1 the kit is an in-memory struct. Wire-format serialization
//! ships in a later commit; at that point the kit becomes the
//! conceptual `.tnpkg` artifact the publisher hands out once per
//! mint.

use crate::ciphertext::Ciphertext;
use crate::error::{Error, Result};
use crate::tree::subset::ReaderKeyset;
use crate::tree::LeafIndex;

/// A single reader's material: publisher binding + keyset.
///
/// Created via [`crate::PublisherState::mint`]. Opaque to the reader;
/// they only ever call [`Self::decrypt`] with ciphertexts the
/// publisher produced.
#[derive(Clone)]
pub struct ReaderKit {
    publisher_id: [u8; 32],
    epoch: u32,
    keyset: ReaderKeyset,
}

impl ReaderKit {
    /// Internal constructor. Publisher-only; readers don't mint their
    /// own kits.
    #[must_use]
    pub(crate) fn new(publisher_id: [u8; 32], epoch: u32, keyset: ReaderKeyset) -> Self {
        Self {
            publisher_id,
            epoch,
            keyset,
        }
    }

    /// Publisher identifier this kit is bound to. Matches the
    /// `publisher_id` on every ciphertext from that publisher.
    #[inline]
    #[must_use]
    pub fn publisher_id(&self) -> [u8; 32] {
        self.publisher_id
    }

    /// Epoch this kit is bound to.
    #[inline]
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The leaf this reader occupies in the publisher's tree.
    #[inline]
    #[must_use]
    pub fn leaf(&self) -> LeafIndex {
        self.keyset.leaf
    }

    /// Access the underlying keyset. Mainly for testing and advanced
    /// scenarios where the caller wants to invoke free-function
    /// primitives directly.
    #[inline]
    #[must_use]
    pub fn keyset(&self) -> &ReaderKeyset {
        &self.keyset
    }

    /// Try to decrypt `ct` with this kit.
    ///
    /// First checks that `ct.publisher_id` and `ct.epoch` match. If
    /// either differs, returns [`Error::NotEntitled`] immediately —
    /// no cryptographic work is performed. Otherwise delegates to
    /// [`crate::decrypt_with_keyset`].
    ///
    /// # Errors
    /// Returns [`Error::NotEntitled`] on publisher/epoch mismatch or
    /// if no cover entry unwraps under this keyset (reader revoked
    /// before the ciphertext was produced, or tampered ciphertext).
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<Vec<u8>> {
        if ct.publisher_id != self.publisher_id || ct.epoch != self.epoch {
            return Err(Error::NotEntitled);
        }
        crate::decrypt_with_keyset(&self.keyset, ct)
    }
}

impl std::fmt::Debug for ReaderKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderKit")
            .field("publisher_id", &hex::encode(self.publisher_id))
            .field("epoch", &self.epoch)
            .field("leaf", &self.keyset.leaf)
            .field("keyset", &"[REDACTED]")
            .finish()
    }
}
