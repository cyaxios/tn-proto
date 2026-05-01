//! btn cipher adapter: wraps `tn_btn::PublisherState` and `tn_btn::ReaderKit`.
//!
//! Two types:
//!
//! - [`BtnPublisherCipher`] — holds a `PublisherState`. `encrypt()` produces
//!   wire-format ciphertext bytes. `decrypt()` either delegates to an attached
//!   reader kit (publisher-as-reader pattern, matching Python's `.btn.mykit`)
//!   or returns `Error::NotEntitled`.
//! - [`BtnReaderCipher`] — holds a `ReaderKit` (by its wire bytes so it can
//!   be cheaply cloned and persisted). `decrypt()` works; `encrypt()` returns
//!   `Error::NotAPublisher`.
//!
//! ## Keystore layout (mirrors Python `BtnGroupCipher`)
//!
//! ```text
//! <keystore>/<group>.btn.state   serialized PublisherState (SECRET)
//! <keystore>/<group>.btn.mykit   self-kit bytes (publisher's own reader slot)
//! ```
//!
//! The publisher mints a kit for itself at creation time so the same party
//! can both write and read (the `with_reader_kit` pattern).

use crate::{Error, Result};
use tn_btn::{Ciphertext, PublisherState, ReaderKit};

// ---------------------------------------------------------------------------
// BtnPublisherCipher
// ---------------------------------------------------------------------------

/// Publisher-side btn cipher.
///
/// Holds a `PublisherState` for encryption.  Optionally holds one or more
/// reader kits (wire bytes) for self-decryption, enabling the
/// publisher-as-reader pattern used by Python's `BtnGroupCipher`.
///
/// Multiple kits support the rotation-with-preservation model: after
/// `tn.rotate`, the current self-kit (post-rotation) sits alongside
/// previous `.btn.mykit.revoked.<ts>` kits. The Runtime loads all of them
/// and tries each on every decrypt so pre-rotation entries stay readable.
pub struct BtnPublisherCipher {
    state: PublisherState,
    reader: Option<BtnReaderCipher>,
}

impl BtnPublisherCipher {
    /// Construct from an already-loaded `PublisherState`.
    pub fn from_state(state: PublisherState) -> Self {
        Self {
            state,
            reader: None,
        }
    }

    /// Attach a reader kit so that `decrypt()` works on this publisher.
    ///
    /// `kit_bytes` must be a valid `ReaderKit` wire blob (the bytes produced
    /// by `tn_btn::ReaderKit::to_bytes()`).
    ///
    /// # Errors
    /// Returns `Error::Btn` if `kit_bytes` cannot be parsed as a `ReaderKit`.
    pub fn with_reader_kit(mut self, kit_bytes: &[u8]) -> Result<Self> {
        self.reader = Some(BtnReaderCipher::from_kit_bytes(kit_bytes)?);
        Ok(self)
    }

    /// Attach multiple reader kits so that `decrypt()` works across rotation
    /// boundaries — the current kit plus any preserved pre-rotation kits.
    ///
    /// Kits are tried in order; first successful decrypt wins. Typical
    /// ordering: current kit first, then rotation-preserved kits.
    ///
    /// # Errors
    /// Returns `Error::Btn` if any blob is malformed, or
    /// `Error::InvalidConfig` if the input is empty.
    pub fn with_reader_kits(mut self, kits: &[impl AsRef<[u8]>]) -> Result<Self> {
        self.reader = Some(BtnReaderCipher::from_multi_kit_bytes(kits)?);
        Ok(self)
    }

    /// Deserialize a `PublisherState` from its wire bytes and construct the
    /// cipher.
    ///
    /// # Errors
    /// Returns `Error::Btn` if the bytes are malformed.
    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self> {
        let state = PublisherState::from_bytes(bytes)?;
        Ok(Self::from_state(state))
    }

    /// Access the underlying `PublisherState` (e.g. to call `mint` or
    /// `revoke`).
    pub fn state(&self) -> &PublisherState {
        &self.state
    }

    /// Mutable access to the underlying `PublisherState`.
    pub fn state_mut(&mut self) -> &mut PublisherState {
        &mut self.state
    }

    /// Serialize the publisher state to bytes for persistence.
    #[must_use]
    pub fn state_to_bytes(&self) -> Vec<u8> {
        self.state.to_bytes()
    }
}

impl super::GroupCipher for BtnPublisherCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ct: Ciphertext = self.state.encrypt(plaintext)?;
        Ok(ct.to_bytes())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match &self.reader {
            Some(r) => r.decrypt(ciphertext),
            None => Err(Error::NotEntitled {
                group: "btn".into(),
            }),
        }
    }

    fn kind(&self) -> &'static str {
        "btn"
    }
}

// ---------------------------------------------------------------------------
// BtnReaderCipher
// ---------------------------------------------------------------------------

/// Reader-side btn cipher.
///
/// Holds one or more parsed `ReaderKit`s. On `decrypt()`, tries each kit
/// in order until one succeeds; returns `Error::NotEntitled` if none do.
///
/// The multi-kit form is how rotation-preserving reads work: after
/// `tn.rotate`, the post-rotation self-kit lives at `<group>.btn.mykit`
/// and pre-rotation kits live at `<group>.btn.mykit.revoked.<ts>`. The
/// Runtime loads all of them into a single BtnReaderCipher so
/// `tn.read()` decrypts seamlessly across rotation boundaries.
pub struct BtnReaderCipher {
    kits: Vec<ReaderKit>,
}

impl BtnReaderCipher {
    /// Construct from one kit's wire bytes (produced by
    /// `tn_btn::ReaderKit::to_bytes()`).
    ///
    /// # Errors
    /// Returns `Error::Btn` if the bytes are malformed.
    pub fn from_kit_bytes(kit_bytes: &[u8]) -> Result<Self> {
        let kit = ReaderKit::from_bytes(kit_bytes)?;
        Ok(Self { kits: vec![kit] })
    }

    /// Construct from multiple kits' wire bytes.
    ///
    /// Each byte slice is a standalone `ReaderKit::to_bytes()` blob.
    /// On decrypt, kits are tried in order; the first successful decrypt
    /// wins. Pass them in "most likely to work" order — for rotation
    /// scenarios that's usually the current kit first, revoked kits after.
    ///
    /// # Errors
    /// Returns `Error::Btn` if any blob is malformed, or
    /// `Error::InvalidConfig` if the input is empty.
    pub fn from_multi_kit_bytes(kits: &[impl AsRef<[u8]>]) -> Result<Self> {
        if kits.is_empty() {
            return Err(Error::InvalidConfig(
                "BtnReaderCipher::from_multi_kit_bytes needs at least one kit".into(),
            ));
        }
        let parsed: Result<Vec<ReaderKit>> = kits
            .iter()
            .map(|b| ReaderKit::from_bytes(b.as_ref()).map_err(Error::from))
            .collect();
        Ok(Self { kits: parsed? })
    }

    /// Access the underlying `ReaderKit`s.
    pub fn kits(&self) -> &[ReaderKit] {
        &self.kits
    }

    /// How many kits this cipher holds. ≥1.
    pub fn kit_count(&self) -> usize {
        self.kits.len()
    }
}

impl super::GroupCipher for BtnReaderCipher {
    fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::NotAPublisher {
            group: "btn".into(),
            reason: "reader-side cipher cannot encrypt; only the publisher holds the master seed"
                .into(),
        })
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ct = Ciphertext::from_bytes(ciphertext)?;
        // Try each kit; first one that decrypts wins. Kits that aren't
        // entitled for this ciphertext return tn_btn::Error::NotEntitled
        // (or similar) — skip to the next.
        let mut last_err: Option<Error> = None;
        for kit in &self.kits {
            match kit.decrypt(&ct) {
                Ok(pt) => return Ok(pt),
                Err(e) => last_err = Some(Error::from(e)),
            }
        }
        Err(last_err.unwrap_or(Error::NotEntitled {
            group: "btn".into(),
        }))
    }

    fn kind(&self) -> &'static str {
        "btn"
    }
}
