//! Byte-oriented BTN broadcast-encryption primitives.
//!
//! This facade keeps the portable wire types as [`Vec<u8>`] while delegating
//! cryptographic work and state management to `tn-btn`.

use crate::{Error, Result};
use tn_btn::{Ciphertext, Config, LeafIndex, PublisherState, ReaderKit};

fn map_btn_error(error: tn_btn::Error) -> Error {
    match error {
        tn_btn::Error::NotEntitled => {
            Error::NotEntitled("no BTN reader kit can open this ciphertext".into())
        }
        error @ (tn_btn::Error::Malformed { .. } | tn_btn::Error::InvalidConfig(_)) => {
            Error::Malformed(error.to_string())
        }
        error @ tn_btn::Error::TreeExhausted { .. } => Error::LimitExceeded(error.to_string()),
        error @ tn_btn::Error::Internal(_) => Error::Btn(error),
    }
}

/// Create a fresh BTN producer.
///
/// # Errors
/// Returns [`Error::Malformed`] if the BTN engine cannot initialize its state.
pub fn setup() -> Result<Producer> {
    Ok(Producer {
        state: PublisherState::setup(Config).map_err(map_btn_error)?,
    })
}

/// Create a subscriber from one or more portable reader-kit values.
///
/// Each item must contain one complete `ReaderKit` wire value. All kits are
/// parsed before the subscriber is returned.
///
/// # Errors
/// Returns [`Error::InvalidArgument`] when `kits` is empty, or
/// [`Error::Malformed`] when any kit is malformed.
pub fn subscribe<I, K>(kits: I) -> Result<Subscriber>
where
    I: IntoIterator<Item = K>,
    K: AsRef<[u8]>,
{
    let kits = kits
        .into_iter()
        .map(|kit| ReaderKit::from_bytes(kit.as_ref()).map_err(map_btn_error))
        .collect::<Result<Vec<_>>>()?;
    if kits.is_empty() {
        return Err(Error::InvalidArgument(
            "btn::subscribe needs at least one reader kit".into(),
        ));
    }
    Ok(Subscriber { kits })
}

/// Stateful BTN producer with authority to mint, revoke, encrypt, and decrypt.
///
/// Serialized producer state contains the master secret and must be protected.
pub struct Producer {
    state: PublisherState,
}

impl Producer {
    /// Restore secret producer state from its portable wire representation.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when `bytes` is not a valid publisher state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            state: PublisherState::from_bytes(bytes).map_err(map_btn_error)?,
        })
    }

    /// Serialize the secret producer state for portable persistence.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.state.to_bytes()
    }

    /// Mint a portable reader kit at the next unused leaf.
    ///
    /// # Errors
    /// Returns [`Error::LimitExceeded`] when the publisher's reader tree is
    /// exhausted.
    pub fn mint(&mut self) -> Result<Vec<u8>> {
        Ok(self.state.mint().map_err(map_btn_error)?.to_bytes())
    }

    /// Encrypt plaintext for the current non-revoked audience.
    ///
    /// # Errors
    /// Returns [`Error::Btn`] if encryption fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .state
            .encrypt(plaintext)
            .map_err(map_btn_error)?
            .to_bytes())
    }

    /// Encrypt plaintext while authenticating out-of-band `aad`.
    ///
    /// # Errors
    /// Returns [`Error::Btn`] if encryption fails.
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .state
            .encrypt_with_aad(plaintext, aad)
            .map_err(map_btn_error)?
            .to_bytes())
    }

    /// Decrypt portable ciphertext directly with the publisher master state.
    ///
    /// This does not mint a reader kit or change [`Self::issued_count`].
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for malformed ciphertext or
    /// [`Error::NotEntitled`] when the producer cannot open it.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = Ciphertext::from_bytes(ciphertext).map_err(map_btn_error)?;
        self.state.decrypt(&ciphertext).map_err(map_btn_error)
    }

    /// Decrypt portable ciphertext with byte-identical out-of-band `aad`.
    ///
    /// This does not mint a reader kit or change [`Self::issued_count`].
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for malformed ciphertext, or
    /// [`Error::NotEntitled`] for failed entitlement or non-matching AAD.
    pub fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = Ciphertext::from_bytes(ciphertext).map_err(map_btn_error)?;
        self.state
            .decrypt_with_aad(&ciphertext, aad)
            .map_err(map_btn_error)
    }

    /// Revoke the reader identified by a portable reader kit.
    ///
    /// Revocation affects ciphertext created after this call only.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when the kit is malformed, or [`Error::Btn`]
    /// when it belongs to another publisher.
    pub fn revoke(&mut self, kit: impl AsRef<[u8]>) -> Result<()> {
        let kit = ReaderKit::from_bytes(kit.as_ref()).map_err(map_btn_error)?;
        self.state.revoke(&kit).map_err(map_btn_error)
    }

    /// Revoke a reader directly by leaf index.
    ///
    /// # Errors
    /// Returns [`Error::Btn`] when `leaf` is outside the configured tree.
    pub fn revoke_by_leaf(&mut self, leaf: u64) -> Result<()> {
        self.state
            .revoke_by_leaf(LeafIndex(leaf))
            .map_err(map_btn_error)
    }

    /// Number of currently active reader kits.
    #[must_use]
    pub fn issued_count(&self) -> usize {
        self.state.issued_count()
    }

    /// Number of revoked readers.
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.state.revoked_count()
    }

    /// Stable 32-byte identifier for this producer state.
    #[must_use]
    pub fn publisher_id(&self) -> [u8; 32] {
        self.state.publisher_id()
    }

    /// Current producer epoch.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.state.epoch()
    }
}

/// BTN reader holding one or more parsed portable reader kits.
pub struct Subscriber {
    kits: Vec<ReaderKit>,
}

impl std::fmt::Debug for Subscriber {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Subscriber")
            .field("kit_count", &self.kits.len())
            .finish()
    }
}

impl Subscriber {
    /// Parse and add another portable reader kit.
    ///
    /// The subscriber is unchanged if parsing fails.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] when `kit` is malformed.
    pub fn add_key(&mut self, kit: impl AsRef<[u8]>) -> Result<()> {
        let kit = ReaderKit::from_bytes(kit.as_ref()).map_err(map_btn_error)?;
        self.kits.push(kit);
        Ok(())
    }

    /// Decrypt portable ciphertext with the first held kit that can open it.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for malformed ciphertext or
    /// [`Error::NotEntitled`] when no held kit is entitled.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(ciphertext, &[])
    }

    /// Decrypt portable ciphertext with byte-identical out-of-band `aad`.
    ///
    /// The ciphertext is parsed once, then every held kit is tried in order.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for malformed ciphertext,
    /// [`Error::NotEntitled`] when no held kit opens it, or [`Error::Btn`] for
    /// an unexpected internal BTN failure.
    pub fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = Ciphertext::from_bytes(ciphertext).map_err(map_btn_error)?;
        for kit in &self.kits {
            match kit.decrypt_with_aad(&ciphertext, aad) {
                Ok(plaintext) => return Ok(plaintext),
                Err(tn_btn::Error::NotEntitled) => {}
                Err(error) => return Err(map_btn_error(error)),
            }
        }
        Err(Error::NotEntitled(
            "no held BTN reader kit can open this ciphertext".into(),
        ))
    }
}
