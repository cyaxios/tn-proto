//! The [`GroupCipher`] extension point and its per-group implementations
//! (`btn`, `jwe`, `bgw`).
//!
//! A TN group's confidentiality is defined by its cipher. [`GroupCipher`] is
//! the trait the [`crate::Runtime`] holds one of per group: it seals plaintext
//! when writing an attested event and opens ciphertext when reading one back.
//! The selection is driven by the group's `cipher:` field in `tn.yaml`.
//!
//! `btn` is first-class in tn-core (see [`btn`]). `jwe` stays Python-owned for
//! this plan — a JWE group configured in a yaml yields a clear
//! [`crate::Error::NotImplemented`] from the Rust runtime. `bgw` is stubbed
//! behind the `bgw` feature flag.

#[cfg(feature = "bgw")]
pub mod bgw;
pub mod btn;
pub mod jwe;

use crate::Result;

/// The pluggable per-group encryption surface.
///
/// An implementor binds a concrete cipher to a concrete party — a btn
/// publisher, a btn reader at a given leaf, JWE, BGW — and exposes the two
/// directional operations the [`crate::Runtime`] needs: seal (publisher-side)
/// and open (reader-side). One `GroupCipher` corresponds to one group's
/// material for one party; the runtime selects it from the group's `cipher:`
/// config. Implementations must be `Send + Sync` so a single instance can back
/// concurrent reads and writes.
///
/// `encrypt` and `decrypt` are not required to round-trip *within one
/// instance*: a reader-side cipher may only open, and a publisher-side cipher
/// is not obligated to open what it sealed. The binding invariant is that a
/// ciphertext produced by a group's publisher opens for any entitled reader of
/// that group.
pub trait GroupCipher: Send + Sync {
    /// Seal `plaintext` into ciphertext for the envelope's `ciphertext` field.
    ///
    /// The publisher-side direction. Returns the raw cipher output bytes (no
    /// envelope framing — the runtime wraps them). For btn this advances no
    /// state the caller must observe; the bytes are self-describing to entitled
    /// readers.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if this party cannot seal for the group (for
    /// example a reader-only cipher, surfaced as
    /// [`crate::Error::NotAPublisher`]) or if the underlying cipher fails.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Open `ciphertext` back into plaintext bytes.
    ///
    /// The reader-side direction; inverse of [`encrypt`](Self::encrypt) for an
    /// entitled party. The input is the raw bytes from the envelope's
    /// `ciphertext` field.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotEntitled`] if this party holds no key that
    /// opens this ciphertext — e.g. a btn reader whose leaf was revoked before
    /// the ciphertext was produced — and other [`crate::Error`] variants on
    /// malformed input or cipher failure.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Return the stable cipher identifier (`"btn"`, `"jwe"`, `"bgw"`).
    ///
    /// Used in logs and diagnostics and to tag which cipher produced a record;
    /// must match the `cipher:` value that selects this implementation.
    fn kind(&self) -> &'static str;
}
