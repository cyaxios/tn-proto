//! The [`GroupCipher`] extension point and its per-group implementations
//! (`btn`, `jwe`, `hibe`).
//!
//! A TN group's confidentiality is defined by its cipher. [`GroupCipher`] is
//! the trait the [`crate::Runtime`] holds one of per group: it seals plaintext
//! when writing an attested event and opens ciphertext when reading one back.
//! The selection is driven by the group's `cipher:` field in `tn.yaml`.
//!
//! `btn` is first-class in tn-core (see [`btn`]). Native builds also support
//! RFC 7516 General JSON JWE with raw X25519 enrollment keys (see [`jwe`]).

pub mod btn;
pub mod hibe;
pub mod jwe;

use crate::Result;

/// The pluggable per-group encryption surface.
///
/// An implementor binds a concrete cipher to a concrete party — a btn
/// publisher, a btn reader at a given leaf, JWE — and exposes the two
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

    /// Return the stable cipher identifier (`"btn"`, `"hibe"`, `"jwe"`).
    ///
    /// Used in logs and diagnostics and to tag which cipher produced a record;
    /// must match the `cipher:` value that selects this implementation.
    fn kind(&self) -> &'static str;

    /// Seal `plaintext` binding `aad` (additional authenticated data) into
    /// the body's authentication tag. `aad` is authenticated, not encrypted.
    /// A cipher may carry it in its standard wire form (JWE does); the reader
    /// must still supply byte-identical `aad` to
    /// [`decrypt_with_aad`](Self::decrypt_with_aad).
    ///
    /// The default delegates to [`encrypt`](Self::encrypt) for an EMPTY
    /// `aad` (so the no-marker path stays byte-identical) and rejects a
    /// non-empty `aad` — a cipher that supports markers overrides this.
    ///
    /// # Errors
    /// Same as [`encrypt`](Self::encrypt); plus [`crate::Error::NotImplemented`]
    /// if a non-empty `aad` is passed to a cipher without marker support.
    fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if aad.is_empty() {
            self.encrypt(plaintext)
        } else {
            Err(crate::Error::NotImplemented(
                "this cipher does not support AAD (marker) binding",
            ))
        }
    }

    /// Open `ciphertext` requiring the same `aad` bound at seal time. A
    /// different or absent `aad` fails the tag. Default: delegate to
    /// [`decrypt`](Self::decrypt) for an empty `aad`, reject non-empty.
    ///
    /// # Errors
    /// Same as [`decrypt`](Self::decrypt); plus [`crate::Error::NotImplemented`]
    /// for a non-empty `aad` on a cipher without marker support.
    fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if aad.is_empty() {
            self.decrypt(ciphertext)
        } else {
            Err(crate::Error::NotImplemented(
                "this cipher does not support AAD (marker) binding",
            ))
        }
    }
}
