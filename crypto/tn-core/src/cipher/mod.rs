//! GroupCipher trait and per-group cipher implementations (btn, jwe, bgw).
//!
//! `btn` is first-class in tn-core. `jwe` stays Python-owned for this plan
//! (a JWE group configured in a yaml yields a clear `NotImplemented` error
//! from the Rust runtime). `bgw` is stubbed behind a `bgw` feature flag.

#[cfg(feature = "bgw")]
pub mod bgw;
pub mod btn;
pub mod jwe;

use crate::Result;

/// Pluggable per-group encryption surface.
///
/// Implementors wrap a specific cipher (btn publisher, btn reader, JWE, BGW)
/// and expose the two operations the Runtime needs: encrypt a plaintext
/// (publisher-side) and decrypt a ciphertext (reader-side). `kind()` returns
/// a stable identifier for logs and diagnostics.
pub trait GroupCipher: Send + Sync {
    /// Encrypt `plaintext`. Returns raw ciphertext bytes for the envelope's
    /// `ciphertext` field.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt `ciphertext`. Returns plaintext bytes.
    ///
    /// Returns `Error::NotEntitled` if this party cannot decrypt (e.g. a btn
    /// reader whose leaf was revoked before this ciphertext was produced).
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Human-readable cipher identifier (`"btn"`, `"jwe"`, `"bgw"`).
    fn kind(&self) -> &'static str;
}
