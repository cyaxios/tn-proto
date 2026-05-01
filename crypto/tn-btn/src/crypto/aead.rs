//! AES-256-GCM authenticated encryption wrapper.
//!
//! Thin convenience layer over the `aes-gcm` crate. Exposes just
//! what `btn` needs: seal a plaintext under a 32-byte key with a
//! 12-byte nonce, open it, produce random nonces.

use crate::crypto::prg::KEY_LEN;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};

/// AES-GCM nonce size (96 bits).
pub const NONCE_LEN: usize = 12;

/// Generate a fresh random 12-byte nonce from the OS CSPRNG.
#[must_use]
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// Seal `plaintext` under `key` with `nonce`, optionally binding
/// `aad` (additional authenticated data).
///
/// Returns ciphertext with the 16-byte AES-GCM tag appended.
///
/// # Errors
/// Returns `Err(())` on internal failure (should not happen with
/// valid inputs; the `aes-gcm` crate only errors on memory
/// allocation issues).
#[allow(clippy::result_unit_err)]
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ())
}

/// Open `ciphertext` under `key` with `nonce` and `aad`. Returns the
/// original plaintext on success.
///
/// # Errors
/// Returns `Err(())` if authentication fails (wrong key, nonce, aad,
/// or tampered ciphertext). No detail is leaked about which.
#[allow(clippy::result_unit_err)]
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let plaintext = b"hello broadcast world";
        let aad = b"binding";
        let ct = seal(&key, &nonce, plaintext, aad).unwrap();
        let pt = open(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn open_wrong_key_fails() {
        let key = [0x11u8; KEY_LEN];
        let wrong = [0x22u8; KEY_LEN];
        let nonce = [0x33u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"payload", b"").unwrap();
        assert!(open(&wrong, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn open_wrong_aad_fails() {
        let key = [0x44u8; KEY_LEN];
        let nonce = [0x55u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"payload", b"aad-a").unwrap();
        assert!(open(&key, &nonce, &ct, b"aad-b").is_err());
    }

    #[test]
    fn random_nonces_are_distinct() {
        let a = random_nonce();
        let b = random_nonce();
        assert_ne!(a, b, "random_nonce collision — OsRng broken?");
    }
}
