//! AES Key Wrap (RFC 3394) wrapper.
//!
//! Used to wrap a 32-byte CEK under each subset key in a `btn`
//! ciphertext. Deterministic, fixed-size output (40 bytes from a
//! 32-byte input).

use crate::crypto::prg::KEY_LEN;

/// Size of an AES-KW-wrapped 32-byte key: 32 + 8 IV bytes = 40.
pub const WRAPPED_LEN: usize = 40;

/// Wrap a 32-byte CEK under a 32-byte KEK.
///
/// # Errors
/// Returns `Err(())` only on internal failure; AES-KW cannot fail for
/// valid inputs of the fixed sizes we use.
#[allow(clippy::result_unit_err)]
pub fn wrap(kek: &[u8; KEY_LEN], cek: &[u8; KEY_LEN]) -> Result<[u8; WRAPPED_LEN], ()> {
    let mut out = [0u8; WRAPPED_LEN];
    aes_kw::Kek::from(*kek)
        .wrap(cek, &mut out)
        .map_err(|_| ())?;
    Ok(out)
}

/// Unwrap a 40-byte wrapped key under a 32-byte KEK.
///
/// # Errors
/// Returns `Err(())` if the wrap's integrity check fails (wrong KEK,
/// tampered bytes, malformed input).
#[allow(clippy::result_unit_err)]
pub fn unwrap(kek: &[u8; KEY_LEN], wrapped: &[u8; WRAPPED_LEN]) -> Result<[u8; KEY_LEN], ()> {
    let mut out = [0u8; KEY_LEN];
    aes_kw::Kek::from(*kek)
        .unwrap(wrapped, &mut out)
        .map_err(|_| ())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let kek = [0x11u8; KEY_LEN];
        let cek = [0x22u8; KEY_LEN];
        let w = wrap(&kek, &cek).unwrap();
        let u = unwrap(&kek, &w).unwrap();
        assert_eq!(u, cek);
    }

    #[test]
    fn unwrap_wrong_kek_fails() {
        let kek = [0x33u8; KEY_LEN];
        let wrong = [0x44u8; KEY_LEN];
        let cek = [0x55u8; KEY_LEN];
        let w = wrap(&kek, &cek).unwrap();
        assert!(unwrap(&wrong, &w).is_err());
    }

    #[test]
    fn wrap_is_deterministic() {
        let kek = [0x66u8; KEY_LEN];
        let cek = [0x77u8; KEY_LEN];
        let a = wrap(&kek, &cek).unwrap();
        let b = wrap(&kek, &cek).unwrap();
        assert_eq!(a, b, "AES-KW must be deterministic for the same inputs");
    }
}
