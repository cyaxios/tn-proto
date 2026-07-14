//! Standard RFC 7516 General JSON JWE bindings.

use curve25519_dalek::montgomery::MontgomeryPoint;
use rand_core::RngCore as _;
use wasm_bindgen::{JsCast as _, JsError, JsValue};
use zeroize::Zeroizing;

use tn_core::cipher::{jwe::JweCipher, GroupCipher as _};

const KEY_BYTES: usize = 32;
const MAX_KEYS: usize = 1_024;

/// Mint a raw X25519 keypair. The private half belongs only in the reader's
/// keystore; publishers enroll the public half.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = "jweKeygen")]
pub fn keygen_js() -> Result<JsValue, JsError> {
    let mut private = Zeroizing::new([0_u8; KEY_BYTES]);
    rand_core::OsRng.fill_bytes(&mut private[..]);
    let public = MontgomeryPoint::mul_base_clamped(*private).to_bytes();

    let pair = js_sys::Object::new();
    set_bytes(&pair, "publicKey", &public)?;
    set_bytes(&pair, "privateKey", &private[..])?;
    Ok(pair.into())
}

/// Encrypt bytes to one or more raw X25519 public keys.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = "jweEncrypt")]
pub fn encrypt_js(
    plaintext: &[u8],
    recipient_public_keys: Vec<JsValue>,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let recipients = parse_keys(recipient_public_keys, "recipient public keys")?;
    let cipher = JweCipher::new("wasm", &recipients, &[]).map_err(to_js_error)?;
    cipher
        .encrypt_with_aad(plaintext, aad.as_deref().unwrap_or(&[]))
        .map_err(to_js_error)
}

/// Decrypt standard General JSON JWE with one or more raw reader private keys.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = "jweDecrypt")]
pub fn decrypt_js(
    ciphertext: &[u8],
    reader_private_keys: Vec<JsValue>,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let readers =
        protect_reader_private_keys(parse_keys(reader_private_keys, "reader private keys")?);
    let cipher = JweCipher::new("wasm", &[], readers.as_slice()).map_err(to_js_error)?;
    cipher
        .decrypt_with_aad(ciphertext, aad.as_deref().unwrap_or(&[]))
        .map_err(to_js_error)
}

fn protect_reader_private_keys(keys: Vec<[u8; KEY_BYTES]>) -> Zeroizing<Vec<[u8; KEY_BYTES]>> {
    Zeroizing::new(keys)
}

fn parse_keys(values: Vec<JsValue>, label: &str) -> Result<Vec<[u8; KEY_BYTES]>, JsError> {
    if values.is_empty() {
        return Err(JsError::new(&format!("{label} cannot be empty")));
    }
    if values.len() > MAX_KEYS {
        return Err(JsError::new(&format!(
            "{label} cannot contain more than {MAX_KEYS} keys"
        )));
    }
    values
        .into_iter()
        .map(|value| parse_key(value, label))
        .collect()
}

fn parse_key(value: JsValue, label: &str) -> Result<[u8; KEY_BYTES], JsError> {
    if !value.is_instance_of::<js_sys::Uint8Array>() {
        return Err(JsError::new(&format!(
            "{label} must contain Uint8Array values"
        )));
    }
    js_sys::Uint8Array::new(&value)
        .to_vec()
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            JsError::new(&format!(
                "{label} must contain raw {KEY_BYTES}-byte X25519 keys, got {}",
                bytes.len()
            ))
        })
}

fn set_bytes(target: &js_sys::Object, name: &str, bytes: &[u8]) -> Result<(), JsError> {
    let value = js_sys::Uint8Array::from(bytes);
    js_sys::Reflect::set(target, &JsValue::from_str(name), &value)
        .map(|_| ())
        .map_err(|error| JsError::new(&format!("failed to set {name}: {error:?}")))
}

fn to_js_error(error: tn_core::Error) -> JsError {
    JsError::new(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    #[test]
    fn reader_private_key_boundary_uses_zeroizing_owner() {
        let readers: Zeroizing<Vec<[u8; KEY_BYTES]>> =
            protect_reader_private_keys(vec![[0xA5; KEY_BYTES]]);

        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>(_: &T) {}
        assert_zeroize_on_drop(&readers);
        assert_eq!(readers.as_slice(), &[[0xA5; KEY_BYTES]]);
    }
}
