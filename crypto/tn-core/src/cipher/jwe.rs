//! Native TN-wrapped compact JWE group cipher.
//!
//! Each ciphertext contains one `dir`/`A256GCM` compact JWE body and a
//! `tn-sealed-box-v1` content-key wrap for every configured recipient DID.
//! Runtime construction is wired separately; this module owns only the cipher.

#[cfg(feature = "fs")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "fs")]
use base64::Engine as _;
#[cfg(feature = "fs")]
use biscuit::jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm};
#[cfg(feature = "fs")]
use biscuit::jwe::{Compact, Header, RegisteredHeader};
#[cfg(feature = "fs")]
use biscuit::jwk::JWK;
#[cfg(feature = "fs")]
use biscuit::Empty;
#[cfg(feature = "fs")]
use rand_core::RngCore as _;
#[cfg(feature = "fs")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "fs")]
use serde_json::{json, Map, Value};
#[cfg(feature = "fs")]
use zeroize::Zeroizing;

#[cfg(feature = "fs")]
use crate::canonical::canonical_bytes;
#[cfg(feature = "fs")]
use crate::recipient_seal::{
    normalize_recipient_dids, seal_key_for_recipient, unseal_key_from_wrap,
};
#[cfg(feature = "fs")]
use crate::{DeviceKey, Error, Result};

#[cfg(feature = "fs")]
const FRAME: &str = "tn-jwe-v1";
#[cfg(feature = "fs")]
const MAX_RECIPIENT_WRAPS: usize = 1_024;

#[cfg(feature = "fs")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JweFrame {
    frame: String,
    body: String,
    recipient_wraps: Vec<Value>,
}

#[cfg(feature = "fs")]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct TnProtectedHeader {
    tn_frame: String,
    tn_aad: String,
}

/// A TN-wrapped compact JWE cipher bound to configured recipients and a device.
#[cfg(feature = "fs")]
pub struct JweCipher {
    recipient_dids: Vec<String>,
    local_did: String,
    device_seed: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "fs")]
impl JweCipher {
    /// Bind a cipher to normalized recipient DIDs and the local device key.
    pub fn new(recipient_dids: &[String], device: &DeviceKey) -> Result<Self> {
        Ok(Self {
            recipient_dids: normalize_recipient_dids(recipient_dids)?,
            local_did: device.did().to_owned(),
            device_seed: Zeroizing::new(device.private_bytes()),
        })
    }
}

#[cfg(feature = "fs")]
fn encrypt_body(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<String> {
    let header = Header {
        registered: RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::DirectSymmetricKey,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            ..Default::default()
        },
        private: TnProtectedHeader {
            tn_frame: FRAME.to_owned(),
            tn_aad: URL_SAFE_NO_PAD.encode(aad),
        },
        ..Default::default()
    };
    let key: JWK<Empty> = JWK::new_octet_key(key, Empty::default());
    let mut nonce = [0_u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let options = EncryptionOptions::AES_GCM {
        nonce: nonce.to_vec(),
    };
    let jwe = Compact::new_decrypted(header, plaintext.to_vec());
    let encrypted = jwe
        .encrypt(&key, &options)
        .map_err(|error| Error::Cipher(format!("JWE body encryption failed: {error}")))?;
    encrypted
        .encrypted()
        .map(ToString::to_string)
        .map_err(|error| Error::Internal(format!("Biscuit returned a decrypted JWE: {error}")))
}

#[cfg(feature = "fs")]
fn decrypt_body(body: &str, key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>> {
    let key: JWK<Empty> = JWK::new_octet_key(key, Empty::default());
    let encrypted = Compact::<Vec<u8>, TnProtectedHeader>::new_encrypted(body);
    let decrypted = encrypted
        .decrypt(
            &key,
            KeyManagementAlgorithm::DirectSymmetricKey,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .map_err(|error| malformed_body(error.to_string()))?;
    let header = decrypted
        .header()
        .map_err(|error| Error::Internal(format!("Biscuit returned an encrypted JWE: {error}")))?;
    if header.private.tn_frame != FRAME {
        return Err(malformed_body("protected tn_frame does not match"));
    }
    if header.private.tn_aad != URL_SAFE_NO_PAD.encode(aad) {
        return Err(Error::Cipher("JWE protected AAD does not match".into()));
    }
    decrypted
        .payload()
        .cloned()
        .map_err(|error| Error::Internal(format!("Biscuit returned an encrypted JWE: {error}")))
}

#[cfg(feature = "fs")]
fn wrap_aad(body: &str) -> Result<Vec<u8>> {
    canonical_bytes(&json!({ "frame": FRAME, "body": body }))
}

#[cfg(feature = "fs")]
fn parse_frame(ciphertext: &[u8]) -> Result<JweFrame> {
    let parsed: JweFrame =
        serde_json::from_slice(ciphertext).map_err(|error| malformed_frame(error.to_string()))?;
    if parsed.frame != FRAME {
        return Err(malformed_frame(format!(
            "unsupported frame {:?}",
            parsed.frame
        )));
    }
    if parsed.recipient_wraps.len() > MAX_RECIPIENT_WRAPS {
        return Err(malformed_frame(
            "recipient_wraps contains more than 1,024 entries",
        ));
    }
    Ok(parsed)
}

#[cfg(feature = "fs")]
fn select_local_wrap<'a>(wraps: &'a [Value], local_did: &str) -> Result<&'a Map<String, Value>> {
    for value in wraps {
        let wrap = value
            .as_object()
            .ok_or_else(|| malformed_frame("recipient wrap must be an object"))?;
        let recipient = wrap
            .get("recipient_identity")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed_frame("recipient wrap requires recipient_identity"))?;
        if recipient == local_did {
            return Ok(wrap);
        }
    }
    Err(Error::NotEntitled {
        group: "jwe".to_owned(),
    })
}

#[cfg(feature = "fs")]
fn malformed_frame(reason: impl Into<String>) -> Error {
    Error::Malformed {
        kind: "JWE frame",
        reason: reason.into(),
    }
}

#[cfg(feature = "fs")]
fn malformed_body(reason: impl Into<String>) -> Error {
    Error::Malformed {
        kind: "JWE body",
        reason: reason.into(),
    }
}

#[cfg(feature = "fs")]
impl super::GroupCipher for JweCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(plaintext, &[])
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(ciphertext, &[])
    }

    fn kind(&self) -> &'static str {
        "jwe"
    }

    fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut content_key = Zeroizing::new([0_u8; 32]);
        rand_core::OsRng.fill_bytes(&mut content_key[..]);
        let body = encrypt_body(plaintext, &content_key, aad)?;
        let wrap_aad = wrap_aad(&body)?;
        let recipient_wraps = self
            .recipient_dids
            .iter()
            .map(|did| seal_key_for_recipient(&content_key, did, &wrap_aad))
            .collect::<Result<Vec<_>>>()?;
        serde_json::to_vec(&JweFrame {
            frame: FRAME.to_owned(),
            body,
            recipient_wraps,
        })
        .map_err(|error| Error::Cipher(format!("JWE frame serialization failed: {error}")))
    }

    fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let frame = parse_frame(ciphertext)?;
        let wrap = select_local_wrap(&frame.recipient_wraps, &self.local_did)?;
        let wrap_aad = wrap_aad(&frame.body)?;
        let content_key = Zeroizing::new(unseal_key_from_wrap(wrap, &self.device_seed, &wrap_aad)?);
        decrypt_body(&frame.body, &content_key, aad)
    }
}

#[cfg(all(test, feature = "fs"))]
mod tests {
    use super::*;
    use crate::cipher::GroupCipher as _;
    use crate::DeviceKey;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{json, Value};

    #[test]
    fn named_recipient_round_trips_and_stranger_is_not_entitled() {
        let writer = DeviceKey::from_private_bytes(&[1_u8; 32]).unwrap();
        let reader = DeviceKey::from_private_bytes(&[2_u8; 32]).unwrap();
        let stranger = DeviceKey::from_private_bytes(&[3_u8; 32]).unwrap();
        let recipients = vec![reader.did().to_owned()];
        let sealer = JweCipher::new(&recipients, &writer).unwrap();
        let opener = JweCipher::new(&recipients, &reader).unwrap();
        let denied = JweCipher::new(&recipients, &stranger).unwrap();
        let ciphertext = sealer.encrypt_with_aad(b"secret", b"marker").unwrap();

        assert_eq!(
            opener.decrypt_with_aad(&ciphertext, b"marker").unwrap(),
            b"secret"
        );
        assert!(matches!(
            denied.decrypt_with_aad(&ciphertext, b"marker"),
            Err(Error::NotEntitled { .. })
        ));
        assert!(opener.decrypt_with_aad(&ciphertext, b"wrong").is_err());
    }

    #[test]
    fn frame_and_protected_header_pin_the_wire_contract() {
        let writer = DeviceKey::from_private_bytes(&[4_u8; 32]).unwrap();
        let reader = DeviceKey::from_private_bytes(&[5_u8; 32]).unwrap();
        let recipients = vec![reader.did().to_owned()];
        let cipher = JweCipher::new(&recipients, &writer).unwrap();
        let ciphertext = cipher.encrypt_with_aad(b"secret", b"marker").unwrap();
        let frame: Value = serde_json::from_slice(&ciphertext).unwrap();
        let frame_object = frame.as_object().unwrap();
        let mut frame_keys: Vec<_> = frame_object.keys().map(String::as_str).collect();
        frame_keys.sort_unstable();

        assert_eq!(frame_keys, ["body", "frame", "recipient_wraps"]);
        assert_eq!(frame["frame"], "tn-jwe-v1");
        assert_eq!(frame["recipient_wraps"].as_array().unwrap().len(), 1);

        let body = frame["body"].as_str().unwrap();
        assert_eq!(body.split('.').count(), 5);
        let protected_segment = body.split('.').next().unwrap();
        let protected_bytes = URL_SAFE_NO_PAD.decode(protected_segment).unwrap();
        let protected: Value = serde_json::from_slice(&protected_bytes).unwrap();

        assert_eq!(protected["alg"], "dir");
        assert_eq!(protected["enc"], "A256GCM");
        assert_eq!(protected["tn_frame"], "tn-jwe-v1");
        assert_eq!(protected["tn_aad"], URL_SAFE_NO_PAD.encode(b"marker"));
    }

    #[test]
    fn excessive_recipient_wraps_are_rejected_before_unwrap() {
        let reader = DeviceKey::from_private_bytes(&[6_u8; 32]).unwrap();
        let recipients = vec![reader.did().to_owned()];
        let cipher = JweCipher::new(&recipients, &reader).unwrap();
        let malformed_wrap = json!({ "recipient_identity": reader.did() });
        let oversized = json!({
            "frame": "tn-jwe-v1",
            "body": "not-a-compact-jwe",
            "recipient_wraps": vec![malformed_wrap; 1_025],
        });

        let error = cipher
            .decrypt(&serde_json::to_vec(&oversized).unwrap())
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Malformed {
                kind: "JWE frame",
                ref reason,
            } if reason.contains("1,024")
        ));
    }
}
