//! Recipient sealed-box wraps for `.tnpkg` body-encryption keys.

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use rand_core::RngCore;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;

use crate::body_encryption::decrypt_body_blob;
use crate::canonical::canonical_bytes;
use crate::tnpkg::Manifest;
use crate::{Error, Result};

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const WRAP_FRAME: &str = "tn-sealed-box-v1";
const WRAP_HKDF_INFO: &[u8] = b"tn-kit-seal-v1";

pub(crate) fn build_recipient_wraps(
    bek: &[u8; 32],
    recipient_dids: &[String],
    manifest: &Manifest,
) -> Result<Vec<Value>> {
    let recipient_dids = normalize_recipient_dids(recipient_dids)?;

    let aad = manifest_aad_for_wrap(manifest)?;
    let mut wraps = Vec::with_capacity(recipient_dids.len());
    for did in &recipient_dids {
        wraps.push(seal_bek_for_recipient(bek, did, &aad)?);
    }
    Ok(wraps)
}

pub(crate) fn normalize_recipient_dids(recipient_dids: &[String]) -> Result<Vec<String>> {
    if recipient_dids.is_empty() {
        return Err(Error::InvalidConfig(
            "recipient sealing requires at least one recipient DID".into(),
        ));
    }

    let mut out = Vec::new();
    for did in recipient_dids {
        did_key_to_ed25519_pub(did)?;
        if !out.iter().any(|seen| seen == did) {
            out.push(did.clone());
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidConfig(
            "recipient sealing requires at least one recipient DID".into(),
        ));
    }
    Ok(out)
}

pub(crate) fn manifest_aad_for_wrap(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut doc = manifest.to_json();
    if let Value::Object(root) = &mut doc {
        root.remove("manifest_signature_b64");
        if let Some(Value::Object(state)) = root.get_mut("state") {
            if let Some(Value::Object(body_encryption)) = state.get_mut("body_encryption") {
                body_encryption.remove("recipient_wrap");
                body_encryption.remove("recipient_wraps");
            }
        }
    }
    canonical_bytes(&doc)
}

pub(crate) fn maybe_unseal_recipient_body(
    manifest: &Manifest,
    body: &BTreeMap<String, Vec<u8>>,
    our_did: &str,
    device_seed: &[u8; 32],
) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    let Some(body_encryption) = manifest
        .state
        .as_ref()
        .and_then(|state| state.get("body_encryption"))
        .and_then(Value::as_object)
    else {
        return Ok(None);
    };

    let wraps = select_recipient_wraps(body_encryption, our_did);
    if !wraps.present {
        return Ok(None);
    }
    if wraps.candidates.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "sealed-box wrap is addressed to {:?}; this runtime is {our_did:?}. Refusing to \
             attempt unwrap.",
            wraps.addressees
        )));
    }

    let aad = manifest_aad_for_wrap(manifest)?;
    let mut last_err = String::new();
    for wrap in wraps.candidates {
        match unseal_bek_from_wrap(wrap, device_seed, &aad) {
            Ok(bek) => {
                let encrypted = body.get("body/encrypted.bin").ok_or_else(|| {
                    Error::Malformed {
                        kind: "recipient-sealed tnpkg body",
                        reason: "manifest declares body_encryption but body/encrypted.bin is \
                                 missing from the zip"
                            .into(),
                    }
                })?;
                return decrypt_body_blob(encrypted, &bek).map(Some);
            }
            Err(err) => {
                last_err = err.to_string();
            }
        }
    }

    Err(Error::Cipher(format!(
        "sealed-box unwrap failed: {last_err}"
    )))
}

fn seal_bek_for_recipient(bek: &[u8; 32], recipient_did: &str, aad: &[u8]) -> Result<Value> {
    let recipient_ed_pub = did_key_to_ed25519_pub(recipient_did)?;
    let recipient_x_pub = ed25519_pub_to_x25519_pub(&recipient_ed_pub)?;

    let mut eph_secret = [0_u8; 32];
    rand_core::OsRng.fill_bytes(&mut eph_secret);
    let eph_pub = MontgomeryPoint::mul_base_clamped(eph_secret);
    let shared = recipient_x_pub.mul_clamped(eph_secret);

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub.as_bytes());
    salt.extend_from_slice(recipient_x_pub.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut wrap_key = [0_u8; 32];
    hk.expand(WRAP_HKDF_INFO, &mut wrap_key)
        .map_err(|e| Error::Cipher(format!("recipient wrap HKDF failed: {e}")))?;

    let mut nonce = [0_u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| Error::Malformed {
        kind: "recipient wrap key",
        reason: e.to_string(),
    })?;
    let wrapped = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: bek.as_slice(),
                aad,
            },
        )
        .map_err(|e| Error::Cipher(format!("recipient wrap AES-GCM failed: {e}")))?;

    let mut out = Map::new();
    out.insert("frame".into(), Value::String(WRAP_FRAME.into()));
    out.insert(
        "recipient_identity".into(),
        Value::String(recipient_did.to_string()),
    );
    out.insert(
        "ephemeral_x25519_pub_b64".into(),
        Value::String(STANDARD.encode(eph_pub.as_bytes())),
    );
    out.insert(
        "wrap_nonce_b64".into(),
        Value::String(STANDARD.encode(nonce)),
    );
    out.insert(
        "wrapped_bek_b64".into(),
        Value::String(STANDARD.encode(wrapped)),
    );
    Ok(Value::Object(out))
}

fn unseal_bek_from_wrap(
    wrap: &Map<String, Value>,
    device_seed: &[u8; 32],
    aad: &[u8],
) -> Result<[u8; 32]> {
    let frame = wrap_field_str(wrap, "frame")?;
    if frame != WRAP_FRAME {
        return Err(Error::Malformed {
            kind: "recipient wrap",
            reason: format!("unsupported frame {frame:?}"),
        });
    }

    let eph_pub = MontgomeryPoint(wrap_field_b64_32(wrap, "ephemeral_x25519_pub_b64")?);
    let nonce = wrap_field_b64_12(wrap, "wrap_nonce_b64")?;
    let wrapped = wrap_field_b64(wrap, "wrapped_bek_b64")?;
    let recipient_x_secret = ed25519_seed_to_x25519_secret(device_seed);
    let recipient_x_pub = MontgomeryPoint::mul_base_clamped(recipient_x_secret);
    let shared = eph_pub.mul_clamped(recipient_x_secret);

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub.as_bytes());
    salt.extend_from_slice(recipient_x_pub.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut wrap_key = [0_u8; 32];
    hk.expand(WRAP_HKDF_INFO, &mut wrap_key)
        .map_err(|e| Error::Cipher(format!("recipient unwrap HKDF failed: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| Error::Malformed {
        kind: "recipient wrap key",
        reason: e.to_string(),
    })?;
    let bek = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: wrapped.as_slice(),
                aad,
            },
        )
        .map_err(|e| Error::Cipher(format!("recipient unwrap AES-GCM failed: {e}")))?;
    if bek.len() != 32 {
        return Err(Error::Malformed {
            kind: "recipient wrap",
            reason: format!("unwrapped BEK is {} bytes; expected 32", bek.len()),
        });
    }
    bek.try_into()
        .map_err(|_| Error::Internal("unwrapped BEK length was validated above".into()))
}

fn did_key_to_ed25519_pub(did: &str) -> Result<[u8; 32]> {
    let payload = did.strip_prefix("did:key:z").ok_or_else(|| {
        Error::InvalidConfig(format!(
            "recipient sealing requires a did:key:z Ed25519 recipient DID; got {did:?}"
        ))
    })?;
    let decoded = bs58::decode(payload).into_vec().map_err(|e| {
        Error::InvalidConfig(format!("recipient DID {did:?} is not valid base58btc: {e}"))
    })?;
    if decoded.len() < 2 {
        return Err(Error::InvalidConfig(format!(
            "recipient DID {did:?} payload is too short"
        )));
    }
    let prefix = [decoded[0], decoded[1]];
    if prefix != ED25519_MULTICODEC {
        return Err(Error::InvalidConfig(format!(
            "recipient sealing requires an Ed25519 did:key recipient; got multicodec prefix \
             [{}, {}] for {did:?}",
            prefix[0], prefix[1]
        )));
    }
    let pub_bytes = &decoded[2..];
    if pub_bytes.len() != 32 {
        return Err(Error::InvalidConfig(format!(
            "recipient DID {did:?} carries a {}-byte Ed25519 public key; expected 32 bytes",
            pub_bytes.len()
        )));
    }
    pub_bytes.try_into().map_err(|_| {
        Error::Internal("recipient DID public key length was validated above".into())
    })
}

fn ed25519_pub_to_x25519_pub(ed_pub: &[u8; 32]) -> Result<MontgomeryPoint> {
    CompressedEdwardsY(*ed_pub)
        .decompress()
        .map(|point| point.to_montgomery())
        .ok_or_else(|| {
            Error::InvalidConfig(
                "recipient DID Ed25519 public key could not be converted to X25519".into(),
            )
        })
}

fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
    let digest = Sha512::digest(seed);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

struct WrapSelection<'a> {
    present: bool,
    candidates: Vec<&'a Map<String, Value>>,
    addressees: Vec<Value>,
}

fn select_recipient_wraps<'a>(
    body_encryption: &'a Map<String, Value>,
    our_did: &str,
) -> WrapSelection<'a> {
    let mut out = WrapSelection {
        present: false,
        candidates: Vec::new(),
        addressees: Vec::new(),
    };

    let mut consider = |wrap: &'a Map<String, Value>| {
        out.present = true;
        let recipient = wrap.get("recipient_identity").cloned().unwrap_or(Value::Null);
        if recipient.as_str() == Some(our_did) {
            out.candidates.push(wrap);
        }
        out.addressees.push(recipient);
    };

    if let Some(Value::Array(wraps)) = body_encryption.get("recipient_wraps") {
        for wrap in wraps {
            if let Some(wrap) = wrap.as_object() {
                consider(wrap);
            }
        }
    } else if let Some(Value::Object(wrap)) = body_encryption.get("recipient_wrap") {
        consider(wrap);
    }

    out
}

fn wrap_field_str<'a>(wrap: &'a Map<String, Value>, field: &'static str) -> Result<&'a str> {
    wrap.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Malformed {
            kind: "recipient wrap",
            reason: format!("{field} missing or not a string"),
        })
}

fn wrap_field_b64(wrap: &Map<String, Value>, field: &'static str) -> Result<Vec<u8>> {
    let raw = wrap_field_str(wrap, field)?;
    STANDARD.decode(raw).map_err(|e| Error::Malformed {
        kind: "recipient wrap",
        reason: format!("{field} is not valid base64: {e}"),
    })
}

fn wrap_field_b64_32(wrap: &Map<String, Value>, field: &'static str) -> Result<[u8; 32]> {
    let bytes = wrap_field_b64(wrap, field)?;
    if bytes.len() != 32 {
        return Err(Error::Malformed {
            kind: "recipient wrap",
            reason: format!("{field} is {} bytes; expected 32", bytes.len()),
        });
    }
    bytes
        .try_into()
        .map_err(|_| Error::Internal("32-byte recipient wrap field validated above".into()))
}

fn wrap_field_b64_12(wrap: &Map<String, Value>, field: &'static str) -> Result<[u8; 12]> {
    let bytes = wrap_field_b64(wrap, field)?;
    if bytes.len() != 12 {
        return Err(Error::Malformed {
            kind: "recipient wrap",
            reason: format!("{field} is {} bytes; expected 12", bytes.len()),
        });
    }
    bytes
        .try_into()
        .map_err(|_| Error::Internal("12-byte recipient wrap field validated above".into()))
}
