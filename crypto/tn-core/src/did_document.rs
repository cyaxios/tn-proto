//! Strict X25519 extraction from an already-authenticated DID document.
//!
//! This module does not resolve or authenticate DID documents. Callers must
//! obtain the document through the DID method's trusted resolution process.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{Map, Value};
use std::collections::HashSet;

use crate::trust::{TrustError, TrustReason};
use crate::trusted_enrollment::sha256_tagged;

/// One X25519 method explicitly authorized by a DID document for key agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedX25519KeyAgreement {
    /// DID subject and controller of the key.
    pub did: String,
    /// Exact DID URL identifying the selected verification method.
    pub verification_method_id: String,
    /// Raw X25519 public key bytes.
    pub public_key: [u8; 32],
    /// Stable digest of `public_key`.
    pub public_key_sha256: String,
}

/// Extract one X25519 key explicitly listed under `keyAgreement`.
///
/// `document` must already have been authenticated by a DID-method resolver.
/// When more than one eligible method exists, `verification_method_id` is
/// required so recipient selection cannot depend on document ordering.
pub fn extract_x25519_key_agreement(
    document: &Value,
    expected_did: &str,
    verification_method_id: Option<&str>,
) -> Result<ResolvedX25519KeyAgreement, TrustError> {
    let object = document
        .as_object()
        .ok_or_else(|| binding_error("DID document must be an object"))?;
    if object.get("id").and_then(Value::as_str) != Some(expected_did) {
        return Err(did_error("DID document id does not match the expected DID"));
    }
    let relations = object
        .get("keyAgreement")
        .and_then(Value::as_array)
        .ok_or_else(|| binding_error("DID document has no keyAgreement relationship"))?;
    let mut found = Vec::new();
    let mut ids = HashSet::new();
    for relation in relations {
        let method = resolve_relationship(object, relation)?;
        let parsed = parse_method(&method, expected_did)?;
        if !ids.insert(parsed.verification_method_id.clone()) {
            return Err(binding_error("duplicate keyAgreement verification method"));
        }
        if verification_method_id.is_none_or(|wanted| wanted == parsed.verification_method_id) {
            found.push(parsed);
        }
    }
    select_method(found, verification_method_id)
}

fn resolve_relationship(
    document: &Map<String, Value>,
    relationship: &Value,
) -> Result<Map<String, Value>, TrustError> {
    if let Some(method) = relationship.as_object() {
        return Ok(method.clone());
    }
    let id = relationship
        .as_str()
        .ok_or_else(|| binding_error("keyAgreement entries must be objects or DID URL strings"))?;
    let methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| binding_error("referenced keyAgreement method is not defined"))?;
    let matches = methods
        .iter()
        .filter_map(Value::as_object)
        .filter(|method| method.get("id").and_then(Value::as_str) == Some(id))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [method] => Ok((*method).clone()),
        [] => Err(binding_error(
            "referenced keyAgreement method is not defined",
        )),
        _ => Err(binding_error(
            "referenced keyAgreement method is duplicated",
        )),
    }
}

fn parse_method(
    method: &Map<String, Value>,
    expected_did: &str,
) -> Result<ResolvedX25519KeyAgreement, TrustError> {
    let id = required_string(method, "id")?;
    if !id.starts_with(&format!("{expected_did}#")) {
        return Err(binding_error(
            "keyAgreement method id is outside the DID subject",
        ));
    }
    if required_string(method, "controller")? != expected_did {
        return Err(binding_error(
            "keyAgreement method has a different controller",
        ));
    }
    let method_type = required_string(method, "type")?;
    let public_key = match (method.get("publicKeyJwk"), method.get("publicKeyMultibase")) {
        (Some(jwk), None) if is_jwk_type(method_type) => decode_jwk(jwk)?,
        (None, Some(multibase)) if is_multikey_type(method_type) => decode_multibase(multibase)?,
        (Some(_), Some(_)) => {
            return Err(binding_error("keyAgreement method has two key encodings"))
        }
        _ => {
            return Err(binding_error(
                "unsupported X25519 keyAgreement method encoding",
            ))
        }
    };
    if public_key == [0; 32] {
        return Err(binding_error("X25519 public key must not be all zero"));
    }
    Ok(ResolvedX25519KeyAgreement {
        did: expected_did.to_string(),
        verification_method_id: id.to_string(),
        public_key,
        public_key_sha256: sha256_tagged(&public_key),
    })
}

fn decode_jwk(value: &Value) -> Result<[u8; 32], TrustError> {
    let jwk = value
        .as_object()
        .ok_or_else(|| binding_error("publicKeyJwk must be an object"))?;
    if jwk.contains_key("d") {
        return Err(binding_error(
            "publicKeyJwk must not contain private key material",
        ));
    }
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("X25519")
    {
        return Err(binding_error("publicKeyJwk must be an OKP X25519 key"));
    }
    let encoded = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| binding_error("publicKeyJwk.x must be a string"))?;
    if encoded.contains('=') {
        return Err(binding_error("publicKeyJwk.x must be unpadded base64url"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| binding_error("publicKeyJwk.x is not canonical base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded || bytes.len() != 32 {
        return Err(binding_error("publicKeyJwk.x must encode exactly 32 bytes"));
    }
    bytes
        .try_into()
        .map_err(|_| binding_error("invalid X25519 key length"))
}

fn decode_multibase(value: &Value) -> Result<[u8; 32], TrustError> {
    let encoded = value
        .as_str()
        .ok_or_else(|| binding_error("publicKeyMultibase must be a string"))?;
    let payload = encoded
        .strip_prefix('z')
        .ok_or_else(|| binding_error("publicKeyMultibase must use base58btc"))?;
    let bytes = bs58::decode(payload)
        .into_vec()
        .map_err(|_| binding_error("publicKeyMultibase is not base58btc"))?;
    if bs58::encode(&bytes).into_string() != payload {
        return Err(binding_error(
            "publicKeyMultibase is not canonical base58btc",
        ));
    }
    if bytes.len() != 34 || bytes[..2] != [0xec, 0x01] {
        return Err(binding_error(
            "publicKeyMultibase must contain x25519-pub bytes",
        ));
    }
    bytes[2..]
        .try_into()
        .map_err(|_| binding_error("invalid X25519 key length"))
}

fn select_method(
    mut found: Vec<ResolvedX25519KeyAgreement>,
    requested: Option<&str>,
) -> Result<ResolvedX25519KeyAgreement, TrustError> {
    match found.len() {
        1 => Ok(found.remove(0)),
        0 if requested.is_some() => {
            Err(binding_error("requested keyAgreement method was not found"))
        }
        0 => Err(binding_error(
            "DID document has no usable X25519 keyAgreement method",
        )),
        _ => Err(binding_error(
            "ambiguous X25519 keyAgreement methods; select one by id",
        )),
    }
}

fn required_string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, TrustError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| binding_error(format!("keyAgreement method {name} must be a string")))
}

fn is_jwk_type(method_type: &str) -> bool {
    matches!(method_type, "JsonWebKey" | "JsonWebKey2020")
}

fn is_multikey_type(method_type: &str) -> bool {
    matches!(
        method_type,
        "Multikey" | "X25519KeyAgreementKey2019" | "X25519KeyAgreementKey2020"
    )
}

fn binding_error(detail: impl Into<String>) -> TrustError {
    TrustError::new(TrustReason::BindingInvalid, detail)
}

fn did_error(detail: impl Into<String>) -> TrustError {
    TrustError::new(TrustReason::DidInvalid, detail)
}
