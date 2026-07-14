use serde_json::json;
use tn_core::did_document::extract_x25519_key_agreement;

const DID: &str = "did:example:reader";
const METHOD: &str = "did:example:reader#jwe-1";

fn x25519_multibase(key: [u8; 32]) -> String {
    let mut bytes = vec![0xec, 0x01];
    bytes.extend_from_slice(&key);
    format!("z{}", bs58::encode(bytes).into_string())
}

#[test]
fn extracts_embedded_multikey_from_key_agreement() {
    let key = [0x41; 32];
    let document = json!({
        "id": DID,
        "keyAgreement": [{
            "id": METHOD,
            "type": "Multikey",
            "controller": DID,
            "publicKeyMultibase": x25519_multibase(key),
        }]
    });

    let resolved = extract_x25519_key_agreement(&document, DID, None).unwrap();
    assert_eq!(resolved.did, DID);
    assert_eq!(resolved.verification_method_id, METHOD);
    assert_eq!(resolved.public_key, key);
    assert!(resolved.public_key_sha256.starts_with("sha256:"));
}

#[test]
fn resolves_referenced_x25519_jwk() {
    let key = [0x52; 32];
    let x = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key);
    let document = json!({
        "id": DID,
        "verificationMethod": [{
            "id": METHOD,
            "type": "JsonWebKey2020",
            "controller": DID,
            "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": x}
        }],
        "keyAgreement": [METHOD]
    });

    let resolved = extract_x25519_key_agreement(&document, DID, Some(METHOD)).unwrap();
    assert_eq!(resolved.public_key, key);
}

#[test]
fn skips_well_formed_non_x25519_key_agreement_methods() {
    let x25519 = [0x53; 32];
    let x = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, x25519);
    let ed = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        [0x54; 32],
    );
    let mut ed_multicodec = vec![0xed, 0x01];
    ed_multicodec.extend_from_slice(&[0x55; 32]);
    let ed_multibase = format!("z{}", bs58::encode(ed_multicodec).into_string());
    let document = json!({
        "id": DID,
        "keyAgreement": [
            {
                "id": "did:example:reader#ed-1",
                "type": "JsonWebKey2020",
                "controller": DID,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": ed}
            },
            {
                "id": "did:example:reader#ed-2",
                "type": "Ed25519VerificationKey2020",
                "controller": DID,
                "publicKeyMultibase": ed_multibase
            },
            {
                "id": METHOD,
                "type": "JsonWebKey2020",
                "controller": DID,
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": x}
            }
        ]
    });

    let resolved = extract_x25519_key_agreement(&document, DID, None).unwrap();
    assert_eq!(resolved.verification_method_id, METHOD);
    assert_eq!(resolved.public_key, x25519);
}

#[test]
fn skips_well_formed_unsupported_key_agreement_encoding() {
    let x25519 = [0x56; 32];
    let x = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, x25519);
    let document = json!({
        "id": DID,
        "keyAgreement": [
            {
                "id": "did:example:reader#legacy-ed",
                "type": "Ed25519VerificationKey2018",
                "controller": DID,
                "publicKeyHex": "5757575757575757575757575757575757575757575757575757575757575757"
            },
            {
                "id": METHOD,
                "type": "JsonWebKey2020",
                "controller": DID,
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": x}
            }
        ]
    });

    let resolved = extract_x25519_key_agreement(&document, DID, None).unwrap();
    assert_eq!(resolved.verification_method_id, METHOD);
    assert_eq!(resolved.public_key, x25519);
}

#[test]
fn refuses_key_not_authorized_for_key_agreement() {
    let document = json!({
        "id": DID,
        "verificationMethod": [{
            "id": METHOD,
            "type": "Multikey",
            "controller": DID,
            "publicKeyMultibase": x25519_multibase([0x63; 32]),
        }],
        "authentication": [METHOD]
    });

    let error = extract_x25519_key_agreement(&document, DID, None).unwrap_err();
    assert!(error.to_string().contains("keyAgreement"));
}

#[test]
fn refuses_wrong_controller_private_jwk_and_ambiguous_keys() {
    let x = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        [0x74; 32],
    );
    for method in [
        json!({
            "id": METHOD,
            "type": "JsonWebKey2020",
            "controller": "did:example:attacker",
            "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": x}
        }),
        json!({
            "id": METHOD,
            "type": "JsonWebKey2020",
            "controller": DID,
            "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": x, "d": x}
        }),
    ] {
        let document = json!({"id": DID, "keyAgreement": [method]});
        assert!(extract_x25519_key_agreement(&document, DID, None).is_err());
    }

    let document = json!({
        "id": DID,
        "keyAgreement": [
            {
                "id": METHOD,
                "type": "Multikey",
                "controller": DID,
                "publicKeyMultibase": x25519_multibase([0x75; 32])
            },
            {
                "id": "did:example:reader#jwe-2",
                "type": "Multikey",
                "controller": DID,
                "publicKeyMultibase": x25519_multibase([0x76; 32])
            }
        ]
    });
    assert!(extract_x25519_key_agreement(&document, DID, None)
        .unwrap_err()
        .to_string()
        .contains("ambiguous"));
}

#[test]
fn refuses_wrong_did_noncanonical_or_zero_key() {
    let multibase = x25519_multibase([0x77; 32]);
    let wrong_did = json!({
        "id": "did:example:other",
        "keyAgreement": [{
            "id": METHOD,
            "type": "Multikey",
            "controller": DID,
            "publicKeyMultibase": multibase
        }]
    });
    assert!(extract_x25519_key_agreement(&wrong_did, DID, None).is_err());

    let zero = json!({
        "id": DID,
        "keyAgreement": [{
            "id": METHOD,
            "type": "Multikey",
            "controller": DID,
            "publicKeyMultibase": x25519_multibase([0; 32])
        }]
    });
    assert!(extract_x25519_key_agreement(&zero, DID, None).is_err());

    let padded_jwk = json!({
        "id": DID,
        "keyAgreement": [{
            "id": METHOD,
            "type": "JsonWebKey2020",
            "controller": DID,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c="
            }
        }]
    });
    assert!(extract_x25519_key_agreement(&padded_jwk, DID, None).is_err());
}
