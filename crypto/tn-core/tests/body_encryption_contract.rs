use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::PathBuf;

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tn_core::body_encryption::{
    decrypt_body_blob, decrypt_legacy_vault_body_blob, encrypt_body_blob_with_nonce,
    pack_body_plaintext_zip, BodyPlaintext,
};
use zip::CompressionMethod;

fn fixture_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("tests");
    p.push("fixtures");
    p.push("body_encryption");
    p
}

fn read_json(name: &str) -> Value {
    let raw = fs::read_to_string(fixture_dir().join(name)).expect("read body encryption fixture");
    serde_json::from_str(&raw).expect("parse body encryption fixture")
}

fn read_hex(name: &str) -> Vec<u8> {
    let raw = fs::read_to_string(fixture_dir().join(name)).expect("read hex fixture");
    hex::decode(raw.trim()).expect("hex fixture")
}

fn fixture_body(doc: &Value) -> BodyPlaintext {
    let mut body = BTreeMap::new();
    let body_utf8 = doc
        .get("body_utf8")
        .and_then(Value::as_object)
        .expect("body_utf8 object");
    for (name, value) in body_utf8 {
        body.insert(
            name.clone(),
            value
                .as_str()
                .expect("fixture body string")
                .as_bytes()
                .to_vec(),
        );
    }
    body
}

#[test]
fn pack_body_plaintext_zip_is_standard_stored_zip() {
    let doc = read_json("vector.json");
    let body = fixture_body(&doc);
    let plaintext = pack_body_plaintext_zip(&body).expect("pack plaintext zip");

    let mut zip = zip::ZipArchive::new(Cursor::new(plaintext)).expect("read plaintext zip");
    let mut recovered = BTreeMap::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).expect("zip entry");
        assert_eq!(entry.compression(), CompressionMethod::Stored);
        assert_eq!(
            entry.last_modified().expect("zip mtime").to_string(),
            "1980-01-01 00:00:00"
        );
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("read entry");
        recovered.insert(entry.name().to_string(), bytes);
    }
    assert_eq!(recovered, body);
}

#[test]
fn decrypt_body_blob_matches_shared_fixture() {
    let doc = read_json("vector.json");
    let key: [u8; 32] = hex::decode(doc["key_hex"].as_str().expect("key_hex"))
        .expect("key hex")
        .try_into()
        .expect("32-byte key");
    let blob = read_hex("sealed_blob.hex");
    let recovered = decrypt_body_blob(&blob, &key).expect("decrypt body blob");

    assert_eq!(recovered, fixture_body(&doc));
}

#[test]
fn encrypt_body_blob_with_nonce_round_trips() {
    let doc = read_json("vector.json");
    let body = fixture_body(&doc);
    let key: [u8; 32] = hex::decode(doc["key_hex"].as_str().expect("key_hex"))
        .expect("key hex")
        .try_into()
        .expect("32-byte key");
    let nonce: [u8; 12] = hex::decode(doc["nonce_hex"].as_str().expect("nonce_hex"))
        .expect("nonce hex")
        .try_into()
        .expect("12-byte nonce");

    let blob = encrypt_body_blob_with_nonce(&body, &key, &nonce).expect("encrypt body blob");

    assert_eq!(&blob[..12], nonce.as_slice());
    let recovered = decrypt_body_blob(&blob, &key).expect("decrypt generated body blob");
    assert_eq!(recovered, body);
}

#[test]
fn decrypt_legacy_vault_body_blob_round_trips_dashboard_shape() {
    let doc = read_json("vector.json");
    let body = fixture_body(&doc);
    let key: [u8; 32] = hex::decode(doc["key_hex"].as_str().expect("key_hex"))
        .expect("key hex")
        .try_into()
        .expect("32-byte key");
    let nonce: [u8; 12] = hex::decode(doc["nonce_hex"].as_str().expect("nonce_hex"))
        .expect("nonce hex")
        .try_into()
        .expect("12-byte nonce");
    let plaintext = pack_body_plaintext_zip(&body).expect("pack plaintext zip");
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES key");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: b"tn-vault-body-v1",
            },
        )
        .expect("encrypt legacy dashboard body");

    let recovered = decrypt_legacy_vault_body_blob(&ciphertext, &key, &STANDARD.encode(nonce))
        .expect("decrypt legacy dashboard body blob");

    assert_eq!(recovered, body);
}

#[test]
fn decrypt_legacy_vault_body_blob_accepts_legacy_binary_plaintext_frame() {
    let doc = read_json("vector.json");
    let body = fixture_body(&doc);
    let key: [u8; 32] = hex::decode(doc["key_hex"].as_str().expect("key_hex"))
        .expect("key hex")
        .try_into()
        .expect("32-byte key");
    let nonce: [u8; 12] = hex::decode(doc["nonce_hex"].as_str().expect("nonce_hex"))
        .expect("nonce hex")
        .try_into()
        .expect("12-byte nonce");
    let plaintext = legacy_binary_plaintext_frame(&body);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES key");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: b"tn-vault-body-v1",
            },
        )
        .expect("encrypt legacy dashboard body");

    let recovered = decrypt_legacy_vault_body_blob(&ciphertext, &key, &STANDARD.encode(nonce))
        .expect("decrypt legacy dashboard body blob");

    assert_eq!(recovered, body);
}

#[test]
fn decrypt_legacy_vault_body_blob_accepts_legacy_dashboard_json_body() {
    let doc = read_json("vector.json");
    let key: [u8; 32] = hex::decode(doc["key_hex"].as_str().expect("key_hex"))
        .expect("key hex")
        .try_into()
        .expect("32-byte key");
    let nonce: [u8; 12] = hex::decode(doc["nonce_hex"].as_str().expect("nonce_hex"))
        .expect("nonce hex")
        .try_into()
        .expect("12-byte nonce");
    let private = vec![7u8; 32];
    let public = b"did:key:zLegacyPub";
    let state = vec![1u8, 2, 3, 4];
    let plaintext = json!({
        "version": "keystore-v1",
        "did": "did:key:zLegacyPub",
        "ceremony_id": "browser_abc123",
        "yaml": "ceremony_id: browser_abc123\n",
        "files": {
            "local.private": STANDARD.encode(&private),
            "local.public": STANDARD.encode(public),
            "default.btn.state": STANDARD.encode(&state),
        },
    })
    .to_string()
    .into_bytes();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES key");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: b"tn-vault-body-v1",
            },
        )
        .expect("encrypt legacy dashboard JSON body");

    let recovered = decrypt_legacy_vault_body_blob(&ciphertext, &key, &STANDARD.encode(nonce))
        .expect("decrypt legacy dashboard JSON body blob");

    assert_eq!(
        recovered.get("body/tn.yaml").map(Vec::as_slice),
        Some("ceremony_id: browser_abc123\n".as_bytes())
    );
    assert_eq!(
        recovered.get("body/local.private").map(Vec::as_slice),
        Some(private.as_slice())
    );
    assert_eq!(
        recovered.get("body/local.public").map(Vec::as_slice),
        Some(public.as_slice())
    );
    assert_eq!(
        recovered.get("body/default.btn.state").map(Vec::as_slice),
        Some(state.as_slice())
    );
}

#[test]
fn decrypt_legacy_vault_body_blob_accepts_empty_zip_body() {
    let doc = read_json("vector.json");
    let key: [u8; 32] = hex::decode(doc["key_hex"].as_str().expect("key_hex"))
        .expect("key hex")
        .try_into()
        .expect("32-byte key");
    let nonce: [u8; 12] = hex::decode(doc["nonce_hex"].as_str().expect("nonce_hex"))
        .expect("nonce hex")
        .try_into()
        .expect("12-byte nonce");
    let plaintext = pack_body_plaintext_zip(&BodyPlaintext::new()).expect("pack empty zip");
    assert_eq!(&plaintext[..4], b"PK\x05\x06");

    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES key");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: b"tn-vault-body-v1",
            },
        )
        .expect("encrypt legacy empty zip body");

    let recovered = decrypt_legacy_vault_body_blob(&ciphertext, &key, &STANDARD.encode(nonce))
        .expect("decrypt legacy empty zip body blob");

    assert!(recovered.is_empty());
}

fn legacy_binary_plaintext_frame(body: &BodyPlaintext) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    for (name, data) in body {
        out.extend_from_slice(&(name.len() as u32).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}
