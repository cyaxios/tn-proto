use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::PathBuf;

use serde_json::Value;
use tn_core::body_encryption::{
    decrypt_body_blob, encrypt_body_blob_with_nonce, pack_body_plaintext_zip, BodyPlaintext,
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
