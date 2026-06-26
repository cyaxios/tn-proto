//! Byte-equality test for HKDF group key derivation + HMAC index tokens.

use serde_json::Value;

#[derive(serde::Deserialize)]
struct Vec_ {
    master_hex: String,
    ceremony: String,
    group: String,
    epoch: u64,
    field: String,
    value: Value,
    derived_key_hex: String,
    expected_token: String,
}

#[test]
fn hkdf_and_token_match_golden() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/index_token_vectors.json"
    );
    let vecs: Vec<Vec_> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for v in vecs {
        let master = hex::decode(&v.master_hex).unwrap();
        let gk = tn_core::indexing::derive_group_index_key(&master, &v.ceremony, &v.group, v.epoch)
            .unwrap();
        assert_eq!(
            hex::encode(gk),
            v.derived_key_hex,
            "HKDF mismatch: ceremony={} group={} epoch={}",
            v.ceremony,
            v.group,
            v.epoch
        );
        let tok = tn_core::indexing::index_token(&gk, &v.field, &v.value).unwrap();
        assert_eq!(tok, v.expected_token, "HMAC mismatch: field={}", v.field);
    }
}
