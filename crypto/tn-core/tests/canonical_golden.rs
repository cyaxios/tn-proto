//! Byte-equality test of tn_core::canonical::canonical_bytes against the Python oracle.

use serde_json::Value;
use std::fs;

#[derive(serde::Deserialize)]
struct Vec_ {
    name: String,
    input_json: Value,
    output_hex: String,
}

fn vectors() -> Vec<Vec_> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/canonical_vectors.json"
    );
    serde_json::from_slice(&fs::read(p).expect("fixtures file")).expect("parse")
}

#[test]
fn canonical_matches_python_golden() {
    for v in vectors() {
        let got = tn_core::canonical::canonical_bytes(&v.input_json).expect("canonicalize");
        let got_hex = hex::encode(&got);
        assert_eq!(
            got_hex, v.output_hex,
            "case={} input={}",
            v.name, v.input_json
        );
    }
}

#[test]
fn canonical_wrap_bytes_matches_sentinel() {
    // bytes([0,1,2]) wrapped should produce the same canonical output as {"$b64":"AAEC"}.
    let wrapped = tn_core::canonical::wrap_bytes(&[0u8, 1, 2]);
    let direct: Value = serde_json::from_str(r#"{"$b64":"AAEC"}"#).unwrap();
    assert_eq!(
        tn_core::canonical::canonical_bytes(&wrapped).unwrap(),
        tn_core::canonical::canonical_bytes(&direct).unwrap(),
    );
}
