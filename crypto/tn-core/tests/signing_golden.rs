//! Byte-equality test for Ed25519 DeviceKey + did:key encoding + signature format.

use tn_core::signing::{signature_b64, signature_from_b64, DeviceKey};

#[derive(serde::Deserialize)]
struct Case {
    message_hex: String,
    signature_b64url_nopad: String,
}
#[derive(serde::Deserialize)]
struct Entry {
    seed_hex: String,
    public_hex: String,
    did: String,
    cases: Vec<Case>,
}

#[test]
fn signing_matches_python_golden() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/signing_vectors.json"
    );
    let entries: Vec<Entry> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for e in entries {
        let seed = hex::decode(&e.seed_hex).unwrap();
        let dk = DeviceKey::from_private_bytes(&seed).unwrap();
        assert_eq!(hex::encode(dk.public_bytes()), e.public_hex, "public_hex");
        assert_eq!(dk.did(), e.did, "did");
        for c in e.cases {
            let msg = hex::decode(&c.message_hex).unwrap();
            let sig = dk.sign(&msg);
            assert_eq!(signature_b64(&sig), c.signature_b64url_nopad, "sig b64");
            assert!(DeviceKey::verify_did(&e.did, &msg, &sig).unwrap(), "verify");
            assert_eq!(
                signature_from_b64(&c.signature_b64url_nopad).unwrap(),
                sig,
                "b64 decode"
            );
        }
    }
}
