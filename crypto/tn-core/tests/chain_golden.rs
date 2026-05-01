//! Byte-equality test of tn_core::chain::compute_row_hash against Python oracle.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

#[derive(serde::Deserialize)]
struct GroupInputJson {
    ciphertext_hex: String,
    field_hashes: BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
struct Inputs {
    did: String,
    timestamp: String,
    event_id: String,
    event_type: String,
    level: String,
    prev_hash: String,
    public_fields: BTreeMap<String, Value>,
    groups: BTreeMap<String, GroupInputJson>,
}

#[derive(serde::Deserialize)]
struct Vec_ {
    name: String,
    inputs: Inputs,
    expected_row_hash: String,
}

#[test]
fn row_hash_matches_python_golden() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/row_hash_vectors.json"
    );
    let vecs: Vec<Vec_> = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    for v in vecs {
        let groups: BTreeMap<String, tn_core::chain::GroupInput> = v
            .inputs
            .groups
            .into_iter()
            .map(|(k, g)| {
                (
                    k,
                    tn_core::chain::GroupInput {
                        ciphertext: hex::decode(&g.ciphertext_hex).unwrap(),
                        field_hashes: g.field_hashes,
                    },
                )
            })
            .collect();
        let got = tn_core::chain::compute_row_hash(&tn_core::chain::RowHashInput {
            did: &v.inputs.did,
            timestamp: &v.inputs.timestamp,
            event_id: &v.inputs.event_id,
            event_type: &v.inputs.event_type,
            level: &v.inputs.level,
            prev_hash: &v.inputs.prev_hash,
            public_fields: &v.inputs.public_fields,
            groups: &groups,
        });
        assert_eq!(got, v.expected_row_hash, "case={}", v.name);
    }
}

#[test]
fn chain_state_threading() {
    use tn_core::chain::{ChainState, ZERO_HASH};
    let cs = ChainState::new();
    let (s1, p1) = cs.advance("foo");
    assert_eq!(s1, 1);
    assert_eq!(p1, ZERO_HASH);
    cs.commit("foo", "sha256:aa");
    let (s2, p2) = cs.advance("foo");
    assert_eq!(s2, 2);
    assert_eq!(p2, "sha256:aa");

    // Different event types have independent chains.
    let (s3, p3) = cs.advance("bar");
    assert_eq!(s3, 1);
    assert_eq!(p3, ZERO_HASH);
}
