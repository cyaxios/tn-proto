//! End-to-end envelope byte-equality test against Python oracle.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
struct Inputs {
    seed_hex: String,
    timestamp: String,
    event_id: String,
    event_type: String,
    level: String,
    sequence: u64,
    prev_hash: String,
    public_fields: Map<String, Value>,
    private_fields: Map<String, Value>,
    group: String,
    ceremony_id: String,
    master_index_key_hex: String,
    epoch: u64,
    #[allow(dead_code)]
    cipher: String, // "identity" — ct == canonical_bytes(fields)
}

#[derive(serde::Deserialize)]
struct Vec_ {
    inputs: Inputs,
    expected_field_hashes: BTreeMap<String, String>,
    expected_ciphertext_hex: String,
    expected_row_hash: String,
    expected_signature_b64url: String,
    expected_envelope_ndjson: String,
}

#[test]
fn envelope_matches_python_golden() {
    use tn_core::{
        canonical::canonical_bytes,
        chain::{compute_row_hash, GroupInput, RowHashInput},
        envelope::{build_envelope, EnvelopeInput, GroupPayload},
        indexing::{derive_group_index_key, index_token},
        signing::{signature_b64, DeviceKey},
    };

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/envelope_vectors.json"
    );
    let vecs: Vec<Vec_> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();

    for (idx, v) in vecs.iter().enumerate() {
        let seed = hex::decode(&v.inputs.seed_hex).unwrap();
        let dk = DeviceKey::from_private_bytes(&seed).unwrap();
        let master = hex::decode(&v.inputs.master_index_key_hex).unwrap();
        let gk = derive_group_index_key(
            &master,
            &v.inputs.ceremony_id,
            &v.inputs.group,
            v.inputs.epoch,
        )
        .unwrap();

        // Private fields → sorted BTreeMap → canonical plaintext + field hashes.
        let private_sorted: BTreeMap<String, Value> =
            v.inputs.private_fields.clone().into_iter().collect();
        let mut field_hashes = BTreeMap::new();
        for (k, val) in &private_sorted {
            field_hashes.insert(k.clone(), index_token(&gk, k, val).unwrap());
        }
        assert_eq!(
            field_hashes, v.expected_field_hashes,
            "case {}: field_hashes",
            idx
        );

        // Identity cipher: ct = canonical_bytes(sorted fields as object).
        let plaintext_value = Value::Object(private_sorted.into_iter().collect());
        let ct = canonical_bytes(&plaintext_value).unwrap();
        assert_eq!(
            hex::encode(&ct),
            v.expected_ciphertext_hex,
            "case {}: ct",
            idx
        );

        // Row hash.
        let public_bmap: BTreeMap<String, Value> =
            v.inputs.public_fields.clone().into_iter().collect();
        let mut groups_in = BTreeMap::new();
        groups_in.insert(
            v.inputs.group.clone(),
            GroupInput {
                ciphertext: ct.clone(),
                field_hashes: field_hashes.clone(),
            },
        );
        let row_hash = compute_row_hash(&RowHashInput {
            did: dk.did(),
            timestamp: &v.inputs.timestamp,
            event_id: &v.inputs.event_id,
            event_type: &v.inputs.event_type,
            level: &v.inputs.level,
            prev_hash: &v.inputs.prev_hash,
            public_fields: &public_bmap,
            groups: &groups_in,
        });
        assert_eq!(row_hash, v.expected_row_hash, "case {}: row_hash", idx);

        // Sign.
        let sig = dk.sign(row_hash.as_bytes());
        assert_eq!(
            signature_b64(&sig),
            v.expected_signature_b64url,
            "case {}: sig",
            idx
        );

        // Build group_payloads Map in insertion order.
        let mut group_payloads = Map::new();
        group_payloads.insert(
            v.inputs.group.clone(),
            serde_json::to_value(GroupPayload {
                ciphertext: ct,
                field_hashes: field_hashes.into_iter().collect(),
            })
            .unwrap(),
        );

        let line = build_envelope(EnvelopeInput {
            did: dk.did(),
            timestamp: &v.inputs.timestamp,
            event_id: &v.inputs.event_id,
            event_type: &v.inputs.event_type,
            level: &v.inputs.level,
            sequence: v.inputs.sequence,
            prev_hash: &v.inputs.prev_hash,
            row_hash: &row_hash,
            signature_b64: &signature_b64(&sig),
            public_fields: v.inputs.public_fields.clone(),
            group_payloads,
        })
        .unwrap();
        assert_eq!(
            line, v.expected_envelope_ndjson,
            "case {}: ndjson line",
            idx
        );
    }
}
