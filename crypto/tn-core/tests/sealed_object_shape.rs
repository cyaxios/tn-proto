//! Shape/verify tests for `tn_core::sealed_object` — the pure (no-fs)
//! parse → extract → verify pipeline behind `tn.unseal`, plus the
//! fragile-public-value guard behind `tn.seal`. Mirrors the Python
//! oracle cases in `python/tests/test_seal_unseal.py`
//! (`test_unseal_malformed_sources_raise_unsealerror`,
//! `test_seal_rejects_fragile_public_value`, tamper cases).

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput};
use tn_core::sealed_object::{
    aad_bytes_for, extract_group_blocks, parse_sealed_source, reject_fragile_public,
    require_envelope_shape, verify_sealed, ENVELOPE_RESERVED, JS_SAFE_INT_MAX,
    SEALED_RECEIPT_EVENT, TN_SEALED_KEY,
};
use tn_core::signing::signature_b64;
use tn_core::{DeviceKey, Error};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Hand-build a correctly hashed + signed sealed envelope with one
/// `default` group block and `extra_public` fields on top of the
/// `tn_sealed: 1` marker. The self-describing verify must pass on this
/// regardless of any ceremony config.
fn build_sealed_env(extra_public: &[(&str, Value)]) -> Map<String, Value> {
    let dk = DeviceKey::from_private_bytes(&[7u8; 32]).unwrap();
    let ct: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];
    let mut field_hashes: BTreeMap<String, String> = BTreeMap::new();
    field_hashes.insert(
        "amount".to_string(),
        format!("hmac-sha256:v1:{}", "ab".repeat(32)),
    );

    let timestamp = "2026-07-09T00:00:00.000000Z";
    let event_id = "00000000-0000-4000-8000-0000000000aa";
    let event_type = "obj.test.v1";

    let mut public_for_hash: BTreeMap<String, Value> = BTreeMap::new();
    public_for_hash.insert(TN_SEALED_KEY.to_string(), json!(1));
    for (k, v) in extra_public {
        public_for_hash.insert((*k).to_string(), v.clone());
    }
    let mut groups_for_hash: BTreeMap<String, GroupInput> = BTreeMap::new();
    groups_for_hash.insert(
        "default".to_string(),
        GroupInput {
            ciphertext: ct.clone(),
            field_hashes: field_hashes.clone(),
        },
    );
    let row_hash = compute_row_hash(&RowHashInput {
        device_identity: dk.did(),
        timestamp,
        event_id,
        event_type,
        level: "",
        prev_hash: "",
        public_fields: &public_for_hash,
        groups: &groups_for_hash,
    });
    let sig = dk.sign(row_hash.as_bytes());

    let mut env = Map::new();
    env.insert("device_identity".into(), json!(dk.did()));
    env.insert("timestamp".into(), json!(timestamp));
    env.insert("event_id".into(), json!(event_id));
    env.insert("event_type".into(), json!(event_type));
    env.insert("level".into(), json!(""));
    env.insert("sequence".into(), json!(0));
    env.insert("prev_hash".into(), json!(""));
    env.insert("row_hash".into(), json!(row_hash));
    env.insert("signature".into(), json!(signature_b64(&sig)));
    for (k, v) in extra_public {
        env.insert((*k).to_string(), v.clone());
    }
    env.insert(TN_SEALED_KEY.into(), json!(1));
    env.insert(
        "default".into(),
        json!({
            "ciphertext": STANDARD.encode(&ct),
            "field_hashes": field_hashes,
        }),
    );
    env
}

fn assert_malformed(err: Error) {
    match err {
        Error::Malformed { kind, .. } => assert_eq!(kind, "sealed object"),
        other => panic!("expected Error::Malformed{{kind: \"sealed object\"}}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

#[test]
fn constants_mirror_python() {
    assert_eq!(TN_SEALED_KEY, "tn_sealed");
    assert_eq!(SEALED_RECEIPT_EVENT, "tn.object.sealed");
    assert_eq!(JS_SAFE_INT_MAX, (1u64 << 53) - 1);
    let expected = [
        "device_identity",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "sequence",
        "prev_hash",
        "row_hash",
        "signature",
    ];
    let mut got: Vec<&str> = ENVELOPE_RESERVED.to_vec();
    let mut want: Vec<&str> = expected.to_vec();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want);
}

// ---------------------------------------------------------------------------
// parse / shape (mirror test_unseal_malformed_sources_raise_unsealerror)
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_not_json() {
    assert_malformed(parse_sealed_source("not json at all").unwrap_err());
}

#[test]
fn parse_rejects_json_array() {
    assert_malformed(parse_sealed_source("[1,2,3]").unwrap_err());
}

#[test]
fn parse_rejects_empty_object() {
    assert_malformed(parse_sealed_source("{}").unwrap_err());
}

#[test]
fn parse_rejects_missing_three_of_seven() {
    // Four of the seven required keys present; timestamp / event_id /
    // sequence missing — the strict shape requires all seven.
    let src = r#"{"device_identity":"d","event_type":"x","row_hash":"h","signature":"s"}"#;
    assert_malformed(parse_sealed_source(src).unwrap_err());

    // Same shape through the dict-source entry point.
    let mut env = Map::new();
    env.insert("device_identity".into(), json!("d"));
    env.insert("event_type".into(), json!("x"));
    env.insert("row_hash".into(), json!("h"));
    env.insert("signature".into(), json!("s"));
    assert_malformed(require_envelope_shape(env).unwrap_err());
}

#[test]
fn parse_accepts_complete_envelope() {
    let env = build_sealed_env(&[]);
    let text = serde_json::to_string(&Value::Object(env.clone())).unwrap();
    let parsed = parse_sealed_source(&text).unwrap();
    assert_eq!(parsed, env);
}

// ---------------------------------------------------------------------------
// group-block extraction
// ---------------------------------------------------------------------------

#[test]
fn extract_blocks_decodes_b64_and_rejects_garbage() {
    let env = build_sealed_env(&[]);
    let blocks = extract_group_blocks(&env).unwrap();
    assert_eq!(blocks.len(), 1);
    let block = &blocks["default"];
    assert_eq!(block.ciphertext, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(block.field_hashes.len(), 1);
    assert!(block.field_hashes.contains_key("amount"));

    // A dict value WITHOUT "ciphertext" is a public field, not a block.
    let mut env2 = env.clone();
    env2.insert("meta".into(), json!({"note": "public dict"}));
    assert_eq!(extract_group_blocks(&env2).unwrap().len(), 1);

    // Undecodable base64 in a block is malformed input.
    let mut env3 = env;
    env3.insert(
        "default".into(),
        json!({"ciphertext": "!!!not-base64!!!", "field_hashes": {}}),
    );
    assert_malformed(extract_group_blocks(&env3).unwrap_err());
}

// ---------------------------------------------------------------------------
// self-describing verify
// ---------------------------------------------------------------------------

#[test]
fn verify_self_describing_includes_unknown_public_keys() {
    // An extra public key that is in NO ceremony config: the reader-side
    // recompute in runtime/read.rs filters through the local yaml's
    // public_fields and would drop it (unverifiable foreign object).
    // The sealed-object verify is self-describing: every non-reserved,
    // non-block key is public, so this must pass.
    let env = build_sealed_env(&[("note", json!("hello")), ("pv", json!([1, 2, 3]))]);
    let blocks = extract_group_blocks(&env).unwrap();
    let valid = verify_sealed(&env, &blocks);
    assert!(
        valid.row_hash,
        "row_hash must recompute over ALL public keys"
    );
    assert!(valid.signature, "signature must verify");
}

#[test]
fn verify_flags_tampered_public_field() {
    let env = build_sealed_env(&[]);
    let blocks = extract_group_blocks(&env).unwrap();

    // Flip the tn_sealed marker: row_hash breaks, signature (over the
    // stored row_hash string) still verifies.
    let mut tampered = env.clone();
    tampered.insert(TN_SEALED_KEY.into(), json!(2));
    let valid = verify_sealed(&tampered, &blocks);
    assert!(!valid.row_hash);
    assert!(valid.signature);

    // Swap in a validly-encoded signature from a different object:
    // row_hash still recomputes, only the signature check trips.
    let other_key = DeviceKey::from_private_bytes(&[9u8; 32]).unwrap();
    let foreign_sig = other_key.sign(b"some other message");
    let mut swapped = env;
    swapped.insert("signature".into(), json!(signature_b64(&foreign_sig)));
    let valid = verify_sealed(&swapped, &blocks);
    assert!(valid.row_hash);
    assert!(!valid.signature);
}

#[test]
fn verify_garbage_signature_is_false_not_error() {
    let mut env = build_sealed_env(&[]);
    env.insert("signature".into(), json!("%%%not-base64%%%"));
    let blocks = extract_group_blocks(&env).unwrap();
    let valid = verify_sealed(&env, &blocks);
    assert!(valid.row_hash);
    assert!(!valid.signature);
}

// ---------------------------------------------------------------------------
// fragile-public guard (mirror test_seal_rejects_fragile_public_value)
// ---------------------------------------------------------------------------

fn fragile_err(public: Map<String, Value>) -> String {
    match reject_fragile_public(&public) {
        Err(Error::InvalidConfig(msg)) => msg,
        Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        Ok(()) => panic!("expected fragile-value rejection, got Ok"),
    }
}

#[test]
fn reject_fragile_float() {
    let mut public = Map::new();
    public.insert("pv".into(), json!(3.14));
    let msg = fragile_err(public);
    assert!(msg.contains("'pv'"), "message must name the path: {msg}");
    assert!(msg.contains("float"), "{msg}");

    // Integral float: serde_json keeps 1.0 as f64 — still fragile.
    let mut public = Map::new();
    public.insert("pv".into(), json!(1.0));
    fragile_err(public);
}

#[test]
fn reject_fragile_big_int() {
    let mut public = Map::new();
    public.insert("pv".into(), json!(9_007_199_254_740_993u64)); // 2^53 + 1
    let msg = fragile_err(public);
    assert!(msg.contains("'pv'"), "{msg}");

    let mut public = Map::new();
    public.insert("pv".into(), json!(-9_007_199_254_740_993i64));
    fragile_err(public);
}

#[test]
fn reject_fragile_nested() {
    // List position: path renders as pv[0].
    let mut public = Map::new();
    public.insert("pv".into(), json!([1.0, 2]));
    let msg = fragile_err(public);
    assert!(msg.contains("'pv[0]'"), "{msg}");

    // Dict position: path renders as pv.amt.
    let mut public = Map::new();
    public.insert("pv".into(), json!({"amt": 5.0}));
    let msg = fragile_err(public);
    assert!(msg.contains("'pv.amt'"), "{msg}");
}

#[test]
fn fragile_bool_exempt() {
    let mut public = Map::new();
    public.insert("flag".into(), json!(true));
    public.insert("nested".into(), json!([true, false, {"x": false}]));
    reject_fragile_public(&public).unwrap();
}

#[test]
fn fragile_js_safe_max_ok() {
    let mut public = Map::new();
    public.insert("pv".into(), json!(9_007_199_254_740_991u64)); // 2^53 - 1
    public.insert("nv".into(), json!(-9_007_199_254_740_991i64));
    reject_fragile_public(&public).unwrap();
}

// ---------------------------------------------------------------------------
// aad_bytes_for (relocated from runtime/read.rs)
// ---------------------------------------------------------------------------

#[test]
fn aad_bytes_reconstruct_from_echo() {
    // The writer echoes {"group": marker} as a canonical JSON STRING
    // under tn_aad; readers re-canonicalize this group's marker.
    let env = json!({
        "tn_aad": "{\"default\":{\"case\":\"A-17\"}}",
    });
    assert_eq!(aad_bytes_for(&env, "default"), b"{\"case\":\"A-17\"}");
    // Absent group, absent echo, malformed echo: empty bytes.
    assert_eq!(aad_bytes_for(&env, "other"), b"");
    assert_eq!(aad_bytes_for(&json!({}), "default"), b"");
    assert_eq!(
        aad_bytes_for(&json!({"tn_aad": "not json"}), "default"),
        b""
    );
}
