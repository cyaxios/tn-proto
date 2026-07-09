//! Integration tests for `Runtime::seal` / `Runtime::unseal` — the
//! portable sealed-object verbs. Mirrors the Python oracle suite in
//! `python/tests/test_seal_unseal.py` case-for-case where the behavior
//! is shared, plus the Rust-specific key-bag seams.

#![cfg(feature = "fs")]

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use common::setup_minimal_btn_ceremony;
use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput, ZERO_HASH};
use tn_core::signing::signature_from_b64;
use tn_core::{DeviceKey, Error, Runtime, SealOptions};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn fields(pairs: &[(&str, Value)]) -> Map<String, Value> {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

fn no_receipt() -> SealOptions {
    SealOptions {
        receipt: false,
        ..SealOptions::default()
    }
}

/// Ceremony variant whose `tn.*` events route to the default dedicated
/// admin file (`./.tn/admin/admin.ndjson`) instead of the main log, so
/// the receipt tests read the surface Python's `tn.read(log="admin")`
/// reads.
fn setup_ceremony_with_admin_pel(root: &Path) -> common::BtnCeremony {
    let cer = setup_minimal_btn_ceremony(root);
    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let patched = yaml.replace(
        "protocol_events_location: main_log",
        "protocol_events_location: \"./.tn/admin/admin.ndjson\"",
    );
    assert_ne!(yaml, patched, "ceremony yaml must carry the PEL key to patch");
    std::fs::write(&cer.yaml_path, patched).unwrap();
    cer
}

/// Ceremony variant that routes `pv` to public_fields (mirror of
/// Python's `_ceremony_with_public`). Public values feed the row hash
/// as `str(value)`; group fields do not — the fragile guard only fires
/// in public position.
fn setup_ceremony_with_public_pv(root: &Path) -> common::BtnCeremony {
    let cer = setup_minimal_btn_ceremony(root);
    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let patched = yaml.replace("public_fields: []", "public_fields: [pv]");
    assert_ne!(yaml, patched, "ceremony yaml must carry public_fields to patch");
    std::fs::write(&cer.yaml_path, patched).unwrap();
    cer
}

fn read_ndjson(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// R3 — Runtime::seal
// ---------------------------------------------------------------------------

#[test]
fn seal_returns_standalone_envelope() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal(
            "obj.invoice.v1",
            fields(&[("amount", json!(9800)), ("customer", json!("acme"))]),
            &no_receipt(),
        )
        .unwrap();
    let env = &sealed.envelope;

    // Standalone conventions.
    assert_eq!(env["sequence"], json!(0));
    assert_eq!(env["prev_hash"], json!(""));
    assert_eq!(env["level"], json!(""));
    assert_eq!(env["tn_sealed"], json!(1));
    assert_eq!(env["event_type"], json!("obj.invoice.v1"));

    // Fields are encrypted, not in the clear.
    assert!(!env.contains_key("amount"));
    assert!(!env.contains_key("customer"));
    assert!(env["default"]["ciphertext"].is_string());

    // Always signed, and the signature verifies.
    let row_hash = env["row_hash"].as_str().unwrap();
    let sig = signature_from_b64(env["signature"].as_str().unwrap()).unwrap();
    assert!(DeviceKey::verify_did(
        env["device_identity"].as_str().unwrap(),
        row_hash.as_bytes(),
        &sig
    )
    .unwrap());

    // row_hash is honestly derived from the envelope contents, with
    // public_fields = {tn_sealed: 1} ONLY (no run_id injection, no
    // agent-policy splice — seal bypasses the emit prelude).
    let ct = STANDARD
        .decode(env["default"]["ciphertext"].as_str().unwrap())
        .unwrap();
    let field_hashes: BTreeMap<String, String> = env["default"]["field_hashes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();
    let mut groups = BTreeMap::new();
    groups.insert(
        "default".to_string(),
        GroupInput {
            ciphertext: ct,
            field_hashes,
        },
    );
    let mut public = BTreeMap::new();
    public.insert("tn_sealed".to_string(), json!(1));
    let expected = compute_row_hash(&RowHashInput {
        device_identity: env["device_identity"].as_str().unwrap(),
        timestamp: env["timestamp"].as_str().unwrap(),
        event_id: env["event_id"].as_str().unwrap(),
        event_type: "obj.invoice.v1",
        level: "",
        prev_hash: "",
        public_fields: &public,
        groups: &groups,
    });
    assert_eq!(expected, row_hash);

    // No aad passed -> no tn_aad echo.
    assert!(!env.contains_key("tn_aad"));
}

#[test]
fn seal_rejects_reserved_field() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let err = rt
        .seal("obj.test.v1", fields(&[("tn_sealed", json!(1))]), &no_receipt())
        .unwrap_err();
    match err {
        Error::InvalidConfig(msg) => assert!(msg.contains("tn_sealed"), "{msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[test]
fn seal_does_not_disturb_chain() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    rt.seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    // Chains are per-event_type: log the SAME type the seal used. If
    // seal had advanced that chain, this row would be sequence 2 with a
    // real prev_hash instead of the genesis link.
    rt.log("obj.test.v1", fields(&[("y", json!(2))])).unwrap();

    let rows = read_ndjson(rt.log_path());
    let row = rows
        .iter()
        .find(|e| e["event_type"] == json!("obj.test.v1"))
        .expect("logged row present");
    assert_eq!(row["sequence"], json!(1));
    assert_eq!(row["prev_hash"], json!(ZERO_HASH));
}

#[test]
fn seal_receipt_row_written_by_default() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_ceremony_with_admin_pel(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal(
            "obj.invoice.v1",
            fields(&[("amount", json!(1))]),
            &SealOptions::default(),
        )
        .unwrap();

    let admin_log = td.path().join(".tn").join("admin").join("admin.ndjson");
    let receipts: Vec<Value> = read_ndjson(&admin_log)
        .into_iter()
        .filter(|e| e["event_type"] == json!("tn.object.sealed"))
        .collect();
    assert_eq!(receipts.len(), 1, "exactly one receipt row");
    // The receipt's payload rides in the encrypted default group; read
    // it back through the runtime's own read path (decrypts with the
    // ceremony's kit).
    let raw = rt.read_from(&admin_log).unwrap();
    let receipt = raw
        .iter()
        .find(|e| {
            e.envelope.get("event_type").and_then(Value::as_str) == Some("tn.object.sealed")
        })
        .expect("receipt readable through read_from(admin log)");
    let body = &receipt.plaintext_per_group["default"];
    assert_eq!(body["object_id"], sealed.envelope["row_hash"]);
    assert_eq!(body["object_type"], json!("obj.invoice.v1"));
    assert_eq!(body["groups"], json!(["default"]));
}

#[test]
fn seal_receipt_false_writes_nothing() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_ceremony_with_admin_pel(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    rt.seal("obj.invoice.v1", fields(&[("amount", json!(1))]), &no_receipt())
        .unwrap();

    let admin_log = td.path().join(".tn").join("admin").join("admin.ndjson");
    let receipts: Vec<Value> = read_ndjson(&admin_log)
        .into_iter()
        .filter(|e| e["event_type"] == json!("tn.object.sealed"))
        .collect();
    assert!(receipts.is_empty(), "receipt=false must write no receipt row");
}

#[test]
fn seal_rejects_fragile_public_value() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_ceremony_with_public_pv(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // A public value a foreign JSON runtime would silently reformat
    // must be refused at seal time, not fail at a remote unseal.
    for fragile in [
        json!(1.0),                      // integral float
        json!(3.14),                     // non-integral float
        json!(9_007_199_254_740_993u64), // 2^53 + 1
        json!([1.0, 2]),                 // float in list
        json!({"amt": 5.0}),             // float in dict
    ] {
        let err = rt
            .seal("obj.rt.v1", fields(&[("pv", fragile.clone())]), &no_receipt())
            .unwrap_err();
        match err {
            Error::InvalidConfig(msg) => {
                assert!(msg.contains("public field"), "pv={fragile}: {msg}");
            }
            other => panic!("pv={fragile}: expected InvalidConfig, got {other:?}"),
        }
    }

    // The same fragile value in an ENCRYPTED group (the default) seals
    // fine — group fields are hashed as opaque ciphertext.
    rt.seal("obj.rt.v1", fields(&[("price", json!(19.0))]), &no_receipt())
        .unwrap();
}

#[test]
fn seal_wire_string_has_no_trailing_newline_and_reparses_identically() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    assert!(!sealed.wire.ends_with('\n'), "wire must have no trailing newline");
    assert!(!sealed.wire.contains('\n'), "wire is a single line");
    let reparsed: Map<String, Value> = serde_json::from_str(&sealed.wire).unwrap();
    assert_eq!(reparsed, sealed.envelope);
}
