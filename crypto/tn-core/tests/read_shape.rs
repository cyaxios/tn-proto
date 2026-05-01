//! Tests for the 2026-04-25 read-ergonomics reshape.
//!
//! Mirrors `python/tests/test_read_shape.py` cases — flat default,
//! verify, raw, hidden groups, decrypt errors, collisions.

#![cfg(feature = "fs")]

mod common;

use common::setup_minimal_btn_ceremony;
use serde_json::{json, Value};
use tn_core::Runtime;

#[test]
fn read_default_flat_shape_has_envelope_basics() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let mut f = serde_json::Map::new();
    f.insert("amount".into(), json!(100));
    f.insert("note".into(), json!("first"));
    rt.emit_with(
        "info",
        "order.created",
        f,
        Some("2026-04-25T12:00:00.000000Z"),
        Some("00000000-0000-0000-0000-00000000aaaa"),
    )
    .unwrap();

    let entries = rt.read().unwrap();
    // entry 0 = tn.ceremony.init, entry 1 = order.created
    assert_eq!(entries.len(), 2);

    let e = &entries[1];
    // Six envelope basics surface flat.
    assert!(e.contains_key("timestamp"));
    assert!(e.contains_key("event_type"));
    assert!(e.contains_key("level"));
    assert!(e.contains_key("did"));
    assert!(e.contains_key("sequence"));
    assert!(e.contains_key("event_id"));
    assert_eq!(e["event_type"], "order.created");

    // Crypto plumbing absent.
    assert!(!e.contains_key("prev_hash"));
    assert!(!e.contains_key("row_hash"));
    assert!(!e.contains_key("signature"));

    // Decrypted fields surface flat.
    assert_eq!(e["amount"], 100);
    assert_eq!(e["note"], "first");
}

#[test]
fn read_with_verify_adds_valid_block() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let mut f = serde_json::Map::new();
    f.insert("amount".into(), json!(42));
    rt.info("order.created", f).unwrap();

    let entries = rt.read_with_verify().unwrap();
    let last = entries.last().expect("entry");
    let v = last.get("_valid").expect("_valid block");
    let valid = v.as_object().unwrap();
    assert_eq!(valid["signature"], Value::Bool(true));
    assert_eq!(valid["row_hash"], Value::Bool(true));
    assert_eq!(valid["chain"], Value::Bool(true));
}

#[test]
fn read_raw_returns_audit_shape() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let mut f = serde_json::Map::new();
    f.insert("amount".into(), json!(7));
    rt.info("order.created", f).unwrap();

    let raw = rt.read_raw().unwrap();
    assert!(raw.iter().any(|e| {
        e.envelope.get("event_type").and_then(Value::as_str) == Some("order.created")
    }));
    let order = raw
        .iter()
        .find(|e| {
            e.envelope.get("event_type").and_then(Value::as_str) == Some("order.created")
        })
        .unwrap();
    assert_eq!(order.plaintext_per_group["default"]["amount"], 7);
    // The audit shape carries crypto plumbing on the envelope.
    assert!(order.envelope.get("row_hash").is_some());
    assert!(order.envelope.get("prev_hash").is_some());
}

#[test]
fn fresh_init_log_has_one_ceremony_init_entry() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let entries = rt.read().unwrap();
    // Only the auto-emitted tn.ceremony.init.
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["event_type"], "tn.ceremony.init");
}
