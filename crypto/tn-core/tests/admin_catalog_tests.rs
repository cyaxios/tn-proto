//! Tests for admin_catalog: presence of each kind, schema enforcement.

use serde_json::{json, Map, Value};
use tn_core::admin_catalog::{kind_for, validate_emit, CATALOG};

#[test]
fn catalog_has_twelve_kinds() {
    // 10 from the original 2026-04-23 admin-log spec + 2 from the
    // 2026-04-25 read-ergonomics + agents-group spec
    // (`tn.agents.policy_published`, `tn.read.tampered_row_skipped`).
    assert_eq!(CATALOG.len(), 12, "10 admin + 2 agents/read kinds");
}

#[test]
fn catalog_contains_all_expected_event_types() {
    let expected: std::collections::HashSet<&str> = [
        "tn.ceremony.init",
        "tn.group.added",
        "tn.recipient.added",
        "tn.recipient.revoked",
        "tn.coupon.issued",
        "tn.rotation.completed",
        "tn.enrolment.compiled",
        "tn.enrolment.absorbed",
        "tn.vault.linked",
        "tn.vault.unlinked",
        "tn.agents.policy_published",
        "tn.read.tampered_row_skipped",
    ]
    .into_iter()
    .collect();
    let got: std::collections::HashSet<&str> = CATALOG.iter().map(|k| k.event_type).collect();
    assert_eq!(got, expected);
}

#[test]
fn every_kind_signs_admin_kinds_sync() {
    for k in CATALOG {
        assert!(k.sign, "{} must sign=true per spec §2.1", k.event_type);
        // tn.read.tampered_row_skipped is the one local-only kind
        // (per 2026-04-25 spec §3.3 — runtime-private, not federated).
        if k.event_type == "tn.read.tampered_row_skipped" {
            assert!(!k.sync, "tn.read.tampered_row_skipped is local-only");
        } else {
            assert!(k.sync, "{} must sync=true per spec §2.1", k.event_type);
        }
    }
}

#[test]
fn kind_for_unknown_returns_none() {
    assert!(kind_for("tn.never.existed").is_none());
}

#[test]
fn validate_emit_recipient_added_ok() {
    let mut m = Map::new();
    m.insert("group".into(), json!("default"));
    m.insert("leaf_index".into(), json!(2));
    m.insert("recipient_did".into(), json!("did:key:zFrank"));
    m.insert("kit_sha256".into(), json!("sha256:abc"));
    m.insert("cipher".into(), json!("btn"));
    assert!(validate_emit("tn.recipient.added", &m).is_ok());
}

#[test]
fn validate_emit_missing_field_fails() {
    let mut m = Map::new();
    m.insert("group".into(), json!("default"));
    // leaf_index missing
    let err = validate_emit("tn.recipient.added", &m).unwrap_err();
    assert!(format!("{err}").contains("missing required field"));
}

#[test]
fn validate_emit_wrong_type_fails() {
    let mut m = Map::new();
    m.insert("group".into(), json!(42)); // should be string
    m.insert("leaf_index".into(), json!(2));
    m.insert("recipient_did".into(), Value::Null);
    m.insert("kit_sha256".into(), json!("sha256:abc"));
    m.insert("cipher".into(), json!("btn"));
    assert!(validate_emit("tn.recipient.added", &m).is_err());
}

#[test]
fn validate_emit_unknown_event_type_fails() {
    let m = Map::new();
    let err = validate_emit("tn.bogus", &m).unwrap_err();
    assert!(format!("{err}").contains("unknown admin event_type"));
}

#[test]
fn optional_string_null_accepted() {
    // tn.recipient.added: recipient_did is OptionalString.
    let mut m = Map::new();
    m.insert("group".into(), json!("default"));
    m.insert("leaf_index".into(), json!(0));
    m.insert("recipient_did".into(), Value::Null);
    m.insert("kit_sha256".into(), json!("sha256:xyz"));
    m.insert("cipher".into(), json!("btn"));
    assert!(validate_emit("tn.recipient.added", &m).is_ok());
}
