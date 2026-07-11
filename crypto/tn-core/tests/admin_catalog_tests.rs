//! Tests for admin_catalog: presence of each kind, schema enforcement.

use serde_json::{json, Map, Value};
use tn_core::admin_catalog::{kind_for, validate_emit, FieldType, CATALOG};

#[test]
fn catalog_has_thirteen_kinds() {
    // 10 from the original 2026-04-23 admin-log spec + 2 from the
    // 2026-04-25 read-ergonomics + agents-group spec
    // (`tn.agents.policy_published`, `tn.read.tampered_row_skipped`).
    assert_eq!(
        CATALOG.len(),
        13,
        "10 admin + 2 agents/read kinds + 1 security kind"
    );
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
        "tn.security.unsafe_operation",
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
    m.insert("recipient_identity".into(), json!("did:key:zFrank"));
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
    m.insert("recipient_identity".into(), Value::Null);
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
    // tn.recipient.added: recipient_identity is OptionalString.
    let mut m = Map::new();
    m.insert("group".into(), json!("default"));
    m.insert("leaf_index".into(), json!(0));
    m.insert("recipient_identity".into(), Value::Null);
    m.insert("kit_sha256".into(), json!("sha256:xyz"));
    m.insert("cipher".into(), json!("btn"));
    assert!(validate_emit("tn.recipient.added", &m).is_ok());
}

#[test]
fn unsafe_operation_schema_is_exact() {
    let kind = kind_for("tn.security.unsafe_operation").unwrap();
    assert_eq!(
        kind.schema,
        &[
            ("artifact_digest", FieldType::OptionalString),
            ("group", FieldType::OptionalString),
            ("operation", FieldType::String),
            ("relaxations", FieldType::StringArray),
            ("subject_did", FieldType::OptionalString),
        ]
    );
    assert!(kind.sign);
    assert!(kind.sync);
}

#[test]
fn unsafe_operation_catalog_accepts_the_canonical_payload() {
    let fields = json!({
        "artifact_digest": null,
        "group": null,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": null,
    })
    .as_object()
    .unwrap()
    .clone();

    assert!(validate_emit("tn.security.unsafe_operation", &fields).is_ok());
}

#[test]
fn unsafe_operation_catalog_accepts_a_realistic_full_envelope() {
    let fields = json!({
        "device_identity": "did:key:z6MkPublisher",
        "timestamp": "2026-07-11T12:00:00Z",
        "event_id": "0198a000-0000-7000-8000-000000000001",
        "event_type": "tn.security.unsafe_operation",
        "level": "warning",
        "sequence": 7,
        "prev_hash": "sha256:previous",
        "row_hash": "sha256:current",
        "signature": "base64-signature",
        "artifact_digest": null,
        "group": null,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": null,
    })
    .as_object()
    .unwrap()
    .clone();

    assert!(validate_emit("tn.security.unsafe_operation", &fields).is_ok());
}

#[test]
fn unsafe_operation_catalog_rejects_non_array_relaxations() {
    let fields = json!({
        "artifact_digest": null,
        "group": null,
        "operation": "read",
        "relaxations": "verification_disabled",
        "subject_did": null,
    })
    .as_object()
    .unwrap()
    .clone();

    assert!(validate_emit("tn.security.unsafe_operation", &fields).is_err());
}

#[test]
fn unsafe_operation_catalog_rejects_extra_fields() {
    let fields = json!({
        "artifact_digest": null,
        "extra": "not permitted",
        "group": null,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": null,
    })
    .as_object()
    .unwrap()
    .clone();

    let err = validate_emit("tn.security.unsafe_operation", &fields).unwrap_err();
    assert!(format!("{err}").contains("unexpected field"));
}
