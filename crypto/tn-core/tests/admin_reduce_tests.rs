//! Exhaustive reducer tests: one delta kind per test + Unknown + errors.

use serde_json::{json, Value};
use tn_core::admin_reduce::{reduce, ReduceError, StateDelta};

fn env(event_type: &str, fields: Value) -> Value {
    // Build a realistic envelope with the nine mandatory scalar fields plus
    // the admin fields. Attestation values are not inspected by reduce.
    let mut m = serde_json::Map::new();
    m.insert("device_identity".into(), json!("did:key:zTest"));
    m.insert("timestamp".into(), json!("2026-04-22T12:00:00Z"));
    m.insert(
        "event_id".into(),
        json!("0198a000-0000-7000-8000-000000000001"),
    );
    m.insert("event_type".into(), json!(event_type));
    m.insert("level".into(), json!("info"));
    m.insert("sequence".into(), json!(1));
    m.insert("prev_hash".into(), json!("sha256:previous"));
    m.insert("row_hash".into(), json!("sha256:current"));
    m.insert("signature".into(), json!("base64-signature"));
    if let Value::Object(f) = fields {
        for (k, v) in f {
            m.insert(k, v);
        }
    }
    Value::Object(m)
}

#[test]
fn reduce_ceremony_init() {
    let e = env(
        "tn.ceremony.init",
        json!({
            "ceremony_id": "local_abc",
            "cipher": "btn",
            "device_identity": "did:key:zAlice",
            "created_at": "2026-04-22T12:00:00Z",
        }),
    );
    match reduce(&e).unwrap() {
        StateDelta::CeremonyInit {
            ceremony_id,
            cipher,
            ..
        } => {
            assert_eq!(ceremony_id, "local_abc");
            assert_eq!(cipher, "btn");
        }
        d => panic!("expected CeremonyInit, got {d:?}"),
    }
}

#[test]
fn reduce_group_added() {
    let e = env(
        "tn.group.added",
        json!({
            "group": "pii", "cipher": "btn",
            "publisher_identity": "did:key:zAlice",
            "added_at": "2026-04-22T12:00:00Z",
        }),
    );
    assert!(matches!(reduce(&e).unwrap(), StateDelta::GroupAdded { .. }));
}

#[test]
fn reduce_recipient_added_with_did() {
    let e = env(
        "tn.recipient.added",
        json!({
            "group": "default", "leaf_index": 2,
            "recipient_identity": "did:key:zFrank",
            "kit_sha256": "sha256:abc", "cipher": "btn",
        }),
    );
    match reduce(&e).unwrap() {
        StateDelta::RecipientAdded {
            leaf_index,
            recipient_identity,
            ..
        } => {
            assert_eq!(leaf_index, Some(2));
            assert_eq!(recipient_identity.as_deref(), Some("did:key:zFrank"));
        }
        d => panic!("expected RecipientAdded, got {d:?}"),
    }
}

#[test]
fn reduce_recipient_added_without_did() {
    let e = env(
        "tn.recipient.added",
        json!({
            "group": "default", "leaf_index": 3,
            "recipient_identity": null,
            "kit_sha256": "sha256:xyz", "cipher": "btn",
        }),
    );
    match reduce(&e).unwrap() {
        StateDelta::RecipientAdded {
            recipient_identity, ..
        } => {
            assert_eq!(recipient_identity, None);
        }
        d => panic!("{d:?}"),
    }
}

#[test]
fn reduce_recipient_revoked() {
    let e = env(
        "tn.recipient.revoked",
        json!({
            "group": "default", "leaf_index": 2,
            "recipient_identity": "did:key:zFrank",
        }),
    );
    assert!(matches!(
        reduce(&e).unwrap(),
        StateDelta::RecipientRevoked { .. }
    ));
}

#[test]
fn reduce_coupon_issued() {
    let e = env(
        "tn.coupon.issued",
        json!({
            "group": "default", "slot": 1,
            "recipient_identity": "did:key:zBob", "issued_to": "bob@example.com",
        }),
    );
    assert!(matches!(
        reduce(&e).unwrap(),
        StateDelta::CouponIssued { .. }
    ));
}

#[test]
fn reduce_rotation_completed() {
    let e = env(
        "tn.rotation.completed",
        json!({
            "group": "default", "cipher": "btn",
            "generation": 2,
            "previous_kit_sha256": "sha256:old",
            "old_pool_size": null, "new_pool_size": null,
            "rotated_at": "2026-04-22T12:00:00Z",
        }),
    );
    match reduce(&e).unwrap() {
        StateDelta::RotationCompleted {
            generation,
            old_pool_size,
            ..
        } => {
            assert_eq!(generation, 2);
            assert_eq!(old_pool_size, None);
        }
        d => panic!("{d:?}"),
    }
}

#[test]
fn reduce_enrolment_compiled_and_absorbed() {
    let c = env(
        "tn.enrolment.compiled",
        json!({
            "group": "default", "peer_identity": "did:key:zBob",
            "package_sha256": "sha256:pkg",
            "compiled_at": "2026-04-22T12:00:00Z",
        }),
    );
    assert!(matches!(
        reduce(&c).unwrap(),
        StateDelta::EnrolmentCompiled { .. }
    ));

    let a = env(
        "tn.enrolment.absorbed",
        json!({
            "group": "default", "publisher_identity": "did:key:zAlice",
            "package_sha256": "sha256:pkg",
            "absorbed_at": "2026-04-22T12:05:00Z",
        }),
    );
    assert!(matches!(
        reduce(&a).unwrap(),
        StateDelta::EnrolmentAbsorbed { .. }
    ));
}

#[test]
fn reduce_vault_linked_and_unlinked() {
    let l = env(
        "tn.vault.linked",
        json!({
            "vault_identity": "did:web:tnproto.org",
            "project_id": "proj_test",
            "linked_at": "2026-04-22T12:00:00Z",
        }),
    );
    assert!(matches!(
        reduce(&l).unwrap(),
        StateDelta::VaultLinked { .. }
    ));

    let u = env(
        "tn.vault.unlinked",
        json!({
            "vault_identity": "did:web:tnproto.org",
            "project_id": "proj_test",
            "reason": "user_request",
            "unlinked_at": "2026-04-22T13:00:00Z",
        }),
    );
    match reduce(&u).unwrap() {
        StateDelta::VaultUnlinked { reason, .. } => {
            assert_eq!(reason.as_deref(), Some("user_request"));
        }
        d => panic!("{d:?}"),
    }
}

#[test]
fn reduce_unknown_event_type_returns_unknown() {
    let e = env("order.created", json!({"order_id": "A100"}));
    match reduce(&e).unwrap() {
        StateDelta::Unknown { event_type } => assert_eq!(event_type, "order.created"),
        d => panic!("{d:?}"),
    }
}

#[test]
fn reduce_unsafe_operation_is_valid_without_state_mutation() {
    let e = env(
        "tn.security.unsafe_operation",
        json!({
            "artifact_digest": null,
            "group": null,
            "operation": "read",
            "relaxations": ["verification_disabled"],
            "subject_did": null,
        }),
    );

    match reduce(&e).unwrap() {
        StateDelta::Unknown { event_type } => {
            assert_eq!(event_type, "tn.security.unsafe_operation");
        }
        d => panic!("expected no-state-mutation Unknown, got {d:?}"),
    }
}

fn canonical_unsafe_operation_fields() -> Value {
    json!({
        "artifact_digest": null,
        "group": null,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": null,
    })
}

fn assert_unsafe_operation_schema_violation(fields: Value) {
    let envelope = env("tn.security.unsafe_operation", fields);
    assert!(matches!(
        reduce(&envelope).unwrap_err(),
        ReduceError::SchemaViolation(_)
    ));
}

#[test]
fn reduce_unsafe_operation_rejects_unknown_operation() {
    let mut fields = canonical_unsafe_operation_fields();
    fields["operation"] = json!("delete_everything");

    assert_unsafe_operation_schema_violation(fields);
}

#[test]
fn reduce_unsafe_operation_rejects_unknown_relaxation() {
    let mut fields = canonical_unsafe_operation_fields();
    fields["relaxations"] = json!(["trust_everything"]);

    assert_unsafe_operation_schema_violation(fields);
}

#[test]
fn reduce_unsafe_operation_rejects_empty_relaxations() {
    let mut fields = canonical_unsafe_operation_fields();
    fields["relaxations"] = json!([]);

    assert_unsafe_operation_schema_violation(fields);
}

#[test]
fn reduce_missing_event_type_errors() {
    let e = json!({"did": "did:key:zTest"});
    assert!(matches!(
        reduce(&e).unwrap_err(),
        ReduceError::MissingEventType
    ));
}

#[test]
fn reduce_schema_violation_on_catalogued_event() {
    // tn.recipient.added missing kit_sha256.
    let e = env(
        "tn.recipient.added",
        json!({
            "group": "default", "leaf_index": 1,
            "recipient_identity": null,
            "cipher": "btn",
        }),
    );
    assert!(matches!(
        reduce(&e).unwrap_err(),
        ReduceError::SchemaViolation(_)
    ));
}

#[test]
fn serde_roundtrip_delta() {
    // Serialize + deserialize a delta; the wire shape is the PyO3 handoff.
    let d = StateDelta::RecipientAdded {
        group: "default".into(),
        leaf_index: Some(2),
        recipient_identity: Some("did:key:zFrank".into()),
        kit_sha256: "sha256:abc".into(),
        cipher: "btn".into(),
    };
    let s = serde_json::to_string(&d).unwrap();
    assert!(s.contains("\"kind\":\"recipient_added\""));
    let back: StateDelta = serde_json::from_str(&s).unwrap();
    assert!(matches!(back, StateDelta::RecipientAdded { .. }));
}

/// Drift guard: every CATALOG entry must have a matching build_delta arm.
///
/// For each catalog kind, build a minimally-valid envelope whose fields
/// satisfy validate_emit, call reduce(), and assert:
///   1. It returns Ok (not Unknown, not an error).
///   2. The resulting StateDelta serializes with `kind` equal to the
///      snake_case of the event_type (e.g. "tn.recipient.added" -> "recipient_added").
///
/// If someone adds a catalog entry without a build_delta arm, `reduce` hits
/// the `unreachable!()` and this test panics with a clear message.
#[test]
fn catalog_and_reducer_do_not_drift() {
    use tn_core::admin_catalog::{FieldType, CATALOG};

    // These catalog-valid observability/provenance events intentionally
    // resolve to StateDelta::Unknown without mutating admin state.
    let no_state_mutation: std::collections::HashSet<&str> = [
        "tn.agents.policy_published",
        "tn.read.tampered_row_skipped",
        "tn.security.unsafe_operation",
    ]
    .into_iter()
    .collect();

    for kind in CATALOG {
        let mut fields = serde_json::Map::new();
        for (name, ftype) in kind.schema {
            let v = match ftype {
                FieldType::String => json!("x"),
                FieldType::OptionalString => json!(null),
                FieldType::Int => json!(0),
                FieldType::OptionalInt => json!(null),
                FieldType::Iso8601 => json!("2026-04-22T12:00:00Z"),
                FieldType::StringArray => json!(["verification_disabled"]),
            };
            fields.insert((*name).to_string(), v);
        }
        if kind.event_type == "tn.security.unsafe_operation" {
            fields.insert("operation".into(), json!("read"));
        }
        let envelope = env(kind.event_type, Value::Object(fields));

        let delta = reduce(&envelope).unwrap_or_else(|e| {
            panic!(
                "catalog/reducer drift: {:?} failed to reduce: {}",
                kind.event_type, e
            )
        });

        // Unknown variant means build_delta doesn't know this event_type.
        if let StateDelta::Unknown { event_type } = &delta {
            if no_state_mutation.contains(event_type.as_str()) {
                continue;
            }
            panic!(
                "catalog/reducer drift: {:?} reduced to Unknown; \
                 add a build_delta arm in admin_reduce.rs",
                event_type
            );
        }

        // The serialized `kind` tag should equal the last two dotted parts
        // of the event_type, joined by underscore (snake_case of the
        // stripped "tn." prefix). E.g. "tn.recipient.added" -> "recipient_added".
        let wire = serde_json::to_value(&delta).unwrap();
        let wire_kind = wire.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let expected_kind = kind
            .event_type
            .strip_prefix("tn.")
            .unwrap_or(kind.event_type)
            .replace('.', "_");
        assert_eq!(
            wire_kind, expected_kind,
            "wire kind mismatch for {}: got {:?}, expected {:?}",
            kind.event_type, wire_kind, expected_kind
        );
    }
}
