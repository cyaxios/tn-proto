//! Cross-SDK contract tests for unsafe-operation notice values.

use serde_json::json;
use tn_core::unsafe_operation::{UnsafeOperation, UnsafeOperationNotice, UnsafeRelaxation};

#[test]
fn operation_enum_uses_the_exact_wire_values() {
    let cases = [
        (UnsafeOperation::Read, "read"),
        (UnsafeOperation::Watch, "watch"),
        (UnsafeOperation::JweAddRecipient, "jwe_add_recipient"),
        (UnsafeOperation::HibeGrant, "hibe_grant"),
        (
            UnsafeOperation::LegacyPackageImport,
            "legacy_package_import",
        ),
    ];

    for (value, wire) in cases {
        assert_eq!(serde_json::to_value(value).unwrap(), json!(wire));
        assert_eq!(
            serde_json::from_value::<UnsafeOperation>(json!(wire)).unwrap(),
            value
        );
    }
    assert!(serde_json::from_value::<UnsafeOperation>(json!("other")).is_err());
}

#[test]
fn relaxation_enum_uses_the_exact_wire_values() {
    let cases = [
        (
            UnsafeRelaxation::VerificationDisabled,
            "verification_disabled",
        ),
        (
            UnsafeRelaxation::SignatureNotRequired,
            "signature_not_required",
        ),
        (
            UnsafeRelaxation::UnauthenticatedAllowed,
            "unauthenticated_allowed",
        ),
        (
            UnsafeRelaxation::UnknownWriterAllowed,
            "unknown_writer_allowed",
        ),
        (
            UnsafeRelaxation::UnverifiedKeyBinding,
            "unverified_key_binding",
        ),
        (
            UnsafeRelaxation::PlaintextBearerDelivery,
            "plaintext_bearer_delivery",
        ),
        (
            UnsafeRelaxation::LegacySignerMismatch,
            "legacy_signer_mismatch",
        ),
    ];

    for (value, wire) in cases {
        assert_eq!(serde_json::to_value(value).unwrap(), json!(wire));
        assert_eq!(
            serde_json::from_value::<UnsafeRelaxation>(json!(wire)).unwrap(),
            value
        );
    }
    assert!(serde_json::from_value::<UnsafeRelaxation>(json!("other")).is_err());
}

#[test]
fn notice_serializes_to_the_exact_canonical_five_field_payload() {
    let notice = UnsafeOperationNotice::new(
        UnsafeOperation::Read,
        [UnsafeRelaxation::VerificationDisabled],
    );

    assert_eq!(
        serde_json::to_string(&notice).unwrap(),
        r#"{"artifact_digest":null,"group":null,"operation":"read","relaxations":["verification_disabled"],"subject_did":null}"#
    );
}

#[test]
fn notice_serialization_sorts_and_deduplicates_relaxations() {
    let notice = UnsafeOperationNotice {
        artifact_digest: Some("sha256:abc".into()),
        group: Some("default".into()),
        operation: UnsafeOperation::LegacyPackageImport,
        relaxations: vec![
            UnsafeRelaxation::VerificationDisabled,
            UnsafeRelaxation::LegacySignerMismatch,
            UnsafeRelaxation::VerificationDisabled,
            UnsafeRelaxation::SignatureNotRequired,
        ],
        subject_did: Some("did:key:z6MkExample".into()),
    };

    assert_eq!(
        serde_json::to_value(notice).unwrap()["relaxations"],
        json!([
            "legacy_signer_mismatch",
            "signature_not_required",
            "verification_disabled"
        ])
    );
}

#[test]
fn constructor_stores_relaxations_in_canonical_order() {
    let notice = UnsafeOperationNotice::new(
        UnsafeOperation::Watch,
        [
            UnsafeRelaxation::UnknownWriterAllowed,
            UnsafeRelaxation::UnauthenticatedAllowed,
            UnsafeRelaxation::UnknownWriterAllowed,
        ],
    );

    assert_eq!(
        notice.relaxations,
        vec![
            UnsafeRelaxation::UnauthenticatedAllowed,
            UnsafeRelaxation::UnknownWriterAllowed,
        ]
    );
}

#[test]
fn deserialization_normalizes_relaxations_and_rejects_extra_fields() {
    let notice: UnsafeOperationNotice = serde_json::from_value(json!({
        "artifact_digest": null,
        "group": null,
        "operation": "read",
        "relaxations": [
            "verification_disabled",
            "signature_not_required",
            "verification_disabled"
        ],
        "subject_did": null,
    }))
    .unwrap();
    assert_eq!(
        notice.relaxations,
        vec![
            UnsafeRelaxation::SignatureNotRequired,
            UnsafeRelaxation::VerificationDisabled,
        ]
    );

    let with_extra = json!({
        "artifact_digest": null,
        "extra": "not permitted",
        "group": null,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": null,
    });
    assert!(serde_json::from_value::<UnsafeOperationNotice>(with_extra).is_err());
}

#[test]
fn deserialization_requires_all_five_fields_even_when_nullable() {
    let complete = json!({
        "artifact_digest": null,
        "group": null,
        "operation": "read",
        "relaxations": ["verification_disabled"],
        "subject_did": null,
    });

    for missing in [
        "artifact_digest",
        "group",
        "operation",
        "relaxations",
        "subject_did",
    ] {
        let mut incomplete = complete.clone();
        incomplete.as_object_mut().unwrap().remove(missing);
        assert!(
            serde_json::from_value::<UnsafeOperationNotice>(incomplete).is_err(),
            "missing {missing:?} must be rejected"
        );
    }
}
