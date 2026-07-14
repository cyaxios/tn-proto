use std::time::{Duration, SystemTime};

use serde_json::json;
use tn_core::did_document::ResolvedX25519KeyAgreement;
use tn_core::jwe_binding::{
    AuthenticatedDidResolution, FingerprintPin, JweBindingEvidence, JweBindingExpectation,
    JweBindingScope, VerifiedJweRecipient,
};

fn scope() -> JweBindingScope {
    JweBindingScope {
        audience_did: tn_core::DeviceKey::generate().did().to_string(),
        ceremony_id: "ceremony-1".into(),
        group: "partners".into(),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        ttl: Duration::from_secs(600),
    }
}

#[test]
fn authenticated_did_resolution_normalizes_to_scoped_binding() {
    let reader_did = "did:example:reader";
    let resolved = ResolvedX25519KeyAgreement {
        did: reader_did.into(),
        verification_method_id: format!("{reader_did}#jwe-1"),
        public_key: [0x32; 32],
        public_key_sha256: tn_core::trusted_enrollment::sha256_tagged(&[0x32; 32]),
    };
    let evidence = AuthenticatedDidResolution {
        resolver: "did:web resolver with TLS and method verification".into(),
        resolution_digest: tn_core::trusted_enrollment::sha256_tagged(b"resolution-result"),
        document_digest: tn_core::trusted_enrollment::sha256_tagged(b"document"),
    };

    let binding = VerifiedJweRecipient::from_did_resolution(resolved, scope(), evidence).unwrap();
    assert_eq!(binding.reader_did, reader_did);
    assert_eq!(binding.public_key, [0x32; 32]);
    assert!(binding.binding_digest.starts_with("sha256:"));
    assert!(matches!(
        binding.evidence,
        JweBindingEvidence::DidDocument { .. }
    ));
}

#[test]
fn fingerprint_pin_requires_an_exact_public_key_fingerprint() {
    let reader_did = "did:example:reader";
    let key = [0x43; 32];
    let fingerprint = tn_core::trusted_enrollment::sha256_tagged(&key);
    let pin = FingerprintPin {
        expected_fingerprint: fingerprint,
        verified_by: "operator:alice".into(),
        verification_method: "voice call plus QR comparison".into(),
        evidence: "ticket-1234".into(),
    };

    let binding =
        VerifiedJweRecipient::from_fingerprint_pin(reader_did, key, scope(), pin).unwrap();
    assert!(matches!(
        binding.evidence,
        JweBindingEvidence::FingerprintPin { .. }
    ));

    let mismatch = FingerprintPin {
        expected_fingerprint: tn_core::trusted_enrollment::sha256_tagged(&[0x44; 32]),
        verified_by: "operator:alice".into(),
        verification_method: "voice call".into(),
        evidence: "ticket-1234".into(),
    };
    assert!(
        VerifiedJweRecipient::from_fingerprint_pin(reader_did, key, scope(), mismatch).is_err()
    );
}

#[test]
fn fingerprint_pin_rejects_nonzero_low_order_x25519_key() {
    let mut low_order = [0_u8; 32];
    low_order[0] = 1;
    let pin = FingerprintPin {
        expected_fingerprint: tn_core::trusted_enrollment::sha256_tagged(&low_order),
        verified_by: "operator:alice".into(),
        verification_method: "authenticated call".into(),
        evidence: "ticket-17".into(),
    };
    let error =
        VerifiedJweRecipient::from_fingerprint_pin("did:example:reader", low_order, scope(), pin)
            .unwrap_err();
    assert_eq!(error.reason, tn_core::TrustReason::BindingInvalid);
    assert!(error.detail.contains("low-order"));
}

#[test]
fn evidence_metadata_is_mandatory() {
    let resolved = ResolvedX25519KeyAgreement {
        did: "did:example:reader".into(),
        verification_method_id: "did:example:reader#jwe-1".into(),
        public_key: [0x55; 32],
        public_key_sha256: tn_core::trusted_enrollment::sha256_tagged(&[0x55; 32]),
    };
    let missing_resolver = AuthenticatedDidResolution {
        resolver: String::new(),
        resolution_digest: tn_core::trusted_enrollment::sha256_tagged(b"resolution-result"),
        document_digest: tn_core::trusted_enrollment::sha256_tagged(b"document"),
    };
    assert!(
        VerifiedJweRecipient::from_did_resolution(resolved, scope(), missing_resolver).is_err()
    );

    let missing_pin_method = FingerprintPin {
        expected_fingerprint: tn_core::trusted_enrollment::sha256_tagged(&[0x55; 32]),
        verified_by: "operator:alice".into(),
        verification_method: String::new(),
        evidence: "ticket".into(),
    };
    assert!(VerifiedJweRecipient::from_fingerprint_pin(
        "did:example:reader",
        [0x55; 32],
        scope(),
        missing_pin_method,
    )
    .is_err());
}

#[test]
fn normalized_binding_rechecks_reader_publisher_scope_and_freshness() {
    let reader_did = "did:example:reader";
    let publisher_did = tn_core::DeviceKey::generate().did().to_string();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let key = [0x66; 32];
    let binding = VerifiedJweRecipient::from_fingerprint_pin(
        reader_did,
        key,
        JweBindingScope {
            audience_did: publisher_did.clone(),
            ceremony_id: "ceremony-1".into(),
            group: "partners".into(),
            now,
            ttl: Duration::from_secs(600),
        },
        FingerprintPin {
            expected_fingerprint: tn_core::trusted_enrollment::sha256_tagged(&key),
            verified_by: "operator:alice".into(),
            verification_method: "in-person QR".into(),
            evidence: "ticket-1234".into(),
        },
    )
    .unwrap();

    binding
        .validate_for(&JweBindingExpectation {
            reader_did,
            audience_did: &publisher_did,
            ceremony_id: "ceremony-1",
            group: "partners",
            now: now + Duration::from_secs(300),
        })
        .unwrap();

    let stranger = tn_core::DeviceKey::generate().did().to_string();
    let wrong_publisher = binding
        .validate_for(&JweBindingExpectation {
            reader_did,
            audience_did: &stranger,
            ceremony_id: "ceremony-1",
            group: "partners",
            now,
        })
        .unwrap_err();
    assert_eq!(wrong_publisher.reason, tn_core::TrustReason::WrongRecipient);

    let expired = binding
        .validate_for(&JweBindingExpectation {
            reader_did,
            audience_did: &publisher_did,
            ceremony_id: "ceremony-1",
            group: "partners",
            now: now + Duration::from_secs(600),
        })
        .unwrap_err();
    assert_eq!(expired.reason, tn_core::TrustReason::StatementExpired);

    let expected = JweBindingExpectation {
        reader_did,
        audience_did: &publisher_did,
        ceremony_id: "ceremony-1",
        group: "partners",
        now,
    };
    let mut mutated_evidence = binding.clone();
    if let JweBindingEvidence::FingerprintPin { verified_by, .. } = &mut mutated_evidence.evidence {
        *verified_by = "operator:mallory".into();
    }
    assert_eq!(
        mutated_evidence.validate_for(&expected).unwrap_err().reason,
        tn_core::TrustReason::BindingInvalid
    );
    let mut mutated_digest = binding;
    mutated_digest.binding_digest = tn_core::trusted_enrollment::sha256_tagged(b"other binding");
    assert_eq!(
        mutated_digest.validate_for(&expected).unwrap_err().reason,
        tn_core::TrustReason::BindingInvalid
    );
}

#[test]
fn authenticated_document_adapter_hashes_the_exact_document_it_extracts() {
    let reader_did = "did:example:reader";
    let key = [0x77; 32];
    let mut encoded = vec![0xec, 0x01];
    encoded.extend_from_slice(&key);
    let method_id = format!("{reader_did}#jwe-1");
    let document = json!({
        "id": reader_did,
        "keyAgreement": [{
            "id": method_id,
            "type": "Multikey",
            "controller": reader_did,
            "publicKeyMultibase": format!("z{}", bs58::encode(encoded).into_string())
        }]
    });
    let resolution_digest = tn_core::trusted_enrollment::sha256_tagged(b"resolution-result");

    let binding = VerifiedJweRecipient::from_authenticated_did_document(
        &document,
        reader_did,
        Some(&method_id),
        scope(),
        "did:web resolver with TLS and method verification",
        &resolution_digest,
    )
    .unwrap();

    let canonical = tn_core::canonical::canonical_bytes(&document).unwrap();
    match binding.evidence {
        JweBindingEvidence::DidDocument {
            document_digest,
            resolution_digest: retained_resolution,
            ..
        } => {
            assert_eq!(
                document_digest,
                tn_core::trusted_enrollment::sha256_tagged(&canonical)
            );
            assert_eq!(retained_resolution, resolution_digest);
        }
        other => panic!("unexpected evidence: {other:?}"),
    }
}
