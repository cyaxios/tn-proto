use std::time::{Duration, SystemTime};

use tn_core::did_document::ResolvedX25519KeyAgreement;
use tn_core::jwe_binding::{
    AuthenticatedDidResolution, FingerprintPin, JweBindingEvidence, JweBindingScope,
    VerifiedJweRecipient,
};
use tn_core::{AcceptedOffer, VerifiedJweBinding, VerifiedPrincipal};

fn scope() -> JweBindingScope {
    JweBindingScope {
        audience_did: tn_core::DeviceKey::generate().did().to_string(),
        ceremony_id: "ceremony-1".into(),
        group: "partners".into(),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        ttl: Duration::from_secs(600),
    }
}

fn accepted(challenge_digest: Option<&str>) -> AcceptedOffer {
    AcceptedOffer {
        binding: VerifiedJweBinding {
            principal: VerifiedPrincipal {
                did: tn_core::DeviceKey::generate().did().to_string(),
                purpose: "jwe-reader".into(),
                audience_did: scope().audience_did,
                ceremony_id: "ceremony-1".into(),
                group: "partners".into(),
                proof_digest: "sha256:proof".into(),
                issued_at: "2027-01-15T08:00:00.000000Z".into(),
                expires_at: "2027-01-15T08:10:00.000000Z".into(),
            },
            public_key: [0x21; 32],
            public_key_sha256: tn_core::trusted_enrollment::sha256_tagged(&[0x21; 32]),
            proof_digest: "sha256:proof".into(),
            challenge_digest: challenge_digest.map(str::to_string),
        },
        offer_digest: "sha256:offer".into(),
        artifact_digest: "sha256:artifact".into(),
    }
}

#[test]
fn accepted_offer_normalizes_key_card_and_challenge_sources() {
    let card = VerifiedJweRecipient::from_accepted_offer(&accepted(None));
    assert!(matches!(
        card.evidence,
        JweBindingEvidence::SignedKeyCard { .. }
    ));
    assert_eq!(card.binding_digest, "sha256:offer");

    let challenged = VerifiedJweRecipient::from_accepted_offer(&accepted(Some("sha256:challenge")));
    assert!(matches!(
        challenged.evidence,
        JweBindingEvidence::ChallengeResponse { .. }
    ));
    assert_eq!(challenged.public_key, [0x21; 32]);
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
