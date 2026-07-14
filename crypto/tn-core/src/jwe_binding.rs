//! Normalized, public-only evidence authorizing a JWE recipient key.

use curve25519_dalek::montgomery::MontgomeryPoint;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq as _;

use crate::canonical::canonical_bytes;
use crate::did_document::{extract_x25519_key_agreement, ResolvedX25519KeyAgreement};
use crate::trust::{ed25519_did_to_x25519_public, AcceptedOffer, TrustError, TrustReason};
use crate::trusted_enrollment::{
    canonical_utc_timestamp, sha256_tagged, validate_statement_freshness,
};

/// Publisher scope and validity assigned to non-offer binding evidence.
#[derive(Debug, Clone)]
pub struct JweBindingScope {
    /// Publisher DID accepting the recipient binding.
    pub audience_did: String,
    /// Ceremony in which the binding is valid.
    pub ceremony_id: String,
    /// JWE group in which the key is authorized.
    pub group: String,
    /// Binding acceptance time.
    pub now: SystemTime,
    /// Maximum lifetime of the accepted binding.
    pub ttl: Duration,
}

/// Receiver expectations rechecked immediately before recipient registration.
#[derive(Debug, Clone)]
pub struct JweBindingExpectation<'a> {
    /// Exact reader DID being enrolled.
    pub reader_did: &'a str,
    /// Exact publisher DID accepting the binding.
    pub audience_did: &'a str,
    /// Exact ceremony scope.
    pub ceremony_id: &'a str,
    /// Exact JWE group scope.
    pub group: &'a str,
    /// Registration instant used for expiry checking.
    pub now: SystemTime,
}

/// Evidence retained from an authenticated DID-method resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDidResolution {
    /// DID method/resolver authentication description.
    pub resolver: String,
    /// Digest of the resolver result including its verification metadata.
    pub resolution_digest: String,
    /// Digest of the exact DID document parsed by TN.
    pub document_digest: String,
}

/// Explicit record of an out-of-band X25519 fingerprint comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintPin {
    /// Expected `sha256:<hex>` digest of the raw X25519 key.
    pub expected_fingerprint: String,
    /// Operator or system that performed the comparison.
    pub verified_by: String,
    /// Out-of-band comparison method.
    pub verification_method: String,
    /// Evidence reference; TN retains only its digest.
    pub evidence: String,
}

/// How a DID-to-X25519 binding was authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JweBindingEvidence {
    /// Portable subject-signed proof without a publisher challenge.
    SignedKeyCard {
        /// Canonical inner offer digest.
        offer_digest: String,
        /// Exact package digest.
        artifact_digest: String,
        /// Subject-signed proof digest.
        proof_digest: String,
    },
    /// Subject-signed proof bound to a publisher's one-time challenge.
    ChallengeResponse {
        /// Canonical inner offer digest.
        offer_digest: String,
        /// Exact package digest.
        artifact_digest: String,
        /// Subject-signed proof digest.
        proof_digest: String,
        /// Publisher challenge digest named by the proof.
        challenge_digest: String,
    },
    /// X25519 key selected from authenticated DID resolution output.
    DidDocument {
        /// Selected method's DID URL.
        verification_method_id: String,
        /// Resolver/method authentication description.
        resolver: String,
        /// Authenticated resolution result digest.
        resolution_digest: String,
        /// Parsed DID document digest.
        document_digest: String,
    },
    /// Explicit out-of-band public-key fingerprint comparison.
    FingerprintPin {
        /// Fingerprint compared by the operator.
        expected_fingerprint: String,
        /// Operator or system that performed the comparison.
        verified_by: String,
        /// Comparison method.
        verification_method: String,
        /// Digest of the evidence reference.
        evidence_digest: String,
    },
}

impl JweBindingEvidence {
    /// Stable source name for storage and audit records.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SignedKeyCard { .. } => "signed-key-card",
            Self::ChallengeResponse { .. } => "challenge-response",
            Self::DidDocument { .. } => "did-document",
            Self::FingerprintPin { .. } => "fingerprint-pin",
        }
    }

    /// Canonical-ready JSON representation of the public evidence metadata.
    pub fn to_value(&self) -> Value {
        match self {
            Self::SignedKeyCard {
                offer_digest,
                artifact_digest,
                proof_digest,
            } => json!({
                "kind": self.kind(), "offer_digest": offer_digest,
                "artifact_digest": artifact_digest, "proof_digest": proof_digest,
            }),
            Self::ChallengeResponse {
                offer_digest,
                artifact_digest,
                proof_digest,
                challenge_digest,
            } => json!({
                "kind": self.kind(), "offer_digest": offer_digest,
                "artifact_digest": artifact_digest, "proof_digest": proof_digest,
                "challenge_digest": challenge_digest,
            }),
            Self::DidDocument {
                verification_method_id,
                resolver,
                resolution_digest,
                document_digest,
            } => json!({
                "kind": self.kind(), "verification_method_id": verification_method_id,
                "resolver": resolver, "resolution_digest": resolution_digest,
                "document_digest": document_digest,
            }),
            Self::FingerprintPin {
                expected_fingerprint,
                verified_by,
                verification_method,
                evidence_digest,
            } => json!({
                "kind": self.kind(), "expected_fingerprint": expected_fingerprint,
                "verified_by": verified_by, "verification_method": verification_method,
                "evidence_digest": evidence_digest,
            }),
        }
    }
}

/// A scoped DID-to-X25519 binding accepted through any safe enrollment route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJweRecipient {
    /// DID whose X25519 key was authenticated.
    pub reader_did: String,
    /// Publisher DID that accepted this binding.
    pub audience_did: String,
    /// Ceremony scope.
    pub ceremony_id: String,
    /// JWE group scope.
    pub group: String,
    /// Raw public X25519 key.
    pub public_key: [u8; 32],
    /// Digest of the raw public key.
    pub public_key_sha256: String,
    /// Digest covering key, scope, validity, and evidence.
    pub binding_digest: String,
    /// Canonical UTC issuance timestamp.
    pub issued_at: String,
    /// Canonical UTC expiry timestamp.
    pub expires_at: String,
    /// Authentication evidence retained for audit.
    pub evidence: JweBindingEvidence,
    /// Construction seal covering every public field.
    integrity_digest: String,
}

impl VerifiedJweRecipient {
    /// Normalize an already verified signed offer or challenge response.
    pub fn from_accepted_offer(accepted: &AcceptedOffer) -> Result<Self, TrustError> {
        accepted.validate_integrity()?;
        let binding = &accepted.binding;
        let principal = &binding.principal;
        if principal.purpose != "jwe-reader" {
            return Err(binding_error(
                "accepted offer proof purpose must be jwe-reader",
            ));
        }
        if principal.proof_digest != binding.proof_digest {
            return Err(binding_error(
                "accepted offer principal and key binding name different proofs",
            ));
        }
        if accepted.offer_digest != binding.proof_digest {
            return Err(binding_error(
                "accepted offer digest does not name the verified proof",
            ));
        }
        validate_public_key(&binding.public_key, &binding.public_key_sha256)?;
        for (digest, name) in [
            (&principal.proof_digest, "principal proof_digest"),
            (&accepted.offer_digest, "offer_digest"),
            (&accepted.artifact_digest, "artifact_digest"),
        ] {
            validate_digest(digest, name)?;
        }
        if let Some(challenge_digest) = &binding.challenge_digest {
            validate_digest(challenge_digest, "challenge_digest")?;
        }
        let evidence = match &binding.challenge_digest {
            Some(challenge_digest) => JweBindingEvidence::ChallengeResponse {
                offer_digest: accepted.offer_digest.clone(),
                artifact_digest: accepted.artifact_digest.clone(),
                proof_digest: binding.proof_digest.clone(),
                challenge_digest: challenge_digest.clone(),
            },
            None => JweBindingEvidence::SignedKeyCard {
                offer_digest: accepted.offer_digest.clone(),
                artifact_digest: accepted.artifact_digest.clone(),
                proof_digest: binding.proof_digest.clone(),
            },
        };
        let mut result = Self {
            reader_did: principal.did.clone(),
            audience_did: principal.audience_did.clone(),
            ceremony_id: principal.ceremony_id.clone(),
            group: principal.group.clone(),
            public_key: binding.public_key,
            public_key_sha256: binding.public_key_sha256.clone(),
            binding_digest: String::new(),
            issued_at: principal.issued_at.clone(),
            expires_at: principal.expires_at.clone(),
            evidence,
            integrity_digest: String::new(),
        };
        result.binding_digest = normalized_binding_digest(&result);
        result.integrity_digest = binding_integrity_digest(&result);
        Ok(result)
    }

    /// Extract and bind a key from the exact authenticated DID document.
    ///
    /// The caller remains responsible for DID-method resolution security;
    /// this adapter hashes the exact document it parses so the retained
    /// evidence cannot accidentally describe different bytes.
    pub fn from_authenticated_did_document(
        document: &Value,
        expected_did: &str,
        verification_method_id: Option<&str>,
        scope: JweBindingScope,
        resolver: &str,
        resolution_digest: &str,
    ) -> Result<Self, TrustError> {
        require_text(resolver, "resolver")?;
        validate_digest(resolution_digest, "resolution_digest")?;
        let key_agreement =
            extract_x25519_key_agreement(document, expected_did, verification_method_id)?;
        let document_bytes =
            canonical_bytes(document).map_err(|error| binding_error(error.to_string()))?;
        Self::from_did_resolution(
            key_agreement,
            scope,
            AuthenticatedDidResolution {
                resolver: resolver.to_string(),
                resolution_digest: resolution_digest.to_string(),
                document_digest: sha256_tagged(&document_bytes),
            },
        )
    }

    /// Normalize one key from authenticated DID-method resolution output.
    pub fn from_did_resolution(
        resolved: ResolvedX25519KeyAgreement,
        scope: JweBindingScope,
        evidence: AuthenticatedDidResolution,
    ) -> Result<Self, TrustError> {
        validate_scope(&scope)?;
        require_text(&evidence.resolver, "resolver")?;
        validate_digest(&evidence.resolution_digest, "resolution_digest")?;
        validate_digest(&evidence.document_digest, "document_digest")?;
        validate_public_key(&resolved.public_key, &resolved.public_key_sha256)?;
        let did_key_agreement = ed25519_did_to_x25519_public(&resolved.did)?;
        if resolved.public_key != did_key_agreement {
            return Err(binding_error(
                "DID document X25519 key does not match the reader's Ed25519 did:key",
            ));
        }
        let source = JweBindingEvidence::DidDocument {
            verification_method_id: resolved.verification_method_id,
            resolver: evidence.resolver,
            resolution_digest: evidence.resolution_digest,
            document_digest: evidence.document_digest,
        };
        build_binding(resolved.did, resolved.public_key, scope, source)
    }

    /// Normalize a public key whose fingerprint was compared out of band.
    pub fn from_fingerprint_pin(
        reader_did: impl Into<String>,
        public_key: [u8; 32],
        scope: JweBindingScope,
        pin: FingerprintPin,
    ) -> Result<Self, TrustError> {
        validate_scope(&scope)?;
        validate_digest(&pin.expected_fingerprint, "expected_fingerprint")?;
        if sha256_tagged(&public_key) != pin.expected_fingerprint {
            return Err(binding_error(
                "pinned fingerprint does not match the X25519 public key",
            ));
        }
        require_text(&pin.verified_by, "verified_by")?;
        require_text(&pin.verification_method, "verification_method")?;
        require_text(&pin.evidence, "evidence")?;
        let source = JweBindingEvidence::FingerprintPin {
            expected_fingerprint: pin.expected_fingerprint,
            verified_by: pin.verified_by,
            verification_method: pin.verification_method,
            evidence_digest: sha256_tagged(pin.evidence.as_bytes()),
        };
        build_binding(reader_did.into(), public_key, scope, source)
    }

    /// Recheck identity, scope, key digest, and freshness before registration.
    pub fn validate_for(&self, expected: &JweBindingExpectation<'_>) -> Result<(), TrustError> {
        require_did(expected.reader_did, "expected reader_did")?;
        require_did(expected.audience_did, "expected audience_did")?;
        if self.reader_did != expected.reader_did {
            return Err(TrustError::new(
                TrustReason::WrongRecipient,
                "JWE binding names a different reader",
            ));
        }
        if self.audience_did != expected.audience_did {
            return Err(TrustError::new(
                TrustReason::WrongRecipient,
                "JWE binding names a different publisher",
            ));
        }
        if self.ceremony_id != expected.ceremony_id || self.group != expected.group {
            return Err(TrustError::new(
                TrustReason::ScopeMismatch,
                "JWE binding ceremony or group does not match",
            ));
        }
        validate_public_key(&self.public_key, &self.public_key_sha256)?;
        validate_digest(&self.binding_digest, "binding_digest")?;
        if !digest_matches(&normalized_binding_digest(self), &self.binding_digest) {
            return Err(binding_error(
                "JWE binding digest does not cover its current fields and evidence",
            ));
        }
        if !digest_matches(&binding_integrity_digest(self), &self.integrity_digest) {
            return Err(binding_error(
                "JWE binding fields no longer match their verified construction",
            ));
        }
        validate_statement_freshness(&self.issued_at, &self.expires_at, expected.now)
    }

    /// Digest named by the signed activation response.
    ///
    /// Offer routes retain their original offer digest for wire compatibility;
    /// direct routes use the normalized binding digest itself.
    pub fn activation_reference_digest(&self) -> &str {
        match &self.evidence {
            JweBindingEvidence::SignedKeyCard { offer_digest, .. }
            | JweBindingEvidence::ChallengeResponse { offer_digest, .. } => offer_digest,
            JweBindingEvidence::DidDocument { .. } | JweBindingEvidence::FingerprintPin { .. } => {
                &self.binding_digest
            }
        }
    }
}

fn build_binding(
    reader_did: String,
    public_key: [u8; 32],
    scope: JweBindingScope,
    evidence: JweBindingEvidence,
) -> Result<VerifiedJweRecipient, TrustError> {
    require_did(&reader_did, "reader_did")?;
    let issued_at = canonical_utc_timestamp(scope.now)?;
    let expires_at = canonical_utc_timestamp(scope.now + scope.ttl)?;
    let public_key_sha256 = sha256_tagged(&public_key);
    validate_public_key(&public_key, &public_key_sha256)?;
    let mut result = VerifiedJweRecipient {
        reader_did,
        audience_did: scope.audience_did,
        ceremony_id: scope.ceremony_id,
        group: scope.group,
        public_key,
        public_key_sha256,
        binding_digest: String::new(),
        issued_at,
        expires_at,
        evidence,
        integrity_digest: String::new(),
    };
    result.binding_digest = normalized_binding_digest(&result);
    result.integrity_digest = binding_integrity_digest(&result);
    Ok(result)
}

fn normalized_binding_digest(binding: &VerifiedJweRecipient) -> String {
    let value = json!({
        "reader_did": binding.reader_did,
        "audience_did": binding.audience_did,
        "ceremony_id": binding.ceremony_id,
        "group": binding.group,
        "public_key_sha256": binding.public_key_sha256,
        "issued_at": binding.issued_at,
        "expires_at": binding.expires_at,
        "evidence": binding.evidence.to_value(),
    });
    canonical_value_digest(&value)
}

fn binding_integrity_digest(binding: &VerifiedJweRecipient) -> String {
    let value = json!({
        "reader_did": binding.reader_did,
        "audience_did": binding.audience_did,
        "ceremony_id": binding.ceremony_id,
        "group": binding.group,
        "public_key_sha256": binding.public_key_sha256,
        "binding_digest": binding.binding_digest,
        "issued_at": binding.issued_at,
        "expires_at": binding.expires_at,
        "evidence": binding.evidence.to_value(),
    });
    canonical_value_digest(&value)
}

fn canonical_value_digest(value: &Value) -> String {
    let bytes = canonical_bytes(value)
        .expect("verified JWE binding integrity contains only canonical JSON values");
    sha256_tagged(&bytes)
}

fn digest_matches(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn validate_scope(scope: &JweBindingScope) -> Result<(), TrustError> {
    require_did(&scope.audience_did, "audience_did")?;
    require_text(&scope.ceremony_id, "ceremony_id")?;
    require_text(&scope.group, "group")?;
    if scope.ttl.is_zero() {
        return Err(binding_error("binding ttl must be greater than zero"));
    }
    Ok(())
}

fn validate_public_key(public_key: &[u8; 32], digest: &str) -> Result<(), TrustError> {
    if *public_key == [0; 32] {
        return Err(binding_error("X25519 public key must not be all zero"));
    }
    validate_digest(digest, "public_key_sha256")?;
    if sha256_tagged(public_key) != digest {
        return Err(binding_error(
            "public key digest does not match the X25519 key",
        ));
    }
    let validation_private = [1_u8; 32];
    let shared = MontgomeryPoint(*public_key)
        .mul_clamped(validation_private)
        .to_bytes();
    if shared == [0_u8; 32] {
        return Err(binding_error("X25519 public key is a low-order encoding"));
    }
    Ok(())
}

fn validate_digest(value: &str, name: &str) -> Result<(), TrustError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| binding_error(format!("{name} must use sha256:<hex>")))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(binding_error(format!(
            "{name} must contain 64 lowercase hex characters"
        )));
    }
    Ok(())
}

fn require_did(value: &str, name: &str) -> Result<(), TrustError> {
    if !value.starts_with("did:") || value.chars().any(char::is_whitespace) {
        return Err(TrustError::new(
            TrustReason::DidInvalid,
            format!("{name} must be a DID"),
        ));
    }
    Ok(())
}

fn require_text(value: &str, name: &str) -> Result<(), TrustError> {
    if value.trim().is_empty() {
        return Err(binding_error(format!("{name} must not be empty")));
    }
    Ok(())
}

fn binding_error(detail: impl Into<String>) -> TrustError {
    TrustError::new(TrustReason::BindingInvalid, detail)
}

#[cfg(test)]
mod tests {
    use super::VerifiedJweRecipient;
    use crate::trust::{AcceptedOffer, VerifiedJweBinding, VerifiedPrincipal};
    use crate::trusted_enrollment::sha256_tagged;

    #[test]
    fn accepted_offer_digest_must_name_the_verified_proof() {
        let public_key = [0x42; 32];
        let proof_digest = sha256_tagged(b"verified offer proof");
        let accepted = AcceptedOffer::new_verified(
            VerifiedJweBinding {
                principal: VerifiedPrincipal {
                    did: "did:example:reader".into(),
                    purpose: "jwe-reader".into(),
                    audience_did: "did:example:publisher".into(),
                    ceremony_id: "ceremony-1".into(),
                    group: "partners".into(),
                    proof_digest: proof_digest.clone(),
                    issued_at: "2030-01-01T00:00:00Z".into(),
                    expires_at: "2030-01-01T00:10:00Z".into(),
                },
                public_key,
                public_key_sha256: sha256_tagged(&public_key),
                proof_digest,
                challenge_digest: None,
            },
            sha256_tagged(b"different offer"),
            sha256_tagged(b"artifact"),
        );

        let error = VerifiedJweRecipient::from_accepted_offer(&accepted).unwrap_err();
        assert!(error.detail.contains("offer digest"));
    }
}
