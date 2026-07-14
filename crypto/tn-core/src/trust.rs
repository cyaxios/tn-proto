//! Strict trusted-principal primitives shared by enrollment ceremonies.
//!
//! The general [`crate::DeviceKey::verify_did`] verifier intentionally keeps
//! its legacy multi-curve, boolean API. Ceremony code uses this module
//! instead: only canonical Ed25519 `did:key` identifiers are accepted, and
//! every failure carries a stable [`TrustReason`]. Mirrors `python/tn/trust.py`
//! decision-for-decision so the two SDKs accept and reject the same
//! identities.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Verifier as _, VerifyingKey};
use serde_json::json;
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Stable machine-readable reasons for trust-boundary rejection.
///
/// The wire strings ([`TrustReason::as_str`]) are frozen by
/// `docs/superpowers/specs/2026-07-11-trusted-enrollment-secure-read-design.md`
/// and shared with the Python, TypeScript, and C# SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustReason {
    /// Malformed canonical JSON, an unsupported version, or an unknown field
    /// in a versioned security statement.
    StatementInvalid,
    /// An otherwise valid statement is outside its acceptance window.
    StatementExpired,
    /// The signature does not verify under the complete Ed25519 DID named by
    /// the statement or package.
    SignatureInvalid,
    /// The identifier is not a canonical Ed25519 `did:key`.
    DidInvalid,
    /// The signing identity does not match the statement's asserted signer.
    DidSignerMismatch,
    /// The outer package signer and the inner statement subject differ.
    OuterInnerSignerMismatch,
    /// The statement or package names a different recipient.
    WrongRecipient,
    /// Ceremony or group scope does not match the receiver's expectation.
    ScopeMismatch,
    /// A package body member does not match its signed digest index.
    BodyDigestMismatch,
    /// A reader proof requires a challenge that is not retained.
    ChallengeMissing,
    /// The bound challenge is outside its acceptance window.
    ChallengeExpired,
    /// The bound challenge was already consumed.
    ChallengeReplayed,
    /// A replayed nonce or scope arrived with different canonical bytes.
    ReplayConflict,
    /// The purpose-specific key binding is invalid.
    BindingInvalid,
    /// The authenticated principal is not authorized by receiver-local policy.
    UntrustedPrincipal,
    /// An authority assertion regressed to a lower path epoch.
    EpochRollback,
    /// A conflicting assertion arrived at the already-pinned epoch.
    EpochConflict,
}

impl TrustReason {
    /// Return the frozen wire string for this reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StatementInvalid => "statement_invalid",
            Self::StatementExpired => "statement_expired",
            Self::SignatureInvalid => "signature_invalid",
            Self::DidInvalid => "did_invalid",
            Self::DidSignerMismatch => "did_signer_mismatch",
            Self::OuterInnerSignerMismatch => "outer_inner_signer_mismatch",
            Self::WrongRecipient => "wrong_recipient",
            Self::ScopeMismatch => "scope_mismatch",
            Self::BodyDigestMismatch => "body_digest_mismatch",
            Self::ChallengeMissing => "challenge_missing",
            Self::ChallengeExpired => "challenge_expired",
            Self::ChallengeReplayed => "challenge_replayed",
            Self::ReplayConflict => "replay_conflict",
            Self::BindingInvalid => "binding_invalid",
            Self::UntrustedPrincipal => "untrusted_principal",
            Self::EpochRollback => "epoch_rollback",
            Self::EpochConflict => "epoch_conflict",
        }
    }
}

impl std::fmt::Display for TrustReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected trust statement with a stable reason and human detail.
///
/// Displays as `"<reason>: <detail>"`, matching the Python `TrustError`
/// message shape, so the machine-readable reason is always the message
/// prefix regardless of the SDK boundary it crosses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustError {
    /// Stable machine-readable rejection reason.
    pub reason: TrustReason,
    /// Human-readable context for the rejection.
    pub detail: String,
}

impl TrustError {
    /// Construct a rejection with a stable reason and human detail.
    pub fn new(reason: TrustReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

impl std::error::Error for TrustError {}

/// Identity and scope established by a verified key-binding proof.
///
/// APIs that accept a verified principal re-check this retained scope
/// against their own receiver, ceremony, and group before acting on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPrincipal {
    /// Complete Ed25519 `did:key` of the proven subject.
    pub did: String,
    /// Proof purpose: `jwe-reader`, `hibe-reader`, or `hibe-authority`.
    pub purpose: String,
    /// DID the proof was addressed to.
    pub audience_did: String,
    /// Ceremony scope the proof binds.
    pub ceremony_id: String,
    /// Group scope the proof binds.
    pub group: String,
    /// `sha256:<hex>` over the complete signed proof statement.
    pub proof_digest: String,
    /// Canonical UTC issuance timestamp of the proof.
    pub issued_at: String,
    /// Canonical UTC expiry timestamp of the proof.
    pub expires_at: String,
}

/// A verified principal together with its bound X25519 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJweBinding {
    /// The verified subject and its retained scope.
    pub principal: VerifiedPrincipal,
    /// The proven 32-byte X25519 public key.
    pub public_key: [u8; 32],
    /// `sha256:<hex>` over the raw public key bytes.
    pub public_key_sha256: String,
    /// `sha256:<hex>` over the complete signed proof statement.
    pub proof_digest: String,
    /// Digest of the publisher challenge the proof answered, when present.
    pub challenge_digest: Option<String>,
}

/// Digest-bound result of accepting an authenticated JWE offer.
///
/// Registration and enrollment-response compilation consume this single
/// value; callers cannot pair one valid binding with another offer's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedOffer {
    /// The verified DID-to-X25519 binding.
    pub binding: VerifiedJweBinding,
    /// `sha256:<hex>` over the canonical inner offer statement (with
    /// signature); stable across compliant `.tnpkg` containers.
    pub offer_digest: String,
    /// `sha256:<hex>` over the exact retained `.tnpkg` bytes.
    pub artifact_digest: String,
    /// Construction seal set only by the verified enrollment store.
    integrity_digest: String,
}

impl AcceptedOffer {
    pub(crate) fn new_verified(
        binding: VerifiedJweBinding,
        offer_digest: String,
        artifact_digest: String,
    ) -> Self {
        let mut accepted = Self {
            binding,
            offer_digest,
            artifact_digest,
            integrity_digest: String::new(),
        };
        accepted.integrity_digest = accepted_offer_integrity(&accepted);
        accepted
    }

    /// Reject mutation of any field after verified store promotion.
    pub fn validate_integrity(&self) -> Result<(), TrustError> {
        let expected = accepted_offer_integrity(self);
        if expected.len() == self.integrity_digest.len()
            && bool::from(expected.as_bytes().ct_eq(self.integrity_digest.as_bytes()))
        {
            Ok(())
        } else {
            Err(TrustError::new(
                TrustReason::BindingInvalid,
                "accepted offer no longer matches its verified promotion",
            ))
        }
    }
}

fn accepted_offer_integrity(accepted: &AcceptedOffer) -> String {
    let binding = &accepted.binding;
    let principal = &binding.principal;
    let value = json!({
        "reader_did": principal.did,
        "purpose": principal.purpose,
        "audience_did": principal.audience_did,
        "ceremony_id": principal.ceremony_id,
        "group": principal.group,
        "principal_proof_digest": principal.proof_digest,
        "issued_at": principal.issued_at,
        "expires_at": principal.expires_at,
        "public_key_hex": hex::encode(binding.public_key),
        "public_key_sha256": binding.public_key_sha256,
        "binding_proof_digest": binding.proof_digest,
        "challenge_digest": binding.challenge_digest,
        "offer_digest": accepted.offer_digest,
        "artifact_digest": accepted.artifact_digest,
    });
    let bytes = crate::canonical::canonical_bytes(&value)
        .expect("accepted offer integrity contains only canonical JSON values");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn did_error(detail: impl Into<String>) -> TrustError {
    TrustError::new(TrustReason::DidInvalid, detail)
}

/// Return the raw Ed25519 public key from a canonical `did:key` identifier.
///
/// Only base58btc multibase, the Ed25519 multicodec (`0xed 0x01`), and an
/// exactly 32-byte raw public key are accepted. The payload must be the
/// canonical base58btc encoding of its bytes — lossy or padded variants are
/// rejected rather than normalized.
///
/// # Errors
///
/// Returns [`TrustError`] with reason [`TrustReason::DidInvalid`] for every
/// non-canonical or non-Ed25519 identifier.
pub fn parse_ed25519_did_key(did: &str) -> Result<[u8; 32], TrustError> {
    let Some(payload) = did.strip_prefix("did:key:z") else {
        return Err(did_error(
            "expected an Ed25519 did:key with a base58btc multibase payload",
        ));
    };
    if payload.is_empty() {
        return Err(did_error("did:key multibase payload is empty"));
    }
    let decoded = bs58::decode(payload)
        .into_vec()
        .map_err(|_| did_error("did:key contains a non-base58btc character"))?;
    if bs58::encode(&decoded).into_string() != payload {
        return Err(did_error("did:key base58btc payload is not canonical"));
    }
    if decoded.len() < 2 || decoded[..2] != ED25519_MULTICODEC {
        return Err(did_error("did:key does not use the Ed25519 multicodec"));
    }
    let public_key = &decoded[2..];
    if public_key.len() != 32 {
        return Err(did_error(format!(
            "Ed25519 did:key must contain 32 public-key bytes, got {}",
            public_key.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(public_key);
    Ok(out)
}

/// Convert a canonical Ed25519 `did:key` to its deterministic X25519
/// `keyAgreement` public key using the same birational map as `did:key`.
pub fn ed25519_did_to_x25519_public(did: &str) -> Result<[u8; 32], TrustError> {
    let ed25519 = parse_ed25519_did_key(did)?;
    CompressedEdwardsY(ed25519)
        .decompress()
        .map(|point| point.to_montgomery().to_bytes())
        .ok_or_else(|| did_error("Ed25519 did:key cannot be converted to X25519"))
}

/// Derive the X25519 `keyAgreement` private scalar for an Ed25519 seed.
///
/// This is the deterministic `did:key` conversion also used for recipient
/// sealing. The returned owner zeroizes the derived secret on drop.
pub fn ed25519_seed_to_x25519_private(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let digest = Sha512::digest(seed);
    let mut private = Zeroizing::new([0_u8; 32]);
    private.copy_from_slice(&digest[..32]);
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    private
}

/// Strictly verify a 64-byte Ed25519 signature for `did`.
///
/// The verification key is always the one embedded in the asserted DID; an
/// unrelated raw verification key never establishes identity.
///
/// # Errors
///
/// Returns [`TrustReason::DidInvalid`] when `did` is not a canonical Ed25519
/// `did:key` and [`TrustReason::SignatureInvalid`] when the signature has the
/// wrong length or does not verify.
pub fn verify_ed25519_did_signature(
    did: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TrustError> {
    let public_key = parse_ed25519_did_key(did)?;
    let signature: &[u8; 64] = signature.try_into().map_err(|_| {
        TrustError::new(
            TrustReason::SignatureInvalid,
            "Ed25519 signature must contain exactly 64 bytes",
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        TrustError::new(
            TrustReason::SignatureInvalid,
            "Ed25519 signature is invalid",
        )
    })?;
    verifying_key
        .verify(message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| {
            TrustError::new(
                TrustReason::SignatureInvalid,
                "Ed25519 signature is invalid",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKey;
    use curve25519_dalek::montgomery::MontgomeryPoint;

    #[test]
    fn parse_rejects_non_canonical_payloads() {
        // Leading '1' (a zero byte) changes the decoded bytes, so it cannot be
        // canonical for an Ed25519 key payload.
        let device = DeviceKey::from_private_bytes(&[1u8; 32]).unwrap();
        let did = device.did().to_string();
        assert_eq!(parse_ed25519_did_key(&did).unwrap(), device.public_bytes());

        for bad in [
            "did:web:example.com",
            "did:key:z",
            "did:key:z0OIl", // non-base58 characters
            "did:key:z6Mk",  // truncated payload
        ] {
            assert_eq!(
                parse_ed25519_did_key(bad).unwrap_err().reason,
                TrustReason::DidInvalid,
                "{bad}"
            );
        }
    }

    #[test]
    fn verify_binds_message_and_did() {
        let device = DeviceKey::from_private_bytes(&[2u8; 32]).unwrap();
        let signature = device.sign(b"statement");
        verify_ed25519_did_signature(device.did(), b"statement", &signature).unwrap();
        assert_eq!(
            verify_ed25519_did_signature(device.did(), b"tampered", &signature)
                .unwrap_err()
                .reason,
            TrustReason::SignatureInvalid
        );
        assert_eq!(
            verify_ed25519_did_signature(device.did(), b"statement", &signature[..63])
                .unwrap_err()
                .reason,
            TrustReason::SignatureInvalid
        );
    }

    #[test]
    fn did_public_and_seed_private_convert_to_the_same_x25519_key() {
        let seed = [3_u8; 32];
        let device = DeviceKey::from_private_bytes(&seed).unwrap();
        let private = ed25519_seed_to_x25519_private(&seed);
        let public = MontgomeryPoint::mul_base_clamped(*private).to_bytes();

        assert_eq!(ed25519_did_to_x25519_public(device.did()).unwrap(), public);
    }
}
