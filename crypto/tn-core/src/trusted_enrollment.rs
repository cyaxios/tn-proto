//! Strict signed statements and receiver-local state for trusted-principal
//! enrollment.
//!
//! This module is the Rust mirror of `python/tn/key_binding.py` (canonical
//! statements and typed verification) plus `python/tn/enrollment.py` (the
//! locked receiver-local challenge/offer/approval/consumed state). Every
//! rejection carries a stable [`TrustReason`]; unknown version-1 fields and
//! unsupported versions fail closed; signatures verify only against the
//! Ed25519 key embedded in the asserted DID.
//!
//! Wire shape: canonical JSON (sorted keys, compact separators, UTF-8) with
//! the signature computed over the complete statement minus `signature_b64`.
//! Timestamps are canonical UTC RFC 3339 strings ending in `Z`; binary values
//! are standard padded base64.

use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::canonical::canonical_bytes;
use crate::signing::DeviceKey;
use crate::trust::{
    parse_ed25519_did_key, verify_ed25519_did_signature, TrustError, TrustReason,
    VerifiedJweBinding, VerifiedPrincipal,
};
use crate::unsafe_operation::UnsafeOperationNotice;

const CHALLENGE_KIND: &str = "tn-enrollment-challenge";
const RESPONSE_KIND: &str = "tn-enrollment-response";
const PURPOSES: [&str; 3] = ["jwe-reader", "hibe-reader", "hibe-authority"];

const CHALLENGE_FIELDS: [&str; 11] = [
    "version",
    "kind",
    "publisher_did",
    "expected_reader_did",
    "ceremony_id",
    "group",
    "nonce_b64",
    "issued_at",
    "expires_at",
    "challenge_id",
    "signature_b64",
];
const PROOF_FIELDS: [&str; 11] = [
    "version",
    "purpose",
    "subject_did",
    "audience_did",
    "ceremony_id",
    "group",
    "issued_at",
    "expires_at",
    "nonce_b64",
    "binding",
    "signature_b64",
];
const RESPONSE_FIELDS: [&str; 12] = [
    "version",
    "kind",
    "publisher_did",
    "reader_did",
    "ceremony_id",
    "group",
    "accepted_offer_digest",
    "x25519_public_key_sha256",
    "group_epoch",
    "issued_at",
    "expires_at",
    "signature_b64",
];

/// One MiB bounds an enrollment offer artifact: one compact proof/package
/// body with generous extension room, far below the generic package ceiling.
pub const MAX_ENROLLMENT_ARTIFACT_BYTES: usize = 1024 * 1024;

fn err(reason: TrustReason, detail: impl Into<String>) -> TrustError {
    TrustError::new(reason, detail)
}

fn statement_invalid(detail: impl Into<String>) -> TrustError {
    err(TrustReason::StatementInvalid, detail)
}

fn binding_invalid(detail: impl Into<String>) -> TrustError {
    err(TrustReason::BindingInvalid, detail)
}

/// Compute the tagged lowercase digest `sha256:<hex>` TN trust records use.
pub fn sha256_tagged(value: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value)))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_digest(value: &str, field: &str, reason: TrustReason) -> Result<(), TrustError> {
    if is_sha256_digest(value) {
        Ok(())
    } else {
        Err(err(
            reason,
            format!("{field} must be a lowercase sha256 digest"),
        ))
    }
}

fn decode_b64_exact(
    value: &str,
    field: &str,
    length: usize,
    reason: TrustReason,
) -> Result<Vec<u8>, TrustError> {
    let decoded = B64_STANDARD
        .decode(value)
        .map_err(|_| err(reason, format!("{field} must be canonical base64")))?;
    if B64_STANDARD.encode(&decoded) != value {
        return Err(err(
            reason,
            format!("{field} must be canonical padded base64"),
        ));
    }
    if decoded.len() != length {
        return Err(err(
            reason,
            format!("{field} must decode to exactly {length} bytes"),
        ));
    }
    Ok(decoded)
}

fn signature_bytes(value: &str, allow_unsigned: bool) -> Result<Option<[u8; 64]>, TrustError> {
    if allow_unsigned && value.is_empty() {
        return Ok(None);
    }
    let decoded = decode_b64_exact(value, "signature_b64", 64, TrustReason::SignatureInvalid)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&decoded);
    Ok(Some(out))
}

fn validate_nonce(value: &str) -> Result<(), TrustError> {
    decode_b64_exact(value, "nonce_b64", 32, TrustReason::StatementInvalid).map(|_| ())
}

fn validate_did(value: &str, field: &str) -> Result<(), TrustError> {
    if value.is_empty() {
        return Err(statement_invalid(format!(
            "{field} must be a non-empty string"
        )));
    }
    parse_ed25519_did_key(value)?;
    Ok(())
}

fn validate_nonempty(value: &str, field: &str) -> Result<(), TrustError> {
    if value.is_empty() {
        return Err(statement_invalid(format!(
            "{field} must be a non-empty string"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical UTC timestamps
// ---------------------------------------------------------------------------

/// Format a `SystemTime` as the canonical UTC statement timestamp: seconds
/// resolution plus a six-digit fraction only when microseconds are non-zero,
/// always ending in `Z` (the exact Python `datetime.isoformat()` shape).
pub fn canonical_utc_timestamp(value: SystemTime) -> Result<String, TrustError> {
    let micros = system_time_micros(value)?;
    format_micros(micros)
}

fn system_time_micros(value: SystemTime) -> Result<i64, TrustError> {
    let since_epoch = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| statement_invalid("timestamps before the UNIX epoch are unsupported"))?;
    i64::try_from(since_epoch.as_micros())
        .map_err(|_| statement_invalid("timestamp is out of range"))
}

fn format_micros(micros: i64) -> Result<String, TrustError> {
    // `OffsetDateTime` covers years -9999..=9999; a hostile or corrupt clock
    // value outside that range is an error, never a panic.
    let odt = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1000)
        .map_err(|_| statement_invalid("timestamp is out of range"))?;
    let fraction = odt.microsecond();
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        odt.year(),
        u8::from(odt.month()),
        odt.day(),
        odt.hour(),
        odt.minute(),
        odt.second()
    );
    Ok(if fraction == 0 {
        format!("{base}Z")
    } else {
        format!("{base}.{fraction:06}Z")
    })
}

/// Parse a canonical statement timestamp to unix microseconds.
fn parse_canonical_utc(text: &str, field: &str) -> Result<i64, TrustError> {
    if !text.ends_with('Z') {
        return Err(statement_invalid(format!(
            "{field} must be a UTC timestamp ending in Z"
        )));
    }
    let odt = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map_err(|_| statement_invalid(format!("{field} is not a valid UTC timestamp")))?;
    let nanos = odt.unix_timestamp_nanos();
    if nanos % 1000 != 0 {
        return Err(statement_invalid(format!(
            "{field} is not in canonical UTC form"
        )));
    }
    let micros = i64::try_from(nanos / 1000)
        .map_err(|_| statement_invalid(format!("{field} is out of range")))?;
    if format_micros(micros)? != text {
        return Err(statement_invalid(format!(
            "{field} is not in canonical UTC form"
        )));
    }
    Ok(micros)
}

fn validate_time_order(issued_at: &str, expires_at: &str) -> Result<(i64, i64), TrustError> {
    let issued = parse_canonical_utc(issued_at, "issued_at")?;
    let expires = parse_canonical_utc(expires_at, "expires_at")?;
    if expires <= issued {
        return Err(statement_invalid("expires_at must be later than issued_at"));
    }
    Ok((issued, expires))
}

fn validate_freshness(
    issued_at: &str,
    expires_at: &str,
    now: SystemTime,
) -> Result<(), TrustError> {
    let (issued, expires) = validate_time_order(issued_at, expires_at)?;
    let now = system_time_micros(now)?;
    if now < issued {
        return Err(statement_invalid("statement was issued in the future"));
    }
    if now >= expires {
        return Err(err(TrustReason::StatementExpired, "statement has expired"));
    }
    Ok(())
}

/// Validate a canonical statement interval at `now`.
///
/// This is the shared freshness gate for normalized trust evidence that is
/// not itself one of the versioned enrollment statements in this module.
pub fn validate_statement_freshness(
    issued_at: &str,
    expires_at: &str,
    now: SystemTime,
) -> Result<(), TrustError> {
    validate_freshness(issued_at, expires_at, now)
}

// ---------------------------------------------------------------------------
// Strict field extraction
// ---------------------------------------------------------------------------

fn exact_fields<'a>(
    value: &'a Value,
    expected: &[&str],
    label: &str,
    reason: TrustReason,
) -> Result<&'a Map<String, Value>, TrustError> {
    let object = value
        .as_object()
        .ok_or_else(|| err(reason, format!("{label} must be an object")))?;
    let mut missing: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect();
    let mut unknown: Vec<&String> = object
        .keys()
        .filter(|key| !expected.contains(&key.as_str()))
        .collect();
    if missing.is_empty() && unknown.is_empty() {
        return Ok(object);
    }
    missing.sort_unstable();
    unknown.sort_unstable();
    let mut details = Vec::new();
    if !missing.is_empty() {
        details.push(format!("missing fields {missing:?}"));
    }
    if !unknown.is_empty() {
        details.push(format!("unknown fields {unknown:?}"));
    }
    Err(err(
        reason,
        format!("{label} has {}", details.join(" and ")),
    ))
}

fn string_field(object: &Map<String, Value>, field: &str) -> Result<String, TrustError> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(statement_invalid(format!("{field} must be a string"))),
    }
}

fn version_field(object: &Map<String, Value>, label: &str) -> Result<u8, TrustError> {
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .filter(|_| !matches!(object.get("version"), Some(Value::Bool(_))))
        .ok_or_else(|| statement_invalid(format!("{label} version must be an integer")))?;
    if version != 1 {
        return Err(statement_invalid(format!("unsupported {label} version")));
    }
    Ok(1)
}

fn u64_field(value: &Value, field: &str, reason: TrustReason) -> Result<u64, TrustError> {
    match value {
        Value::Number(number) if number.is_u64() => Ok(number.as_u64().expect("checked u64")),
        _ => Err(err(
            reason,
            format!("{field} must be an integer greater than or equal to 0"),
        )),
    }
}

// ---------------------------------------------------------------------------
// EnrollmentChallengeV1
// ---------------------------------------------------------------------------

/// A publisher-signed, one-time enrollment challenge (version 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentChallengeV1 {
    /// Statement version; always `1`.
    pub version: u8,
    /// Statement kind; always `tn-enrollment-challenge`.
    pub kind: String,
    /// DID of the issuing publisher.
    pub publisher_did: String,
    /// Exact reader DID the challenge pre-authorizes.
    pub expected_reader_did: String,
    /// Ceremony scope.
    pub ceremony_id: String,
    /// Group scope.
    pub group: String,
    /// Random 256-bit nonce, standard padded base64.
    pub nonce_b64: String,
    /// Canonical UTC issuance timestamp.
    pub issued_at: String,
    /// Canonical UTC expiry timestamp.
    pub expires_at: String,
    /// One-time challenge identifier.
    pub challenge_id: String,
    /// Standard base64 Ed25519 signature; empty only pre-signing.
    pub signature_b64: String,
}

impl EnrollmentChallengeV1 {
    /// Parse and strictly validate a version-1 challenge from JSON.
    ///
    /// # Errors
    ///
    /// [`TrustReason::StatementInvalid`] for unknown fields, unsupported
    /// versions, or non-canonical members; [`TrustReason::DidInvalid`] /
    /// [`TrustReason::SignatureInvalid`] for identity and signature-shape
    /// problems.
    pub fn from_value(value: &Value) -> Result<Self, TrustError> {
        let object = exact_fields(
            value,
            &CHALLENGE_FIELDS,
            "enrollment challenge",
            TrustReason::StatementInvalid,
        )?;
        version_field(object, "enrollment challenge")?;
        let kind = string_field(object, "kind")?;
        if kind != CHALLENGE_KIND {
            return Err(statement_invalid("unsupported enrollment challenge kind"));
        }
        let challenge = Self {
            version: 1,
            kind,
            publisher_did: string_field(object, "publisher_did")?,
            expected_reader_did: string_field(object, "expected_reader_did")?,
            ceremony_id: string_field(object, "ceremony_id")?,
            group: string_field(object, "group")?,
            nonce_b64: string_field(object, "nonce_b64")?,
            issued_at: string_field(object, "issued_at")?,
            expires_at: string_field(object, "expires_at")?,
            challenge_id: string_field(object, "challenge_id")?,
            signature_b64: string_field(object, "signature_b64")?,
        };
        challenge.validate(false)?;
        Ok(challenge)
    }

    fn validate(&self, allow_unsigned: bool) -> Result<(), TrustError> {
        if self.version != 1 || self.kind != CHALLENGE_KIND {
            return Err(statement_invalid("unsupported enrollment challenge"));
        }
        validate_did(&self.publisher_did, "publisher_did")?;
        validate_did(&self.expected_reader_did, "expected_reader_did")?;
        validate_nonempty(&self.ceremony_id, "ceremony_id")?;
        validate_nonempty(&self.group, "group")?;
        validate_nonempty(&self.challenge_id, "challenge_id")?;
        validate_nonce(&self.nonce_b64)?;
        validate_time_order(&self.issued_at, &self.expires_at)?;
        signature_bytes(&self.signature_b64, allow_unsigned)?;
        Ok(())
    }

    fn wire_value(&self, include_signature: bool) -> Value {
        let mut object = Map::new();
        object.insert("version".into(), Value::from(u64::from(self.version)));
        object.insert("kind".into(), Value::from(self.kind.clone()));
        object.insert(
            "publisher_did".into(),
            Value::from(self.publisher_did.clone()),
        );
        object.insert(
            "expected_reader_did".into(),
            Value::from(self.expected_reader_did.clone()),
        );
        object.insert("ceremony_id".into(), Value::from(self.ceremony_id.clone()));
        object.insert("group".into(), Value::from(self.group.clone()));
        object.insert("nonce_b64".into(), Value::from(self.nonce_b64.clone()));
        object.insert("issued_at".into(), Value::from(self.issued_at.clone()));
        object.insert("expires_at".into(), Value::from(self.expires_at.clone()));
        object.insert(
            "challenge_id".into(),
            Value::from(self.challenge_id.clone()),
        );
        if include_signature {
            object.insert(
                "signature_b64".into(),
                Value::from(self.signature_b64.clone()),
            );
        }
        Value::Object(object)
    }

    /// Return the complete signed statement as canonical-ready JSON.
    pub fn to_value(&self) -> Value {
        self.wire_value(true)
    }

    /// Canonical bytes the signature covers (the statement minus
    /// `signature_b64`).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustError> {
        self.validate(true)?;
        canonical_bytes(&self.wire_value(false))
            .map_err(|error| statement_invalid(error.to_string()))
    }

    /// Sign with the publisher device key, which must be the asserted
    /// `publisher_did`.
    pub fn signed(mut self, key: &DeviceKey) -> Result<Self, TrustError> {
        self.validate(true)?;
        if key.did() != self.publisher_did {
            return Err(err(
                TrustReason::DidSignerMismatch,
                "signing key identity does not match the statement signer",
            ));
        }
        let signature = key.sign(&self.signing_bytes()?);
        self.signature_b64 = B64_STANDARD.encode(signature);
        Ok(self)
    }

    /// Digest over the complete signed statement, `sha256:<hex>`.
    pub fn digest(&self) -> Result<String, TrustError> {
        self.validate(false)?;
        Ok(sha256_tagged(
            &canonical_bytes(&self.wire_value(true))
                .map_err(|error| statement_invalid(error.to_string()))?,
        ))
    }
}

/// Receiver expectations for verifying an [`EnrollmentChallengeV1`].
#[derive(Debug, Clone)]
pub struct ChallengeExpectation {
    /// The publisher the challenge must be signed by.
    pub publisher_did: String,
    /// The exact reader the challenge must name.
    pub reader_did: String,
    /// Expected ceremony scope.
    pub ceremony_id: String,
    /// Expected group scope.
    pub group: String,
    /// Verification instant.
    pub now: SystemTime,
}

/// Verify a signed enrollment challenge against explicit expectations.
///
/// # Errors
///
/// Stable [`TrustReason`]s: `did_signer_mismatch` for the wrong publisher,
/// `wrong_recipient` for a different reader, `scope_mismatch` for
/// ceremony/group drift, `statement_expired` outside the window, and
/// `signature_invalid` for a bad signature.
pub fn verify_enrollment_challenge(
    challenge: &EnrollmentChallengeV1,
    expected: &ChallengeExpectation,
) -> Result<(), TrustError> {
    challenge.validate(false)?;
    validate_did(&expected.publisher_did, "expected_publisher_did")?;
    validate_did(&expected.reader_did, "expected_reader_did")?;
    if challenge.publisher_did != expected.publisher_did {
        return Err(err(
            TrustReason::DidSignerMismatch,
            "challenge publisher does not match the expected publisher",
        ));
    }
    if challenge.expected_reader_did != expected.reader_did {
        return Err(err(
            TrustReason::WrongRecipient,
            "challenge names a different reader",
        ));
    }
    if challenge.ceremony_id != expected.ceremony_id || challenge.group != expected.group {
        return Err(err(
            TrustReason::ScopeMismatch,
            "challenge ceremony or group does not match",
        ));
    }
    validate_freshness(&challenge.issued_at, &challenge.expires_at, expected.now)?;
    let signature = signature_bytes(&challenge.signature_b64, false)?
        .expect("validate(false) guarantees a signature");
    verify_ed25519_did_signature(
        &challenge.publisher_did,
        &challenge.signing_bytes()?,
        &signature,
    )
}

// ---------------------------------------------------------------------------
// KeyBindingProofV1
// ---------------------------------------------------------------------------

/// A subject-signed key-binding proof (version 1) for one of the three
/// enrollment purposes: `jwe-reader`, `hibe-reader`, or `hibe-authority`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBindingProofV1 {
    /// Statement version; always `1`.
    pub version: u8,
    /// Proof purpose.
    pub purpose: String,
    /// DID of the proving subject; the signature verifies against it.
    pub subject_did: String,
    /// DID the proof is addressed to.
    pub audience_did: String,
    /// Ceremony scope.
    pub ceremony_id: String,
    /// Group scope.
    pub group: String,
    /// Canonical UTC issuance timestamp.
    pub issued_at: String,
    /// Canonical UTC expiry timestamp.
    pub expires_at: String,
    /// Random 256-bit nonce, standard padded base64.
    pub nonce_b64: String,
    /// Purpose-specific binding object.
    pub binding: Value,
    /// Standard base64 Ed25519 signature; empty only pre-signing.
    pub signature_b64: String,
}

fn validate_binding(binding: &Value, purpose: &str) -> Result<(), TrustError> {
    match purpose {
        "jwe-reader" => {
            let object = exact_fields(
                binding,
                &["algorithm", "public_key_b64", "challenge_digest"],
                "jwe-reader binding",
                TrustReason::BindingInvalid,
            )?;
            if object.get("algorithm").and_then(Value::as_str) != Some("X25519") {
                return Err(binding_invalid(
                    "jwe-reader binding algorithm must be X25519",
                ));
            }
            let public_key = object
                .get("public_key_b64")
                .and_then(Value::as_str)
                .ok_or_else(|| binding_invalid("binding.public_key_b64 must be a string"))?;
            decode_b64_exact(
                public_key,
                "binding.public_key_b64",
                32,
                TrustReason::BindingInvalid,
            )?;
            validate_optional_challenge_digest(object)
        }
        "hibe-reader" => {
            let object = exact_fields(
                binding,
                &["algorithm", "delivery", "challenge_digest"],
                "hibe-reader binding",
                TrustReason::BindingInvalid,
            )?;
            if object.get("algorithm").and_then(Value::as_str) != Some("Ed25519-did-key") {
                return Err(binding_invalid(
                    "hibe-reader binding algorithm must be Ed25519-did-key",
                ));
            }
            if object.get("delivery").and_then(Value::as_str) != Some("recipient-seal-v1") {
                return Err(binding_invalid(
                    "hibe-reader delivery must be recipient-seal-v1",
                ));
            }
            validate_optional_challenge_digest(object)
        }
        "hibe-authority" => {
            let object = exact_fields(
                binding,
                &[
                    "algorithm",
                    "mpk_sha256",
                    "path_epoch",
                    "max_depth",
                    "id_path",
                ],
                "hibe-authority binding",
                TrustReason::BindingInvalid,
            )?;
            if object.get("algorithm").and_then(Value::as_str) != Some("TN-BBG-HIBE-BLS12-381") {
                return Err(binding_invalid(
                    "hibe-authority binding algorithm must be TN-BBG-HIBE-BLS12-381",
                ));
            }
            let mpk_sha256 = object
                .get("mpk_sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| binding_invalid("binding.mpk_sha256 must be a string"))?;
            validate_digest(
                mpk_sha256,
                "binding.mpk_sha256",
                TrustReason::BindingInvalid,
            )?;
            u64_field(
                object.get("path_epoch").unwrap_or(&Value::Null),
                "binding.path_epoch",
                TrustReason::BindingInvalid,
            )?;
            let max_depth = u64_field(
                object.get("max_depth").unwrap_or(&Value::Null),
                "binding.max_depth",
                TrustReason::BindingInvalid,
            )?;
            if max_depth < 1 {
                return Err(binding_invalid(
                    "binding.max_depth must be an integer greater than or equal to 1",
                ));
            }
            let id_path = object
                .get("id_path")
                .and_then(Value::as_str)
                .ok_or_else(|| binding_invalid("binding.id_path must be a string"))?;
            let parts: Vec<&str> = id_path.split('/').collect();
            if parts.iter().any(|part| part.is_empty()) || parts.len() as u64 > max_depth {
                return Err(binding_invalid(
                    "binding.id_path must contain one to max_depth non-empty components",
                ));
            }
            Ok(())
        }
        _ => Err(statement_invalid("unsupported key-binding proof purpose")),
    }
}

fn validate_optional_challenge_digest(object: &Map<String, Value>) -> Result<(), TrustError> {
    match object.get("challenge_digest") {
        Some(Value::Null) => Ok(()),
        Some(Value::String(digest)) => validate_digest(
            digest,
            "binding.challenge_digest",
            TrustReason::BindingInvalid,
        ),
        _ => Err(binding_invalid(
            "binding.challenge_digest must be a digest string or null",
        )),
    }
}

impl KeyBindingProofV1 {
    /// Parse and strictly validate a version-1 key-binding proof from JSON.
    ///
    /// # Errors
    ///
    /// [`TrustReason::StatementInvalid`] for unknown fields and versions,
    /// [`TrustReason::BindingInvalid`] for purpose-specific binding errors.
    pub fn from_value(value: &Value) -> Result<Self, TrustError> {
        let object = exact_fields(
            value,
            &PROOF_FIELDS,
            "key-binding proof",
            TrustReason::StatementInvalid,
        )?;
        version_field(object, "key-binding proof")?;
        let purpose = string_field(object, "purpose")?;
        if !PURPOSES.contains(&purpose.as_str()) {
            return Err(statement_invalid("unsupported key-binding proof purpose"));
        }
        let binding = object
            .get("binding")
            .cloned()
            .ok_or_else(|| binding_invalid("key-binding proof binding must be an object"))?;
        let proof = Self {
            version: 1,
            purpose,
            subject_did: string_field(object, "subject_did")?,
            audience_did: string_field(object, "audience_did")?,
            ceremony_id: string_field(object, "ceremony_id")?,
            group: string_field(object, "group")?,
            issued_at: string_field(object, "issued_at")?,
            expires_at: string_field(object, "expires_at")?,
            nonce_b64: string_field(object, "nonce_b64")?,
            binding,
            signature_b64: string_field(object, "signature_b64")?,
        };
        proof.validate(false)?;
        Ok(proof)
    }

    fn validate(&self, allow_unsigned: bool) -> Result<(), TrustError> {
        if self.version != 1 || !PURPOSES.contains(&self.purpose.as_str()) {
            return Err(statement_invalid("unsupported key-binding proof"));
        }
        validate_did(&self.subject_did, "subject_did")?;
        validate_did(&self.audience_did, "audience_did")?;
        validate_nonempty(&self.ceremony_id, "ceremony_id")?;
        validate_nonempty(&self.group, "group")?;
        validate_nonce(&self.nonce_b64)?;
        validate_time_order(&self.issued_at, &self.expires_at)?;
        validate_binding(&self.binding, &self.purpose)?;
        signature_bytes(&self.signature_b64, allow_unsigned)?;
        Ok(())
    }

    fn wire_value(&self, include_signature: bool) -> Value {
        let mut object = Map::new();
        object.insert("version".into(), Value::from(u64::from(self.version)));
        object.insert("purpose".into(), Value::from(self.purpose.clone()));
        object.insert("subject_did".into(), Value::from(self.subject_did.clone()));
        object.insert(
            "audience_did".into(),
            Value::from(self.audience_did.clone()),
        );
        object.insert("ceremony_id".into(), Value::from(self.ceremony_id.clone()));
        object.insert("group".into(), Value::from(self.group.clone()));
        object.insert("issued_at".into(), Value::from(self.issued_at.clone()));
        object.insert("expires_at".into(), Value::from(self.expires_at.clone()));
        object.insert("nonce_b64".into(), Value::from(self.nonce_b64.clone()));
        object.insert("binding".into(), self.binding.clone());
        if include_signature {
            object.insert(
                "signature_b64".into(),
                Value::from(self.signature_b64.clone()),
            );
        }
        Value::Object(object)
    }

    /// Return the complete signed statement as canonical-ready JSON.
    pub fn to_value(&self) -> Value {
        self.wire_value(true)
    }

    /// Canonical bytes the signature covers.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustError> {
        self.validate(true)?;
        canonical_bytes(&self.wire_value(false))
            .map_err(|error| statement_invalid(error.to_string()))
    }

    /// Sign with the subject device key, which must be the asserted
    /// `subject_did`.
    pub fn signed(mut self, key: &DeviceKey) -> Result<Self, TrustError> {
        self.validate(true)?;
        if key.did() != self.subject_did {
            return Err(err(
                TrustReason::DidSignerMismatch,
                "signing key identity does not match the statement signer",
            ));
        }
        let signature = key.sign(&self.signing_bytes()?);
        self.signature_b64 = B64_STANDARD.encode(signature);
        Ok(self)
    }

    /// Digest over the complete signed statement, `sha256:<hex>`.
    pub fn digest(&self) -> Result<String, TrustError> {
        self.validate(false)?;
        Ok(sha256_tagged(
            &canonical_bytes(&self.wire_value(true))
                .map_err(|error| statement_invalid(error.to_string()))?,
        ))
    }
}

/// Receiver expectations for verifying a [`KeyBindingProofV1`].
#[derive(Debug, Clone)]
pub struct ProofExpectation {
    /// Required proof purpose.
    pub purpose: String,
    /// The audience the proof must be addressed to (the receiver).
    pub audience_did: String,
    /// Expected ceremony scope.
    pub ceremony_id: String,
    /// Expected group scope.
    pub group: String,
    /// Verification instant.
    pub now: SystemTime,
}

/// Verify a key-binding proof and return the established principal.
///
/// Reader purposes require the retained challenge when the binding names one:
/// a bound digest without a challenge is `challenge_missing`, a challenge
/// outside its window is `challenge_expired`, and a proof bound to different
/// challenge bytes is `binding_invalid`.
///
/// # Errors
///
/// Stable [`TrustReason`]s exactly as in the shared statement vectors.
pub fn verify_key_binding_proof(
    proof: &KeyBindingProofV1,
    expected: &ProofExpectation,
    challenge: Option<&EnrollmentChallengeV1>,
) -> Result<VerifiedPrincipal, TrustError> {
    proof.validate(false)?;
    if !PURPOSES.contains(&expected.purpose.as_str()) || proof.purpose != expected.purpose {
        return Err(binding_invalid("key-binding proof purpose does not match"));
    }
    validate_did(&expected.audience_did, "expected_audience_did")?;
    if proof.audience_did != expected.audience_did {
        return Err(err(
            TrustReason::WrongRecipient,
            "key-binding proof names a different audience",
        ));
    }
    if proof.ceremony_id != expected.ceremony_id || proof.group != expected.group {
        return Err(err(
            TrustReason::ScopeMismatch,
            "key-binding proof ceremony or group does not match",
        ));
    }
    validate_freshness(&proof.issued_at, &proof.expires_at, expected.now)?;

    if proof.purpose == "jwe-reader" || proof.purpose == "hibe-reader" {
        let bound_digest = proof
            .binding
            .get("challenge_digest")
            .and_then(Value::as_str);
        if challenge.is_none() && bound_digest.is_some() {
            return Err(err(
                TrustReason::ChallengeMissing,
                "reader proof requires a challenge",
            ));
        }
        if let Some(challenge) = challenge {
            verify_enrollment_challenge(
                challenge,
                &ChallengeExpectation {
                    publisher_did: expected.audience_did.clone(),
                    reader_did: proof.subject_did.clone(),
                    ceremony_id: expected.ceremony_id.clone(),
                    group: expected.group.clone(),
                    now: expected.now,
                },
            )
            .map_err(|error| {
                if error.reason == TrustReason::StatementExpired {
                    err(TrustReason::ChallengeExpired, error.detail)
                } else {
                    error
                }
            })?;
            let (challenge_issued, challenge_expires) =
                validate_time_order(&challenge.issued_at, &challenge.expires_at)?;
            let proof_issued = parse_canonical_utc(&proof.issued_at, "issued_at")?;
            if proof_issued < challenge_issued || proof_issued >= challenge_expires {
                return Err(binding_invalid(
                    "proof issuance time is outside the challenge validity interval",
                ));
            }
            let challenge_digest = challenge.digest()?;
            if bound_digest != Some(challenge_digest.as_str()) {
                return Err(binding_invalid("proof is bound to a different challenge"));
            }
        }
    }

    let signature = signature_bytes(&proof.signature_b64, false)?
        .expect("validate(false) guarantees a signature");
    verify_ed25519_did_signature(&proof.subject_did, &proof.signing_bytes()?, &signature)?;
    Ok(VerifiedPrincipal {
        did: proof.subject_did.clone(),
        purpose: proof.purpose.clone(),
        audience_did: proof.audience_did.clone(),
        ceremony_id: proof.ceremony_id.clone(),
        group: proof.group.clone(),
        proof_digest: proof.digest()?,
        issued_at: proof.issued_at.clone(),
        expires_at: proof.expires_at.clone(),
    })
}

/// Decode a strict standard-base64 32-byte X25519 public key.
///
/// # Errors
///
/// [`TrustReason::BindingInvalid`] for non-canonical base64 or a wrong
/// length.
pub fn decode_x25519_public_key(value: &str) -> Result<[u8; 32], TrustError> {
    let decoded = decode_b64_exact(
        value,
        "binding.public_key_b64",
        32,
        TrustReason::BindingInvalid,
    )?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Derive the X25519 public key for a raw 32-byte private scalar.
///
/// The reader-side enrollment surfaces use this to prove its retained
/// `.jwe.mykey` derives the public key named in a publisher response.
pub fn x25519_public_key(private: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*private).0
}

/// Verify a `jwe-reader` proof and return the typed X25519 binding.
///
/// # Errors
///
/// Everything [`verify_key_binding_proof`] rejects, plus
/// [`TrustReason::BindingInvalid`] for a malformed bound public key.
pub fn verify_jwe_key_binding(
    proof: &KeyBindingProofV1,
    expected_audience_did: &str,
    expected_ceremony_id: &str,
    expected_group: &str,
    now: SystemTime,
    challenge: Option<&EnrollmentChallengeV1>,
) -> Result<VerifiedJweBinding, TrustError> {
    let principal = verify_key_binding_proof(
        proof,
        &ProofExpectation {
            purpose: "jwe-reader".into(),
            audience_did: expected_audience_did.to_string(),
            ceremony_id: expected_ceremony_id.to_string(),
            group: expected_group.to_string(),
            now,
        },
        challenge,
    )?;
    let public_key = decode_x25519_public_key(
        proof
            .binding
            .get("public_key_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| binding_invalid("binding.public_key_b64 must be a string"))?,
    )?;
    let challenge_digest = match proof.binding.get("challenge_digest") {
        Some(Value::Null) | None => None,
        Some(Value::String(digest)) => Some(digest.clone()),
        Some(_) => return Err(binding_invalid("challenge digest has an invalid type")),
    };
    Ok(VerifiedJweBinding {
        public_key,
        public_key_sha256: sha256_tagged(&public_key),
        proof_digest: principal.proof_digest.clone(),
        challenge_digest,
        principal,
    })
}

/// Receiver-side comparison: the party presenting a statement (for packages,
/// the outer manifest signer) must be the statement subject.
///
/// # Errors
///
/// [`TrustReason::DidSignerMismatch`] when the identities differ.
pub fn ensure_expected_signer(
    expected_signer_did: &str,
    subject_did: &str,
) -> Result<(), TrustError> {
    if expected_signer_did == subject_did {
        Ok(())
    } else {
        Err(err(
            TrustReason::DidSignerMismatch,
            "statement subject does not match the expected signer",
        ))
    }
}

/// Receiver-side comparison of a verified reader key against the expected
/// key digest.
///
/// # Errors
///
/// [`TrustReason::BindingInvalid`] when the digests differ.
pub fn ensure_expected_reader_key(
    binding: &VerifiedJweBinding,
    expected_public_key_sha256: &str,
) -> Result<(), TrustError> {
    if binding.public_key_sha256 == expected_public_key_sha256 {
        Ok(())
    } else {
        Err(binding_invalid(
            "verified reader key differs from the expected X25519 key",
        ))
    }
}

// ---------------------------------------------------------------------------
// HIBE authority binding
// ---------------------------------------------------------------------------

/// Typed view of a verified `hibe-authority` proof binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HibeAuthorityBinding {
    /// Binding algorithm label; always `TN-BBG-HIBE-BLS12-381`.
    pub algorithm: String,
    /// `sha256:<hex>` over the exact MPK bytes.
    pub mpk_sha256: String,
    /// Maximum identity-path depth the MPK supports.
    pub max_depth: u64,
    /// The authority's current sealing path.
    pub id_path: String,
    /// Monotonic path epoch.
    pub path_epoch: u64,
}

/// Extract the typed `hibe-authority` binding from a proof.
///
/// # Errors
///
/// [`TrustReason::BindingInvalid`] when the proof is not a well-formed
/// authority assertion.
pub fn hibe_authority_binding(
    proof: &KeyBindingProofV1,
) -> Result<HibeAuthorityBinding, TrustError> {
    if proof.purpose != "hibe-authority" {
        return Err(binding_invalid("proof is not a hibe-authority assertion"));
    }
    validate_binding(&proof.binding, "hibe-authority")?;
    let object = proof.binding.as_object().expect("validated object");
    Ok(HibeAuthorityBinding {
        algorithm: object["algorithm"].as_str().expect("validated").to_string(),
        mpk_sha256: object["mpk_sha256"]
            .as_str()
            .expect("validated")
            .to_string(),
        max_depth: object["max_depth"].as_u64().expect("validated"),
        id_path: object["id_path"].as_str().expect("validated").to_string(),
        path_epoch: object["path_epoch"].as_u64().expect("validated"),
    })
}

/// Verify MPK bytes against a signed authority binding: exact digest match
/// plus agreement between the encoded and asserted depth.
///
/// # Errors
///
/// [`TrustReason::BindingInvalid`] on any mismatch.
pub fn ensure_mpk_matches(binding: &HibeAuthorityBinding, mpk: &[u8]) -> Result<(), TrustError> {
    if sha256_tagged(mpk) != binding.mpk_sha256 {
        return Err(binding_invalid(
            "MPK bytes do not match the signed mpk_sha256",
        ));
    }
    let encoded_depth = hibe_mpk_max_depth(mpk)?;
    if encoded_depth != binding.max_depth {
        return Err(binding_invalid(format!(
            "encoded MPK depth {encoded_depth} does not match asserted max_depth {}",
            binding.max_depth
        )));
    }
    Ok(())
}

/// Read the maximum depth from the canonical tn-bbg `PublicParams` frame:
/// `version(1) | max_depth(1) | g(48) | g1(48) | g2(96) | g3(96) |
/// hs(96 * max_depth)`.
///
/// This structural probe intentionally avoids the evaluation-only pairing
/// stack; the exact bytes are separately pinned by `mpk_sha256`.
///
/// # Errors
///
/// [`TrustReason::BindingInvalid`] when the bytes are not a well-formed
/// version-1 frame.
pub fn hibe_mpk_max_depth(mpk: &[u8]) -> Result<u64, TrustError> {
    if mpk.len() < 2 || mpk[0] != 1 {
        return Err(binding_invalid(
            "MPK bytes are not a version-1 PublicParams frame",
        ));
    }
    let depth = u64::from(mpk[1]);
    if depth == 0 {
        return Err(binding_invalid("MPK frame declares a zero max_depth"));
    }
    let expected_len = 2 + 48 + 48 + 96 + 96 + 96 * (depth as usize);
    if mpk.len() != expected_len {
        return Err(binding_invalid(
            "MPK frame length does not match its declared depth",
        ));
    }
    Ok(depth)
}

// ---------------------------------------------------------------------------
// EnrollmentResponseV1
// ---------------------------------------------------------------------------

/// The publisher's accepted-enrollment response statement (version 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentResponseV1 {
    /// Statement version; always `1`.
    pub version: u8,
    /// Statement kind; always `tn-enrollment-response`.
    pub kind: String,
    /// DID of the accepting publisher.
    pub publisher_did: String,
    /// DID of the enrolled reader.
    pub reader_did: String,
    /// Ceremony scope.
    pub ceremony_id: String,
    /// Group scope.
    pub group: String,
    /// Enrollment correlation digest: the accepted offer digest for offer
    /// routes, or the verified binding digest for direct routes.
    pub accepted_offer_digest: String,
    /// Digest of the admitted X25519 public key.
    pub x25519_public_key_sha256: String,
    /// Resulting group epoch after registration.
    pub group_epoch: u64,
    /// Canonical UTC issuance timestamp.
    pub issued_at: String,
    /// Canonical UTC expiry timestamp.
    pub expires_at: String,
    /// Standard base64 Ed25519 signature; empty only pre-signing.
    pub signature_b64: String,
}

impl EnrollmentResponseV1 {
    /// Parse and strictly validate a version-1 enrollment response from JSON.
    ///
    /// # Errors
    ///
    /// [`TrustReason::StatementInvalid`] for unknown fields, unsupported
    /// versions, or non-canonical members.
    pub fn from_value(value: &Value) -> Result<Self, TrustError> {
        let object = exact_fields(
            value,
            &RESPONSE_FIELDS,
            "enrollment response",
            TrustReason::StatementInvalid,
        )?;
        version_field(object, "enrollment response")?;
        let kind = string_field(object, "kind")?;
        if kind != RESPONSE_KIND {
            return Err(statement_invalid("unsupported enrollment response kind"));
        }
        let response = Self {
            version: 1,
            kind,
            publisher_did: string_field(object, "publisher_did")?,
            reader_did: string_field(object, "reader_did")?,
            ceremony_id: string_field(object, "ceremony_id")?,
            group: string_field(object, "group")?,
            accepted_offer_digest: string_field(object, "accepted_offer_digest")?,
            x25519_public_key_sha256: string_field(object, "x25519_public_key_sha256")?,
            group_epoch: u64_field(
                object.get("group_epoch").unwrap_or(&Value::Null),
                "group_epoch",
                TrustReason::StatementInvalid,
            )?,
            issued_at: string_field(object, "issued_at")?,
            expires_at: string_field(object, "expires_at")?,
            signature_b64: string_field(object, "signature_b64")?,
        };
        response.validate(false)?;
        Ok(response)
    }

    fn validate(&self, allow_unsigned: bool) -> Result<(), TrustError> {
        if self.version != 1 || self.kind != RESPONSE_KIND {
            return Err(statement_invalid("unsupported enrollment response"));
        }
        validate_did(&self.publisher_did, "publisher_did")?;
        validate_did(&self.reader_did, "reader_did")?;
        validate_nonempty(&self.ceremony_id, "ceremony_id")?;
        validate_nonempty(&self.group, "group")?;
        validate_digest(
            &self.accepted_offer_digest,
            "accepted_offer_digest",
            TrustReason::StatementInvalid,
        )?;
        validate_digest(
            &self.x25519_public_key_sha256,
            "x25519_public_key_sha256",
            TrustReason::StatementInvalid,
        )?;
        validate_time_order(&self.issued_at, &self.expires_at)?;
        signature_bytes(&self.signature_b64, allow_unsigned)?;
        Ok(())
    }

    fn wire_value(&self, include_signature: bool) -> Value {
        let mut object = Map::new();
        object.insert("version".into(), Value::from(u64::from(self.version)));
        object.insert("kind".into(), Value::from(self.kind.clone()));
        object.insert(
            "publisher_did".into(),
            Value::from(self.publisher_did.clone()),
        );
        object.insert("reader_did".into(), Value::from(self.reader_did.clone()));
        object.insert("ceremony_id".into(), Value::from(self.ceremony_id.clone()));
        object.insert("group".into(), Value::from(self.group.clone()));
        object.insert(
            "accepted_offer_digest".into(),
            Value::from(self.accepted_offer_digest.clone()),
        );
        object.insert(
            "x25519_public_key_sha256".into(),
            Value::from(self.x25519_public_key_sha256.clone()),
        );
        object.insert("group_epoch".into(), Value::from(self.group_epoch));
        object.insert("issued_at".into(), Value::from(self.issued_at.clone()));
        object.insert("expires_at".into(), Value::from(self.expires_at.clone()));
        if include_signature {
            object.insert(
                "signature_b64".into(),
                Value::from(self.signature_b64.clone()),
            );
        }
        Value::Object(object)
    }

    /// Return the complete signed statement as canonical-ready JSON.
    pub fn to_value(&self) -> Value {
        self.wire_value(true)
    }

    /// Canonical bytes the signature covers.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustError> {
        self.validate(true)?;
        canonical_bytes(&self.wire_value(false))
            .map_err(|error| statement_invalid(error.to_string()))
    }

    /// Sign with the publisher device key, which must be the asserted
    /// `publisher_did`.
    pub fn signed(mut self, key: &DeviceKey) -> Result<Self, TrustError> {
        self.validate(true)?;
        if key.did() != self.publisher_did {
            return Err(err(
                TrustReason::DidSignerMismatch,
                "signing key identity does not match the statement signer",
            ));
        }
        let signature = key.sign(&self.signing_bytes()?);
        self.signature_b64 = B64_STANDARD.encode(signature);
        Ok(self)
    }

    /// Digest over the complete signed statement, `sha256:<hex>`.
    pub fn digest(&self) -> Result<String, TrustError> {
        self.validate(false)?;
        Ok(sha256_tagged(
            &canonical_bytes(&self.wire_value(true))
                .map_err(|error| statement_invalid(error.to_string()))?,
        ))
    }
}

/// Reader expectations for verifying an [`EnrollmentResponseV1`].
#[derive(Debug, Clone)]
pub struct ResponseExpectation {
    /// The publisher the response must be signed by.
    pub publisher_did: String,
    /// The reader the response must name (the receiver).
    pub reader_did: String,
    /// Expected ceremony scope.
    pub ceremony_id: String,
    /// Expected group scope.
    pub group: String,
    /// Expected enrollment correlation digest (offer or direct binding).
    pub offer_digest: String,
    /// Digest of the reader's own X25519 public key.
    pub public_key_sha256: String,
    /// Verification instant.
    pub now: SystemTime,
}

/// Verify a signed enrollment response against the reader's retained state.
///
/// # Errors
///
/// Stable [`TrustReason`]s: `did_signer_mismatch`, `wrong_recipient`,
/// `scope_mismatch`, `binding_invalid` for digest disagreement,
/// `statement_expired`, and `signature_invalid`.
pub fn verify_enrollment_response(
    response: &EnrollmentResponseV1,
    expected: &ResponseExpectation,
) -> Result<(), TrustError> {
    response.validate(false)?;
    validate_did(&expected.publisher_did, "expected_publisher_did")?;
    validate_did(&expected.reader_did, "expected_reader_did")?;
    if response.publisher_did != expected.publisher_did {
        return Err(err(
            TrustReason::DidSignerMismatch,
            "response publisher does not match the expected publisher",
        ));
    }
    if response.reader_did != expected.reader_did {
        return Err(err(
            TrustReason::WrongRecipient,
            "response names a different reader",
        ));
    }
    if response.ceremony_id != expected.ceremony_id || response.group != expected.group {
        return Err(err(
            TrustReason::ScopeMismatch,
            "response ceremony or group does not match",
        ));
    }
    validate_digest(
        &expected.offer_digest,
        "expected_offer_digest",
        TrustReason::BindingInvalid,
    )?;
    validate_digest(
        &expected.public_key_sha256,
        "expected_public_key_sha256",
        TrustReason::BindingInvalid,
    )?;
    if response.accepted_offer_digest != expected.offer_digest {
        return Err(binding_invalid(
            "response names a different enrollment correlation digest",
        ));
    }
    if response.x25519_public_key_sha256 != expected.public_key_sha256 {
        return Err(binding_invalid("response names a different X25519 key"));
    }
    validate_freshness(&response.issued_at, &response.expires_at, expected.now)?;
    let signature = signature_bytes(&response.signature_b64, false)?
        .expect("validate(false) guarantees a signature");
    verify_ed25519_did_signature(
        &response.publisher_did,
        &response.signing_bytes()?,
        &signature,
    )
}

/// Match an incoming response to the reader's retained enrollment scope.
///
/// The correlation digest names either a retained offer or an explicitly
/// approved direct binding. A mismatch belongs to another enrollment entirely.
///
/// # Errors
///
/// [`TrustReason::ScopeMismatch`] when the digests differ.
pub fn match_response_to_retained_offer(
    response: &EnrollmentResponseV1,
    retained_offer_digest: &str,
) -> Result<(), TrustError> {
    if response.accepted_offer_digest == retained_offer_digest {
        Ok(())
    } else {
        Err(err(
            TrustReason::ScopeMismatch,
            "response names a correlation digest outside this enrollment scope",
        ))
    }
}

// ---------------------------------------------------------------------------
// Reader proof creation
// ---------------------------------------------------------------------------

fn fresh_nonce_b64() -> String {
    use rand_core::RngCore as _;
    let mut nonce = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    B64_STANDARD.encode(nonce)
}

fn reader_proof_frame(
    challenge: &EnrollmentChallengeV1,
    reader_key: &DeviceKey,
    now: SystemTime,
    purpose: &str,
    binding: Value,
) -> Result<KeyBindingProofV1, TrustError> {
    verify_enrollment_challenge(
        challenge,
        &ChallengeExpectation {
            publisher_did: challenge.publisher_did.clone(),
            reader_did: reader_key.did().to_string(),
            ceremony_id: challenge.ceremony_id.clone(),
            group: challenge.group.clone(),
            now,
        },
    )?;
    KeyBindingProofV1 {
        version: 1,
        purpose: purpose.to_string(),
        subject_did: reader_key.did().to_string(),
        audience_did: challenge.publisher_did.clone(),
        ceremony_id: challenge.ceremony_id.clone(),
        group: challenge.group.clone(),
        issued_at: canonical_utc_timestamp(now)?,
        expires_at: challenge.expires_at.clone(),
        nonce_b64: fresh_nonce_b64(),
        binding,
        signature_b64: String::new(),
    }
    .signed(reader_key)
}

/// Create a signed `hibe-reader` proof answering an authority challenge.
///
/// The challenge signature is verified against its asserted publisher and the
/// reader key before any proof is produced.
///
/// # Errors
///
/// Every challenge-verification failure, plus [`TrustReason::WrongRecipient`]
/// when the challenge names a different reader.
pub fn create_hibe_reader_proof(
    challenge: &EnrollmentChallengeV1,
    reader_key: &DeviceKey,
    now: SystemTime,
) -> Result<KeyBindingProofV1, TrustError> {
    let binding = serde_json::json!({
        "algorithm": "Ed25519-did-key",
        "delivery": "recipient-seal-v1",
        "challenge_digest": challenge.digest()?,
    });
    reader_proof_frame(challenge, reader_key, now, "hibe-reader", binding)
}

/// Create a signed `jwe-reader` proof binding the reader's static X25519 key.
///
/// With a challenge, the proof binds its digest (pre-authorized automatic
/// enrollment); without one, `challenge_digest` is `null` and the offer can
/// only reconcile after explicit exact-digest approval.
///
/// # Errors
///
/// Challenge-verification failures when a challenge is supplied, and
/// [`TrustReason::DidSignerMismatch`] when the key cannot sign for itself.
pub fn create_jwe_reader_proof(
    reader_key: &DeviceKey,
    reader_public_key: &[u8; 32],
    publisher_did: &str,
    ceremony_id: &str,
    group: &str,
    challenge: Option<&EnrollmentChallengeV1>,
    now: SystemTime,
    ttl: Duration,
) -> Result<KeyBindingProofV1, TrustError> {
    let binding = |digest: Value| {
        serde_json::json!({
            "algorithm": "X25519",
            "public_key_b64": B64_STANDARD.encode(reader_public_key),
            "challenge_digest": digest,
        })
    };
    if let Some(challenge) = challenge {
        return reader_proof_frame(
            challenge,
            reader_key,
            now,
            "jwe-reader",
            binding(Value::from(challenge.digest()?)),
        );
    }
    validate_did(publisher_did, "publisher_did")?;
    KeyBindingProofV1 {
        version: 1,
        purpose: "jwe-reader".into(),
        subject_did: reader_key.did().to_string(),
        audience_did: publisher_did.to_string(),
        ceremony_id: ceremony_id.to_string(),
        group: group.to_string(),
        issued_at: canonical_utc_timestamp(now)?,
        expires_at: canonical_utc_timestamp(now + ttl)?,
        nonce_b64: fresh_nonce_b64(),
        binding: binding(Value::Null),
        signature_b64: String::new(),
    }
    .signed(reader_key)
}

// ---------------------------------------------------------------------------
// Replay and epoch state transitions
// ---------------------------------------------------------------------------

/// Decision for consuming a one-time challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeDecision {
    /// The challenge was unused; consume it now.
    Fresh,
    /// The identical accepted artifact replayed; converge without mutation.
    IdempotentReplay,
}

/// Classify a challenge-consumption attempt against retained state.
///
/// # Errors
///
/// [`TrustReason::ChallengeReplayed`] when the challenge was consumed and the
/// exact prior artifact is unknown; [`TrustReason::ReplayConflict`] when it
/// was consumed by different artifact bytes.
pub fn classify_challenge_consumption(
    consumed: bool,
    prior_artifact_digest: Option<&str>,
    artifact_digest: &str,
) -> Result<ConsumeDecision, TrustError> {
    if !consumed {
        return Ok(ConsumeDecision::Fresh);
    }
    match prior_artifact_digest {
        Some(prior) if prior == artifact_digest => Ok(ConsumeDecision::IdempotentReplay),
        Some(_) => Err(err(
            TrustReason::ReplayConflict,
            "challenge was consumed by a different signed artifact",
        )),
        None => Err(err(
            TrustReason::ChallengeReplayed,
            "challenge has already been consumed",
        )),
    }
}

/// Decision for installing a HIBE authority assertion epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochDecision {
    /// The incoming epoch advances the pin; install it.
    Install,
    /// The incoming assertion repeats the pinned epoch and MPK exactly.
    Idempotent,
}

/// Classify an incoming authority epoch against the pinned state.
///
/// # Errors
///
/// [`TrustReason::EpochRollback`] for a lower epoch and
/// [`TrustReason::EpochConflict`] for a conflicting MPK at the pinned epoch.
pub fn classify_hibe_epoch(
    current_epoch: u64,
    current_mpk_sha256: &str,
    incoming_epoch: u64,
    incoming_mpk_sha256: &str,
) -> Result<EpochDecision, TrustError> {
    if incoming_epoch > current_epoch {
        return Ok(EpochDecision::Install);
    }
    if incoming_epoch < current_epoch {
        return Err(err(
            TrustReason::EpochRollback,
            "authority assertion regresses to a lower path epoch",
        ));
    }
    if incoming_mpk_sha256 == current_mpk_sha256 {
        Ok(EpochDecision::Idempotent)
    } else {
        Err(err(
            TrustReason::EpochConflict,
            "conflicting MPK at the already-pinned path epoch",
        ))
    }
}

// ---------------------------------------------------------------------------
// Unsafe-operation warning surface
// ---------------------------------------------------------------------------

/// Emit the one structured security warning for an explicitly weakened
/// operation and return the canonical payload text.
///
/// Rust has no language warning facility, so the warning rides the `log`
/// facade at `warn` level with target `tn.security`. The mutation-owning
/// runtime separately emits the one best-effort `tn.security.unsafe_operation`
/// audit event; this function never does.
pub fn emit_unsafe_warning(notice: &UnsafeOperationNotice) -> String {
    let payload = serde_json::to_string(notice)
        .unwrap_or_else(|_| "tn.security.unsafe_operation (unrenderable payload)".to_string());
    log::warn!(target: "tn.security", "tn.security.unsafe_operation {payload}");
    payload
}

// ---------------------------------------------------------------------------
// Offer artifacts: inner package, build, verification
// ---------------------------------------------------------------------------

/// Inner offer `body/package.json` fields (the bilateral `Package` shape).
#[derive(Debug, Clone)]
struct OfferPackageV1 {
    ceremony_id: String,
    group: String,
    group_epoch: u64,
    device_identity: String,
    signer_verify_pub_b64: String,
    recipient_identity: String,
    payload: Map<String, Value>,
    compiled_at: String,
    sig_b64: String,
}

const OFFER_PACKAGE_FIELDS: [&str; 11] = [
    "package_version",
    "package_kind",
    "ceremony_id",
    "group",
    "group_epoch",
    "device_identity",
    "signer_verify_pub_b64",
    "recipient_identity",
    "payload",
    "compiled_at",
    "sig_b64",
];

impl OfferPackageV1 {
    fn from_bytes(raw: &[u8]) -> Result<Self, TrustError> {
        let value: Value = serde_json::from_slice(raw)
            .map_err(|_| statement_invalid("offer package is invalid JSON"))?;
        let object = exact_fields(
            &value,
            &OFFER_PACKAGE_FIELDS,
            "offer package",
            TrustReason::StatementInvalid,
        )?;
        let version = object
            .get("package_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| statement_invalid("unsupported offer package version"))?;
        if version != 1 {
            return Err(statement_invalid("unsupported offer package version"));
        }
        if object.get("package_kind").and_then(Value::as_str) != Some("offer") {
            return Err(statement_invalid("package is not an offer"));
        }
        let payload = object
            .get("payload")
            .and_then(Value::as_object)
            .ok_or_else(|| statement_invalid("offer payload must be an object"))?
            .clone();
        Ok(Self {
            ceremony_id: string_field(object, "ceremony_id")?,
            group: string_field(object, "group")?,
            group_epoch: u64_field(
                object.get("group_epoch").unwrap_or(&Value::Null),
                "group_epoch",
                TrustReason::StatementInvalid,
            )?,
            device_identity: string_field(object, "device_identity")?,
            signer_verify_pub_b64: string_field(object, "signer_verify_pub_b64")?,
            recipient_identity: string_field(object, "recipient_identity")?,
            payload,
            compiled_at: string_field(object, "compiled_at")?,
            sig_b64: string_field(object, "sig_b64")?,
        })
    }

    fn wire_value(&self, include_signature: bool) -> Value {
        let mut object = Map::new();
        object.insert("package_version".into(), Value::from(1u64));
        object.insert("package_kind".into(), Value::from("offer"));
        object.insert("ceremony_id".into(), Value::from(self.ceremony_id.clone()));
        object.insert("group".into(), Value::from(self.group.clone()));
        object.insert("group_epoch".into(), Value::from(self.group_epoch));
        object.insert(
            "device_identity".into(),
            Value::from(self.device_identity.clone()),
        );
        object.insert(
            "signer_verify_pub_b64".into(),
            Value::from(self.signer_verify_pub_b64.clone()),
        );
        object.insert(
            "recipient_identity".into(),
            Value::from(self.recipient_identity.clone()),
        );
        object.insert("payload".into(), Value::Object(self.payload.clone()));
        object.insert("compiled_at".into(), Value::from(self.compiled_at.clone()));
        if include_signature {
            object.insert("sig_b64".into(), Value::from(self.sig_b64.clone()));
        }
        Value::Object(object)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, TrustError> {
        canonical_bytes(&self.wire_value(false))
            .map_err(|error| statement_invalid(error.to_string()))
    }

    fn verify_inner_signature(&self) -> Result<(), TrustError> {
        let declared = B64_STANDARD
            .decode(&self.signer_verify_pub_b64)
            .map_err(|_| {
                err(
                    TrustReason::SignatureInvalid,
                    "offer signature is malformed",
                )
            })?;
        let signature = B64_STANDARD.decode(&self.sig_b64).map_err(|_| {
            err(
                TrustReason::SignatureInvalid,
                "offer signature is malformed",
            )
        })?;
        let did_public_key = parse_ed25519_did_key(&self.device_identity)?;
        if declared != did_public_key {
            return Err(err(
                TrustReason::DidSignerMismatch,
                "offer verification key does not match its asserted DID",
            ));
        }
        verify_ed25519_did_signature(&self.device_identity, &self.signing_bytes()?, &signature)
    }
}

/// Inputs for building a signed reader offer artifact.
///
/// Not `Debug`: it borrows the reader's signing key.
#[derive(Clone)]
pub struct OfferArtifactSpec<'a> {
    /// Ceremony scope of the enrollment.
    pub ceremony_id: &'a str,
    /// Group being enrolled into.
    pub group: &'a str,
    /// Publisher the offer is addressed to.
    pub publisher_did: &'a str,
    /// The reader's signing identity.
    pub reader_key: &'a DeviceKey,
    /// The reader's static X25519 public key for this group.
    pub reader_public_key: [u8; 32],
    /// Publisher-issued challenge, when this enrollment was pre-authorized.
    pub challenge: Option<&'a EnrollmentChallengeV1>,
    /// Issuance instant for the proof and manifest.
    pub now: SystemTime,
}

/// A built reader offer: exact archive bytes plus the digests receivers pin.
#[derive(Debug, Clone)]
pub struct OfferArtifact {
    /// The complete signed `.tnpkg` bytes.
    pub tnpkg: Vec<u8>,
    /// Digest of the canonical inner proof statement (with signature).
    pub offer_digest: String,
    /// Digest of the exact archive bytes.
    pub artifact_digest: String,
    /// The signed key-binding proof carried in the offer.
    pub proof: KeyBindingProofV1,
}

/// Default validity for an unsolicited offer proof.
const UNSOLICITED_OFFER_TTL: Duration = Duration::from_secs(600);

/// Assemble one signed enrollment `.tnpkg`: canonical `body/metadata.json` +
/// `body/package.json` (an inner-signed bilateral package carrying `payload`)
/// under a body-indexed manifest signed by `signer`.
#[allow(clippy::too_many_arguments)]
fn assemble_enrollment_package(
    kind: crate::tnpkg::ManifestKind,
    package_kind: &str,
    ceremony_id: &str,
    group: &str,
    group_epoch: u64,
    signer: &DeviceKey,
    recipient_did: &str,
    payload: Map<String, Value>,
    compiled_at: &str,
    purpose: &str,
) -> Result<Vec<u8>, TrustError> {
    let mut package = Map::new();
    package.insert("package_version".into(), Value::from(1u64));
    package.insert("package_kind".into(), Value::from(package_kind));
    package.insert("ceremony_id".into(), Value::from(ceremony_id));
    package.insert("group".into(), Value::from(group));
    package.insert("group_epoch".into(), Value::from(group_epoch));
    package.insert("device_identity".into(), Value::from(signer.did()));
    package.insert(
        "signer_verify_pub_b64".into(),
        Value::from(B64_STANDARD.encode(signer.public_bytes())),
    );
    package.insert("recipient_identity".into(), Value::from(recipient_did));
    package.insert("payload".into(), Value::Object(payload));
    package.insert("compiled_at".into(), Value::from(compiled_at));
    let signing = canonical_bytes(&Value::Object(package.clone()))
        .map_err(|error| statement_invalid(error.to_string()))?;
    package.insert(
        "sig_b64".into(),
        Value::from(B64_STANDARD.encode(signer.sign(&signing))),
    );

    let metadata = serde_json::json!({
        "ceremony_id": ceremony_id,
        "group": group,
        "purpose": purpose,
    });
    let mut body = std::collections::BTreeMap::new();
    body.insert(
        "body/metadata.json".to_string(),
        canonical_bytes(&metadata).map_err(|error| statement_invalid(error.to_string()))?,
    );
    body.insert(
        "body/package.json".to_string(),
        canonical_bytes(&Value::Object(package))
            .map_err(|error| statement_invalid(error.to_string()))?,
    );

    let mut manifest = crate::tnpkg::Manifest {
        kind,
        version: 1,
        publisher_identity: signer.did().to_string(),
        recipient_identity: Some(recipient_did.to_string()),
        ceremony_id: ceremony_id.to_string(),
        as_of: compiled_at.to_string(),
        scope: group.to_string(),
        clock: std::collections::BTreeMap::new(),
        event_count: 1,
        head_row_hash: None,
        state: None,
        body_sha256: std::collections::BTreeMap::new(),
        body_sha256_present: false,
        manifest_signature_b64: None,
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signer.private_bytes());
    crate::tnpkg::sign_manifest_with_body(&mut manifest, &body, &signing_key)
        .map_err(|error| statement_invalid(error.to_string()))?;
    crate::tnpkg::write_tnpkg_bytes(&manifest, &body)
        .map_err(|error| statement_invalid(error.to_string()))
}

/// Build a complete signed offer `.tnpkg`: inner signed offer package with
/// the key-binding proof, plus a body-indexed signed manifest.
///
/// # Errors
///
/// Challenge/DID validation failures, plus [`TrustReason::StatementInvalid`]
/// when the archive cannot be constructed.
pub fn build_offer_artifact(spec: &OfferArtifactSpec<'_>) -> Result<OfferArtifact, TrustError> {
    let proof = create_jwe_reader_proof(
        spec.reader_key,
        &spec.reader_public_key,
        spec.publisher_did,
        spec.ceremony_id,
        spec.group,
        spec.challenge,
        spec.now,
        UNSOLICITED_OFFER_TTL,
    )?;
    let compiled_at = canonical_utc_timestamp(spec.now)?;
    let mut payload = Map::new();
    payload.insert("key_binding_proof".into(), proof.to_value());
    payload.insert(
        "x25519_pub_b64".into(),
        Value::from(B64_STANDARD.encode(spec.reader_public_key)),
    );
    let tnpkg = assemble_enrollment_package(
        crate::tnpkg::ManifestKind::Offer,
        "offer",
        spec.ceremony_id,
        spec.group,
        0,
        spec.reader_key,
        spec.publisher_did,
        payload,
        &compiled_at,
        "jwe-reader",
    )?;
    let offer_digest = proof.digest()?;
    let artifact_digest = sha256_tagged(&tnpkg);
    Ok(OfferArtifact {
        tnpkg,
        offer_digest,
        artifact_digest,
        proof,
    })
}

/// Build a complete signed `enrolment` response `.tnpkg` addressed to the
/// enrolled reader, carrying the signed response statement.
///
/// # Errors
///
/// Statement validation failures, plus [`TrustReason::DidSignerMismatch`]
/// when `publisher_key` is not the response publisher.
pub fn build_enrollment_response_artifact(
    response: &EnrollmentResponseV1,
    publisher_key: &DeviceKey,
) -> Result<Vec<u8>, TrustError> {
    response.validate(false)?;
    if publisher_key.did() != response.publisher_did {
        return Err(err(
            TrustReason::DidSignerMismatch,
            "publisher key does not match the response publisher",
        ));
    }
    let mut payload = Map::new();
    payload.insert("enrollment_response".into(), response.to_value());
    assemble_enrollment_package(
        crate::tnpkg::ManifestKind::Enrolment,
        "enrolment",
        &response.ceremony_id,
        &response.group,
        response.group_epoch,
        publisher_key,
        &response.reader_did,
        payload,
        &response.issued_at,
        "jwe-reader",
    )
}

/// Receiver-retained state for a challenge digest bound by an offer.
#[derive(Debug, Clone)]
pub enum ChallengeState {
    /// The challenge is retained and available.
    Retained(EnrollmentChallengeV1),
    /// The digest names no retained challenge.
    Missing,
    /// The retained challenge is outside its acceptance window.
    Expired,
    /// The challenge was consumed. Verification proceeds at the proof's
    /// original valid instant; the caller must classify exactness against its
    /// consumption record (an identical artifact is an idempotent replay, a
    /// different one a conflict).
    Consumed(EnrollmentChallengeV1),
    /// The challenge was consumed and the exact prior artifact is unknown.
    ConsumedReplayed,
    /// The challenge was consumed by different artifact bytes.
    ConsumedConflict,
}

/// Receiver-local resolution of retained challenges by digest.
pub trait ChallengeLedger {
    /// Resolve the retained state for `challenge_digest`.
    ///
    /// # Errors
    ///
    /// Implementations surface corrupt retained state as [`TrustError`].
    fn resolve(&self, challenge_digest: &str) -> Result<ChallengeState, TrustError>;
}

/// A ledger with no retained challenges (unsolicited-only receivers).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoChallengeLedger;

impl ChallengeLedger for NoChallengeLedger {
    fn resolve(&self, _challenge_digest: &str) -> Result<ChallengeState, TrustError> {
        Ok(ChallengeState::Missing)
    }
}

/// Receiver expectations for verifying an offer `.tnpkg`.
#[derive(Debug, Clone)]
pub struct OfferVerification<'a> {
    /// The local publisher DID the offer must be addressed to.
    pub expected_publisher_did: &'a str,
    /// Expected ceremony scope.
    pub expected_ceremony_id: &'a str,
    /// Expected group scope.
    pub expected_group: &'a str,
    /// Optional receiver-side expectation of the reader key digest.
    pub expected_public_key_sha256: Option<&'a str>,
    /// Verification instant.
    pub now: SystemTime,
}

/// The verified content of one authenticated offer artifact.
#[derive(Debug, Clone)]
pub struct VerifiedOffer {
    /// The verified DID-to-X25519 binding.
    pub binding: VerifiedJweBinding,
    /// The proven reader DID.
    pub reader_did: String,
    /// Ceremony scope the offer binds.
    pub ceremony_id: String,
    /// Group scope the offer binds.
    pub group: String,
    /// Digest of the canonical inner proof statement (with signature).
    pub offer_digest: String,
    /// Digest of the exact artifact bytes.
    pub artifact_digest: String,
    /// Digest of the bound challenge, when the offer was challenged.
    pub challenge_digest: Option<String>,
    /// Identifier of the bound challenge, when retained.
    pub challenge_id: Option<String>,
}

fn map_package_read_error(error: &crate::Error) -> TrustError {
    match error {
        crate::Error::Malformed { kind, reason } => {
            if *kind == "tnpkg body index" {
                err(TrustReason::BodyDigestMismatch, reason.clone())
            } else if *kind == "tnpkg manifest signature"
                || *kind == "tnpkg manifest pubkey"
                || *kind == "tnpkg manifest publisher_identity"
                || reason == "manifest is unsigned"
            {
                err(TrustReason::SignatureInvalid, reason.clone())
            } else {
                statement_invalid(reason.clone())
            }
        }
        other => statement_invalid(other.to_string()),
    }
}

/// Verify a complete offer `.tnpkg` against receiver expectations and the
/// retained challenge ledger. Performs the full pre-mutation check sequence:
/// bounded read, manifest signature, exact body digests, kind, outer/inner
/// signer agreement, recipient, scope, DID-bound inner signature, proof and
/// challenge verification, and the optional reader-key expectation.
///
/// # Errors
///
/// Stable [`TrustReason`]s exactly as pinned by the shared lifecycle vectors.
pub fn verify_offer_artifact(
    artifact: &[u8],
    expected: &OfferVerification<'_>,
    ledger: &dyn ChallengeLedger,
) -> Result<VerifiedOffer, TrustError> {
    if artifact.len() > MAX_ENROLLMENT_ARTIFACT_BYTES {
        return Err(statement_invalid(format!(
            "enrollment artifact size {} exceeds the maximum enrollment artifact size of {} bytes",
            artifact.len(),
            MAX_ENROLLMENT_ARTIFACT_BYTES
        )));
    }
    let (manifest, body) =
        crate::tnpkg::read_tnpkg_verified(crate::tnpkg::TnpkgSource::Bytes(artifact))
            .map_err(|error| map_package_read_error(&error))?;
    if manifest.kind != crate::tnpkg::ManifestKind::Offer {
        return Err(statement_invalid("artifact is not an offer"));
    }
    let package_raw = body
        .get("body/package.json")
        .ok_or_else(|| statement_invalid("offer body is missing package.json"))?;
    let package = OfferPackageV1::from_bytes(package_raw)?;
    if manifest.publisher_identity != package.device_identity {
        return Err(err(
            TrustReason::OuterInnerSignerMismatch,
            "outer manifest and inner offer name different signers",
        ));
    }
    parse_ed25519_did_key(expected.expected_publisher_did)?;
    if manifest.recipient_identity.as_deref() != Some(expected.expected_publisher_did)
        || package.recipient_identity != expected.expected_publisher_did
    {
        return Err(err(
            TrustReason::WrongRecipient,
            "offer names a different publisher",
        ));
    }
    if manifest.ceremony_id != expected.expected_ceremony_id
        || package.ceremony_id != expected.expected_ceremony_id
        || manifest.scope != package.group
        || package.group != expected.expected_group
    {
        return Err(err(
            TrustReason::ScopeMismatch,
            "offer ceremony or group does not match",
        ));
    }
    package.verify_inner_signature()?;
    let proof_value = package
        .payload
        .get("key_binding_proof")
        .ok_or_else(|| binding_invalid("offer lacks a key-binding proof"))?;
    let proof = KeyBindingProofV1::from_value(proof_value)?;
    if proof.subject_did != manifest.publisher_identity {
        return Err(err(
            TrustReason::OuterInnerSignerMismatch,
            "outer manifest signer and proof subject differ",
        ));
    }

    let bound_digest = proof
        .binding
        .get("challenge_digest")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut verification_now = expected.now;
    let mut challenge: Option<EnrollmentChallengeV1> = None;
    let mut challenge_id: Option<String> = None;
    if let Some(digest) = &bound_digest {
        validate_digest(digest, "challenge digest", TrustReason::BindingInvalid)?;
        match ledger.resolve(digest)? {
            ChallengeState::Retained(retained) => {
                challenge_id = Some(retained.challenge_id.clone());
                challenge = Some(retained);
            }
            ChallengeState::Missing => {
                return Err(err(
                    TrustReason::ChallengeMissing,
                    "challenge digest is not retained",
                ));
            }
            ChallengeState::Expired => {
                return Err(err(
                    TrustReason::ChallengeExpired,
                    "retained challenge is outside its acceptance window",
                ));
            }
            ChallengeState::Consumed(retained) => {
                // Freshness authorized the original promotion; a replay
                // reverifies at the proof's original valid instant, and the
                // caller classifies byte-exactness afterwards.
                verification_now = SystemTime::UNIX_EPOCH
                    + Duration::from_micros(
                        parse_canonical_utc(&proof.issued_at, "issued_at")?
                            .try_into()
                            .map_err(|_| statement_invalid("issued_at is out of range"))?,
                    );
                challenge_id = Some(retained.challenge_id.clone());
                challenge = Some(retained);
            }
            ChallengeState::ConsumedReplayed => {
                return Err(err(
                    TrustReason::ChallengeReplayed,
                    "challenge has already been consumed",
                ));
            }
            ChallengeState::ConsumedConflict => {
                return Err(err(
                    TrustReason::ReplayConflict,
                    "challenge was consumed by a different signed artifact",
                ));
            }
        }
    }

    let binding = verify_jwe_key_binding(
        &proof,
        expected.expected_publisher_did,
        expected.expected_ceremony_id,
        expected.expected_group,
        verification_now,
        challenge.as_ref(),
    )?;
    if let Some(declared) = package.payload.get("x25519_pub_b64") {
        let declared = declared
            .as_str()
            .ok_or_else(|| binding_invalid("offer public key is invalid"))?;
        let declared_key = decode_x25519_public_key(declared)
            .map_err(|_| binding_invalid("offer public key is invalid"))?;
        if declared_key != binding.public_key {
            return Err(binding_invalid(
                "offer public key differs from the signed binding",
            ));
        }
    }
    if let Some(expected_key) = expected.expected_public_key_sha256 {
        ensure_expected_reader_key(&binding, expected_key)?;
    }
    let offer_digest = proof.digest()?;
    Ok(VerifiedOffer {
        reader_did: proof.subject_did.clone(),
        ceremony_id: proof.ceremony_id.clone(),
        group: proof.group.clone(),
        offer_digest,
        artifact_digest: sha256_tagged(artifact),
        challenge_digest: binding.challenge_digest.clone(),
        challenge_id,
        binding,
    })
}

/// Receiver-local authorization for one verified offer: the reader DID must
/// be explicitly trusted (preauthorized) or the exact offer digest approved.
///
/// # Errors
///
/// [`TrustReason::UntrustedPrincipal`] when neither authorization applies.
pub fn authorize_offer(
    offer: &VerifiedOffer,
    trusted_reader_dids: &[String],
    approved_exact_digest: bool,
) -> Result<(), TrustError> {
    if approved_exact_digest
        || trusted_reader_dids
            .iter()
            .any(|did| did == &offer.reader_did)
    {
        Ok(())
    } else {
        Err(err(
            TrustReason::UntrustedPrincipal,
            "offer requires exact-digest administrator approval",
        ))
    }
}

// ---------------------------------------------------------------------------
// One-time HIBE reader-grant consumption and artifact labeling
// ---------------------------------------------------------------------------

/// The scope digest one delivered HIBE reader grant consumes a challenge for:
/// `sha256:<hex>` over the canonical grant statement binding the proof digest
/// to the exact reader, ceremony, group, and identity path (the Python
/// `_hibe_grant_digests` shape).
///
/// # Errors
///
/// [`TrustReason::StatementInvalid`] for malformed inputs.
pub fn hibe_grant_digest(
    proof_digest: &str,
    reader_did: &str,
    ceremony_id: &str,
    group: &str,
    id_path: &str,
) -> Result<String, TrustError> {
    validate_digest(proof_digest, "proof_digest", TrustReason::StatementInvalid)?;
    validate_nonempty(reader_did, "reader_did")?;
    validate_nonempty(ceremony_id, "ceremony_id")?;
    validate_nonempty(group, "group")?;
    validate_nonempty(id_path, "id_path")?;
    let statement = serde_json::json!({
        "version": 1,
        "purpose": "hibe-reader-grant",
        "proof_digest": proof_digest,
        "reader_did": reader_did,
        "ceremony_id": ceremony_id,
        "group": group,
        "id_path": id_path,
    });
    Ok(sha256_tagged(
        &canonical_bytes(&statement).map_err(|error| statement_invalid(error.to_string()))?,
    ))
}

/// The durable record one delivered HIBE reader grant consumes its challenge
/// with (kind `hibe-reader-grant` in the `consumed/` ledger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HibeGrantConsumptionV1 {
    /// Digest of the complete signed reader proof.
    pub proof_digest: String,
    /// Digest of the grant scope statement ([`hibe_grant_digest`]).
    pub grant_digest: String,
    /// Digest of the exact delivered `.tnpkg` bytes.
    pub artifact_digest: String,
}

/// Stamp the Python-parity `hibe_grant` manifest state onto a grant artifact
/// and re-sign it: `{delivery, delegated_subauthority, id_path, unsafe}`.
///
/// Only plaintext-body artifacts can be relabeled: a recipient-sealed body
/// binds its manifest as wrap AAD, so mutating the manifest after sealing
/// would break every reader's unwrap. Sealed inputs are refused.
///
/// # Errors
///
/// [`TrustReason::StatementInvalid`] for sealed or unreadable artifacts and
/// [`TrustReason::DidSignerMismatch`] when `signer` is not the artifact
/// publisher.
pub fn label_hibe_grant_artifact(
    tnpkg: &[u8],
    signer: &DeviceKey,
    delivery: &str,
    delegated_subauthority: bool,
    id_path: &str,
    unsafe_delivery: bool,
) -> Result<Vec<u8>, TrustError> {
    let (mut manifest, body) = crate::tnpkg::read_tnpkg(crate::tnpkg::TnpkgSource::Bytes(tnpkg))
        .map_err(|error| statement_invalid(error.to_string()))?;
    if manifest.publisher_identity != signer.did() {
        return Err(err(
            TrustReason::DidSignerMismatch,
            "labeling key does not match the artifact publisher",
        ));
    }
    let body_is_sealed = manifest
        .state
        .as_ref()
        .and_then(|state| state.get("body_encryption"))
        .is_some()
        || body.contains_key("body/encrypted.bin");
    if body_is_sealed {
        return Err(statement_invalid(
            "a recipient-sealed grant binds its manifest as wrap AAD and cannot be relabeled",
        ));
    }
    let mut state = match manifest.state.take() {
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(statement_invalid("manifest state must be an object"));
        }
        None => Map::new(),
    };
    state.insert(
        "hibe_grant".into(),
        serde_json::json!({
            "delivery": delivery,
            "delegated_subauthority": delegated_subauthority,
            "id_path": id_path,
            "unsafe": unsafe_delivery,
        }),
    );
    manifest.state = Some(Value::Object(state));
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signer.private_bytes());
    crate::tnpkg::sign_manifest_with_body(&mut manifest, &body, &signing_key)
        .map_err(|error| statement_invalid(error.to_string()))?;
    crate::tnpkg::write_tnpkg_bytes(&manifest, &body)
        .map_err(|error| statement_invalid(error.to_string()))
}

// ---------------------------------------------------------------------------
// Receiver-local enrollment state store (version 1)
// ---------------------------------------------------------------------------

#[cfg(feature = "fs")]
pub use store::{EnrollmentStore, PendingOffer};

#[cfg(feature = "fs")]
mod store {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::trust::AcceptedOffer;

    /// A verified binding backed by the complete retained signed artifact.
    #[derive(Debug, Clone)]
    pub struct PendingOffer {
        /// Ceremony scope of the retained offer.
        pub ceremony_id: String,
        /// Group scope of the retained offer.
        pub group: String,
        /// The proven reader DID.
        pub reader_did: String,
        /// Digest of the canonical inner proof statement.
        pub offer_digest: String,
        /// Path of the retained exact artifact bytes.
        pub artifact_path: PathBuf,
        /// The verified DID-to-X25519 binding.
        pub verified: VerifiedJweBinding,
    }

    /// Durable version-1 enrollment state for one publisher ceremony.
    ///
    /// Locked layout under one private state root:
    /// `challenges/`, `offers/`, `approvals/`, `consumed/`, `accepted/`,
    /// `preauthorized/`, plus one `enrollment.lock` serializing consumption,
    /// approval, and promotion across processes. Writes are atomic
    /// (same-directory temporary file + rename) and occur only after
    /// validation.
    pub struct EnrollmentStore {
        publisher: DeviceKey,
        ceremony_id: String,
        groups: BTreeSet<String>,
        state_root: PathBuf,
        storage: crate::storage::FsStorage,
    }

    fn scope_component(value: &str) -> String {
        format!("sha256-{}", hex::encode(Sha256::digest(value.as_bytes())))
    }

    fn digest_component(digest: &str) -> Result<String, TrustError> {
        validate_digest(digest, "digest", TrustReason::StatementInvalid)?;
        Ok(digest["sha256:".len()..].to_string())
    }

    fn safe_id_component(id: &str) -> Result<String, TrustError> {
        let valid = !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && !id.starts_with('.');
        if valid {
            Ok(id.to_string())
        } else {
            Err(statement_invalid("challenge id is invalid"))
        }
    }

    fn canonical_json_line(value: &Value) -> Result<Vec<u8>, TrustError> {
        let mut bytes =
            canonical_bytes(value).map_err(|error| statement_invalid(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn read_json_object(path: &Path, label: &str) -> Result<Value, TrustError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|_| statement_invalid(format!("{label} is unreadable")))?;
        let value: Value = serde_json::from_str(&raw)
            .map_err(|_| statement_invalid(format!("{label} is unreadable")))?;
        if value.is_object() {
            Ok(value)
        } else {
            Err(statement_invalid(format!("{label} must be an object")))
        }
    }

    fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), TrustError> {
        crate::keystore_backend::atomic_write_bytes(path, bytes)
            .map_err(|error| statement_invalid(format!("state write failed: {error}")))
    }

    impl ChallengeLedger for EnrollmentStore {
        fn resolve(&self, challenge_digest: &str) -> Result<ChallengeState, TrustError> {
            let Some(challenge) = self.find_challenge(challenge_digest)? else {
                return Ok(ChallengeState::Missing);
            };
            let consumed_path = self.consumed_path(&challenge.challenge_id)?;
            if !consumed_path.exists() {
                return Ok(ChallengeState::Retained(challenge));
            }
            Ok(ChallengeState::Consumed(challenge))
        }
    }

    impl EnrollmentStore {
        /// Open (or lazily create) the version-1 enrollment state for one
        /// publisher ceremony.
        ///
        /// # Errors
        ///
        /// [`TrustReason::DidInvalid`] when the publisher key does not carry a
        /// canonical Ed25519 `did:key`.
        pub fn new(
            publisher: DeviceKey,
            ceremony_id: String,
            groups: Vec<String>,
            state_root: PathBuf,
        ) -> Result<Self, TrustError> {
            parse_ed25519_did_key(publisher.did())?;
            validate_nonempty(&ceremony_id, "ceremony_id")?;
            Ok(Self {
                publisher,
                ceremony_id,
                groups: groups.into_iter().collect(),
                state_root,
                storage: crate::storage::FsStorage::new(),
            })
        }

        /// The private state root this store owns.
        pub fn state_root(&self) -> &Path {
            &self.state_root
        }

        fn validate_scope(&self, reader_did: &str, group: &str) -> Result<(), TrustError> {
            parse_ed25519_did_key(reader_did)?;
            if group.is_empty() {
                return Err(err(TrustReason::ScopeMismatch, "group must be non-empty"));
            }
            if !self.groups.contains(group) {
                return Err(err(
                    TrustReason::ScopeMismatch,
                    format!("group {group:?} is not present in this ceremony"),
                ));
            }
            Ok(())
        }

        fn locked<T>(&self, f: impl FnOnce() -> Result<T, TrustError>) -> Result<T, TrustError> {
            use crate::storage::Storage as _;
            std::fs::create_dir_all(&self.state_root)
                .map_err(|error| statement_invalid(format!("state root create failed: {error}")))?;
            let lock_path = self.state_root.join("enrollment.lock");
            let mut f = Some(f);
            let mut outcome: Option<Result<T, TrustError>> = None;
            self.storage
                .with_advisory_lock(&lock_path, &mut || {
                    let f = f.take().expect("advisory lock body runs once");
                    outcome = Some(f());
                    Ok(())
                })
                .map_err(|error| statement_invalid(format!("state lock failed: {error}")))?;
            outcome.expect("advisory lock body ran")
        }

        fn challenges_dir(&self) -> PathBuf {
            self.state_root.join("challenges")
        }

        fn offer_path(
            &self,
            ceremony_id: &str,
            group: &str,
            reader_did: &str,
            offer_digest: &str,
        ) -> Result<PathBuf, TrustError> {
            Ok(self
                .state_root
                .join("offers")
                .join(scope_component(ceremony_id))
                .join(scope_component(group))
                .join(hex::encode(Sha256::digest(reader_did.as_bytes())))
                .join(format!("{}.tnpkg", digest_component(offer_digest)?)))
        }

        fn approval_path(&self, offer_digest: &str) -> Result<PathBuf, TrustError> {
            Ok(self
                .state_root
                .join("approvals")
                .join(format!("{}.json", digest_component(offer_digest)?)))
        }

        fn accepted_path(&self, offer_digest: &str) -> Result<PathBuf, TrustError> {
            Ok(self
                .state_root
                .join("accepted")
                .join(format!("{}.json", digest_component(offer_digest)?)))
        }

        fn consumed_path(&self, challenge_id: &str) -> Result<PathBuf, TrustError> {
            Ok(self
                .state_root
                .join("consumed")
                .join(format!("{}.json", safe_id_component(challenge_id)?)))
        }

        fn preauthorized_path(&self, reader_did: &str, group: &str) -> PathBuf {
            self.state_root
                .join("preauthorized")
                .join(scope_component(&self.ceremony_id))
                .join(scope_component(group))
                .join(format!(
                    "{}.json",
                    hex::encode(Sha256::digest(reader_did.as_bytes()))
                ))
        }

        /// Persist exact DID/ceremony/group authorization for challenged
        /// offers.
        ///
        /// # Errors
        ///
        /// [`TrustReason::ReplayConflict`] when a conflicting record exists.
        pub fn preauthorize(&self, reader_did: &str, group: &str) -> Result<(), TrustError> {
            self.validate_scope(reader_did, group)?;
            let record = serde_json::json!({
                "version": 1,
                "ceremony_id": self.ceremony_id,
                "group": group,
                "reader_did": reader_did,
            });
            let bytes = canonical_json_line(&record)?;
            let path = self.preauthorized_path(reader_did, group);
            self.locked(|| {
                if path.exists() {
                    let existing = std::fs::read(&path).map_err(|error| {
                        statement_invalid(format!("preauthorization record is unreadable: {error}"))
                    })?;
                    if existing != bytes {
                        return Err(err(
                            TrustReason::ReplayConflict,
                            "preauthorization scope conflicts with existing state",
                        ));
                    }
                    return Ok(());
                }
                atomic_write(&path, &bytes)
            })
        }

        fn is_preauthorized(&self, reader_did: &str, group: &str) -> Result<bool, TrustError> {
            let path = self.preauthorized_path(reader_did, group);
            if !path.exists() {
                return Ok(false);
            }
            let record = read_json_object(&path, "preauthorization record")?;
            let expected = serde_json::json!({
                "version": 1,
                "ceremony_id": self.ceremony_id,
                "group": group,
                "reader_did": reader_did,
            });
            if record == expected {
                Ok(true)
            } else {
                Err(err(
                    TrustReason::ReplayConflict,
                    "preauthorization record does not match the requested scope",
                ))
            }
        }

        /// Issue and durably retain a one-time publisher-signed challenge.
        ///
        /// # Errors
        ///
        /// Scope validation failures, plus state I/O surfaced as
        /// [`TrustReason::StatementInvalid`].
        pub fn issue_challenge(
            &self,
            reader_did: &str,
            group: &str,
            ttl: Duration,
            now: SystemTime,
        ) -> Result<EnrollmentChallengeV1, TrustError> {
            self.validate_scope(reader_did, group)?;
            if ttl.is_zero() {
                return Err(statement_invalid("challenge ttl must be positive"));
            }
            let challenge_id = new_challenge_id();
            let challenge = EnrollmentChallengeV1 {
                version: 1,
                kind: CHALLENGE_KIND.to_string(),
                publisher_did: self.publisher.did().to_string(),
                expected_reader_did: reader_did.to_string(),
                ceremony_id: self.ceremony_id.clone(),
                group: group.to_string(),
                nonce_b64: fresh_nonce_b64(),
                issued_at: canonical_utc_timestamp(now)?,
                expires_at: canonical_utc_timestamp(now + ttl)?,
                challenge_id,
                signature_b64: String::new(),
            }
            .signed(&self.publisher)?;
            self.retain_challenge(&challenge)?;
            Ok(challenge)
        }

        /// Durably retain an externally issued signed challenge.
        ///
        /// # Errors
        ///
        /// Validation failures for the challenge or state I/O.
        pub fn retain_challenge(
            &self,
            challenge: &EnrollmentChallengeV1,
        ) -> Result<(), TrustError> {
            challenge.validate(false)?;
            let record = serde_json::json!({
                "version": 1,
                "challenge_digest": challenge.digest()?,
                "challenge": challenge.to_value(),
            });
            let bytes = canonical_json_line(&record)?;
            let path = self.challenges_dir().join(format!(
                "{}.json",
                safe_id_component(&challenge.challenge_id)?
            ));
            self.locked(|| atomic_write(&path, &bytes))
        }

        fn find_challenge(
            &self,
            challenge_digest: &str,
        ) -> Result<Option<EnrollmentChallengeV1>, TrustError> {
            let dir = self.challenges_dir();
            if !dir.exists() {
                return Ok(None);
            }
            let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
                .map_err(|error| statement_invalid(format!("challenge dir unreadable: {error}")))?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect();
            paths.sort();
            for path in paths {
                let record = read_json_object(&path, "challenge record")?;
                if record.get("version").and_then(Value::as_u64) != Some(1) {
                    return Err(statement_invalid("unsupported challenge record"));
                }
                if record.get("challenge_digest").and_then(Value::as_str) != Some(challenge_digest)
                {
                    continue;
                }
                let challenge = EnrollmentChallengeV1::from_value(
                    record
                        .get("challenge")
                        .ok_or_else(|| statement_invalid("challenge record is malformed"))?,
                )?;
                let actual = challenge.digest()?;
                let stem_matches = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .is_some_and(|stem| stem == challenge.challenge_id);
                if actual != challenge_digest || !stem_matches {
                    return Err(err(
                        TrustReason::ReplayConflict,
                        "retained challenge digest or identifier conflicts with its bytes",
                    ));
                }
                return Ok(Some(challenge));
            }
            Ok(None)
        }

        fn consumed_record(&self, challenge_id: &str) -> Result<Option<Value>, TrustError> {
            let path = self.consumed_path(challenge_id)?;
            if !path.exists() {
                return Ok(None);
            }
            Ok(Some(read_json_object(&path, "consumed challenge record")?))
        }

        fn classify_consumed(
            &self,
            challenge_id: &str,
            offer_digest: &str,
            artifact_digest: &str,
        ) -> Result<ConsumeDecision, TrustError> {
            let Some(record) = self.consumed_record(challenge_id)? else {
                return Ok(ConsumeDecision::Fresh);
            };
            let prior_offer = record.get("offer_digest").and_then(Value::as_str);
            let prior_artifact = record.get("artifact_digest").and_then(Value::as_str);
            if prior_offer.is_some() && prior_offer != Some(offer_digest) {
                return Err(err(
                    TrustReason::ReplayConflict,
                    "challenge was consumed by a different signed artifact",
                ));
            }
            classify_challenge_consumption(true, prior_artifact, artifact_digest)
        }

        fn verify_retained(
            &self,
            artifact: &[u8],
            now: SystemTime,
        ) -> Result<VerifiedOffer, TrustError> {
            // The store admits any group declared by this ceremony; the exact
            // scope is read from the (signed) manifest and then re-verified
            // against the inner statements.
            let (manifest, _) =
                crate::tnpkg::read_tnpkg_verified(crate::tnpkg::TnpkgSource::Bytes(artifact))
                    .map_err(|error| map_package_read_error(&error))?;
            let group = manifest.scope;
            if !self.groups.contains(&group) {
                return Err(err(
                    TrustReason::ScopeMismatch,
                    format!("group {group:?} is not present in this ceremony"),
                ));
            }
            let verified = verify_offer_artifact(
                artifact,
                &OfferVerification {
                    expected_publisher_did: self.publisher.did(),
                    expected_ceremony_id: &self.ceremony_id,
                    expected_group: &group,
                    expected_public_key_sha256: None,
                    now,
                },
                self,
            )?;
            if let (Some(challenge_id), Some(_)) =
                (&verified.challenge_id, &verified.challenge_digest)
            {
                self.classify_consumed(
                    challenge_id,
                    &verified.offer_digest,
                    &verified.artifact_digest,
                )?;
            }
            Ok(verified)
        }

        fn pending_from(&self, verified: &VerifiedOffer) -> Result<PendingOffer, TrustError> {
            Ok(PendingOffer {
                ceremony_id: verified.ceremony_id.clone(),
                group: verified.group.clone(),
                reader_did: verified.reader_did.clone(),
                offer_digest: verified.offer_digest.clone(),
                artifact_path: self.offer_path(
                    &verified.ceremony_id,
                    &verified.group,
                    &verified.reader_did,
                    &verified.offer_digest,
                )?,
                verified: verified.binding.clone(),
            })
        }

        /// Verify and retain exact `.tnpkg` bytes without authorizing them.
        ///
        /// # Errors
        ///
        /// The full offer-verification reason set, plus
        /// [`TrustReason::ReplayConflict`] when the digest already names
        /// different retained bytes.
        pub fn stage_offer(
            &self,
            artifact: &[u8],
            now: SystemTime,
        ) -> Result<PendingOffer, TrustError> {
            // Reject malformed input before the lock file can become the
            // first persistent mutation; reverify under the lock.
            self.verify_retained(artifact, now)?;
            self.locked(|| {
                let verified = self.verify_retained(artifact, now)?;
                let pending = self.pending_from(&verified)?;
                if pending.artifact_path.exists() {
                    let existing = std::fs::read(&pending.artifact_path).map_err(|error| {
                        statement_invalid(format!("retained offer is unreadable: {error}"))
                    })?;
                    if existing != artifact {
                        return Err(err(
                            TrustReason::ReplayConflict,
                            "offer digest already names different retained artifact bytes",
                        ));
                    }
                } else {
                    atomic_write(&pending.artifact_path, artifact)?;
                }
                Ok(pending)
            })
        }

        fn find_pending_path(&self, offer_digest: &str) -> Result<PathBuf, TrustError> {
            let component = digest_component(offer_digest)?;
            let offers = self.state_root.join("offers");
            let mut matches = Vec::new();
            if offers.exists() {
                let mut stack = vec![offers];
                while let Some(dir) = stack.pop() {
                    let entries = std::fs::read_dir(&dir).map_err(|error| {
                        statement_invalid(format!("pending offers unreadable: {error}"))
                    })?;
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_dir() {
                            stack.push(path);
                        } else if path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name == format!("{component}.tnpkg"))
                        {
                            matches.push(path);
                        }
                    }
                }
            }
            matches.sort();
            match matches.len() {
                0 => Err(err(
                    TrustReason::UntrustedPrincipal,
                    "pending offer digest was not found",
                )),
                1 => Ok(matches.remove(0)),
                _ => Err(err(
                    TrustReason::ReplayConflict,
                    "pending offer digest is ambiguous",
                )),
            }
        }

        fn read_retained(&self, path: &Path) -> Result<Vec<u8>, TrustError> {
            let metadata = std::fs::metadata(path)
                .map_err(|_| statement_invalid("retained offer is unreadable"))?;
            if metadata.len() > MAX_ENROLLMENT_ARTIFACT_BYTES as u64 {
                return Err(statement_invalid(
                    "retained offer exceeds the maximum enrollment artifact size",
                ));
            }
            std::fs::read(path).map_err(|_| statement_invalid("retained offer is unreadable"))
        }

        fn verify_pending_digest(
            &self,
            offer_digest: &str,
            now: SystemTime,
        ) -> Result<(VerifiedOffer, Vec<u8>), TrustError> {
            let path = self.find_pending_path(offer_digest)?;
            let artifact = self.read_retained(&path)?;
            let verified = self.verify_retained(&artifact, now)?;
            if verified.offer_digest != offer_digest {
                return Err(err(
                    TrustReason::ReplayConflict,
                    "offer digest does not match bytes",
                ));
            }
            let expected_path = self.offer_path(
                &verified.ceremony_id,
                &verified.group,
                &verified.reader_did,
                &verified.offer_digest,
            )?;
            if path != expected_path {
                return Err(err(
                    TrustReason::ReplayConflict,
                    "pending offer is stored at a wrong path",
                ));
            }
            Ok((verified, artifact))
        }

        fn accepted_record(&self, verified: &VerifiedOffer) -> Value {
            serde_json::json!({
                "version": 1,
                "ceremony_id": verified.ceremony_id,
                "group": verified.group,
                "reader_did": verified.reader_did,
                "offer_digest": verified.offer_digest,
                "artifact_digest": verified.artifact_digest,
                "challenge_id": verified.challenge_id,
                "proof_digest": verified.binding.proof_digest,
                "public_key_sha256": verified.binding.public_key_sha256,
            })
        }

        fn is_accepted_exact(&self, verified: &VerifiedOffer) -> Result<bool, TrustError> {
            let path = self.accepted_path(&verified.offer_digest)?;
            if !path.exists() {
                return Ok(false);
            }
            let record = read_json_object(&path, "accepted offer record")?;
            if record == self.accepted_record(verified) {
                Ok(true)
            } else {
                Err(err(
                    TrustReason::ReplayConflict,
                    "accepted offer record conflicts with retained artifact bytes",
                ))
            }
        }

        fn promote_locked(&self, verified: &VerifiedOffer) -> Result<AcceptedOffer, TrustError> {
            if let Some(challenge_id) = &verified.challenge_id {
                let decision = self.classify_consumed(
                    challenge_id,
                    &verified.offer_digest,
                    &verified.artifact_digest,
                )?;
                if decision == ConsumeDecision::Fresh {
                    let record = serde_json::json!({
                        "version": 1,
                        "challenge_id": challenge_id,
                        "offer_digest": verified.offer_digest,
                        "artifact_digest": verified.artifact_digest,
                    });
                    atomic_write(
                        &self.consumed_path(challenge_id)?,
                        &canonical_json_line(&record)?,
                    )?;
                }
            }
            if !self.is_accepted_exact(verified)? {
                atomic_write(
                    &self.accepted_path(&verified.offer_digest)?,
                    &canonical_json_line(&self.accepted_record(verified))?,
                )?;
            }
            Ok(AcceptedOffer::new_verified(
                verified.binding.clone(),
                verified.offer_digest.clone(),
                verified.artifact_digest.clone(),
            ))
        }

        fn is_approved_exact(&self, verified: &VerifiedOffer) -> Result<bool, TrustError> {
            let path = self.approval_path(&verified.offer_digest)?;
            if !path.exists() {
                return Ok(false);
            }
            let record = read_json_object(&path, "offer approval")?;
            if record.get("version").and_then(Value::as_u64) != Some(1)
                || record.get("offer_digest").and_then(Value::as_str)
                    != Some(verified.offer_digest.as_str())
            {
                return Err(err(
                    TrustReason::ReplayConflict,
                    "approval does not match the exact offer digest",
                ));
            }
            if record.get("artifact_digest").and_then(Value::as_str)
                != Some(verified.artifact_digest.as_str())
            {
                return Err(err(
                    TrustReason::ReplayConflict,
                    "approval does not match the exact retained offer artifact",
                ));
            }
            Ok(true)
        }

        /// Reload and reverify one retained offer by its exact digest.
        ///
        /// # Errors
        ///
        /// [`TrustReason::UntrustedPrincipal`] for an unknown digest and the
        /// full verification reason set for corrupt retained state.
        pub fn pending_offer(
            &self,
            offer_digest: &str,
            now: SystemTime,
        ) -> Result<PendingOffer, TrustError> {
            self.locked(|| {
                let (verified, _artifact) = self.verify_pending_digest(offer_digest, now)?;
                self.pending_from(&verified)
            })
        }

        /// Reverify and promote a preauthorized or exact-approved offer.
        ///
        /// # Errors
        ///
        /// [`TrustReason::UntrustedPrincipal`] when neither an exact-digest
        /// approval nor a preauthorization applies.
        pub fn reconcile(
            &self,
            offer_digest: &str,
            now: SystemTime,
        ) -> Result<AcceptedOffer, TrustError> {
            self.locked(|| {
                let (verified, _artifact) = self.verify_pending_digest(offer_digest, now)?;
                let mut authorized = self.is_approved_exact(&verified)?;
                if !authorized && verified.challenge_id.is_some() {
                    authorized = self.is_preauthorized(&verified.reader_did, &verified.group)?;
                }
                if !authorized {
                    return Err(err(
                        TrustReason::UntrustedPrincipal,
                        "offer requires exact-digest administrator approval",
                    ));
                }
                self.promote_locked(&verified)
            })
        }

        /// Classify a HIBE reader-grant attempt against the consumed ledger.
        ///
        /// A fresh challenge passes; one consumed by any prior grant or
        /// enrollment rejects the new attempt.
        ///
        /// # Errors
        ///
        /// [`TrustReason::ChallengeReplayed`] when the challenge was already
        /// consumed (by an exact prior grant or a non-grant consumption) and
        /// [`TrustReason::ReplayConflict`] when it was consumed by a
        /// different signed proof or grant.
        pub fn check_hibe_grant_challenge(
            &self,
            challenge_id: &str,
            proof_digest: &str,
            grant_digest: &str,
        ) -> Result<(), TrustError> {
            let Some(record) = self.consumed_record(challenge_id)? else {
                return Ok(());
            };
            if record.get("kind").and_then(Value::as_str) != Some("hibe-reader-grant") {
                return Err(err(
                    TrustReason::ChallengeReplayed,
                    "HIBE reader challenge has already been consumed",
                ));
            }
            if record.get("proof_digest").and_then(Value::as_str) != Some(proof_digest)
                || record.get("grant_digest").and_then(Value::as_str) != Some(grant_digest)
            {
                return Err(err(
                    TrustReason::ReplayConflict,
                    "HIBE reader challenge was consumed by a different signed proof or grant",
                ));
            }
            // The exact committed grant exists; a NEW grant call is still a
            // replay of the one-time challenge (redelivery recovery of the
            // retained artifact is not part of this surface).
            Err(err(
                TrustReason::ChallengeReplayed,
                "HIBE reader challenge has already been consumed",
            ))
        }

        /// Atomically consume one challenge for one delivered grant: retain
        /// the exact delivery bytes under `hibe-grants/` and write the
        /// `hibe-reader-grant` consumption record under the store lock.
        /// The identical concurrent commit converges on the same retained
        /// path; a different one is a conflict.
        ///
        /// # Errors
        ///
        /// [`TrustReason::ReplayConflict`] when another grant concurrently
        /// consumed the challenge.
        pub fn commit_hibe_grant(
            &self,
            challenge_id: &str,
            consumption: &HibeGrantConsumptionV1,
            package: &[u8],
        ) -> Result<PathBuf, TrustError> {
            validate_digest(
                &consumption.proof_digest,
                "proof_digest",
                TrustReason::StatementInvalid,
            )?;
            validate_digest(
                &consumption.grant_digest,
                "grant_digest",
                TrustReason::StatementInvalid,
            )?;
            validate_digest(
                &consumption.artifact_digest,
                "artifact_digest",
                TrustReason::StatementInvalid,
            )?;
            let retained_path = self.state_root.join("hibe-grants").join(format!(
                "{}.tnpkg",
                digest_component(&consumption.grant_digest)?
            ));
            let consumed_path = self.consumed_path(challenge_id)?;
            self.locked(|| {
                if let Some(record) = self.consumed_record(challenge_id)? {
                    let exact = record.get("kind").and_then(Value::as_str)
                        == Some("hibe-reader-grant")
                        && record.get("proof_digest").and_then(Value::as_str)
                            == Some(consumption.proof_digest.as_str())
                        && record.get("grant_digest").and_then(Value::as_str)
                            == Some(consumption.grant_digest.as_str());
                    if exact {
                        return Ok(retained_path.clone());
                    }
                    return Err(err(
                        TrustReason::ReplayConflict,
                        "HIBE reader challenge was concurrently consumed by another grant",
                    ));
                }
                atomic_write(&retained_path, package)?;
                let record = serde_json::json!({
                    "version": 1,
                    "kind": "hibe-reader-grant",
                    "challenge_id": challenge_id,
                    "proof_digest": consumption.proof_digest,
                    "grant_digest": consumption.grant_digest,
                    "artifact_digest": consumption.artifact_digest,
                });
                // The grant record is compact canonical JSON without a
                // trailing newline, byte-matching the Python commit.
                atomic_write(
                    &consumed_path,
                    &canonical_bytes(&record)
                        .map_err(|error| statement_invalid(error.to_string()))?,
                )?;
                Ok(retained_path.clone())
            })
        }

        /// Approve an exact digest, reverify, consume, and promote under one
        /// lock.
        ///
        /// # Errors
        ///
        /// [`TrustReason::UntrustedPrincipal`] for an unknown digest, plus the
        /// full verification and replay reason set.
        pub fn approve_and_reconcile(
            &self,
            offer_digest: &str,
            now: SystemTime,
        ) -> Result<AcceptedOffer, TrustError> {
            digest_component(offer_digest)?;
            self.locked(|| {
                let (verified, _artifact) = self.verify_pending_digest(offer_digest, now)?;
                let approval_path = self.approval_path(offer_digest)?;
                if approval_path.exists() {
                    self.is_approved_exact(&verified)?;
                } else {
                    let record = serde_json::json!({
                        "version": 1,
                        "offer_digest": offer_digest,
                        "artifact_digest": verified.artifact_digest,
                        "approved_at": canonical_utc_timestamp(now)?,
                    });
                    atomic_write(&approval_path, &canonical_json_line(&record)?)?;
                }
                self.promote_locked(&verified)
            })
        }
    }

    fn new_challenge_id() -> String {
        // uuid v4 canonical form, matching the Python store's identifiers.
        uuid::Uuid::new_v4().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_timestamps_round_trip() {
        for text in ["2026-07-11T14:00:00Z", "2026-07-11T14:00:00.123456Z"] {
            let micros = parse_canonical_utc(text, "issued_at").unwrap();
            assert_eq!(format_micros(micros).unwrap(), text);
        }
        for bad in [
            "2026-07-11T14:00:00+00:00",
            "2026-07-11T14:00:00",
            "2026-07-11 14:00:00Z",
            "2026-07-11T14:00:00.000Z",
            "2026-07-11T14:00:00.1234567Z",
        ] {
            assert!(parse_canonical_utc(bad, "issued_at").is_err(), "{bad}");
        }
    }

    #[test]
    fn mpk_depth_probe_reads_the_frame() {
        let mut mpk = vec![1u8, 3u8];
        mpk.extend(std::iter::repeat(0xAB).take(48 + 48 + 96 + 96 + 96 * 3));
        assert_eq!(hibe_mpk_max_depth(&mpk).unwrap(), 3);
        assert!(hibe_mpk_max_depth(&mpk[..mpk.len() - 1]).is_err());
        assert!(hibe_mpk_max_depth(&[2u8, 3u8]).is_err());
        assert!(hibe_mpk_max_depth(&[]).is_err());
    }
}
