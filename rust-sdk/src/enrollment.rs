//! Trusted-principal enrollment surfaces for the Rust SDK.
//!
//! This module wires `tn-core`'s strict trust layer
//! ([`tn_core::trust`] / [`tn_core::trusted_enrollment`]) to a [`Tn`] handle:
//! locked receiver-local enrollment state under
//! `.tn/<stem>/enrollment/v1/`, the reader-side response install into
//! `<keystore>/trust/verified_publishers.v1.json`, and the shared
//! unsafe-operation observability (one structured warning through the core
//! `log` facade, one best-effort `tn.security.unsafe_operation` audit event
//! from the mutation-owning runtime layer).
//!
//! Every trust rejection surfaces as [`crate::Error::InvalidArgument`] whose
//! message is exactly `"<stable reason>: <detail>"`, so the machine-readable
//! reason survives the SDK boundary unchanged.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::tn::Tn;
use crate::{Error, Result};

pub use tn_core::trust::{
    parse_ed25519_did_key, verify_ed25519_did_signature, AcceptedOffer, TrustError, TrustReason,
    VerifiedJweBinding, VerifiedPrincipal,
};
pub use tn_core::trusted_enrollment::{
    canonical_utc_timestamp, classify_challenge_consumption, classify_hibe_epoch,
    create_hibe_reader_proof, create_jwe_reader_proof, decode_x25519_public_key,
    ensure_expected_reader_key, ensure_expected_signer, ensure_mpk_matches, hibe_authority_binding,
    hibe_mpk_max_depth, match_response_to_retained_offer, sha256_tagged,
    verify_enrollment_challenge, verify_enrollment_response, verify_jwe_key_binding,
    verify_key_binding_proof, x25519_public_key, ChallengeExpectation, ChallengeLedger,
    ChallengeState, ConsumeDecision, EnrollmentChallengeV1, EnrollmentResponseV1, EpochDecision,
    HibeAuthorityBinding, KeyBindingProofV1, ProofExpectation, ResponseExpectation,
};
pub use tn_core::{UnsafeOperation, UnsafeOperationNotice, UnsafeRelaxation};

/// Options for [`crate::pkg::Package::absorb_with_options`].
///
/// The default is strict: security-sensitive version-1 packages fail closed
/// and other kinds go through the runtime's verified absorb path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AbsorbOptionsV1 {
    /// Import a legacy package (no signed body index / legacy signer
    /// guarantees) through the named unsafe path. The import is retained as
    /// unverified material — it never marks a package or installed principal
    /// as verified — and emits the common unsafe-operation warning and audit
    /// event. Version-1 offers and enrollment responses still fail closed.
    pub unsafe_legacy_signer: bool,
}

/// Options for [`crate::pkg::Package::offer_v1`] (reader side).
#[derive(Debug, Clone)]
pub struct OfferOptionsV1 {
    /// Group the reader wants to enroll into.
    pub group: String,
    /// Publisher DID the offer is addressed to.
    pub publisher_did: String,
    /// Destination `.tnpkg` path.
    pub out_path: PathBuf,
    /// Publisher-issued challenge for pre-authorized enrollment; `None`
    /// produces an unsolicited offer that requires exact-digest approval.
    pub challenge: Option<EnrollmentChallengeV1>,
}

/// Options for [`crate::pkg::Package::compile_enrolment_v1`] (publisher
/// side).
#[derive(Debug, Clone)]
pub struct CompileEnrolmentOptionsV1 {
    /// Group the reader was enrolled into.
    pub group: String,
    /// Enrolled reader DID; must match the accepted offer's principal.
    pub reader_did: String,
    /// Destination `.tnpkg` path.
    pub out_path: PathBuf,
    /// The atomically accepted offer this response acknowledges.
    pub accepted_offer: AcceptedOffer,
    /// Validity window for the signed response statement.
    pub ttl: Duration,
}

/// Options for [`crate::admin::Admin::install_hibe_authority_assertion`].
#[derive(Debug, Clone)]
pub struct InstallHibeAssertionOptions {
    /// Group the authority material belongs to.
    pub group: String,
    /// The exact MPK bytes being pinned.
    pub mpk: Vec<u8>,
    /// The signed `hibe-authority` assertion.
    pub assertion: KeyBindingProofV1,
    /// The authority DID this writer is configured to trust.
    pub expected_authority_did: String,
    /// Verification instant.
    pub now: SystemTime,
}

/// Options for [`crate::admin::Admin::grant_reader_verified`].
#[derive(Debug, Clone)]
pub struct GrantReaderOptionsV1 {
    /// HIBE group to grant into.
    pub group: String,
    /// Reader DID receiving the grant; must be a complete Ed25519 `did:key`.
    pub reader_did: String,
    /// Destination `.tnpkg` path.
    pub out_path: PathBuf,
    /// Optional explicit identity path. An ancestor of the group's sealing
    /// path is subtree delegation and requires `allow_subauthority`.
    pub id_path: Option<String>,
    /// A valid `hibe-reader` proof for the exact reader/ceremony/group scope.
    pub proof: KeyBindingProofV1,
    /// Explicit opt-in for ancestor (subtree-delegating) grants.
    pub allow_subauthority: bool,
    /// The only plaintext compatibility path. Emits the common
    /// unsafe-operation warning and audit event and labels the artifact as
    /// unsafe bearer delivery; there is no implicit plaintext fallback.
    pub unsafe_plaintext: bool,
}

/// Result of a signed HIBE authority path rotation.
#[derive(Debug, Clone)]
pub struct HibeAuthorityUpdate {
    /// Rotated group.
    pub group: String,
    /// The new sealing path.
    pub id_path: String,
    /// The strictly greater path epoch.
    pub path_epoch: u64,
    /// The new signed authority assertion for the rotated path.
    pub assertion: KeyBindingProofV1,
}

/// Result of installing a verified publisher response on the reader side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResponseOutcome {
    /// The installed publisher DID.
    pub publisher_did: String,
    /// The private record the publisher was installed into.
    pub record_path: PathBuf,
}

/// Map a strict trust rejection into the SDK error surface, preserving the
/// stable `"<reason>: <detail>"` message shape.
pub(crate) fn trust_err(error: TrustError) -> Error {
    Error::InvalidArgument(error.to_string())
}

// ---------------------------------------------------------------------------
// Ceremony introspection helpers
// ---------------------------------------------------------------------------

fn read_yaml(tn: &Tn) -> Result<serde_yml::Value> {
    let raw = fs::read_to_string(tn.yaml_path())?;
    Ok(serde_yml::from_str(&raw)?)
}

fn yaml_relative(tn: &Tn, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        tn.yaml_path()
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(path)
    }
}

/// Resolve the active ceremony's keystore directory from its yaml.
pub(crate) fn keystore_dir(tn: &Tn) -> Result<PathBuf> {
    let doc = read_yaml(tn)?;
    let keystore = doc
        .get("keystore")
        .and_then(|keystore| keystore.get("path"))
        .and_then(serde_yml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::InvalidArgument("tn.yaml is missing keystore.path".into()))?;
    Ok(yaml_relative(tn, keystore))
}

/// Resolve the active ceremony id from its yaml.
pub(crate) fn ceremony_id(tn: &Tn) -> Result<String> {
    let doc = read_yaml(tn)?;
    doc.get("ceremony")
        .and_then(|ceremony| ceremony.get("id"))
        .and_then(serde_yml::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::InvalidArgument("tn.yaml is missing ceremony.id".into()))
}

/// Load the active device signing key from the keystore.
pub(crate) fn device_key(tn: &Tn) -> Result<tn_core::DeviceKey> {
    let seed = fs::read(keystore_dir(tn)?.join("local.private"))?;
    Ok(tn_core::DeviceKey::from_private_bytes(&seed)?)
}

/// The per-ceremony private enrollment state root:
/// `<yaml_dir>/.tn/<stem>/enrollment/v1`.
pub(crate) fn enrollment_state_root(tn: &Tn) -> PathBuf {
    let yaml = tn.yaml_path();
    let stem = yaml
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("tn");
    yaml.parent()
        .unwrap_or_else(|| Path::new(""))
        .join(".tn")
        .join(stem)
        .join("enrollment")
        .join("v1")
}

/// Open the locked enrollment store for the active ceremony.
pub(crate) fn enrollment_store(tn: &Tn) -> Result<tn_core::trusted_enrollment::EnrollmentStore> {
    let device = device_key(tn)?;
    tn_core::trusted_enrollment::EnrollmentStore::new(
        device,
        ceremony_id(tn)?,
        tn.group_names(),
        enrollment_state_root(tn),
    )
    .map_err(trust_err)
}

/// Persist exact reader/ceremony/group authorization for challenged offers.
///
/// # Errors
///
/// Scope validation failures and state conflicts as stable trust reasons.
pub fn preauthorize_reader(tn: &Tn, reader_did: &str, group: &str) -> Result<()> {
    enrollment_store(tn)?
        .preauthorize(reader_did, group)
        .map_err(trust_err)
}

fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    tn_core::keystore_backend::atomic_write_bytes(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Return the reader's static X25519 public key for `group`, minting and
/// atomically persisting the private key on first use. Re-running reuses the
/// exact existing key; private bytes remain zeroized outside storage.
pub(crate) fn ensure_reader_mykey(tn: &Tn, group: &str) -> Result<[u8; 32]> {
    let path = keystore_dir(tn)?.join(format!("{group}.jwe.mykey"));
    let private = if path.exists() {
        read_x25519_private(&path)?
    } else {
        use rand_core::RngCore as _;
        let mut fresh = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(&mut fresh[..]);
        write_secret_file(&path, &fresh[..])?;
        fresh
    };
    Ok(x25519_public_key(&private))
}

fn read_x25519_private(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(fs::read(path)?);
    bytes
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::InvalidArgument(format!(
                "{} is not a raw 32-byte X25519 private key",
                path.display()
            ))
        })
}

const SENT_OFFERS_FILENAME: &str = "enrollment_offers.v1.json";
const ACTIVATION_EXPECTATIONS_FILENAME: &str = "jwe_activation_expectations.v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SentOfferRecordV1 {
    ceremony_id: String,
    group: String,
    publisher_did: String,
    reader_did: String,
    x25519_public_key_sha256: String,
    expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SentOffersV1 {
    version: u32,
    offers: BTreeMap<String, SentOfferRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationExpectationRecordV1 {
    publisher_did: String,
    reader_did: String,
    ceremony_id: String,
    group: String,
    x25519_public_key_sha256: String,
    issued_at: String,
    expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationExpectationsV1 {
    version: u32,
    expectations: BTreeMap<String, ActivationExpectationRecordV1>,
}

fn sent_offers_path(tn: &Tn) -> Result<PathBuf> {
    Ok(keystore_dir(tn)?.join("trust").join(SENT_OFFERS_FILENAME))
}

fn activation_expectations_path(tn: &Tn) -> Result<PathBuf> {
    Ok(keystore_dir(tn)?
        .join("trust")
        .join(ACTIVATION_EXPECTATIONS_FILENAME))
}

fn read_sent_offers(tn: &Tn) -> Result<SentOffersV1> {
    let path = sent_offers_path(tn)?;
    if !path.exists() {
        return Ok(SentOffersV1 {
            version: 1,
            offers: BTreeMap::new(),
        });
    }
    let document: SentOffersV1 =
        serde_json::from_str(&fs::read_to_string(&path)?).map_err(|_| {
            trust_err(TrustError::new(
                TrustReason::StatementInvalid,
                "retained sent-offer record is malformed",
            ))
        })?;
    if document.version != 1 {
        return Err(trust_err(TrustError::new(
            TrustReason::StatementInvalid,
            "retained sent-offer record has an unsupported version",
        )));
    }
    Ok(document)
}

fn read_activation_expectations(tn: &Tn) -> Result<ActivationExpectationsV1> {
    let path = activation_expectations_path(tn)?;
    if !path.exists() {
        return Ok(ActivationExpectationsV1 {
            version: 1,
            expectations: BTreeMap::new(),
        });
    }
    let document: ActivationExpectationsV1 = read_trust_document(&path)?;
    if document.version != 1 {
        return Err(trust_err(TrustError::new(
            TrustReason::StatementInvalid,
            "JWE activation expectation record has an unsupported version",
        )));
    }
    Ok(document)
}

fn read_trust_document<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    serde_json::from_str(&fs::read_to_string(path)?).map_err(|_| {
        trust_err(TrustError::new(
            TrustReason::StatementInvalid,
            format!("private trust record in {} is malformed", path.display()),
        ))
    })
}

pub(crate) fn retain_sent_offer(
    tn: &Tn,
    publisher_did: &str,
    ceremony_id: &str,
    group: &str,
    offer_digest: &str,
    public_key_sha256: &str,
    expires_at: &str,
) -> Result<()> {
    let mut document = read_sent_offers(tn)?;
    let incoming = SentOfferRecordV1 {
        ceremony_id: ceremony_id.to_string(),
        group: group.to_string(),
        publisher_did: publisher_did.to_string(),
        reader_did: tn.did().to_string(),
        x25519_public_key_sha256: public_key_sha256.to_string(),
        expires_at: expires_at.to_string(),
    };
    if document
        .offers
        .get(offer_digest)
        .is_some_and(|existing| existing != &incoming)
    {
        return Err(trust_err(TrustError::new(
            TrustReason::ReplayConflict,
            "offer digest is already retained with different enrollment scope",
        )));
    }
    document.offers.insert(offer_digest.to_string(), incoming);
    write_secret_file(&sent_offers_path(tn)?, &serde_json::to_vec(&document)?)
}

pub(crate) fn retained_response_expectation(
    tn: &Tn,
    response: &EnrollmentResponseV1,
    now: SystemTime,
) -> Result<ResponseExpectation> {
    let document = read_sent_offers(tn)?;
    if let Some(retained) = document.offers.get(&response.accepted_offer_digest) {
        return sent_offer_expectation(tn, response, retained, now);
    }
    let direct = read_activation_expectations(tn)?;
    let retained = direct
        .expectations
        .get(&response.accepted_offer_digest)
        .ok_or_else(unsolicited_activation_error)?;
    direct_activation_expectation(tn, response, retained, now)
}

fn sent_offer_expectation(
    tn: &Tn,
    response: &EnrollmentResponseV1,
    retained: &SentOfferRecordV1,
    now: SystemTime,
) -> Result<ResponseExpectation> {
    if retained.reader_did != tn.did() {
        return Err(trust_err(TrustError::new(
            TrustReason::WrongRecipient,
            "retained offer names a different reader",
        )));
    }
    Ok(ResponseExpectation {
        publisher_did: retained.publisher_did.clone(),
        reader_did: retained.reader_did.clone(),
        ceremony_id: retained.ceremony_id.clone(),
        group: retained.group.clone(),
        offer_digest: response.accepted_offer_digest.clone(),
        public_key_sha256: retained.x25519_public_key_sha256.clone(),
        now,
    })
}

fn direct_activation_expectation(
    tn: &Tn,
    response: &EnrollmentResponseV1,
    retained: &ActivationExpectationRecordV1,
    now: SystemTime,
) -> Result<ResponseExpectation> {
    if retained.reader_did != tn.did() {
        return Err(trust_err(TrustError::new(
            TrustReason::WrongRecipient,
            "JWE activation approval names a different reader",
        )));
    }
    tn_core::trusted_enrollment::validate_statement_freshness(
        &retained.issued_at,
        &retained.expires_at,
        now,
    )
    .map_err(trust_err)?;
    Ok(ResponseExpectation {
        publisher_did: retained.publisher_did.clone(),
        reader_did: retained.reader_did.clone(),
        ceremony_id: retained.ceremony_id.clone(),
        group: retained.group.clone(),
        offer_digest: response.accepted_offer_digest.clone(),
        public_key_sha256: retained.x25519_public_key_sha256.clone(),
        now,
    })
}

fn unsolicited_activation_error() -> Error {
    trust_err(TrustError::new(
        TrustReason::ScopeMismatch,
        "response matches neither a retained sent offer nor an approved direct activation",
    ))
}

pub(crate) fn approve_jwe_activation(
    tn: &Tn,
    options: &crate::pkg::ApproveJweActivationOptions,
) -> Result<()> {
    parse_ed25519_did_key(&options.publisher_did).map_err(trust_err)?;
    require_nonempty(&options.ceremony_id, "ceremony_id")?;
    require_nonempty(&options.group, "group")?;
    require_sha256_digest(&options.binding_digest, "binding_digest")?;
    require_sha256_digest(
        &options.x25519_public_key_sha256,
        "x25519_public_key_sha256",
    )?;
    if options.ttl.is_zero() {
        return Err(Error::InvalidArgument(
            "JWE activation approval ttl must be greater than zero".into(),
        ));
    }
    let local_digest = local_jwe_public_key_digest(tn, &options.group)?;
    if local_digest != options.x25519_public_key_sha256 {
        return Err(trust_err(TrustError::new(
            TrustReason::BindingInvalid,
            "approved activation does not name this reader's local JWE key",
        )));
    }
    persist_activation_expectation(tn, options)
}

fn persist_activation_expectation(
    tn: &Tn,
    options: &crate::pkg::ApproveJweActivationOptions,
) -> Result<()> {
    let now = SystemTime::now();
    let mut document = read_activation_expectations(tn)?;
    if document
        .expectations
        .get(&options.binding_digest)
        .is_some_and(|existing| !same_activation_scope(existing, tn, options))
    {
        return Err(trust_err(TrustError::new(
            TrustReason::ReplayConflict,
            "binding digest already has a different direct activation approval",
        )));
    }
    let incoming = ActivationExpectationRecordV1 {
        publisher_did: options.publisher_did.clone(),
        reader_did: tn.did().to_string(),
        ceremony_id: options.ceremony_id.clone(),
        group: options.group.clone(),
        x25519_public_key_sha256: options.x25519_public_key_sha256.clone(),
        issued_at: canonical_utc_timestamp(now).map_err(trust_err)?,
        expires_at: canonical_utc_timestamp(now + options.ttl).map_err(trust_err)?,
    };
    document
        .expectations
        .insert(options.binding_digest.clone(), incoming);
    write_secret_file(
        &activation_expectations_path(tn)?,
        &serde_json::to_vec(&document)?,
    )
}

fn same_activation_scope(
    record: &ActivationExpectationRecordV1,
    tn: &Tn,
    options: &crate::pkg::ApproveJweActivationOptions,
) -> bool {
    record.publisher_did == options.publisher_did
        && record.reader_did == tn.did()
        && record.ceremony_id == options.ceremony_id
        && record.group == options.group
        && record.x25519_public_key_sha256 == options.x25519_public_key_sha256
}

fn require_nonempty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::InvalidArgument(format!("{name} must not be empty")))
    } else {
        Ok(())
    }
}

fn require_sha256_digest(value: &str, name: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(Error::InvalidArgument(format!(
            "{name} must use sha256:<hex>"
        )));
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "{name} must contain 64 lowercase hex characters"
        )))
    }
}

fn local_jwe_public_key_digest(tn: &Tn, group: &str) -> Result<String> {
    let mykey_path = keystore_dir(tn)?.join(format!("{group}.jwe.mykey"));
    if !mykey_path.exists() {
        return Err(trust_err(TrustError::new(
            TrustReason::BindingInvalid,
            format!("no {group}.jwe.mykey in this keystore"),
        )));
    }
    let private = read_x25519_private(&mykey_path)?;
    Ok(sha256_tagged(&x25519_public_key(&private)))
}

// ---------------------------------------------------------------------------
// Offer / response artifact helpers
// ---------------------------------------------------------------------------

fn verified_package(
    bytes: &[u8],
) -> Result<(
    tn_core::Manifest,
    std::collections::BTreeMap<String, Vec<u8>>,
)> {
    Ok(tn_core::tnpkg::read_tnpkg_verified(
        tn_core::tnpkg::TnpkgSource::Bytes(bytes),
    )?)
}

fn package_payload(body: &std::collections::BTreeMap<String, Vec<u8>>) -> Result<Value> {
    let raw = body
        .get("body/package.json")
        .ok_or_else(|| Error::InvalidArgument("package is missing body/package.json".into()))?;
    Ok(serde_json::from_slice(raw)?)
}

fn enrollment_package_string<'a>(package: &'a Value, field: &str) -> Result<&'a str> {
    package.get(field).and_then(Value::as_str).ok_or_else(|| {
        trust_err(TrustError::new(
            TrustReason::StatementInvalid,
            format!("enrolment package is missing {field}"),
        ))
    })
}

fn verify_enrollment_package_scope(
    manifest: &tn_core::Manifest,
    package: &Value,
    response: &EnrollmentResponseV1,
) -> Result<()> {
    let inner_publisher = enrollment_package_string(package, "device_identity")?;
    if manifest.publisher_identity != inner_publisher || inner_publisher != response.publisher_did {
        return Err(trust_err(TrustError::new(
            TrustReason::OuterInnerSignerMismatch,
            "outer manifest, inner enrolment, and response name different publishers",
        )));
    }
    let inner_reader = enrollment_package_string(package, "recipient_identity")?;
    if manifest.recipient_identity.as_deref() != Some(inner_reader)
        || inner_reader != response.reader_did
    {
        return Err(trust_err(TrustError::new(
            TrustReason::WrongRecipient,
            "outer manifest, inner enrolment, and response name different readers",
        )));
    }
    let ceremony = enrollment_package_string(package, "ceremony_id")?;
    let group = enrollment_package_string(package, "group")?;
    if manifest.ceremony_id != ceremony
        || manifest.scope != group
        || ceremony != response.ceremony_id
        || group != response.group
    {
        return Err(trust_err(TrustError::new(
            TrustReason::ScopeMismatch,
            "outer manifest, inner enrolment, and response have different scope",
        )));
    }
    Ok(())
}

/// Recompute the stable offer digest from exact offer artifact bytes: the
/// digest over the canonical inner proof statement, including its signature.
///
/// # Errors
///
/// [`crate::Error`] when the artifact is not a verifiable offer package.
pub fn offer_digest_of_artifact(bytes: &[u8]) -> Result<String> {
    let (manifest, body) = verified_package(bytes)?;
    if manifest.kind != tn_core::ManifestKind::Offer {
        return Err(Error::InvalidArgument("artifact is not an offer".into()));
    }
    let package = package_payload(&body)?;
    let proof = package
        .get("payload")
        .and_then(|payload| payload.get("key_binding_proof"))
        .ok_or_else(|| Error::InvalidArgument("offer lacks a key-binding proof".into()))?;
    let proof = KeyBindingProofV1::from_value(proof).map_err(trust_err)?;
    proof.digest().map_err(trust_err)
}

/// Extract and strictly parse the signed enrollment response carried by an
/// `enrolment` `.tnpkg`.
///
/// # Errors
///
/// [`crate::Error`] when the artifact fails verified reading or carries no
/// well-formed response statement.
pub fn read_enrollment_response(bytes: &[u8]) -> Result<EnrollmentResponseV1> {
    let (manifest, body) = verified_package(bytes)?;
    if manifest.kind != tn_core::ManifestKind::Enrolment {
        return Err(Error::InvalidArgument(
            "artifact is not an enrolment response package".into(),
        ));
    }
    let package = package_payload(&body)?;
    if package.get("package_version").and_then(Value::as_u64) != Some(1)
        || package.get("package_kind").and_then(Value::as_str) != Some("enrolment")
    {
        return Err(trust_err(TrustError::new(
            TrustReason::StatementInvalid,
            "package is not a version-1 enrolment response",
        )));
    }
    let response = package
        .get("payload")
        .and_then(|payload| payload.get("enrollment_response"))
        .ok_or_else(|| {
            Error::InvalidArgument("enrolment package lacks an enrollment_response".into())
        })?;
    let response = EnrollmentResponseV1::from_value(response).map_err(trust_err)?;
    verify_enrollment_package_scope(&manifest, &package, &response)?;
    Ok(response)
}

/// The reader's private verified-publisher record:
/// `<keystore>/trust/verified_publishers.v1.json`.
pub fn verified_publishers_path(tn: &Tn) -> Result<PathBuf> {
    Ok(keystore_dir(tn)?
        .join("trust")
        .join("verified_publishers.v1.json"))
}

/// Verify an accepted enrollment response against the reader's retained
/// offer and install the publisher into the private trust record.
///
/// The reader's local `.jwe.mykey` for the response group must already exist
/// and derive the public key the response names.
///
/// # Errors
///
/// `scope_mismatch` for a response naming a different retained offer, the
/// full response-verification reason set, and `binding_invalid` when the
/// local reader key does not derive the named public key.
pub fn install_publisher_response(
    tn: &Tn,
    response: &EnrollmentResponseV1,
    expected: &ResponseExpectation,
) -> Result<InstallResponseOutcome> {
    match_response_to_retained_offer(response, &expected.offer_digest).map_err(trust_err)?;
    verify_enrollment_response(response, expected).map_err(trust_err)?;

    let derived = local_jwe_public_key_digest(tn, &response.group)?;
    if derived != response.x25519_public_key_sha256 {
        return Err(trust_err(TrustError::new(
            TrustReason::BindingInvalid,
            "local reader key does not derive the public key named in the response",
        )));
    }

    let record_path = verified_publishers_path(tn)?;
    let mut document: Map<String, Value> = if record_path.exists() {
        serde_json::from_str(&fs::read_to_string(&record_path)?)
            .ok()
            .and_then(|value: Value| value.as_object().cloned())
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "invalid verified publisher record in {}",
                    record_path.display()
                ))
            })?
    } else {
        let mut fresh = Map::new();
        fresh.insert("version".into(), Value::from(1u64));
        fresh.insert("publishers".into(), Value::Object(Map::new()));
        fresh
    };
    let publishers = document
        .entry("publishers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(publishers) = publishers.as_object_mut() else {
        return Err(Error::InvalidArgument(
            "verified publisher record: publishers must be an object".into(),
        ));
    };
    publishers.insert(
        response.publisher_did.clone(),
        serde_json::json!({
            "version": 1,
            "ceremony_id": response.ceremony_id,
            "group": response.group,
            "group_epoch": response.group_epoch,
            "accepted_offer_digest": response.accepted_offer_digest,
            "activation_reference_digest": response.accepted_offer_digest,
            "x25519_public_key_sha256": response.x25519_public_key_sha256,
            "response_digest": response.digest().map_err(trust_err)?,
            "installed_at": canonical_utc_timestamp(SystemTime::now()).map_err(trust_err)?,
        }),
    );
    let bytes = serde_json::to_vec(&Value::Object(document))?;
    tn_core::keystore_backend::atomic_write_bytes(&record_path, &bytes)?;
    tn.runtime().reload_group_cipher(&response.group)?;
    tn.reload_read_trust_provider()?;
    Ok(InstallResponseOutcome {
        publisher_did: response.publisher_did.clone(),
        record_path,
    })
}

// ---------------------------------------------------------------------------
// Unsafe-operation observability
// ---------------------------------------------------------------------------

/// Emit the one structured security warning (through the core `log` facade)
/// and the one best-effort audit event for an explicitly weakened operation.
pub(crate) fn warn_and_audit_unsafe(tn: &Tn, notice: &UnsafeOperationNotice) {
    tn_core::trusted_enrollment::emit_unsafe_warning(notice);
    tn.emit_unsafe_operation_audit(notice);
}

// ---------------------------------------------------------------------------
// HIBE authority pin state
// ---------------------------------------------------------------------------

pub(crate) fn hibe_pin_path(tn: &Tn, group: &str) -> Result<PathBuf> {
    Ok(keystore_dir(tn)?
        .join("trust")
        .join(format!("hibe_authority.{group}.v1.json")))
}

/// The pinned authority state for one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HibeAuthorityPin {
    pub authority_did: String,
    pub mpk_sha256: String,
    pub max_depth: u64,
    pub id_path: String,
    pub path_epoch: u64,
    pub assertion_digest: String,
}

pub(crate) fn load_hibe_pin(tn: &Tn, group: &str) -> Result<Option<HibeAuthorityPin>> {
    let path = hibe_pin_path(tn, group)?;
    if !path.exists() {
        return Ok(None);
    }
    let value: Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
    let field = |name: &str| -> Result<String> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "pinned hibe authority state in {} is missing {name}",
                    path.display()
                ))
            })
    };
    Ok(Some(HibeAuthorityPin {
        authority_did: field("authority_did")?,
        mpk_sha256: field("mpk_sha256")?,
        max_depth: value
            .get("max_depth")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                Error::InvalidArgument("pinned hibe authority state is missing max_depth".into())
            })?,
        id_path: field("id_path")?,
        path_epoch: value
            .get("path_epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                Error::InvalidArgument("pinned hibe authority state is missing path_epoch".into())
            })?,
        assertion_digest: field("assertion_digest")?,
    }))
}

pub(crate) fn store_hibe_pin(tn: &Tn, group: &str, pin: &HibeAuthorityPin) -> Result<()> {
    let path = hibe_pin_path(tn, group)?;
    let record = serde_json::json!({
        "version": 1,
        "authority_did": pin.authority_did,
        "mpk_sha256": pin.mpk_sha256,
        "max_depth": pin.max_depth,
        "id_path": pin.id_path,
        "path_epoch": pin.path_epoch,
        "assertion_digest": pin.assertion_digest,
    });
    let bytes = serde_json::to_vec(&record)?;
    tn_core::keystore_backend::atomic_write_bytes(&path, &bytes)?;
    Ok(())
}
