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

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

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

/// Return the reader's static X25519 keypair for `group`, minting and
/// atomically persisting the private key on first use. Re-running reuses the
/// exact existing key; it is never exported.
pub(crate) fn ensure_reader_mykey(tn: &Tn, group: &str) -> Result<([u8; 32], [u8; 32])> {
    let path = keystore_dir(tn)?.join(format!("{group}.jwe.mykey"));
    let private: [u8; 32] = if path.exists() {
        fs::read(&path)?.as_slice().try_into().map_err(|_| {
            Error::InvalidArgument(format!(
                "{} is not a raw 32-byte X25519 private key",
                path.display()
            ))
        })?
    } else {
        use rand_core::RngCore as _;
        let mut fresh = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut fresh);
        write_secret_file(&path, &fresh)?;
        fresh
    };
    Ok((private, x25519_public_key(&private)))
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
    let response = package
        .get("payload")
        .and_then(|payload| payload.get("enrollment_response"))
        .ok_or_else(|| {
            Error::InvalidArgument("enrolment package lacks an enrollment_response".into())
        })?;
    EnrollmentResponseV1::from_value(response).map_err(trust_err)
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

    let mykey_path = keystore_dir(tn)?.join(format!("{}.jwe.mykey", response.group));
    if !mykey_path.exists() {
        return Err(trust_err(TrustError::new(
            TrustReason::BindingInvalid,
            format!(
                "no {}.jwe.mykey in this keystore; the response cannot bind a reader key",
                response.group
            ),
        )));
    }
    let private: [u8; 32] = fs::read(&mykey_path)?.as_slice().try_into().map_err(|_| {
        Error::InvalidArgument(format!(
            "{} is not a raw 32-byte X25519 private key",
            mykey_path.display()
        ))
    })?;
    let derived = sha256_tagged(&x25519_public_key(&private));
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
            "x25519_public_key_sha256": response.x25519_public_key_sha256,
            "response_digest": response.digest().map_err(trust_err)?,
            "installed_at": canonical_utc_timestamp(SystemTime::now()).map_err(trust_err)?,
        }),
    );
    let bytes = serde_json::to_vec(&Value::Object(document))?;
    tn_core::keystore_backend::atomic_write_bytes(&record_path, &bytes)?;
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
