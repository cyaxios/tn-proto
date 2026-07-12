//! Enrollment-lifecycle contract tests over the shared trust vectors plus the
//! locked receiver-local enrollment state store.
//!
//! The `enrollment_lifecycle.json` fixture drives the receiver-side decision
//! procedure exactly: challenge issuance, authenticated offer absorption with
//! every stable rejection reason, atomic exact-digest approval, and accepted
//! enrollment-response verification. The `first_decrypt` phase is owned by the
//! managed JWE SDKs (Python, TypeScript, C#); Rust keeps its documented native
//! JWE `NotImplemented` sentinel and therefore skips those cases explicitly.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::Value;

use tn_core::trust::{TrustError, TrustReason};
use tn_core::trusted_enrollment::{
    authorize_offer, match_response_to_retained_offer, sha256_tagged, verify_enrollment_challenge,
    verify_enrollment_response, verify_offer_artifact, ChallengeExpectation, ChallengeLedger,
    ChallengeState, EnrollmentChallengeV1, EnrollmentResponseV1, EnrollmentStore,
    OfferVerification, ResponseExpectation,
};
use tn_core::DeviceKey;

fn fixture_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("tests");
    p.push("fixtures");
    p.push("trust");
    p.push("v1");
    p
}

fn fixture(name: &str) -> Value {
    let raw = fs::read_to_string(fixture_dir().join(name))
        .unwrap_or_else(|err| panic!("read fixture {name}: {err}"));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("parse fixture {name}: {err}"))
}

fn cases(document: &Value) -> &Vec<Value> {
    document["cases"].as_array().expect("fixture cases array")
}

fn case_by_id<'a>(document: &'a Value, id: &str) -> &'a Value {
    cases(document)
        .iter()
        .find(|case| case["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing fixture case {id}"))
}

fn parse_time(text: &str) -> SystemTime {
    let odt = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|err| panic!("parse fixture time {text}: {err}"));
    SystemTime::UNIX_EPOCH + Duration::from_nanos(odt.unix_timestamp_nanos() as u64)
}

fn fixture_challenge(document: &Value) -> EnrollmentChallengeV1 {
    EnrollmentChallengeV1::from_value(
        &case_by_id(document, "issue_signed_challenge")["input"]["challenge"],
    )
    .expect("fixture challenge parses")
}

fn device_from_vectors(role: &str) -> DeviceKey {
    let vectors = fixture("did_key_vectors.json");
    let seed = B64
        .decode(
            case_by_id(&vectors, &format!("{role}_ed25519_did_key"))["input"]["seed_b64"]
                .as_str()
                .expect("seed"),
        )
        .expect("decode seed");
    DeviceKey::from_private_bytes(&seed).expect("device key")
}

/// Fixture-shaped receiver challenge ledger: resolves the retained state the
/// `challenge_state` validation input describes.
struct FixtureLedger {
    state: String,
    challenge: EnrollmentChallengeV1,
    expected_digest: String,
}

impl ChallengeLedger for FixtureLedger {
    fn resolve(&self, challenge_digest: &str) -> Result<ChallengeState, TrustError> {
        if challenge_digest != self.expected_digest {
            return Ok(ChallengeState::Missing);
        }
        Ok(match self.state.as_str() {
            "issued" => ChallengeState::Retained(self.challenge.clone()),
            "missing" => ChallengeState::Missing,
            "expired" => ChallengeState::Expired,
            "consumed" => ChallengeState::ConsumedReplayed,
            other => panic!("unknown fixture challenge_state {other:?}"),
        })
    }
}

fn run_absorb_case(document: &Value, case: &Value) -> Result<(String, String), TrustError> {
    let input = &case["input"];
    let validation = &input["validation"];
    let artifact = B64
        .decode(input["tnpkg_b64"].as_str().expect("tnpkg"))
        .expect("decode tnpkg");
    let ledger = FixtureLedger {
        state: validation["challenge_state"]
            .as_str()
            .expect("challenge_state")
            .to_string(),
        challenge: fixture_challenge(document),
        expected_digest: validation["expected_challenge_digest"]
            .as_str()
            .expect("challenge digest")
            .to_string(),
    };
    let expected = OfferVerification {
        expected_publisher_did: validation["local_recipient_did"]
            .as_str()
            .expect("local recipient"),
        expected_ceremony_id: validation["expected_ceremony_id"]
            .as_str()
            .expect("ceremony"),
        expected_group: validation["expected_group"].as_str().expect("group"),
        expected_public_key_sha256: validation["expected_public_key_sha256"].as_str(),
        now: parse_time(validation["now"].as_str().expect("now")),
    };
    let verified = verify_offer_artifact(&artifact, &expected, &ledger)?;
    let trusted: Vec<String> = validation["trusted_reader_dids"]
        .as_array()
        .expect("trusted readers")
        .iter()
        .map(|did| did.as_str().expect("did").to_string())
        .collect();
    authorize_offer(&verified, &trusted, false)?;
    Ok((verified.offer_digest, verified.artifact_digest))
}

#[test]
fn enrollment_lifecycle_fixture_decides_exactly() {
    let document = fixture("enrollment_lifecycle.json");
    for case in cases(&document) {
        let id = case["id"].as_str().expect("case id");
        let input = &case["input"];
        let expected = &case["expected"];
        let accepted = expected["accepted"].as_bool().expect("accepted");
        match input["operation"].as_str().expect("operation") {
            "issue_challenge" => {
                // The signed fixture challenge verifies against the exact
                // publisher/reader scope it was issued for, and its retained
                // digest matches the frozen value.
                let challenge =
                    EnrollmentChallengeV1::from_value(&input["challenge"]).expect("parse");
                assert!(accepted, "case {id}");
                assert_eq!(
                    challenge.digest().expect("digest"),
                    expected["challenge_digest"].as_str().expect("digest"),
                    "case {id}: retained challenge digest"
                );
                verify_enrollment_challenge(
                    &challenge,
                    &ChallengeExpectation {
                        publisher_did: input["publisher_did"]
                            .as_str()
                            .expect("publisher")
                            .to_string(),
                        reader_did: input["reader_did"].as_str().expect("reader").to_string(),
                        ceremony_id: challenge.ceremony_id.clone(),
                        group: challenge.group.clone(),
                        now: parse_time(&challenge.issued_at),
                    },
                )
                .expect("fixture challenge verifies");
                // Ed25519 determinism: re-signing with the publisher seed
                // reproduces the frozen signature.
                let resigned = EnrollmentChallengeV1 {
                    signature_b64: String::new(),
                    ..challenge.clone()
                }
                .signed(&device_from_vectors("publisher"))
                .expect("re-sign");
                assert_eq!(resigned.signature_b64, challenge.signature_b64, "case {id}");
            }
            "absorb_offer" => match run_absorb_case(&document, case) {
                Ok((offer_digest, artifact_digest)) => {
                    assert!(accepted, "case {id}: expected rejection");
                    assert_eq!(
                        offer_digest,
                        expected["offer_digest"].as_str().expect("offer digest"),
                        "case {id}"
                    );
                    assert_eq!(
                        artifact_digest,
                        expected["artifact_digest"]
                            .as_str()
                            .expect("artifact digest"),
                        "case {id}"
                    );
                }
                Err(error) => {
                    assert!(!accepted, "case {id}: expected acceptance, got {error}");
                    assert_eq!(
                        error.reason.as_str(),
                        expected["reason"].as_str().expect("reason"),
                        "case {id}: {}",
                        error.detail
                    );
                }
            },
            "approve_offer" => {
                let outcome = approve_case_through_store(&document, case);
                match outcome {
                    Ok(offer_digest) => {
                        assert!(accepted, "case {id}: expected rejection");
                        assert_eq!(
                            offer_digest,
                            input["pending_offer_digest"].as_str().expect("digest"),
                            "case {id}"
                        );
                    }
                    Err(error) => {
                        assert!(!accepted, "case {id}: expected acceptance, got {error}");
                        assert_eq!(
                            error.reason.as_str(),
                            expected["reason"].as_str().expect("reason"),
                            "case {id}: {}",
                            error.detail
                        );
                    }
                }
            }
            "verify_response" => {
                let response =
                    EnrollmentResponseV1::from_value(&input["response"]).expect("parse response");
                let now = parse_time(&response.issued_at);
                let outcome = match_response_to_retained_offer(
                    &response,
                    input["expected_offer_digest"].as_str().expect("digest"),
                )
                .and_then(|()| {
                    verify_enrollment_response(
                        &response,
                        &ResponseExpectation {
                            publisher_did: response.publisher_did.clone(),
                            reader_did: response.reader_did.clone(),
                            ceremony_id: response.ceremony_id.clone(),
                            group: response.group.clone(),
                            offer_digest: input["expected_offer_digest"]
                                .as_str()
                                .expect("digest")
                                .to_string(),
                            public_key_sha256: input["expected_public_key_sha256"]
                                .as_str()
                                .expect("public key sha")
                                .to_string(),
                            now,
                        },
                    )
                });
                match outcome {
                    Ok(()) => assert!(accepted, "case {id}: expected rejection"),
                    Err(error) => {
                        assert!(!accepted, "case {id}: expected acceptance, got {error}");
                        assert_eq!(
                            error.reason.as_str(),
                            expected["reason"].as_str().expect("reason"),
                            "case {id}: {}",
                            error.detail
                        );
                    }
                }
            }
            "first_decrypt" => {
                // Managed JWE first decrypt is owned by the Python,
                // TypeScript, and C# SDKs. The Rust runtime keeps its
                // documented `NotImplemented` sentinel for JWE groups, so
                // this phase is intentionally not executed here.
            }
            other => panic!("unknown lifecycle operation {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// EnrollmentStore: locked receiver-local state
// ---------------------------------------------------------------------------

fn store_for(document: &Value, root: &std::path::Path) -> EnrollmentStore {
    let publisher = device_from_vectors("publisher");
    let ceremony_id = fixture_challenge(document).ceremony_id;
    EnrollmentStore::new(
        publisher,
        ceremony_id,
        vec!["default".to_string(), "fraud".to_string()],
        root.join("enrollment").join("v1"),
    )
    .expect("store")
}

/// Seed the store's `challenges/` tree with the fixture challenge exactly the
/// way `issue_challenge` retains one.
fn seed_fixture_challenge(store: &EnrollmentStore, document: &Value) {
    store
        .retain_challenge(&fixture_challenge(document))
        .expect("retain fixture challenge");
}

fn approve_case_through_store(document: &Value, case: &Value) -> Result<String, TrustError> {
    let td = tempfile::tempdir().expect("tempdir");
    let store = store_for(document, td.path());
    seed_fixture_challenge(&store, document);
    let input = &case["input"];
    let artifact = B64
        .decode(input["tnpkg_b64"].as_str().expect("tnpkg"))
        .expect("decode tnpkg");
    let now = parse_time("2026-07-11T14:05:00Z");
    store.stage_offer(&artifact, now)?;
    let accepted = store.approve_and_reconcile(
        input["approved_offer_digest"].as_str().expect("digest"),
        now,
    )?;
    Ok(accepted.offer_digest)
}

#[test]
fn store_stage_approve_reconcile_is_atomic_and_idempotent() {
    let document = fixture("enrollment_lifecycle.json");
    let offer_case = case_by_id(&document, "absorb_authenticated_offer");
    let artifact = B64
        .decode(offer_case["input"]["tnpkg_b64"].as_str().expect("tnpkg"))
        .expect("decode tnpkg");
    let offer_digest = offer_case["expected"]["offer_digest"]
        .as_str()
        .expect("offer digest");
    let artifact_digest = offer_case["expected"]["artifact_digest"]
        .as_str()
        .expect("artifact digest");
    let now = parse_time("2026-07-11T14:05:00Z");

    let td = tempfile::tempdir().expect("tempdir");
    let store = store_for(&document, td.path());
    seed_fixture_challenge(&store, &document);

    // Stage retains the exact artifact bytes at the locked layout path.
    let pending = store.stage_offer(&artifact, now).expect("stage");
    assert_eq!(pending.offer_digest, offer_digest);
    assert!(pending.artifact_path.exists(), "artifact is retained");
    assert!(
        pending.artifact_path.starts_with(store.state_root()),
        "retained under the private state root"
    );
    assert_eq!(
        fs::read(&pending.artifact_path).expect("read retained"),
        artifact,
        "retained bytes are exact"
    );
    assert!(
        store.state_root().join("challenges").is_dir(),
        "locked layout: challenges/"
    );
    assert!(
        store.state_root().join("offers").is_dir(),
        "locked layout: offers/"
    );

    // Staging the identical artifact again is an idempotent no-op.
    let replay = store.stage_offer(&artifact, now).expect("replay stage");
    assert_eq!(replay.offer_digest, offer_digest);

    // An unapproved, non-preauthorized offer cannot be promoted.
    let unauthorized = store
        .reconcile(offer_digest, now)
        .expect_err("reconcile requires approval or preauthorization");
    assert_eq!(unauthorized.reason, TrustReason::UntrustedPrincipal);

    // Approval consumes the challenge and promotes atomically.
    let accepted = store
        .approve_and_reconcile(offer_digest, now)
        .expect("approve and reconcile");
    assert_eq!(accepted.offer_digest, offer_digest);
    assert_eq!(accepted.artifact_digest, artifact_digest);
    assert!(
        store.state_root().join("approvals").is_dir(),
        "locked layout: approvals/"
    );
    assert!(
        store.state_root().join("consumed").is_dir(),
        "locked layout: consumed/"
    );
    assert!(
        store.state_root().join("accepted").is_dir(),
        "locked layout: accepted/"
    );
    assert!(
        store.state_root().join("enrollment.lock").exists(),
        "locked layout: enrollment.lock"
    );

    // Exact repeats converge on the same accepted state.
    let repeat = store
        .approve_and_reconcile(offer_digest, now)
        .expect("repeat approval is idempotent");
    assert_eq!(repeat.offer_digest, accepted.offer_digest);
    assert_eq!(repeat.artifact_digest, accepted.artifact_digest);
    let reconciled = store
        .reconcile(offer_digest, now)
        .expect("reconcile after approval");
    assert_eq!(reconciled.offer_digest, accepted.offer_digest);
}

#[test]
fn store_preauthorized_reader_reconciles_without_exact_approval() {
    let document = fixture("enrollment_lifecycle.json");
    let offer_case = case_by_id(&document, "absorb_authenticated_offer");
    let artifact = B64
        .decode(offer_case["input"]["tnpkg_b64"].as_str().expect("tnpkg"))
        .expect("decode tnpkg");
    let offer_digest = offer_case["expected"]["offer_digest"]
        .as_str()
        .expect("offer digest");
    let reader_did = offer_case["input"]["validation"]["trusted_reader_dids"][0]
        .as_str()
        .expect("reader did");
    let now = parse_time("2026-07-11T14:05:00Z");

    let td = tempfile::tempdir().expect("tempdir");
    let store = store_for(&document, td.path());
    seed_fixture_challenge(&store, &document);
    store
        .preauthorize(reader_did, "default")
        .expect("preauthorize");
    store.stage_offer(&artifact, now).expect("stage");
    let accepted = store
        .reconcile(offer_digest, now)
        .expect("preauthorized reconcile");
    assert_eq!(accepted.binding.principal.did, reader_did);
}

#[test]
fn store_rejects_a_conflicting_artifact_for_a_consumed_challenge() {
    let document = fixture("enrollment_lifecycle.json");
    let offer_case = case_by_id(&document, "absorb_authenticated_offer");
    let artifact = B64
        .decode(offer_case["input"]["tnpkg_b64"].as_str().expect("tnpkg"))
        .expect("decode tnpkg");
    let offer_digest = offer_case["expected"]["offer_digest"]
        .as_str()
        .expect("offer digest");
    let now = parse_time("2026-07-11T14:05:00Z");

    let td = tempfile::tempdir().expect("tempdir");
    let store = store_for(&document, td.path());
    seed_fixture_challenge(&store, &document);
    store.stage_offer(&artifact, now).expect("stage");
    store
        .approve_and_reconcile(offer_digest, now)
        .expect("approve");

    // A different signed artifact binding the already-consumed challenge is a
    // conflict, not an idempotent replay: the challenge was consumed by
    // different exact bytes.
    let challenge = fixture_challenge(&document);
    let reader = device_from_vectors("reader");
    let conflicting_offer = tn_core::trusted_enrollment::build_offer_artifact(
        &tn_core::trusted_enrollment::OfferArtifactSpec {
            ceremony_id: &challenge.ceremony_id,
            group: &challenge.group,
            publisher_did: &challenge.publisher_did,
            reader_key: &reader,
            reader_public_key: [9u8; 32],
            challenge: Some(&challenge),
            now,
        },
    )
    .expect("build conflicting offer");
    let conflict = store
        .stage_offer(&conflicting_offer.tnpkg, now)
        .expect_err("a consumed challenge rejects different artifact bytes");
    assert_eq!(conflict.reason, TrustReason::ReplayConflict);
}

// ---------------------------------------------------------------------------
// Unsafe-operation warning surface
// ---------------------------------------------------------------------------

/// Captures `tn.security`-targeted warn records emitted through the `log`
/// facade so tests can count the one structured warning.
struct CaptureLogger;

static CAPTURED_WARNINGS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

impl log::Log for CaptureLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.target() == "tn.security"
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) && record.level() == log::Level::Warn {
            CAPTURED_WARNINGS
                .lock()
                .expect("warning capture lock")
                .push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

#[test]
fn unsafe_warning_emits_once_with_the_canonical_payload() {
    static LOGGER: CaptureLogger = CaptureLogger;
    // Another test binary may have set a logger first; ignore the error and
    // rely on the returned payload in that case.
    let logger_installed = log::set_logger(&LOGGER).is_ok();
    log::set_max_level(log::LevelFilter::Warn);

    let unsafe_events = fixture("unsafe_operation_event.json");
    let case = case_by_id(&unsafe_events, "read_verification_disabled");
    let notice: tn_core::UnsafeOperationNotice =
        serde_json::from_value(case["input"].clone()).expect("notice parses");
    let payload = tn_core::trusted_enrollment::emit_unsafe_warning(&notice);
    assert_eq!(
        payload,
        case["expected"]["canonical_json"]
            .as_str()
            .expect("canonical"),
        "warning payload is the exact five-field canonical statement"
    );
    if logger_installed {
        let captured = CAPTURED_WARNINGS.lock().expect("warning capture lock");
        assert_eq!(captured.len(), 1, "exactly one structured warning");
        assert!(
            captured[0].contains("tn.security.unsafe_operation"),
            "warning names the event type: {}",
            captured[0]
        );
        assert!(
            captured[0].contains(&payload),
            "warning carries the canonical payload: {}",
            captured[0]
        );
    }
}

#[test]
fn store_retains_multi_group_offers_from_one_reader_without_collision() {
    // One reader DID enrolling into two groups yields two retained artifacts
    // under group-scoped digest paths — no filename collision.
    let document = fixture("enrollment_lifecycle.json");
    let td = tempfile::tempdir().expect("tempdir");
    let store = store_for(&document, td.path());
    let publisher = device_from_vectors("publisher");
    let reader = device_from_vectors("reader");
    let now = parse_time("2026-07-11T14:05:00Z");
    let mut paths = Vec::new();
    for group in ["default", "fraud"] {
        let challenge = store
            .issue_challenge(reader.did(), group, Duration::from_secs(600), now)
            .expect("issue challenge");
        let offer = tn_core::trusted_enrollment::build_offer_artifact(
            &tn_core::trusted_enrollment::OfferArtifactSpec {
                ceremony_id: &challenge.ceremony_id,
                group,
                publisher_did: publisher.did(),
                reader_key: &reader,
                reader_public_key: [7u8; 32],
                challenge: Some(&challenge),
                now,
            },
        )
        .expect("build offer");
        let pending = store.stage_offer(&offer.tnpkg, now).expect("stage");
        assert_eq!(pending.group, group);
        assert_eq!(pending.offer_digest, offer.offer_digest);
        assert_eq!(
            sha256_tagged(&offer.tnpkg),
            offer.artifact_digest,
            "artifact digest covers the exact retained bytes"
        );
        paths.push(pending.artifact_path);
    }
    assert_ne!(paths[0], paths[1], "group-scoped retention paths differ");
    assert!(paths.iter().all(|p| p.exists()));
}

// ---------------------------------------------------------------------------
// One-time HIBE grant challenge consumption
// ---------------------------------------------------------------------------

#[test]
fn hibe_grant_challenge_consumption_is_one_time_and_atomic() {
    use tn_core::trusted_enrollment::{hibe_grant_digest, HibeGrantConsumptionV1};

    let document = fixture("enrollment_lifecycle.json");
    let td = tempfile::tempdir().expect("tempdir");
    let store = store_for(&document, td.path());
    let reader = device_from_vectors("reader");
    let now = parse_time("2026-07-11T14:05:00Z");
    let challenge = store
        .issue_challenge(reader.did(), "default", Duration::from_secs(600), now)
        .expect("issue challenge");

    let proof_digest = sha256_tagged(b"proof-bytes");
    let grant_digest = hibe_grant_digest(
        &proof_digest,
        reader.did(),
        &challenge.ceremony_id,
        "default",
        "org/fraud/case-17",
    )
    .expect("grant digest");
    let consumption = HibeGrantConsumptionV1 {
        proof_digest: proof_digest.clone(),
        grant_digest: grant_digest.clone(),
        artifact_digest: sha256_tagged(b"grant-package"),
    };

    // An unconsumed challenge passes the grant gate.
    store
        .check_hibe_grant_challenge(&challenge.challenge_id, &proof_digest, &grant_digest)
        .expect("fresh challenge is grantable");

    // Committing retains the exact delivery bytes and consumes atomically.
    let retained = store
        .commit_hibe_grant(&challenge.challenge_id, &consumption, b"grant-package")
        .expect("commit grant");
    assert!(retained.exists(), "delivery artifact retained");
    assert!(retained.starts_with(store.state_root()));
    assert_eq!(
        fs::read(&retained).expect("retained bytes"),
        b"grant-package"
    );
    let consumed_path = store
        .state_root()
        .join("consumed")
        .join(format!("{}.json", challenge.challenge_id));
    let record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&consumed_path).expect("consumed record"))
            .expect("record json");
    assert_eq!(record["kind"].as_str(), Some("hibe-reader-grant"));
    assert_eq!(record["proof_digest"].as_str(), Some(proof_digest.as_str()));
    assert_eq!(record["grant_digest"].as_str(), Some(grant_digest.as_str()));

    // The identical concurrent commit converges; a different one conflicts.
    let repeat = store
        .commit_hibe_grant(&challenge.challenge_id, &consumption, b"grant-package")
        .expect("exact concurrent commit converges");
    assert_eq!(repeat, retained);
    let conflicting = HibeGrantConsumptionV1 {
        proof_digest: sha256_tagged(b"other-proof"),
        grant_digest: sha256_tagged(b"other-grant"),
        artifact_digest: sha256_tagged(b"other-package"),
    };
    let conflict = store
        .commit_hibe_grant(&challenge.challenge_id, &conflicting, b"other-package")
        .expect_err("different grant cannot reuse the challenge");
    assert_eq!(conflict.reason, TrustReason::ReplayConflict);

    // A consumed challenge rejects every NEW grant attempt.
    let replay = store
        .check_hibe_grant_challenge(&challenge.challenge_id, &proof_digest, &grant_digest)
        .expect_err("consumed challenge is not grantable again");
    assert_eq!(replay.reason, TrustReason::ChallengeReplayed);
    let foreign = store
        .check_hibe_grant_challenge(
            &challenge.challenge_id,
            &sha256_tagged(b"other-proof"),
            &sha256_tagged(b"other-grant"),
        )
        .expect_err("a different proof conflicts with the committed grant");
    assert_eq!(foreign.reason, TrustReason::ReplayConflict);

    // A challenge consumed by ENROLLMENT (not a grant) reads as replayed.
    let enrollment_challenge = store
        .issue_challenge(reader.did(), "fraud", Duration::from_secs(600), now)
        .expect("second challenge");
    let offer = tn_core::trusted_enrollment::build_offer_artifact(
        &tn_core::trusted_enrollment::OfferArtifactSpec {
            ceremony_id: &enrollment_challenge.ceremony_id,
            group: "fraud",
            publisher_did: &enrollment_challenge.publisher_did,
            reader_key: &reader,
            reader_public_key: [7u8; 32],
            challenge: Some(&enrollment_challenge),
            now,
        },
    )
    .expect("build offer");
    store.stage_offer(&offer.tnpkg, now).expect("stage");
    store
        .approve_and_reconcile(&offer.offer_digest, now)
        .expect("enrollment consumption");
    let cross = store
        .check_hibe_grant_challenge(
            &enrollment_challenge.challenge_id,
            &proof_digest,
            &grant_digest,
        )
        .expect_err("an enrollment-consumed challenge cannot back a grant");
    assert_eq!(cross.reason, TrustReason::ChallengeReplayed);
}

// ---------------------------------------------------------------------------
// HIBE grant artifact labeling
// ---------------------------------------------------------------------------

#[test]
fn hibe_grant_artifacts_are_labeled_and_sealed_bodies_refuse_relabeling() {
    use tn_core::trusted_enrollment::label_hibe_grant_artifact;

    let device = device_from_vectors("authority");
    let signing = ed25519_dalek::SigningKey::from_bytes(&device.private_bytes());
    let mut body = std::collections::BTreeMap::new();
    body.insert("body/keys/default.hibe.sk".to_string(), vec![0x77u8; 16]);
    let mut manifest = tn_core::Manifest {
        kind: tn_core::ManifestKind::KitBundle,
        version: 1,
        publisher_identity: device.did().to_string(),
        recipient_identity: Some(device.did().to_string()),
        ceremony_id: "cer_grant_label".into(),
        as_of: "2026-07-11T14:00:00Z".into(),
        scope: "default".into(),
        clock: std::collections::BTreeMap::new(),
        event_count: 0,
        head_row_hash: None,
        state: None,
        body_sha256: std::collections::BTreeMap::new(),
        body_sha256_present: false,
        manifest_signature_b64: None,
    };
    tn_core::tnpkg::sign_manifest_with_body(&mut manifest, &body, &signing).expect("sign");
    let plaintext = tn_core::tnpkg::write_tnpkg_bytes(&manifest, &body).expect("package");

    // The unsafe plaintext label matches the Python manifest-state shape.
    let labeled = label_hibe_grant_artifact(
        &plaintext,
        &device,
        "unsafe-plaintext-bearer",
        true,
        "org/fraud",
        true,
    )
    .expect("label plaintext grant");
    let (labeled_manifest, _) =
        tn_core::tnpkg::read_tnpkg_verified(tn_core::tnpkg::TnpkgSource::Bytes(&labeled))
            .expect("labeled artifact stays verifiable");
    let state = labeled_manifest.state.clone().expect("manifest state");
    let grant = state.get("hibe_grant").expect("hibe_grant state");
    assert_eq!(
        grant.get("delivery").and_then(serde_json::Value::as_str),
        Some("unsafe-plaintext-bearer")
    );
    assert_eq!(
        grant
            .get("delegated_subauthority")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        grant.get("id_path").and_then(serde_json::Value::as_str),
        Some("org/fraud")
    );
    assert_eq!(
        grant.get("unsafe").and_then(serde_json::Value::as_bool),
        Some(true)
    );

    // A recipient-sealed body binds its manifest as wrap AAD; relabeling it
    // would break every reader's unwrap, so the labeler refuses.
    let mut sealed_manifest = tn_core::Manifest {
        state: Some(serde_json::json!({
            "body_encryption": {"frame": "tn-body-aes256gcm-v1"}
        })),
        manifest_signature_b64: None,
        body_sha256: std::collections::BTreeMap::new(),
        body_sha256_present: false,
        ..labeled_manifest
    };
    let mut sealed_body = std::collections::BTreeMap::new();
    sealed_body.insert("body/encrypted.bin".to_string(), vec![0u8; 8]);
    tn_core::tnpkg::sign_manifest_with_body(&mut sealed_manifest, &sealed_body, &signing)
        .expect("sign sealed");
    let sealed =
        tn_core::tnpkg::write_tnpkg_bytes(&sealed_manifest, &sealed_body).expect("sealed package");
    let refused = label_hibe_grant_artifact(
        &sealed,
        &device,
        "recipient-seal-v1",
        false,
        "org/fraud/case-17",
        false,
    )
    .expect_err("sealed bodies cannot be relabeled");
    assert_eq!(refused.reason, TrustReason::StatementInvalid);
}
