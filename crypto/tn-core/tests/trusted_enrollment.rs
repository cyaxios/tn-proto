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
