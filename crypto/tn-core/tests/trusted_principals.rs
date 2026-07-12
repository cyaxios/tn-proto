//! Shared-vector contract tests for the strict trusted-principal layer.
//!
//! Every case in `tests/fixtures/trust/v1/{did_key_vectors,signed_statements,
//! state_transitions}.json` must produce the exact accept/reject decision and
//! stable reason the fixture pins. Canonical signing bytes are reconstructed
//! independently from the fixture statement JSON and compared to the frozen
//! `canonical_b64` value, so the Rust encoder cannot drift from the shared
//! wire contract.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::Value;

use tn_core::canonical::canonical_bytes;
use tn_core::trust::{parse_ed25519_did_key, TrustError, TrustReason};
use tn_core::trusted_enrollment::{
    classify_challenge_consumption, classify_hibe_epoch, decode_x25519_public_key,
    ensure_expected_reader_key, ensure_expected_signer, hibe_authority_binding,
    verify_enrollment_challenge, verify_enrollment_response, verify_jwe_key_binding,
    verify_key_binding_proof, ChallengeExpectation, ConsumeDecision, EnrollmentChallengeV1,
    EnrollmentResponseV1, EpochDecision, KeyBindingProofV1, ProofExpectation, ResponseExpectation,
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

fn expected_reason(case: &Value) -> &str {
    case["expected"]["reason"]
        .as_str()
        .expect("rejected case carries a stable reason")
}

fn assert_reason(case_id: &str, error: &TrustError, expected: &str) {
    assert_eq!(
        error.reason.as_str(),
        expected,
        "case {case_id}: expected reason {expected}, got {} ({})",
        error.reason.as_str(),
        error.detail
    );
}

// ---------------------------------------------------------------------------
// did_key_vectors.json
// ---------------------------------------------------------------------------

#[test]
fn did_key_vectors_decide_exactly() {
    let document = fixture("did_key_vectors.json");
    for case in cases(&document) {
        let id = case["id"].as_str().expect("case id");
        let accepted = case["expected"]["valid"].as_bool().expect("valid flag");
        match case["kind"].as_str().expect("kind") {
            "ed25519-did-key" => {
                let did = case["input"]["did"].as_str().expect("did");
                match parse_ed25519_did_key(did) {
                    Ok(public_key) => {
                        assert!(accepted, "case {id}: expected rejection, got acceptance");
                        let expected_pub = B64
                            .decode(case["expected"]["public_key_b64"].as_str().expect("pub"))
                            .expect("decode expected public key");
                        assert_eq!(public_key.as_slice(), expected_pub.as_slice(), "case {id}");
                        // The DID round-trips through DeviceKey: the seed in the
                        // vector derives exactly this identifier.
                        let seed = B64
                            .decode(case["input"]["seed_b64"].as_str().expect("seed"))
                            .expect("decode seed");
                        let device = DeviceKey::from_private_bytes(&seed).expect("device key");
                        assert_eq!(device.did(), did, "case {id}: seed-derived DID");
                    }
                    Err(error) => {
                        assert!(!accepted, "case {id}: expected acceptance, got {error}");
                        assert_reason(id, &error, expected_reason(case));
                    }
                }
            }
            "x25519-key" => {
                let encoded = case["input"]["public_key_b64"].as_str().expect("pub");
                match decode_x25519_public_key(encoded) {
                    Ok(public_key) => {
                        assert!(accepted, "case {id}: expected rejection");
                        let expected_pub = B64
                            .decode(case["expected"]["public_key_b64"].as_str().expect("pub"))
                            .expect("decode expected public key");
                        assert_eq!(public_key.as_slice(), expected_pub.as_slice(), "case {id}");
                    }
                    Err(error) => {
                        assert!(!accepted, "case {id}: expected acceptance, got {error}");
                        assert_reason(id, &error, expected_reason(case));
                    }
                }
            }
            other => panic!("unknown did_key_vectors kind {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// signed_statements.json
// ---------------------------------------------------------------------------

fn statement_without_signature(statement: &Value) -> Value {
    let mut copy = statement.clone();
    copy.as_object_mut()
        .expect("statement object")
        .remove("signature_b64");
    copy
}

/// Reconstruct the canonical signing bytes independently from the fixture
/// statement JSON and require byte equality with the frozen vector.
fn assert_canonical_bytes(case: &Value) {
    let id = case["id"].as_str().expect("case id");
    let statement = &case["input"]["statement"];
    let expected = case["canonical_b64"].as_str().expect("canonical_b64");
    let reconstructed =
        canonical_bytes(&statement_without_signature(statement)).expect("canonical bytes");
    assert_eq!(
        B64.encode(&reconstructed),
        expected,
        "case {id}: independently reconstructed canonical bytes differ from the frozen vector"
    );
}

fn run_challenge_case(case: &Value) -> Result<(), TrustError> {
    let challenge = EnrollmentChallengeV1::from_value(&case["input"]["statement"])?;
    let validation = &case["input"]["validation"];
    // The parsed statement's own signing bytes must equal the frozen vector.
    assert_eq!(
        B64.encode(challenge.signing_bytes()?),
        case["canonical_b64"].as_str().expect("canonical_b64"),
        "parsed challenge signing bytes"
    );
    verify_enrollment_challenge(
        &challenge,
        &ChallengeExpectation {
            publisher_did: validation["expected_publisher_did"]
                .as_str()
                .expect("publisher")
                .to_string(),
            reader_did: validation["expected_reader_did"]
                .as_str()
                .expect("reader")
                .to_string(),
            ceremony_id: validation["expected_ceremony_id"]
                .as_str()
                .expect("ceremony")
                .to_string(),
            group: validation["expected_group"]
                .as_str()
                .expect("group")
                .to_string(),
            now: parse_time(validation["now"].as_str().expect("now")),
        },
    )
}

fn run_proof_case(document: &Value, case: &Value, purpose: &str) -> Result<(), TrustError> {
    let proof = KeyBindingProofV1::from_value(&case["input"]["statement"])?;
    let validation = &case["input"]["validation"];
    assert_eq!(
        B64.encode(proof.signing_bytes()?),
        case["canonical_b64"].as_str().expect("canonical_b64"),
        "parsed proof signing bytes"
    );
    // Receiver-side check: the party presenting this proof (the outer package
    // signer, in package flows) must be the proof subject.
    if let Some(expected_signer) = validation["expected_signer_did"].as_str() {
        ensure_expected_signer(expected_signer, &proof.subject_did)?;
    }
    let challenge_source = match purpose {
        "jwe-reader" => Some("valid_enrollment_challenge"),
        "hibe-reader" => Some("valid_hibe_reader_challenge"),
        _ => None,
    };
    let challenge = challenge_source.map(|source| {
        EnrollmentChallengeV1::from_value(&case_by_id(document, source)["input"]["statement"])
            .expect("companion challenge parses")
    });
    let expected = ProofExpectation {
        purpose: validation["expected_purpose"]
            .as_str()
            .expect("purpose")
            .to_string(),
        audience_did: validation["expected_audience_did"]
            .as_str()
            .expect("audience")
            .to_string(),
        ceremony_id: validation["expected_ceremony_id"]
            .as_str()
            .expect("ceremony")
            .to_string(),
        group: validation["expected_group"]
            .as_str()
            .expect("group")
            .to_string(),
        now: parse_time(validation["now"].as_str().expect("now")),
    };
    if purpose == "jwe-reader" {
        let binding = verify_jwe_key_binding(
            &proof,
            &expected.audience_did,
            &expected.ceremony_id,
            &expected.group,
            expected.now,
            challenge.as_ref(),
        )?;
        ensure_expected_reader_key(
            &binding,
            validation["expected_public_key_sha256"]
                .as_str()
                .expect("expected key sha"),
        )?;
        assert_eq!(
            binding.challenge_digest.as_deref(),
            validation["challenge_digest"].as_str(),
            "verified binding retains the challenge digest"
        );
        return Ok(());
    }
    let principal = verify_key_binding_proof(&proof, &expected, challenge.as_ref())?;
    assert_eq!(principal.did, proof.subject_did);
    assert_eq!(principal.purpose, purpose);
    if purpose == "hibe-authority" {
        let binding = hibe_authority_binding(&proof)?;
        let mpk = B64
            .decode(validation["expected_mpk_b64"].as_str().expect("mpk"))
            .expect("decode mpk");
        assert_eq!(
            binding.mpk_sha256,
            format!("sha256:{}", {
                use sha2::Digest as _;
                hex::encode(sha2::Sha256::digest(&mpk))
            }),
            "authority binding pins the exact fixture MPK bytes"
        );
    }
    Ok(())
}

fn run_response_case(case: &Value) -> Result<(), TrustError> {
    let response = EnrollmentResponseV1::from_value(&case["input"]["statement"])?;
    let validation = &case["input"]["validation"];
    assert_eq!(
        B64.encode(response.signing_bytes()?),
        case["canonical_b64"].as_str().expect("canonical_b64"),
        "parsed response signing bytes"
    );
    verify_enrollment_response(
        &response,
        &ResponseExpectation {
            publisher_did: validation["expected_publisher_did"]
                .as_str()
                .expect("publisher")
                .to_string(),
            reader_did: validation["expected_reader_did"]
                .as_str()
                .expect("reader")
                .to_string(),
            ceremony_id: validation["expected_ceremony_id"]
                .as_str()
                .expect("ceremony")
                .to_string(),
            group: validation["expected_group"]
                .as_str()
                .expect("group")
                .to_string(),
            offer_digest: validation["expected_offer_digest"]
                .as_str()
                .expect("offer digest")
                .to_string(),
            public_key_sha256: validation["expected_public_key_sha256"]
                .as_str()
                .expect("public key sha")
                .to_string(),
            now: parse_time(validation["now"].as_str().expect("now")),
        },
    )
}

#[test]
fn signed_statements_decide_exactly() {
    let document = fixture("signed_statements.json");
    for case in cases(&document) {
        let id = case["id"].as_str().expect("case id");
        assert_canonical_bytes(case);
        let accepted = case["expected"]["accepted"].as_bool().expect("accepted");
        let outcome = match case["kind"].as_str().expect("kind") {
            "EnrollmentChallengeV1" => run_challenge_case(case),
            "KeyBindingProofV1/jwe-reader" => run_proof_case(&document, case, "jwe-reader"),
            "KeyBindingProofV1/hibe-reader" => run_proof_case(&document, case, "hibe-reader"),
            "KeyBindingProofV1/hibe-authority" => run_proof_case(&document, case, "hibe-authority"),
            "EnrollmentResponseV1" => run_response_case(case),
            other => panic!("unknown signed_statements kind {other:?}"),
        };
        match outcome {
            Ok(()) => assert!(accepted, "case {id}: expected rejection, got acceptance"),
            Err(error) => {
                assert!(!accepted, "case {id}: expected acceptance, got {error}");
                assert_reason(id, &error, expected_reason(case));
            }
        }
    }
}

#[test]
fn statement_signing_round_trips_against_fixture_signatures() {
    // Ed25519 is deterministic: re-signing the canonical bytes with the
    // fixture seed must reproduce the frozen signature exactly.
    let vectors = fixture("did_key_vectors.json");
    let statements = fixture("signed_statements.json");
    let device = |role: &str| {
        let seed = B64
            .decode(
                case_by_id(&vectors, &format!("{role}_ed25519_did_key"))["input"]["seed_b64"]
                    .as_str()
                    .expect("seed"),
            )
            .expect("decode seed");
        DeviceKey::from_private_bytes(&seed).expect("device key")
    };

    let challenge = EnrollmentChallengeV1::from_value(
        &case_by_id(&statements, "valid_enrollment_challenge")["input"]["statement"],
    )
    .expect("challenge parses");
    let resigned = EnrollmentChallengeV1 {
        signature_b64: String::new(),
        ..challenge.clone()
    }
    .signed(&device("publisher"))
    .expect("sign challenge");
    assert_eq!(resigned.signature_b64, challenge.signature_b64);

    let wrong_signer = EnrollmentChallengeV1 {
        signature_b64: String::new(),
        ..challenge
    }
    .signed(&device("reader"))
    .expect_err("a non-publisher key cannot sign the challenge");
    assert_eq!(wrong_signer.reason, TrustReason::DidSignerMismatch);

    let proof = KeyBindingProofV1::from_value(
        &case_by_id(&statements, "valid_jwe_reader_proof")["input"]["statement"],
    )
    .expect("proof parses");
    let resigned = KeyBindingProofV1 {
        signature_b64: String::new(),
        ..proof.clone()
    }
    .signed(&device("reader"))
    .expect("sign proof");
    assert_eq!(resigned.signature_b64, proof.signature_b64);

    let response = EnrollmentResponseV1::from_value(
        &case_by_id(&statements, "valid_enrollment_response")["input"]["statement"],
    )
    .expect("response parses");
    let resigned = EnrollmentResponseV1 {
        signature_b64: String::new(),
        ..response.clone()
    }
    .signed(&device("publisher"))
    .expect("sign response");
    assert_eq!(resigned.signature_b64, response.signature_b64);
}

// ---------------------------------------------------------------------------
// state_transitions.json
// ---------------------------------------------------------------------------

#[test]
fn state_transitions_decide_exactly() {
    let document = fixture("state_transitions.json");
    for case in cases(&document) {
        let id = case["id"].as_str().expect("case id");
        let input = &case["input"];
        let expected = &case["expected"];
        let accepted = expected["accepted"].as_bool().expect("accepted");
        match input["operation"].as_str().expect("operation") {
            "consume_challenge" => {
                let outcome = classify_challenge_consumption(
                    input["consumed"].as_bool().expect("consumed"),
                    input["prior_artifact_digest"].as_str(),
                    input["artifact_digest"].as_str().expect("artifact"),
                );
                match outcome {
                    Ok(decision) => {
                        assert!(accepted, "case {id}: expected rejection");
                        assert_eq!(expected["next_state"].as_str(), Some("consumed"));
                        let idempotent = expected["idempotent"].as_bool().unwrap_or(false);
                        assert_eq!(
                            decision == ConsumeDecision::IdempotentReplay,
                            idempotent,
                            "case {id}: idempotence flag"
                        );
                    }
                    Err(error) => {
                        assert!(!accepted, "case {id}: expected acceptance, got {error}");
                        assert_reason(id, &error, expected_reason(case));
                    }
                }
            }
            "install_hibe_assertion" => {
                let outcome = classify_hibe_epoch(
                    input["current_epoch"].as_u64().expect("current epoch"),
                    input["current_mpk_sha256"].as_str().expect("current mpk"),
                    input["incoming_epoch"].as_u64().expect("incoming epoch"),
                    input["incoming_mpk_sha256"].as_str().expect("incoming mpk"),
                );
                match outcome {
                    Ok(decision) => {
                        assert!(accepted, "case {id}: expected rejection");
                        assert_eq!(
                            expected["next_epoch"].as_u64(),
                            input["incoming_epoch"].as_u64(),
                            "case {id}: accepted install lands on the incoming epoch"
                        );
                        let idempotent = expected["idempotent"].as_bool().unwrap_or(false);
                        assert_eq!(
                            decision == EpochDecision::Idempotent,
                            idempotent,
                            "case {id}: idempotence flag"
                        );
                    }
                    Err(error) => {
                        assert!(!accepted, "case {id}: expected acceptance, got {error}");
                        assert_reason(id, &error, expected_reason(case));
                    }
                }
            }
            other => panic!("unknown state transition operation {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Strictness beyond the frozen vectors
// ---------------------------------------------------------------------------

#[test]
fn unknown_fields_and_versions_fail_closed_for_every_statement() {
    let statements = fixture("signed_statements.json");
    for (case_id, kind) in [
        ("valid_enrollment_challenge", "challenge"),
        ("valid_jwe_reader_proof", "proof"),
        ("valid_enrollment_response", "response"),
    ] {
        let statement = case_by_id(&statements, case_id)["input"]["statement"].clone();

        let mut with_unknown = statement.clone();
        with_unknown
            .as_object_mut()
            .expect("object")
            .insert("unexpected".into(), Value::Bool(true));
        let mut with_version = statement.clone();
        with_version
            .as_object_mut()
            .expect("object")
            .insert("version".into(), Value::from(2));

        for mutated in [with_unknown, with_version] {
            let error = match kind {
                "challenge" => EnrollmentChallengeV1::from_value(&mutated).map(|_| ()),
                "proof" => KeyBindingProofV1::from_value(&mutated).map(|_| ()),
                _ => EnrollmentResponseV1::from_value(&mutated).map(|_| ()),
            }
            .expect_err("strict parser rejects unknown fields and versions");
            assert_eq!(error.reason, TrustReason::StatementInvalid, "{case_id}");
        }
    }
}

#[test]
fn trust_reasons_expose_the_exact_wire_strings() {
    let expected = [
        (TrustReason::StatementInvalid, "statement_invalid"),
        (TrustReason::StatementExpired, "statement_expired"),
        (TrustReason::SignatureInvalid, "signature_invalid"),
        (TrustReason::DidInvalid, "did_invalid"),
        (TrustReason::DidSignerMismatch, "did_signer_mismatch"),
        (
            TrustReason::OuterInnerSignerMismatch,
            "outer_inner_signer_mismatch",
        ),
        (TrustReason::WrongRecipient, "wrong_recipient"),
        (TrustReason::ScopeMismatch, "scope_mismatch"),
        (TrustReason::BodyDigestMismatch, "body_digest_mismatch"),
        (TrustReason::ChallengeMissing, "challenge_missing"),
        (TrustReason::ChallengeExpired, "challenge_expired"),
        (TrustReason::ChallengeReplayed, "challenge_replayed"),
        (TrustReason::ReplayConflict, "replay_conflict"),
        (TrustReason::BindingInvalid, "binding_invalid"),
        (TrustReason::UntrustedPrincipal, "untrusted_principal"),
        (TrustReason::EpochRollback, "epoch_rollback"),
        (TrustReason::EpochConflict, "epoch_conflict"),
    ];
    for (reason, wire) in expected {
        assert_eq!(reason.as_str(), wire);
        let error = TrustError::new(reason, "detail");
        assert_eq!(error.to_string(), format!("{wire}: detail"));
    }
}
