from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tn.key_binding import (
    EnrollmentChallengeV1,
    EnrollmentResponseV1,
    KeyBindingProofV1,
    verify_enrollment_challenge,
    verify_enrollment_response,
    verify_jwe_key_binding,
    verify_key_binding_proof,
)
from tn.signing import DeviceKey
from tn.trust import TrustError, TrustReason


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/trust/v1"


def _cases() -> dict[str, dict[str, object]]:
    document = json.loads((FIXTURES / "signed_statements.json").read_text(encoding="utf-8"))
    return {case["id"]: case for case in document["cases"]}


def _device(role: str) -> DeviceKey:
    document = json.loads((FIXTURES / "did_key_vectors.json").read_text(encoding="utf-8"))
    case = next(case for case in document["cases"] if case["id"] == f"{role}_ed25519_did_key")
    return DeviceKey.from_private_bytes(base64.b64decode(case["input"]["seed_b64"], validate=True))


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@pytest.mark.parametrize(
    ("case_id", "parser"),
    [
        ("valid_enrollment_challenge", EnrollmentChallengeV1.from_dict),
        ("valid_jwe_reader_proof", KeyBindingProofV1.from_dict),
        ("valid_enrollment_response", EnrollmentResponseV1.from_dict),
    ],
)
def test_statement_parsers_reject_unknown_fields_and_versions(case_id: str, parser: object) -> None:
    statement = dict(_cases()[case_id]["input"]["statement"])
    statement["unexpected"] = True
    with pytest.raises(TrustError) as raised:
        parser(statement)
    assert raised.value.reason is TrustReason.STATEMENT_INVALID

    statement.pop("unexpected")
    statement["version"] = 2
    with pytest.raises(TrustError) as raised:
        parser(statement)
    assert raised.value.reason is TrustReason.STATEMENT_INVALID


@pytest.mark.parametrize(
    ("case_id", "parser"),
    [
        ("valid_enrollment_challenge", EnrollmentChallengeV1.from_dict),
        ("valid_jwe_reader_proof", KeyBindingProofV1.from_dict),
        ("valid_enrollment_response", EnrollmentResponseV1.from_dict),
    ],
)
@pytest.mark.parametrize("invalid_version", [True, 1.0])
def test_direct_value_objects_require_an_exact_integer_version(
    case_id: str,
    parser: object,
    invalid_version: object,
) -> None:
    statement = parser(_cases()[case_id]["input"]["statement"])
    with pytest.raises(TrustError) as raised:
        replace(statement, version=invalid_version).signing_bytes()
    assert raised.value.reason is TrustReason.STATEMENT_INVALID


@pytest.mark.parametrize(
    ("case_id", "mutation"),
    [
        ("valid_jwe_reader_proof", {"algorithm": "Ed25519-did-key"}),
        ("valid_jwe_reader_proof", {"public_key_b64": base64.b64encode(bytes(31)).decode()}),
        ("valid_hibe_reader_proof", {"delivery": "plaintext"}),
        ("valid_hibe_authority_proof", {"max_depth": 0}),
    ],
)
def test_proof_parser_rejects_purpose_specific_binding_errors(
    case_id: str,
    mutation: dict[str, object],
) -> None:
    statement = dict(_cases()[case_id]["input"]["statement"])
    statement["binding"] = {**statement["binding"], **mutation}
    with pytest.raises(TrustError) as raised:
        KeyBindingProofV1.from_dict(statement)
    assert raised.value.reason is TrustReason.BINDING_INVALID


def test_proof_parser_rejects_extra_binding_fields() -> None:
    statement = dict(_cases()["valid_jwe_reader_proof"]["input"]["statement"])
    statement["binding"] = {**statement["binding"], "extra": True}
    with pytest.raises(TrustError) as raised:
        KeyBindingProofV1.from_dict(statement)
    assert raised.value.reason is TrustReason.BINDING_INVALID


def test_proof_binding_is_a_defensive_immutable_snapshot() -> None:
    statement = dict(_cases()["valid_jwe_reader_proof"]["input"]["statement"])
    source_binding = dict(statement["binding"])
    statement["binding"] = source_binding
    proof = KeyBindingProofV1.from_dict(statement)
    original_public_key = proof.binding["public_key_b64"]

    source_binding["public_key_b64"] = base64.b64encode(bytes(32)).decode("ascii")
    assert proof.binding["public_key_b64"] == original_public_key
    with pytest.raises(TypeError):
        proof.binding["public_key_b64"] = base64.b64encode(bytes(32)).decode("ascii")

    replacement_source = dict(proof.binding)
    replacement = replace(proof, binding=replacement_source)
    replacement_source["public_key_b64"] = base64.b64encode(bytes(32)).decode("ascii")
    assert replacement.binding["public_key_b64"] == original_public_key


def test_time_fields_must_be_utc_ordered_and_fresh() -> None:
    statement = dict(_cases()["valid_enrollment_challenge"]["input"]["statement"])
    statement["expires_at"] = statement["issued_at"]
    with pytest.raises(TrustError) as raised:
        EnrollmentChallengeV1.from_dict(statement)
    assert raised.value.reason is TrustReason.STATEMENT_INVALID

    challenge = EnrollmentChallengeV1.from_dict(
        _cases()["valid_enrollment_challenge"]["input"]["statement"]
    )
    with pytest.raises(TrustError) as raised:
        verify_enrollment_challenge(
            challenge,
            expected_publisher_did=challenge.publisher_did,
            expected_reader_did=challenge.expected_reader_did,
            expected_ceremony_id=challenge.ceremony_id,
            expected_group=challenge.group,
            now=challenge.issued_at - timedelta(seconds=1),
        )
    assert raised.value.reason is TrustReason.STATEMENT_INVALID

    with pytest.raises(TrustError) as raised:
        verify_enrollment_challenge(
            challenge,
            expected_publisher_did=challenge.publisher_did,
            expected_reader_did=challenge.expected_reader_did,
            expected_ceremony_id=challenge.ceremony_id,
            expected_group=challenge.group,
            now=datetime.now(),
        )
    assert raised.value.reason is TrustReason.STATEMENT_INVALID


def test_sign_methods_replace_signature_and_enforce_signer_did() -> None:
    cases = _cases()
    publisher = _device("publisher")
    reader = _device("reader")

    challenge = EnrollmentChallengeV1.from_dict(
        cases["valid_enrollment_challenge"]["input"]["statement"]
    )
    unsigned_challenge = replace(challenge, signature_b64="")
    assert unsigned_challenge.sign(publisher).signature_b64 == challenge.signature_b64
    with pytest.raises(TrustError) as raised:
        unsigned_challenge.sign(reader)
    assert raised.value.reason is TrustReason.DID_SIGNER_MISMATCH

    proof = KeyBindingProofV1.from_dict(cases["valid_jwe_reader_proof"]["input"]["statement"])
    validation = cases["valid_enrollment_challenge"]["input"]["validation"]
    verify_enrollment_challenge(
        challenge,
        expected_publisher_did=validation["expected_publisher_did"],
        expected_reader_did=validation["expected_reader_did"],
        expected_ceremony_id=validation["expected_ceremony_id"],
        expected_group=validation["expected_group"],
        now=_utc(validation["now"]),
    )
    assert replace(proof, signature_b64="").sign(reader).signature_b64 == proof.signature_b64

    response = EnrollmentResponseV1.from_dict(
        cases["valid_enrollment_response"]["input"]["statement"]
    )
    assert (
        replace(response, signature_b64="").sign(publisher).signature_b64 == response.signature_b64
    )


def test_challenge_signature_is_checked_before_reader_proof_is_accepted() -> None:
    cases = _cases()
    proof = KeyBindingProofV1.from_dict(cases["valid_jwe_reader_proof"]["input"]["statement"])
    challenge_statement = dict(cases["valid_enrollment_challenge"]["input"]["statement"])
    challenge_statement["signature_b64"] = base64.b64encode(bytes(64)).decode("ascii")
    challenge = EnrollmentChallengeV1.from_dict(challenge_statement)
    validation = cases["valid_jwe_reader_proof"]["input"]["validation"]

    with pytest.raises(TrustError) as raised:
        verify_key_binding_proof(
            proof,
            expected_purpose="jwe-reader",
            expected_audience_did=validation["expected_audience_did"],
            expected_ceremony_id=validation["expected_ceremony_id"],
            expected_group=validation["expected_group"],
            now=_utc(validation["now"]),
            challenge=challenge,
        )
    assert raised.value.reason is TrustReason.SIGNATURE_INVALID


def test_jwe_binding_returns_verified_key_and_digests() -> None:
    cases = _cases()
    proof = KeyBindingProofV1.from_dict(cases["valid_jwe_reader_proof"]["input"]["statement"])
    challenge = EnrollmentChallengeV1.from_dict(
        cases["valid_enrollment_challenge"]["input"]["statement"]
    )
    validation = cases["valid_jwe_reader_proof"]["input"]["validation"]
    binding = verify_jwe_key_binding(
        proof,
        expected_audience_did=validation["expected_audience_did"],
        expected_ceremony_id=validation["expected_ceremony_id"],
        expected_group=validation["expected_group"],
        now=_utc(validation["now"]),
        challenge=challenge,
    )
    assert len(binding.public_key) == 32
    assert binding.public_key_sha256 == validation["expected_public_key_sha256"]
    assert binding.proof_digest.startswith("sha256:")
    assert binding.challenge_digest == validation["challenge_digest"]


def test_response_mismatches_have_stable_reasons() -> None:
    case = _cases()["valid_enrollment_response"]
    response = EnrollmentResponseV1.from_dict(case["input"]["statement"])
    validation = case["input"]["validation"]
    common = {
        "response": response,
        "expected_publisher_did": validation["expected_publisher_did"],
        "expected_reader_did": validation["expected_reader_did"],
        "expected_ceremony_id": validation["expected_ceremony_id"],
        "expected_group": validation["expected_group"],
        "expected_offer_digest": validation["expected_offer_digest"],
        "expected_public_key_sha256": validation["expected_public_key_sha256"],
        "now": _utc(validation["now"]),
    }
    verify_enrollment_response(**common)

    with pytest.raises(TrustError) as raised:
        verify_enrollment_response(**{**common, "expected_reader_did": _device("authority").did})
    assert raised.value.reason is TrustReason.WRONG_RECIPIENT

    with pytest.raises(TrustError) as raised:
        verify_enrollment_response(**{**common, "expected_public_key_sha256": "sha256:" + "0" * 64})
    assert raised.value.reason is TrustReason.BINDING_INVALID


def test_device_key_verify_remains_boolean_for_legacy_and_malformed_inputs() -> None:
    key = _device("publisher")
    message = b"legacy DeviceKey.verify contract"
    signature = key.sign(message)
    assert DeviceKey.verify(key.did, message, signature) is True
    assert DeviceKey.verify(key.did, message + b"!", signature) is False
    assert DeviceKey.verify("did:key:z0OIl", message, signature) is False
    assert DeviceKey.verify("not-a-did", message, signature) is False
