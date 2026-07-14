from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
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
from tn.trust import TrustError, TrustReason, parse_ed25519_did_key


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/trust/v1"


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _case(case_id: str) -> dict[str, object]:
    cases = _fixture("signed_statements.json")["cases"]
    return next(case for case in cases if case["id"] == case_id)


def _challenge_for(proof: KeyBindingProofV1) -> EnrollmentChallengeV1 | None:
    if proof.purpose == "hibe-authority":
        return None
    case_id = (
        "valid_enrollment_challenge"
        if proof.purpose == "jwe-reader"
        else "valid_hibe_reader_challenge"
    )
    return EnrollmentChallengeV1.from_dict(_case(case_id)["input"]["statement"])


def _verify_proof_fixture(case: dict[str, object]) -> None:
    statement = case["input"]["statement"]
    validation = case["input"]["validation"]
    proof = KeyBindingProofV1.from_dict(statement)

    if proof.subject_did != validation["expected_signer_did"]:
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "proof subject does not match the expected signer",
        )

    challenge = _challenge_for(proof)
    principal = verify_key_binding_proof(
        proof,
        expected_purpose=validation["expected_purpose"],
        expected_audience_did=validation["expected_audience_did"],
        expected_ceremony_id=validation["expected_ceremony_id"],
        expected_group=validation["expected_group"],
        now=_utc(validation["now"]),
        challenge=challenge,
    )
    assert principal.did == proof.subject_did

    if proof.purpose == "jwe-reader":
        binding = verify_jwe_key_binding(
            proof,
            expected_audience_did=validation["expected_audience_did"],
            expected_ceremony_id=validation["expected_ceremony_id"],
            expected_group=validation["expected_group"],
            now=_utc(validation["now"]),
            challenge=challenge,
        )
        if binding.public_key_sha256 != validation["expected_public_key_sha256"]:
            raise TrustError(
                TrustReason.BINDING_INVALID,
                "X25519 public key digest does not match the expected binding",
            )
    elif proof.purpose == "hibe-authority":
        try:
            mpk = base64.b64decode(validation["expected_mpk_b64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise TrustError(TrustReason.BINDING_INVALID, "expected MPK is not base64") from exc
        expected_mpk_digest = "sha256:" + hashlib.sha256(mpk).hexdigest()
        if len(mpk) != 96 or proof.binding["mpk_sha256"] != expected_mpk_digest:
            raise TrustError(
                TrustReason.BINDING_INVALID,
                "HIBE MPK does not match the authority proof binding",
            )


def test_strict_ed25519_did_key_vectors() -> None:
    for case in _fixture("did_key_vectors.json")["cases"]:
        if case["kind"] != "ed25519-did-key":
            continue
        if case["expected"]["valid"]:
            assert parse_ed25519_did_key(case["input"]["did"]) == base64.b64decode(
                case["expected"]["public_key_b64"],
                validate=True,
            )
        else:
            with pytest.raises(TrustError) as raised:
                parse_ed25519_did_key(case["input"]["did"])
            assert raised.value.reason is TrustReason.DID_INVALID


@pytest.mark.parametrize(
    "case_id",
    ["valid_enrollment_challenge", "valid_hibe_reader_challenge"],
)
def test_accepted_challenge_vectors_have_exact_signing_bytes_and_verify(case_id: str) -> None:
    case = _case(case_id)
    challenge = EnrollmentChallengeV1.from_dict(case["input"]["statement"])
    assert challenge.signing_bytes() == base64.b64decode(case["canonical_b64"], validate=True)

    validation = case["input"]["validation"]
    verify_enrollment_challenge(
        challenge,
        expected_publisher_did=validation["expected_publisher_did"],
        expected_reader_did=validation["expected_reader_did"],
        expected_ceremony_id=validation["expected_ceremony_id"],
        expected_group=validation["expected_group"],
        now=_utc(validation["now"]),
    )


@pytest.mark.parametrize(
    ("case_id", "reason"),
    [
        ("challenge_unknown_field", TrustReason.STATEMENT_INVALID),
        ("challenge_unsupported_version", TrustReason.STATEMENT_INVALID),
        ("challenge_expired_statement", TrustReason.STATEMENT_EXPIRED),
        ("challenge_signature_mutated", TrustReason.SIGNATURE_INVALID),
    ],
)
def test_rejected_challenge_vectors_map_to_stable_reasons(
    case_id: str,
    reason: TrustReason,
) -> None:
    case = _case(case_id)
    validation = case["input"]["validation"]
    with pytest.raises(TrustError) as raised:
        challenge = EnrollmentChallengeV1.from_dict(case["input"]["statement"])
        verify_enrollment_challenge(
            challenge,
            expected_publisher_did=validation["expected_publisher_did"],
            expected_reader_did=validation["expected_reader_did"],
            expected_ceremony_id=validation["expected_ceremony_id"],
            expected_group=validation["expected_group"],
            now=_utc(validation["now"]),
        )
    assert raised.value.reason is reason


@pytest.mark.parametrize(
    "case_id",
    ["valid_jwe_reader_proof", "valid_hibe_reader_proof", "valid_hibe_authority_proof"],
)
def test_accepted_proof_vectors_have_exact_signing_bytes_and_verify(case_id: str) -> None:
    case = _case(case_id)
    proof = KeyBindingProofV1.from_dict(case["input"]["statement"])
    assert proof.signing_bytes() == base64.b64decode(case["canonical_b64"], validate=True)
    _verify_proof_fixture(case)


@pytest.mark.parametrize(
    ("case_id", "reason"),
    [
        ("jwe_proof_signer_did_mismatch", TrustReason.DID_SIGNER_MISMATCH),
        ("jwe_proof_wrong_recipient", TrustReason.WRONG_RECIPIENT),
        ("jwe_proof_scope_mismatch", TrustReason.SCOPE_MISMATCH),
        ("jwe_proof_binding_mismatch", TrustReason.BINDING_INVALID),
    ],
)
def test_rejected_proof_vectors_map_to_stable_reasons(
    case_id: str,
    reason: TrustReason,
) -> None:
    with pytest.raises(TrustError) as raised:
        _verify_proof_fixture(_case(case_id))
    assert raised.value.reason is reason


def test_hibe_authority_proof_binds_the_expected_mpk_bytes() -> None:
    case = json.loads(json.dumps(_case("valid_hibe_authority_proof")))
    case["input"]["validation"]["expected_mpk_b64"] = base64.b64encode(bytes(96)).decode("ascii")
    with pytest.raises(TrustError) as raised:
        _verify_proof_fixture(case)
    assert raised.value.reason is TrustReason.BINDING_INVALID


def test_valid_enrollment_response_has_exact_signing_bytes_and_verifies() -> None:
    case = _case("valid_enrollment_response")
    response = EnrollmentResponseV1.from_dict(case["input"]["statement"])
    assert response.signing_bytes() == base64.b64decode(case["canonical_b64"], validate=True)

    validation = case["input"]["validation"]
    verify_enrollment_response(
        response,
        expected_publisher_did=validation["expected_publisher_did"],
        expected_reader_did=validation["expected_reader_did"],
        expected_ceremony_id=validation["expected_ceremony_id"],
        expected_group=validation["expected_group"],
        expected_offer_digest=validation["expected_offer_digest"],
        expected_public_key_sha256=validation["expected_public_key_sha256"],
        now=_utc(validation["now"]),
    )


def test_reader_proof_requires_a_verified_challenge() -> None:
    case = _case("valid_jwe_reader_proof")
    proof = KeyBindingProofV1.from_dict(case["input"]["statement"])
    validation = case["input"]["validation"]

    with pytest.raises(TrustError) as raised:
        verify_key_binding_proof(
            proof,
            expected_purpose="jwe-reader",
            expected_audience_did=validation["expected_audience_did"],
            expected_ceremony_id=validation["expected_ceremony_id"],
            expected_group=validation["expected_group"],
            now=_utc(validation["now"]),
            challenge=None,
        )
    assert raised.value.reason is TrustReason.CHALLENGE_MISSING
