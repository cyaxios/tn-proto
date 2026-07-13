from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests/fixtures/trust/v1"
FIXTURE_NAMES = {
    "did_key_vectors.json",
    "enrollment_lifecycle.json",
    "package_body_index.json",
    "read_cursor_vectors.json",
    "read_policy_matrix.json",
    "signed_statements.json",
    "state_transitions.json",
    "unsafe_operation_event.json",
}
APPROVED_REASONS = {
    "statement_invalid",
    "statement_expired",
    "signature_invalid",
    "did_invalid",
    "did_signer_mismatch",
    "outer_inner_signer_mismatch",
    "wrong_recipient",
    "scope_mismatch",
    "body_digest_mismatch",
    "challenge_missing",
    "challenge_expired",
    "challenge_replayed",
    "replay_conflict",
    "binding_invalid",
    "untrusted_principal",
    "epoch_rollback",
    "epoch_conflict",
    "record_invalid",
    "row_hash_invalid",
    "chain_invalid",
    "signature_required",
    "writer_untrusted",
    "aad_invalid",
    "not_a_recipient",
}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _leaf_differences(left: Any, right: Any) -> int:
    if isinstance(left, dict) and isinstance(right, dict):
        keys = set(left) | set(right)
        return sum(
            1 if key not in left or key not in right else _leaf_differences(left[key], right[key])
            for key in keys
        )
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return 1
        return sum(_leaf_differences(a, b) for a, b in zip(left, right, strict=True))
    return int(left != right)


def test_checked_in_trust_vectors_are_deterministic() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools/fixtures/build_trust_v1.py"), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_fixture_set_uses_one_canonical_envelope() -> None:
    assert {path.name for path in FIXTURE_ROOT.glob("*.json")} == FIXTURE_NAMES

    for path in sorted(FIXTURE_ROOT.glob("*.json")):
        raw = path.read_bytes()
        document = json.loads(raw)
        assert raw == _canonical_bytes(document) + b"\n"
        assert document["schema"] == "tn.trust-fixtures/v1"
        assert document["canonicalization"] == "tn-canonical-json-v1"
        assert document["fixture"] == path.stem
        assert document["cases"]


def test_every_negative_vector_has_one_approved_reason_and_one_mutation() -> None:
    for path in sorted(FIXTURE_ROOT.glob("*.json")):
        cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
        by_id = {case["id"]: case for case in cases}
        assert len(by_id) == len(cases)

        for case in cases:
            expected = case["expected"]
            reasons = expected.get("reasons", [expected.get("reason")])
            assert all(reason is None or reason in APPROVED_REASONS for reason in reasons)
            if expected.get("accepted", expected.get("valid", True)):
                continue

            if path.name == "read_policy_matrix.json":
                assert "reasons" in expected and "reason" not in expected
            else:
                assert "reason" in expected and "reasons" not in expected

            baseline_id = case.get("baseline")
            assert baseline_id in by_id, f"{path.name}:{case['id']} has no baseline"
            case_input = case["input"]
            baseline_input = by_id[baseline_id]["input"]
            if (
                path.name == "signed_statements.json"
                and expected.get("reason") != "signature_invalid"
            ):
                case_input = json.loads(json.dumps(case_input))
                baseline_input = json.loads(json.dumps(baseline_input))
                case_input["statement"].pop("signature_b64")
                baseline_input["statement"].pop("signature_b64")
            assert _leaf_differences(case_input, baseline_input) == 1, (
                f"{path.name}:{case['id']} must change exactly one input property"
            )


def test_signed_statement_vectors_are_real_ed25519_signatures() -> None:
    document = json.loads(
        (FIXTURE_ROOT / "signed_statements.json").read_text(encoding="utf-8"),
    )
    cases = document["cases"]
    positive_kinds = {case["kind"] for case in cases if case["expected"]["accepted"] is True}
    assert positive_kinds == {
        "EnrollmentChallengeV1",
        "EnrollmentResponseV1",
        "KeyBindingProofV1/hibe-authority",
        "KeyBindingProofV1/hibe-reader",
        "KeyBindingProofV1/jwe-reader",
    }
    accepted_challenge_publishers = {
        case["input"]["statement"]["publisher_did"]
        for case in cases
        if case["expected"]["accepted"] and case["kind"] == "EnrollmentChallengeV1"
    }
    reader_proof_audiences = {
        case["input"]["statement"]["audience_did"]
        for case in cases
        if case["expected"]["accepted"]
        and case["kind"] in {"KeyBindingProofV1/jwe-reader", "KeyBindingProofV1/hibe-reader"}
    }
    assert reader_proof_audiences == accepted_challenge_publishers

    for case in cases:
        statement = case["input"]["statement"]
        signing_value = dict(statement)
        signature = base64.b64decode(signing_value.pop("signature_b64"), validate=True)
        canonical = _canonical_bytes(signing_value)
        assert base64.b64decode(case["canonical_b64"], validate=True) == canonical
        public_key = base64.b64decode(case["signer_public_key_b64"], validate=True)
        verifier = Ed25519PublicKey.from_public_bytes(public_key)
        if case["expected"].get("reason") == "signature_invalid":
            with pytest.raises(InvalidSignature):
                verifier.verify(signature, canonical)
            continue
        verifier.verify(signature, canonical)


def test_manifest_vectors_use_exact_body_index_and_signing_domain() -> None:
    cases = json.loads(
        (FIXTURE_ROOT / "package_body_index.json").read_text(encoding="utf-8"),
    )["cases"]
    for case in cases:
        manifest = json.loads(
            base64.b64decode(case["input"]["manifest_b64"], validate=True),
        )
        signing_value = dict(manifest)
        signature = base64.b64decode(
            signing_value.pop("manifest_signature_b64"),
            validate=True,
        )
        canonical = _canonical_bytes(signing_value)
        assert base64.b64decode(case["canonical_b64"], validate=True) == canonical
        public_key = base64.b64decode(case["signer_public_key_b64"], validate=True)
        verifier = Ed25519PublicKey.from_public_bytes(public_key)
        if case["expected"].get("reason") == "signature_invalid":
            with pytest.raises(InvalidSignature):
                verifier.verify(signature, canonical)
            continue
        verifier.verify(signature, canonical)
        if not case["expected"]["accepted"]:
            continue
        body_members = {
            path: base64.b64decode(value, validate=True)
            for path, value in case["input"]["body_members_b64"].items()
        }
        assert manifest["body_sha256"] == {
            path: "sha256:" + hashlib.sha256(value).hexdigest()
            for path, value in body_members.items()
        }


def test_check_reports_extra_stale_fixture_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = ROOT / "tools/fixtures/build_trust_v1.py"
    spec = importlib.util.spec_from_file_location("build_trust_v1_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    output_root = tmp_path / "tests/fixtures/trust/v1"
    output_root.mkdir(parents=True)
    expected_path = output_root / "expected.json"
    stale_path = output_root / "stale.json"
    expected_path.write_bytes(b"expected\n")
    stale_path.write_bytes(b"stale\n")
    module.ROOT = tmp_path
    module.OUTPUT_ROOT = output_root

    assert module._check({expected_path: b"expected\n"}) == 1
    assert stale_path.read_bytes() == b"stale\n"
    assert "tests/fixtures/trust/v1/stale.json" in capsys.readouterr().err


def test_vectors_cover_downstream_enrollment_and_read_contracts() -> None:
    lifecycle = json.loads(
        (FIXTURE_ROOT / "enrollment_lifecycle.json").read_text(encoding="utf-8"),
    )
    assert {case["phase"] for case in lifecycle["cases"]} >= {
        "challenge",
        "offer",
        "approval",
        "response",
        "first_decrypt",
    }

    transitions = json.loads(
        (FIXTURE_ROOT / "state_transitions.json").read_text(encoding="utf-8"),
    )
    reasons = {
        case["expected"].get("reason")
        for case in transitions["cases"]
        if not case["expected"]["accepted"]
    }
    assert {"challenge_replayed", "replay_conflict", "epoch_rollback", "epoch_conflict"} <= reasons

    read_cases = json.loads(
        (FIXTURE_ROOT / "read_policy_matrix.json").read_text(encoding="utf-8"),
    )["cases"]
    assert {
        case["input"]["policy"]["verify"]
        for case in read_cases
        if isinstance(case["input"]["policy"]["verify"], str)
        and not case["expected"].get("parameter_error")
    } == {
        "auto",
        "raise",
        "skip",
    }
    for case in read_cases:
        if case["expected"].get("parameter_error"):
            continue
        verify = case["input"]["policy"]["verify"]
        expected_mode = {
            "auto": "raise",
            "raise": "raise",
            "skip": "skip",
            True: "raise",
            False: "disabled",
        }[verify]
        assert case["expected"]["resolved_mode"] == expected_mode
    read_reasons = {reason for case in read_cases for reason in case["expected"].get("reasons", [])}
    assert {
        "record_invalid",
        "row_hash_invalid",
        "chain_invalid",
        "signature_required",
        "signature_invalid",
        "writer_untrusted",
        "aad_invalid",
        "not_a_recipient",
    } <= read_reasons
    read_by_id = {case["id"]: case for case in read_cases}
    assert read_by_id["true_local_signed"]["input"]["policy"]["verify"] is True
    assert read_by_id["true_local_signed"]["expected"]["accepted"] is True
    assert read_by_id["true_local_signed"]["expected"]["resolved_mode"] == "raise"
    string_disabled = read_by_id["string_disabled_parameter_error"]
    assert string_disabled["input"]["policy"]["verify"] == "disabled"
    assert string_disabled["expected"]["accepted"] is False
    assert string_disabled["expected"]["parameter_error"] is True
    assert "resolved_mode" not in string_disabled["expected"]
    assert read_by_id["disabled_ignores_unknown_writer"]["expected"] == {
        "accepted": True,
        "reasons": ["writer_untrusted"],
        "resolved_mode": "disabled",
        "writer_authenticated": False,
        "writer_authorized": False,
    }
    assert read_by_id["explicit_foreign_unsigned"]["expected"]["accepted"] is True
    assert read_by_id["explicit_foreign_unsigned"]["expected"]["writer_authenticated"] is False
    assert read_by_id["explicit_foreign_unsigned"]["expected"]["writer_authorized"] is False
    assert read_by_id["auto_local_profile_unsigned"]["expected"]["writer_authorized"] is False
    assert read_by_id["explicit_allow_unknown_writer"]["expected"]["accepted"] is True
    assert read_by_id["explicit_allow_unknown_writer"]["expected"]["writer_authorized"] is False
    for case_id in ("row_hash_invalid", "chain_invalid", "row_then_chain_invalid"):
        assert read_by_id[case_id]["expected"]["writer_authorized"] is False
    assert read_by_id["row_hash_absent_not_required"]["expected"]["accepted"] is True
    assert read_by_id["chain_disabled"]["expected"]["accepted"] is True
    assert read_by_id["explicit_trusted_writers_override"]["expected"]["accepted"] is True

    offer_case = next(
        case for case in lifecycle["cases"] if case["id"] == "absorb_authenticated_offer"
    )
    offer_bytes = base64.b64decode(offer_case["input"]["tnpkg_b64"], validate=True)
    with zipfile.ZipFile(io.BytesIO(offer_bytes)) as archive:
        assert set(archive.namelist()) == {
            "manifest.json",
            "body/metadata.json",
            "body/package.json",
        }
        manifest = json.loads(archive.read("manifest.json"))
        package_body = json.loads(archive.read("body/package.json"))
        assert package_body["package_kind"] == "offer"
        assert package_body["payload"]["key_binding_proof"]["purpose"] == "jwe-reader"
        assert manifest["body_sha256"] == {
            name: "sha256:" + hashlib.sha256(archive.read(name)).hexdigest()
            for name in ("body/metadata.json", "body/package.json")
        }
    assert (
        not {
            "binding_valid",
            "body_digest_valid",
            "inner_subject_did",
            "outer_signer_did",
            "signature_signer_did",
        }
        & offer_case["input"].keys()
    )

    decrypt_case = next(
        case
        for case in lifecycle["cases"]
        if case["id"] == "first_decrypt_with_retained_reader_key"
    )
    from tn.cipher import _jwe_open

    reader_private = X25519PrivateKey.from_private_bytes(
        base64.b64decode(decrypt_case["input"]["reader_private_seed_b64"], validate=True),
    )
    plaintext = _jwe_open(
        base64.b64decode(decrypt_case["input"]["jwe_b64"], validate=True),
        reader_private,
        base64.b64decode(decrypt_case["input"]["aad_b64"], validate=True),
    )
    assert plaintext == base64.b64decode(
        decrypt_case["expected"]["plaintext_b64"],
        validate=True,
    )

    cursors = json.loads(
        (FIXTURE_ROOT / "read_cursor_vectors.json").read_text(encoding="utf-8"),
    )["cases"]
    assert {case["source_kind"] for case in cursors} >= {
        "detached",
        "file-posix",
        "file-windows",
        "handler",
        "multi-source",
    }

    unsafe_cases = json.loads(
        (FIXTURE_ROOT / "unsafe_operation_event.json").read_text(encoding="utf-8"),
    )["cases"]
    accepted_notices = [
        case["expected"].get("normalized", case["input"])
        for case in unsafe_cases
        if case["expected"]["accepted"]
    ]
    assert {notice["operation"] for notice in accepted_notices} == {
        "read",
        "watch",
        "jwe_add_recipient",
        "hibe_grant",
        "legacy_package_import",
    }
    assert {relaxation for notice in accepted_notices for relaxation in notice["relaxations"]} == {
        "verification_disabled",
        "signature_not_required",
        "unauthenticated_allowed",
        "unknown_writer_allowed",
        "unverified_key_binding",
        "plaintext_bearer_delivery",
        "legacy_signer_mismatch",
    }
