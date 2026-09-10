from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tn
from tn import admin
from tn import cipher as cipher_mod
from tn.cipher import HibeGroupCipher
from tn.key_binding import verify_key_binding_proof
from tn.signing import DeviceKey
from tn.trust import TrustError, TrustReason


@pytest.fixture(autouse=True)
def _reset_runtime():
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()


def _new_cfg(tmp_path: Path, name: str, *, cipher: str = "btn"):
    yaml_path = tmp_path / name / "tn.yaml"
    tn.init(yaml_path, log_path=tmp_path / name / "log.ndjson", cipher=cipher)
    cfg = tn.current_config()
    tn.flush_and_close()
    return cfg


def _authority_with_path(tmp_path: Path, *, path: str, max_depth: int):
    cfg = _new_cfg(tmp_path, "authority", cipher="hibe")
    cfg.groups["default"].cipher = HibeGroupCipher.create(
        cfg.keystore,
        "default",
        id_path=path,
        max_depth=max_depth,
    )
    return cfg


def _external_writer(
    cfg,
    *,
    mpk: bytes,
    path: str,
    ceremony_id: str,
) -> HibeGroupCipher:
    cfg.ceremony_id = ceremony_id
    cipher = HibeGroupCipher.create(
        cfg.keystore,
        "default",
        authority_mpk=mpk,
        id_path=path,
    )
    cfg.groups["default"].cipher = cipher
    return cipher


def test_authority_assertion_binds_real_did_mpk_depth_path_epoch_and_writer(
    tmp_path: Path,
) -> None:
    authority = _authority_with_path(
        tmp_path,
        path="org/fraud/case-17",
        max_depth=3,
    )
    writer = _new_cfg(tmp_path, "writer")

    assertion = admin.issue_authority_assertion(
        "default",
        audience_did=writer.device.device_identity,
        ttl=timedelta(minutes=5),
        cfg=authority,
    )

    cipher = authority.groups["default"].cipher
    assert assertion.purpose == "hibe-authority"
    assert assertion.subject_did == authority.device.device_identity
    assert assertion.audience_did == writer.device.device_identity
    assert assertion.ceremony_id == authority.ceremony_id
    assert assertion.group == "default"
    assert dict(assertion.binding) == {
        "algorithm": "TN-BBG-HIBE-BLS12-381",
        "mpk_sha256": "sha256:" + hashlib.sha256(cipher.mpk()).hexdigest(),
        "max_depth": 3,
        "id_path": "org/fraud/case-17",
        "path_epoch": 0,
    }
    principal = verify_key_binding_proof(
        assertion,
        expected_purpose="hibe-authority",
        expected_audience_did=writer.device.device_identity,
        expected_ceremony_id=authority.ceremony_id,
        expected_group="default",
        now=assertion.issued_at,
        challenge=None,
    )
    assert principal.did == authority.device.device_identity


def test_external_writer_requires_pin_and_stops_after_assertion_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority_with_path(
        tmp_path,
        path="org/fraud/case-17",
        max_depth=3,
    )
    writer = _new_cfg(tmp_path, "writer")
    authority_cipher = authority.groups["default"].cipher
    writer_cipher = _external_writer(
        writer,
        mpk=authority_cipher.mpk(),
        path="org/fraud/case-17",
        ceremony_id=authority.ceremony_id,
    )
    assertion = admin.issue_authority_assertion(
        "default",
        audience_did=writer.device.device_identity,
        ttl=timedelta(minutes=5),
        cfg=authority,
    )

    with pytest.raises(TrustError) as unpinned:
        writer_cipher.encrypt(b"before pin")
    assert unpinned.value.reason is TrustReason.UNTRUSTED_PRINCIPAL

    admin.install_authority_assertion(
        "default",
        mpk=authority_cipher.mpk(),
        assertion=assertion,
        expected_authority_did=authority.device.device_identity,
        cfg=writer,
        now=assertion.issued_at,
    )
    assert writer.groups["default"].cipher.encrypt(b"after pin")

    state = json.loads(
        (writer.keystore / "default.hibe.authority.json").read_text(encoding="utf-8")
    )
    assert state == {
        "version": 1,
        "authority_did": authority.device.device_identity,
        "audience_did": writer.device.device_identity,
        "mpk_sha256": assertion.binding["mpk_sha256"],
        "max_depth": 3,
        "id_path": "org/fraud/case-17",
        "path_epoch": 0,
        "assertion_digest": state["assertion_digest"],
        "expires_at": assertion.expires_at.isoformat().replace("+00:00", "Z"),
    }
    assert state["assertion_digest"].startswith("sha256:")
    assert not (writer.keystore / "default.hibe.msk").exists()

    monkeypatch.setattr(
        cipher_mod,
        "_utc_now",
        lambda: assertion.expires_at + timedelta(seconds=1),
    )
    with pytest.raises(TrustError, match="fresh authority assertion/update") as expired:
        writer.groups["default"].cipher.encrypt(b"after expiry")
    assert expired.value.reason is TrustReason.STATEMENT_EXPIRED


def test_install_rejects_wrong_authority_writer_signature_scope_mpk_and_depth(
    tmp_path: Path,
) -> None:
    authority = _authority_with_path(
        tmp_path,
        path="org/fraud/case-17",
        max_depth=3,
    )
    writer = _new_cfg(tmp_path, "writer")
    other_writer = _new_cfg(tmp_path, "other-writer")
    authority_cipher = authority.groups["default"].cipher
    _external_writer(
        writer,
        mpk=authority_cipher.mpk(),
        path="org/fraud/case-17",
        ceremony_id=authority.ceremony_id,
    )
    assertion = admin.issue_authority_assertion(
        "default",
        audience_did=writer.device.device_identity,
        cfg=authority,
    )

    cases: list[tuple[object, bytes, str, TrustReason]] = []
    cases.append(
        (
            assertion,
            authority_cipher.mpk(),
            DeviceKey.generate().device_identity,
            TrustReason.DID_SIGNER_MISMATCH,
        )
    )
    wrong_writer = admin.issue_authority_assertion(
        "default",
        audience_did=other_writer.device.device_identity,
        cfg=authority,
    )
    cases.append(
        (
            wrong_writer,
            authority_cipher.mpk(),
            authority.device.device_identity,
            TrustReason.WRONG_RECIPIENT,
        )
    )
    bad_signature = replace(
        assertion,
        signature_b64=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    cases.append(
        (
            bad_signature,
            authority_cipher.mpk(),
            authority.device.device_identity,
            TrustReason.SIGNATURE_INVALID,
        )
    )
    other_mpk, _ = tn._hibe.setup(3)
    cases.append(
        (
            assertion,
            other_mpk,
            authority.device.device_identity,
            TrustReason.BINDING_INVALID,
        )
    )
    wrong_depth_binding = dict(assertion.binding)
    wrong_depth_binding.update(max_depth=2, id_path="org/fraud")
    wrong_depth = replace(
        assertion,
        binding=wrong_depth_binding,
        signature_b64="",
    ).sign(authority.device)
    cases.append(
        (
            wrong_depth,
            authority_cipher.mpk(),
            authority.device.device_identity,
            TrustReason.BINDING_INVALID,
        )
    )
    wrong_scope = replace(
        assertion,
        group="other",
        signature_b64="",
    ).sign(authority.device)
    cases.append(
        (
            wrong_scope,
            authority_cipher.mpk(),
            authority.device.device_identity,
            TrustReason.SCOPE_MISMATCH,
        )
    )

    for candidate, mpk, expected_did, reason in cases:
        with pytest.raises(TrustError) as raised:
            admin.install_authority_assertion(
                "default",
                mpk=mpk,
                assertion=candidate,
                expected_authority_did=expected_did,
                cfg=writer,
                now=assertion.issued_at,
            )
        assert raised.value.reason is reason
        assert not (writer.keystore / "default.hibe.authority.json").exists()


@pytest.mark.parametrize(
    "invalid_path",
    [
        " org/fraud/case-17",
        "org/fraud /case-17",
        "org/fraud/case-17\n",
    ],
)
def test_install_rejects_signed_noncanonical_path_before_lock_or_write(
    tmp_path: Path,
    invalid_path: str,
) -> None:
    authority = _authority_with_path(tmp_path, path="org/fraud/case-17", max_depth=3)
    writer = _new_cfg(tmp_path, "writer")
    authority_cipher = authority.groups["default"].cipher
    _external_writer(
        writer,
        mpk=authority_cipher.mpk(),
        path="org/fraud/case-17",
        ceremony_id=authority.ceremony_id,
    )
    assertion = admin.issue_authority_assertion(
        "default",
        audience_did=writer.device.device_identity,
        cfg=authority,
    )
    malformed_binding = dict(assertion.binding)
    malformed_binding["id_path"] = invalid_path
    malformed = replace(
        assertion,
        binding=malformed_binding,
        signature_b64="",
    ).sign(authority.device)
    before = {
        path.relative_to(writer.keystore).as_posix(): path.read_bytes()
        for path in writer.keystore.rglob("*")
        if path.is_file()
    }

    with pytest.raises(TrustError) as raised:
        admin.install_authority_assertion(
            "default",
            mpk=authority_cipher.mpk(),
            assertion=malformed,
            expected_authority_did=authority.device.device_identity,
            cfg=writer,
            now=malformed.issued_at,
        )

    assert raised.value.reason is TrustReason.BINDING_INVALID
    after = {
        path.relative_to(writer.keystore).as_posix(): path.read_bytes()
        for path in writer.keystore.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_install_repairs_exact_repeat_allows_same_material_renewal_and_rejects_conflict_rollback(
    tmp_path: Path,
) -> None:
    authority = _authority_with_path(tmp_path, path="org/fraud/case-17", max_depth=3)
    writer = _new_cfg(tmp_path, "writer")
    authority_cipher = authority.groups["default"].cipher
    _external_writer(
        writer,
        mpk=authority_cipher.mpk(),
        path="org/fraud/case-17",
        ceremony_id=authority.ceremony_id,
    )
    initial = admin.issue_authority_assertion(
        "default",
        audience_did=writer.device.device_identity,
        cfg=authority,
    )

    kwargs = {
        "group": "default",
        "mpk": authority_cipher.mpk(),
        "expected_authority_did": authority.device.device_identity,
        "cfg": writer,
        "now": initial.issued_at,
    }
    admin.install_authority_assertion(assertion=initial, **kwargs)
    original_state = (writer.keystore / "default.hibe.authority.json").read_bytes()
    (writer.keystore / "default.hibe.idpath").write_text("tampered", encoding="utf-8")
    admin.install_authority_assertion(assertion=initial, **kwargs)
    assert (writer.keystore / "default.hibe.authority.json").read_bytes() == original_state
    assert (writer.keystore / "default.hibe.idpath").read_text(encoding="utf-8") == (
        "org/fraud/case-17"
    )

    renewed = admin.issue_authority_assertion(
        "default",
        audience_did=writer.device.device_identity,
        ttl=timedelta(minutes=20),
        cfg=authority,
        now=initial.expires_at + timedelta(seconds=1),
    )
    admin.install_authority_assertion(
        assertion=renewed,
        **{**kwargs, "now": renewed.issued_at},
    )
    renewed_state = json.loads(
        (writer.keystore / "default.hibe.authority.json").read_text(encoding="utf-8")
    )
    assert renewed_state["assertion_digest"] != json.loads(original_state)["assertion_digest"]
    assert renewed_state["expires_at"] == renewed.expires_at.isoformat().replace("+00:00", "Z")

    conflict_binding = dict(renewed.binding)
    conflict_binding["id_path"] = "org/fraud/case-conflict"
    conflicting = replace(
        renewed,
        binding=conflict_binding,
        signature_b64="",
    ).sign(authority.device)
    with pytest.raises(TrustError) as conflict:
        admin.install_authority_assertion(
            assertion=conflicting,
            **{**kwargs, "now": conflicting.issued_at},
        )
    assert conflict.value.reason is TrustReason.EPOCH_CONFLICT

    update = admin.rotate_hibe_path(
        "default",
        "org/fraud/case-18",
        audience_did=writer.device.device_identity,
        cfg=authority,
    )
    assert update.path_epoch == 1
    admin.install_authority_assertion(
        "default",
        mpk=authority.groups["default"].cipher.mpk(),
        assertion=update.assertion,
        expected_authority_did=authority.device.device_identity,
        cfg=writer,
        now=update.assertion.issued_at,
    )
    with pytest.raises(TrustError) as rollback:
        admin.install_authority_assertion(assertion=initial, **kwargs)
    assert rollback.value.reason is TrustReason.EPOCH_ROLLBACK


def test_scoped_hibe_reader_challenge_and_proof_use_reader_did_key(
    tmp_path: Path,
) -> None:
    authority = _new_cfg(tmp_path, "authority", cipher="hibe")
    reader = _new_cfg(tmp_path, "reader")

    challenge = admin.issue_hibe_reader_challenge(
        "default",
        reader.device.device_identity,
        cfg=authority,
    )
    now = datetime.now(UTC)
    proof = admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority.device.device_identity,
        cfg=reader,
        now=now,
    )

    assert proof.purpose == "hibe-reader"
    assert proof.subject_did == reader.device.device_identity
    assert proof.audience_did == authority.device.device_identity
    assert proof.ceremony_id == authority.ceremony_id
    assert proof.group == "default"
    assert proof.binding["algorithm"] == "Ed25519-did-key"
    assert proof.binding["delivery"] == "recipient-seal-v1"
    principal = verify_key_binding_proof(
        proof,
        expected_purpose="hibe-reader",
        expected_audience_did=authority.device.device_identity,
        expected_ceremony_id=authority.ceremony_id,
        expected_group="default",
        now=now,
        challenge=challenge,
    )
    assert principal.did == reader.device.device_identity


def test_reader_proof_rejects_attacker_signed_self_asserted_challenge(tmp_path: Path) -> None:
    authority = _new_cfg(tmp_path, "authority", cipher="hibe")
    attacker = _new_cfg(tmp_path, "attacker", cipher="hibe")
    reader = _new_cfg(tmp_path, "reader")
    attacker_challenge = admin.issue_hibe_reader_challenge(
        "default",
        reader.device.device_identity,
        cfg=attacker,
    )

    with pytest.raises(TrustError) as raised:
        admin.create_hibe_reader_proof(
            attacker_challenge,
            expected_authority_did=authority.device.device_identity,
            cfg=reader,
        )
    assert raised.value.reason is TrustReason.DID_SIGNER_MISMATCH


@pytest.mark.parametrize(
    "kwargs",
    [
        {"audience_did": "did:key:z6Mk-abbreviated"},
        {"ttl": timedelta(0)},
    ],
)
def test_rotate_validates_assertion_inputs_before_mutating(
    tmp_path: Path,
    kwargs: dict[str, object],
) -> None:
    authority = _new_cfg(tmp_path, "authority", cipher="hibe")
    cipher = authority.groups["default"].cipher
    original_path = cipher.id_path()
    original_epoch = cipher.path_epoch()

    with pytest.raises((TrustError, ValueError)):
        admin.rotate_hibe_path(
            "default",
            "policy-next",
            cfg=authority,
            **kwargs,
        )

    assert cipher.id_path() == original_path
    assert cipher.path_epoch() == original_epoch
