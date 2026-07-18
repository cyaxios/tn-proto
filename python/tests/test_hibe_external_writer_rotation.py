from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

import tn
from tn import admin
from tn.cipher import HibeGroupCipher
from tn.trust import TrustError, TrustReason


@pytest.fixture(autouse=True)
def _reset_runtime():
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _new_cfg(tmp_path: Path, name: str, *, cipher: str = "btn"):
    tn.init(
        tmp_path / name / "tn.yaml",
        log_path=tmp_path / name / "log.ndjson",
        cipher=cipher,
    )
    cfg = tn.current_config()
    tn.flush_and_close()
    return cfg


def test_external_writer_must_install_signed_initial_and_higher_epoch_assertions(
    tmp_path: Path,
) -> None:
    authority = _new_cfg(tmp_path, "authority", cipher="hibe")
    authority.groups["default"].cipher = HibeGroupCipher.create(
        authority.keystore,
        "default",
        id_path="org/fraud/case-17",
        max_depth=3,
    )
    writer = _new_cfg(tmp_path, "writer")
    writer.ceremony_id = authority.ceremony_id
    external = HibeGroupCipher.create(
        writer.keystore,
        "default",
        authority_mpk=authority.groups["default"].cipher.mpk(),
        id_path="org/fraud/case-17",
    )
    writer.groups["default"].cipher = external

    with pytest.raises(TrustError) as unpinned:
        external.encrypt(b"raw mpk/path is not authorization")
    assert unpinned.value.reason is TrustReason.UNTRUSTED_PRINCIPAL

    initial = admin.issue_authority_assertion(
        "default",
        audience_did=writer.device.device_identity,
        ttl=timedelta(minutes=30),
        cfg=authority,
    )
    admin.install_authority_assertion(
        "default",
        mpk=authority.groups["default"].cipher.mpk(),
        assertion=initial,
        expected_authority_did=authority.device.device_identity,
        cfg=writer,
        now=initial.issued_at,
    )
    assert writer.groups["default"].cipher.id_path() == "org/fraud/case-17"
    assert writer.groups["default"].cipher.encrypt(b"epoch zero")

    update = admin.rotate_hibe_path(
        "default",
        "org/fraud/case-18",
        audience_did=writer.device.device_identity,
        ttl=timedelta(minutes=30),
        cfg=authority,
    )
    assert update.id_path == "org/fraud/case-18"
    assert update.path_epoch == 1

    # Merely copying the public sibling path is not an authenticated update.
    (writer.keystore / "default.hibe.idpath").write_text(
        update.id_path,
        encoding="utf-8",
    )
    writer.groups["default"].cipher = HibeGroupCipher.load(writer.keystore, "default")
    with pytest.raises(TrustError) as unsigned_update:
        writer.groups["default"].cipher.encrypt(b"unverified sibling")
    assert unsigned_update.value.reason is TrustReason.UNTRUSTED_PRINCIPAL

    admin.install_authority_assertion(
        "default",
        mpk=authority.groups["default"].cipher.mpk(),
        assertion=update.assertion,
        expected_authority_did=authority.device.device_identity,
        cfg=writer,
        now=update.assertion.issued_at,
    )
    assert writer.groups["default"].cipher.id_path() == "org/fraud/case-18"
    assert writer.groups["default"].cipher.encrypt(b"epoch one")


def test_rotation_assertion_is_scoped_to_one_external_writer(tmp_path: Path) -> None:
    authority = _new_cfg(tmp_path, "authority", cipher="hibe")
    first_writer = _new_cfg(tmp_path, "writer-one")
    second_writer = _new_cfg(tmp_path, "writer-two")
    second_writer.ceremony_id = authority.ceremony_id
    mpk = authority.groups["default"].cipher.mpk()
    second_writer.groups["default"].cipher = HibeGroupCipher.create(
        second_writer.keystore,
        "default",
        authority_mpk=mpk,
        id_path="self/epoch-2",
    )

    update = admin.rotate_hibe_path(
        "default",
        "self/epoch-2",
        audience_did=first_writer.device.device_identity,
        cfg=authority,
    )

    with pytest.raises(TrustError) as wrong_writer:
        admin.install_authority_assertion(
            "default",
            mpk=mpk,
            assertion=update.assertion,
            expected_authority_did=authority.device.device_identity,
            cfg=second_writer,
            now=update.assertion.issued_at,
        )
    assert wrong_writer.value.reason is TrustReason.WRONG_RECIPIENT
