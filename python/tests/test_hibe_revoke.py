"""HIBE reader add/remove lifecycle: grant two readers, revoke one, and
verify the forward/backward semantics the docs promise.

  - revoke = rotate the identity path + re-issue kits to the survivors
  - the revoked reader keeps pre-revocation entries (permanent-key limit,
    stated, not hidden) and loses everything after
  - a survivor absorbs their re-issued kit and reads seamlessly across the
    rotation (the superseded key is retained for old entries)
  - grants are recorded in the authority-side registry; the registry and
    the msk never ride a kit
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
import tn.reader
from tn.canonical import _canonical_bytes
from tn.cipher import HibeGroupCipher
from tn.key_binding import KeyBindingProofV1
from tn.signing import DeviceKey


def _new_cfg(tmp_path: Path, name: str, *, cipher: str = "btn"):
    tn.init(
        tmp_path / name / "tn.yaml",
        log_path=tmp_path / name / "log.ndjson",
        cipher=cipher,
    )
    cfg = tn.current_config()
    tn.flush_and_close()
    return cfg


def _grant_reader(authority_cfg, reader_cfg, out_path: Path) -> None:
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        reader_cfg.device.device_identity,
        cfg=authority_cfg,
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
    )
    tn.admin.grant_reader(
        "default",
        reader_did=reader_cfg.device.device_identity,
        out_path=out_path,
        proof=proof,
        cfg=authority_cfg,
    )


def _revocation_fixture(tmp_path: Path):
    alice = _new_cfg(tmp_path, "alice")
    bob = _new_cfg(tmp_path, "bob")
    authority = _new_cfg(tmp_path, "authority", cipher="hibe")
    tn.init(authority.yaml_path)
    authority = tn.current_config()
    _grant_reader(authority, alice, tmp_path / "alice.initial.tnpkg")
    _grant_reader(authority, bob, tmp_path / "bob.initial.tnpkg")
    return authority, alice, bob


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Every test starts and ends with a closed runtime (releases file
    handles before tmp_path cleanup, which Windows requires)."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _by_type(log_path: Path, keystore: Path) -> dict[str, dict]:
    return {
        e["envelope"]["event_type"]: e["plaintext"]["default"]
        for e in tn.reader.read_as_recipient(log_path, keystore, group="default")
    }


def test_hibe_revoke(tmp_path, monkeypatch):
    ws = tmp_path
    a_yaml = ws / "authority" / "tn.yaml"
    a_log = ws / "authority" / "log.ndjson"

    tn.init(ws / "alice" / "tn.yaml", log_path=ws / "alice" / "log.ndjson")
    alice_cfg = tn.current_config()
    alice = alice_cfg.device.device_identity
    tn.flush_and_close()
    tn.init(ws / "bob" / "tn.yaml", log_path=ws / "bob" / "log.ndjson")
    bob_cfg = tn.current_config()
    bob = bob_cfg.device.device_identity
    tn.flush_and_close()
    tn.init(ws / "writer" / "tn.yaml", log_path=ws / "writer" / "log.ndjson")
    writer_cfg = tn.current_config()
    writer_did = writer_cfg.device.device_identity
    tn.flush_and_close()

    # --- Add two readers, seal epoch 1.
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    authority_cfg = tn.current_config()
    a_keystore = authority_cfg.keystore
    authority_cipher = authority_cfg.groups["default"].cipher
    writer_cfg.ceremony_id = authority_cfg.ceremony_id
    writer_cfg.groups["default"].cipher = HibeGroupCipher.create(
        writer_cfg.keystore,
        "default",
        authority_mpk=authority_cipher.mpk(),
        id_path=authority_cipher.id_path(),
    )
    tn.info("e1", note="both readers admitted")
    alice_kit = ws / "alice.tnpkg"
    bob_kit = ws / "bob.tnpkg"
    alice_challenge = tn.admin.issue_hibe_reader_challenge(
        "default", alice, cfg=authority_cfg
    )
    alice_proof = tn.admin.create_hibe_reader_proof(
        alice_challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=alice_cfg,
    )
    bob_challenge = tn.admin.issue_hibe_reader_challenge(
        "default", bob, cfg=authority_cfg
    )
    bob_proof = tn.admin.create_hibe_reader_proof(
        bob_challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=bob_cfg,
    )
    tn.admin.grant_reader(
        "default",
        reader_did=alice,
        out_path=alice_kit,
        proof=alice_proof,
    )
    tn.admin.grant_reader(
        "default",
        reader_did=bob,
        out_path=bob_kit,
        proof=bob_proof,
    )
    grants = json.loads((a_keystore / "default.hibe.grants").read_text())
    assert {g["reader_did"] for g in grants} == {alice, bob}

    # --- Remove bob: rotate + re-issue alice's kit.
    res = tn.admin.revoke_reader(
        "default", bob, out_dir=ws / "regrant"
    )
    assert res.revoked and res.new_path == "self~r1"
    assert res.remaining == [alice]
    assert len(res.kit_paths) == 1 and res.kit_paths[0].exists()
    assert res.path_epoch == 1
    assert res.assertion is not None
    assert res.assertion.binding["id_path"] == "self~r1"
    assert res.assertion.binding["path_epoch"] == 1
    grants = json.loads((a_keystore / "default.hibe.grants").read_text())
    assert {g["reader_did"] for g in grants} == {alice}
    tn.info("e2", note="after bob was removed")
    tn.flush_and_close()

    # Neither the registry nor any master secret rides a kit.
    for kit in (alice_kit, bob_kit, res.kit_paths[0]):
        with zipfile.ZipFile(kit) as zf:
            names = zf.namelist()
        assert not any(n.endswith((".hibe.msk", ".hibe.grants")) for n in names), names

    # --- Bob: keeps e1 (honest limit), locked out of e2.
    tn.init(ws / "bob" / "tn.yaml", log_path=ws / "bob" / "log.ndjson")
    bob_ks = tn.current_config().keystore
    tn.absorb(bob_kit)
    tn.flush_and_close()
    got = _by_type(a_log, bob_ks)
    assert got["e1"]["note"] == "both readers admitted"
    assert got["e2"] == {"$no_read_key": True}, got["e2"]

    # --- Alice: absorbs original + re-issued kit, reads across the
    # rotation without any special handling.
    tn.init(ws / "alice" / "tn.yaml", log_path=ws / "alice" / "log.ndjson")
    alice_ks = tn.current_config().keystore
    tn.absorb(alice_kit)
    tn.absorb(res.kit_paths[0])
    tn.flush_and_close()
    got = _by_type(a_log, alice_ks)
    assert got["e1"]["note"] == "both readers admitted"
    assert got["e2"]["note"] == "after bob was removed"

    # --- Guardrails + the generic verb.
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    with pytest.raises(ValueError):
        tn.admin.revoke_reader("default", "did:key:z6Mk-nobody")
    # revoke_recipient routes hibe groups to the same flow. Its default
    # out_dir lands under cwd; keep it inside the tmp workspace.
    monkeypatch.chdir(ws)
    r2 = tn.admin.revoke_recipient(
        "default",
        recipient_did=alice,
        audience_did=writer_did,
    )
    assert r2.revoked and r2.cipher == "hibe"
    assert r2.new_path == "self~r2"  # counter bumps, not stacks
    assert r2.kit_paths == []  # nobody left to re-kit
    assert r2.path_epoch == 2
    assert r2.authority_assertion is not None
    assert r2.authority_assertion.audience_did == writer_did
    assert r2.authority_assertion.binding["path_epoch"] == 2
    assert r2.authority_assertion.binding["id_path"] == "self~r2"
    tn.admin.install_authority_assertion(
        "default",
        mpk=authority_cipher.mpk(),
        assertion=r2.authority_assertion,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=writer_cfg,
    )
    assert writer_cfg.groups["default"].cipher.path_epoch() == 2
    assert writer_cfg.groups["default"].cipher.id_path() == "self~r2"
    assert writer_cfg.groups["default"].cipher.encrypt(b"after unified revoke")
    tn.flush_and_close()


def test_hibe_ancestor_holder_is_not_claimed_revoked(tmp_path: Path) -> None:
    reader_yaml = tmp_path / "reader" / "tn.yaml"
    tn.init(reader_yaml)
    reader_cfg = tn.current_config()
    tn.flush_and_close()

    authority_yaml = tmp_path / "authority" / "tn.yaml"
    tn.init(authority_yaml, cipher="hibe")
    authority_cfg = tn.current_config()
    tn.admin.rotate_reader_path("default", "org/fraud")
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default", reader_cfg.device.device_identity, cfg=authority_cfg
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
    )
    tn.admin.grant_reader(
        "default",
        reader_did=reader_cfg.device.device_identity,
        id_path="org",
        out_path=tmp_path / "ancestor.tnpkg",
        proof=proof,
        allow_subauthority=True,
        cfg=authority_cfg,
    )

    result = tn.admin.revoke_reader(
        "default",
        reader_cfg.device.device_identity,
        cfg=authority_cfg,
    )

    assert result.revoked is False
    assert result.new_path == "org/fraud"
    assert result.path_epoch == 1
    assert result.assertion is None
    assert result.kit_paths == []
    assert result.remaining == [reader_cfg.device.device_identity]


def test_revoke_fails_before_rotation_when_survivor_registry_is_unverified(
    tmp_path: Path,
) -> None:
    from tn.trust import TrustError, TrustReason

    tn.init(tmp_path / "reader" / "tn.yaml")
    reader_cfg = tn.current_config()
    tn.flush_and_close()
    tn.init(tmp_path / "legacy" / "tn.yaml")
    legacy_cfg = tn.current_config()
    tn.flush_and_close()
    tn.init(tmp_path / "authority" / "tn.yaml", cipher="hibe")
    authority_cfg = tn.current_config()
    cipher = authority_cfg.groups["default"].cipher
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        reader_cfg.device.device_identity,
        cfg=authority_cfg,
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority_cfg.device.device_identity,
        cfg=reader_cfg,
    )
    tn.admin.grant_reader(
        "default",
        reader_did=reader_cfg.device.device_identity,
        out_path=tmp_path / "reader.tnpkg",
        proof=proof,
        cfg=authority_cfg,
    )
    registry_path = authority_cfg.keystore / "default.hibe.grants"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry.append(
        {
            "reader_did": legacy_cfg.device.device_identity,
            "id_path": cipher.id_path(),
        }
    )
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    old_path = cipher.id_path()
    old_epoch = cipher.path_epoch()

    with pytest.raises(TrustError) as raised:
        tn.admin.revoke_reader(
            "default",
            reader_cfg.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority_cfg,
        )

    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert cipher.id_path() == old_path
    assert cipher.path_epoch() == old_epoch


def test_revoke_registry_failure_retries_same_epoch_and_exact_staged_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn._keystore_backend as backend

    authority, alice, bob = _revocation_fixture(tmp_path)
    registry_path = authority.keystore / "default.hibe.grants"
    active_path = authority.keystore / "default.hibe.revocation.active.json"
    original_write = backend.atomic_write_bytes
    failed = False

    def fail_registry_once(path: Path, data: bytes) -> None:
        nonlocal failed
        if Path(path) == registry_path and not failed:
            failed = True
            raise OSError("injected registry failure")
        original_write(Path(path), data)

    monkeypatch.setattr(backend, "atomic_write_bytes", fail_registry_once)
    issued_at = datetime.now(UTC)
    with pytest.raises(OSError, match="injected registry failure"):
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
            now=issued_at,
        )

    intent = json.loads(active_path.read_text(encoding="utf-8"))
    staged = list((authority.keystore / ".hibe-revocations").rglob("*.tnpkg"))
    assert len(staged) == 1
    staged_bytes = staged[0].read_bytes()
    monkeypatch.setattr(backend, "atomic_write_bytes", original_write)

    result = tn.admin.revoke_reader(
        "default",
        bob.device.device_identity,
        out_dir=tmp_path / "regrant",
        cfg=authority,
        now=issued_at + timedelta(seconds=1),
    )

    assert result.revoked is True
    assert result.new_path == "self~r1"
    assert result.path_epoch == 1
    assert authority.groups["default"].cipher.id_path() == "self~r1"
    assert authority.groups["default"].cipher.path_epoch() == 1
    assert result.assertion is not None
    assert result.assertion._wire_value(include_signature=True) == intent["assertion"]
    assert len(result.kit_paths) == 1
    assert result.kit_paths[0].read_bytes() == staged_bytes
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    assert [item["reader_did"] for item in registry] == [alice.device.device_identity]
    survivor = registry[0]
    expected_grant_digest = "sha256:" + hashlib.sha256(
        _canonical_bytes(
            {
                "version": 1,
                "purpose": "hibe-reader-grant",
                "proof_digest": survivor["proof_digest"],
                "reader_did": alice.device.device_identity,
                "ceremony_id": survivor["ceremony_id"],
                "group": "default",
                "id_path": "self~r1",
            }
        )
    ).hexdigest()
    assert survivor["grant_digest"] == expected_grant_digest


def test_revoke_output_failure_recovers_redelivers_and_renews_expired_assertion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn._keystore_backend as backend

    authority, alice, bob = _revocation_fixture(tmp_path)
    writer = _new_cfg(tmp_path, "writer")
    tn.init(authority.yaml_path)
    authority = tn.current_config()
    out_dir = tmp_path / "regrant"
    active_path = authority.keystore / "default.hibe.revocation.active.json"
    original_write = backend.atomic_write_bytes
    failed = False

    def fail_output_once(path: Path, data: bytes) -> None:
        nonlocal failed
        if Path(path).parent == out_dir and Path(path).suffix == ".tnpkg" and not failed:
            failed = True
            raise OSError("injected output failure")
        original_write(Path(path), data)

    monkeypatch.setattr(backend, "atomic_write_bytes", fail_output_once)
    issued_at = datetime.now(UTC)
    with pytest.raises(OSError, match="injected output failure"):
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=out_dir,
            cfg=authority,
            audience_did=writer.device.device_identity,
            ttl=timedelta(minutes=1),
            now=issued_at,
        )

    assert active_path.exists()
    assert authority.groups["default"].cipher.id_path() == "self~r1"
    assert authority.groups["default"].cipher.path_epoch() == 1
    registry = json.loads((authority.keystore / "default.hibe.grants").read_text())
    assert [item["reader_did"] for item in registry] == [alice.device.device_identity]
    staged = list((authority.keystore / ".hibe-revocations").rglob("*.tnpkg"))
    assert len(staged) == 1
    staged_bytes = staged[0].read_bytes()
    with pytest.raises(tn.trust.TrustError) as blocked_rotate:
        tn.admin.rotate_hibe_path("default", "manual-race", cfg=authority)
    assert blocked_rotate.value.reason is tn.trust.TrustReason.EPOCH_CONFLICT
    assert authority.groups["default"].cipher.id_path() == "self~r1"
    assert authority.groups["default"].cipher.path_epoch() == 1
    monkeypatch.setattr(backend, "atomic_write_bytes", original_write)

    recovered = tn.admin.revoke_reader(
        "default",
        bob.device.device_identity,
        out_dir=out_dir,
        cfg=authority,
        audience_did=writer.device.device_identity,
        ttl=timedelta(minutes=1),
        now=issued_at + timedelta(seconds=1),
    )
    assert recovered.path_epoch == 1
    assert recovered.assertion is not None
    assert recovered.assertion.audience_did == writer.device.device_identity
    assert recovered.kit_paths[0].read_bytes() == staged_bytes
    assert not active_path.exists()

    renewed = tn.admin.revoke_reader(
        "default",
        bob.device.device_identity,
        out_dir=out_dir,
        cfg=authority,
        audience_did=writer.device.device_identity,
        ttl=timedelta(minutes=10),
        now=recovered.assertion.expires_at + timedelta(seconds=1),
    )
    assert renewed.path_epoch == recovered.path_epoch == 1
    assert renewed.new_path == recovered.new_path == "self~r1"
    assert renewed.assertion is not None
    assert renewed.assertion.audience_did == writer.device.device_identity
    assert dict(renewed.assertion.binding) == dict(recovered.assertion.binding)
    assert renewed.assertion.signature_b64 != recovered.assertion.signature_b64
    assert renewed.kit_paths[0].read_bytes() == staged_bytes


@pytest.mark.parametrize(
    "failure_point",
    ["prior_archive", "history", "current_sk", "id_path", "path_epoch"],
)
def test_revoke_recovers_after_restart_at_each_rotation_file_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    import tn._keystore_backend as backend

    authority, alice, bob = _revocation_fixture(tmp_path)
    keystore = authority.keystore
    original_write = backend.atomic_write_bytes
    failed = False

    def is_failure_target(path: Path) -> bool:
        if path.parent != keystore:
            return False
        if failure_point == "prior_archive":
            return path.name.startswith("default.hibe.sk.previous.revocation.")
        names = {
            "history": "default.hibe.idpath.history",
            "current_sk": "default.hibe.sk",
            "id_path": "default.hibe.idpath",
            "path_epoch": "default.hibe.path_epoch",
        }
        return path.name == names[failure_point]

    def fail_once(path: Path, data: bytes) -> None:
        nonlocal failed
        path = Path(path)
        if is_failure_target(path) and not failed:
            failed = True
            raise OSError(f"injected {failure_point} rotation failure")
        original_write(path, data)

    monkeypatch.setattr(backend, "atomic_write_bytes", fail_once)
    issued_at = datetime.now(UTC)
    with pytest.raises(OSError, match=f"injected {failure_point}"):
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
            now=issued_at,
        )
    staged = list((keystore / ".hibe-revocations").rglob("*.tnpkg"))
    assert len(staged) == 1
    staged_bytes = staged[0].read_bytes()

    # Rebuild the config/cipher from the partially committed files, exactly as
    # a new process would after the injected crash.
    monkeypatch.setattr(backend, "atomic_write_bytes", original_write)
    tn.flush_and_close()
    tn.init(authority.yaml_path)
    restarted = tn.current_config()
    result = tn.admin.revoke_reader(
        "default",
        bob.device.device_identity,
        out_dir=tmp_path / "regrant",
        cfg=restarted,
        now=issued_at + timedelta(seconds=1),
    )

    assert result.new_path == "self~r1"
    assert result.path_epoch == 1
    assert result.kit_paths[0].read_bytes() == staged_bytes
    assert restarted.groups["default"].cipher.id_path() == "self~r1"
    assert restarted.groups["default"].cipher.path_epoch() == 1
    registry = json.loads((keystore / "default.hibe.grants").read_text())
    assert [item["reader_did"] for item in registry] == [alice.device.device_identity]


def test_revoke_recovery_rejects_foreign_live_rotation_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn._keystore_backend as backend

    authority, _alice, bob = _revocation_fixture(tmp_path)
    registry_path = authority.keystore / "default.hibe.grants"
    original_write = backend.atomic_write_bytes
    failed = False

    def fail_registry_once(path: Path, data: bytes) -> None:
        nonlocal failed
        if Path(path) == registry_path and not failed:
            failed = True
            raise OSError("injected registry failure")
        original_write(Path(path), data)

    monkeypatch.setattr(backend, "atomic_write_bytes", fail_registry_once)
    with pytest.raises(OSError, match="injected registry failure"):
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
        )
    monkeypatch.setattr(backend, "atomic_write_bytes", original_write)
    (authority.keystore / "default.hibe.sk").write_bytes(b"foreign-key-material")

    with pytest.raises(tn.trust.TrustError) as rejected:
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
        )

    assert rejected.value.reason is tn.trust.TrustReason.EPOCH_CONFLICT
    assert not list((tmp_path / "regrant").glob("*.tnpkg"))


@pytest.mark.parametrize("record_kind", ["active", "completed"])
def test_revoke_recovery_rejects_substituted_assertion_signer_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_kind: str,
) -> None:
    import tn._keystore_backend as backend

    authority, _alice, bob = _revocation_fixture(tmp_path)
    out_dir = tmp_path / "regrant"
    if record_kind == "active":
        original_write = backend.atomic_write_bytes
        failed = False

        def fail_output_once(path: Path, data: bytes) -> None:
            nonlocal failed
            if Path(path).parent == out_dir and Path(path).suffix == ".tnpkg" and not failed:
                failed = True
                raise OSError("injected output failure")
            original_write(Path(path), data)

        monkeypatch.setattr(backend, "atomic_write_bytes", fail_output_once)
        with pytest.raises(OSError, match="injected output failure"):
            tn.admin.revoke_reader(
                "default",
                bob.device.device_identity,
                out_dir=out_dir,
                cfg=authority,
            )
        monkeypatch.setattr(backend, "atomic_write_bytes", original_write)
        record_path = authority.keystore / "default.hibe.revocation.active.json"
    else:
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=out_dir,
            cfg=authority,
        )
        record_path = tn.admin._hibe_revocation_completed_path(
            authority,
            "default",
            bob.device.device_identity,
        )
        for path in out_dir.glob("*.tnpkg"):
            path.unlink()

    record = json.loads(record_path.read_text(encoding="utf-8"))
    retained = KeyBindingProofV1.from_dict(record["assertion"])
    attacker = DeviceKey.generate()
    substituted = replace(
        retained,
        subject_did=attacker.device_identity,
        signature_b64="",
    ).sign(attacker)
    record["assertion"] = substituted._wire_value(include_signature=True)
    record_path.write_text(
        json.dumps(record, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    live_paths = [
        authority.keystore / "default.hibe.idpath",
        authority.keystore / "default.hibe.path_epoch",
        authority.keystore / "default.hibe.sk",
        authority.keystore / "default.hibe.grants",
    ]
    before = {path: path.read_bytes() for path in live_paths}

    with pytest.raises(tn.trust.TrustError) as rejected:
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=out_dir,
            cfg=authority,
        )

    assert rejected.value.reason is tn.trust.TrustReason.DID_SIGNER_MISMATCH
    assert {path: path.read_bytes() for path in live_paths} == before
    assert not list(out_dir.glob("*.tnpkg"))


def test_hibe_lifecycle_rejects_unsafe_or_unknown_group_before_lock_path_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn._keystore_backend as backend

    authority = _new_cfg(tmp_path, "authority", cipher="hibe")
    reader_did = DeviceKey.generate().device_identity
    observed_lock_paths: list[Path] = []

    class ForbiddenLock:
        def __init__(self, path: Path) -> None:
            observed_lock_paths.append(Path(path))
            raise AssertionError("lifecycle lock was derived before group validation")

    monkeypatch.setattr(backend, "AdvisoryFileLock", ForbiddenLock)
    invalid_groups = [
        "../escape",
        "..\\escape",
        str(tmp_path / "absolute"),
        "C:\\outside",
        "\\\\server\\share\\outside",
        "/absolute",
    ]
    operations = [
        lambda group: tn.admin.grant_reader(
            group,
            reader_did=reader_did,
            out_path=tmp_path / "must-not-exist.tnpkg",
            cfg=authority,
            unsafe_plaintext=True,
        ),
        lambda group: tn.admin.rotate_hibe_path(group, "next", cfg=authority),
        lambda group: tn.admin.revoke_reader(
            group,
            reader_did,
            out_dir=tmp_path / "must-not-exist",
            cfg=authority,
        ),
    ]
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    for group in invalid_groups:
        for operation in operations:
            with pytest.raises(tn.trust.TrustError) as rejected:
                operation(group)
            assert rejected.value.reason is tn.trust.TrustReason.SCOPE_MISMATCH
    for operation in operations:
        with pytest.raises(KeyError):
            operation("missing")

    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert observed_lock_paths == []


def test_revoke_uses_durable_accepted_admission_after_proof_expiry_and_restart(
    tmp_path: Path,
) -> None:
    authority, alice, bob = _revocation_fixture(tmp_path)
    registry = json.loads((authority.keystore / "default.hibe.grants").read_text())
    alice_record = next(
        item for item in registry if item["reader_did"] == alice.device.device_identity
    )
    proof_expiry = datetime.fromisoformat(
        alice_record["proof_expires_at"].replace("Z", "+00:00")
    )
    tn.flush_and_close()
    tn.init(authority.yaml_path)
    restarted = tn.current_config()

    result = tn.admin.revoke_reader(
        "default",
        bob.device.device_identity,
        out_dir=tmp_path / "regrant",
        cfg=restarted,
        now=proof_expiry + timedelta(days=1),
    )

    assert result.revoked is True
    assert result.remaining == [alice.device.device_identity]
    assert result.path_epoch == 1
    assert result.kit_paths[0].exists()


@pytest.mark.parametrize("mutation", ["missing", "scope", "forged"])
def test_revoke_rejects_untrusted_durable_survivor_admission(
    tmp_path: Path,
    mutation: str,
) -> None:
    authority, alice, bob = _revocation_fixture(tmp_path)
    registry_path = authority.keystore / "default.hibe.grants"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    survivor = next(
        item for item in registry if item["reader_did"] == alice.device.device_identity
    )
    if mutation == "missing":
        survivor["accepted_admission"] = None
    else:
        admission = dict(survivor["accepted_admission"])
        if mutation == "scope":
            admission["group"] = "other"
        else:
            attacker = DeviceKey.generate()
            admission["authority_did"] = attacker.device_identity
            unsigned = {key: value for key, value in admission.items() if key != "signature_b64"}
            admission["signature_b64"] = base64.b64encode(
                attacker.sign(_canonical_bytes(unsigned))
            ).decode("ascii")
        survivor["accepted_admission"] = admission
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    old_path = authority.groups["default"].cipher.id_path()
    old_epoch = authority.groups["default"].cipher.path_epoch()

    with pytest.raises(tn.trust.TrustError):
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
        )

    assert authority.groups["default"].cipher.id_path() == old_path
    assert authority.groups["default"].cipher.path_epoch() == old_epoch
    assert not (tmp_path / "regrant").exists()


def test_revoke_rejects_unsafe_survivor_without_accepted_admission(
    tmp_path: Path,
) -> None:
    authority, _alice, bob = _revocation_fixture(tmp_path)
    unsafe_reader = DeviceKey.generate().device_identity
    with pytest.warns(tn.security_audit.TnSecurityWarning):
        tn.admin.grant_reader(
            "default",
            reader_did=unsafe_reader,
            out_path=tmp_path / "unsafe.tnpkg",
            cfg=authority,
            unsafe_plaintext=True,
        )
    old_path = authority.groups["default"].cipher.id_path()
    old_epoch = authority.groups["default"].cipher.path_epoch()

    with pytest.raises(tn.trust.TrustError) as rejected:
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
        )

    assert rejected.value.reason is tn.trust.TrustReason.UNTRUSTED_PRINCIPAL
    assert authority.groups["default"].cipher.id_path() == old_path
    assert authority.groups["default"].cipher.path_epoch() == old_epoch


def test_revoke_fences_old_challenge_and_allows_new_post_cutoff_challenge(
    tmp_path: Path,
) -> None:
    authority, _alice, bob = _revocation_fixture(tmp_path)
    carol = _new_cfg(tmp_path, "carol")
    tn.init(authority.yaml_path)
    authority = tn.current_config()
    old_challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        carol.device.device_identity,
        cfg=authority,
    )
    old_proof = tn.admin.create_hibe_reader_proof(
        old_challenge,
        expected_authority_did=authority.device.device_identity,
        cfg=carol,
    )
    tn.admin.revoke_reader(
        "default",
        bob.device.device_identity,
        out_dir=tmp_path / "regrant",
        cfg=authority,
    )

    with pytest.raises(tn.trust.TrustError) as fenced:
        tn.admin.grant_reader(
            "default",
            reader_did=carol.device.device_identity,
            out_path=tmp_path / "old-proof.tnpkg",
            proof=old_proof,
            cfg=authority,
        )
    assert fenced.value.reason is tn.trust.TrustReason.CHALLENGE_REPLAYED
    assert not (tmp_path / "old-proof.tnpkg").exists()

    new_challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        carol.device.device_identity,
        cfg=authority,
    )
    new_proof = tn.admin.create_hibe_reader_proof(
        new_challenge,
        expected_authority_did=authority.device.device_identity,
        cfg=carol,
    )
    result = tn.admin.grant_reader(
        "default",
        reader_did=carol.device.device_identity,
        out_path=tmp_path / "new-proof.tnpkg",
        proof=new_proof,
        cfg=authority,
    )
    assert result.kit_path == tmp_path / "new-proof.tnpkg"
    assert result.kit_path.exists()


def test_revoke_generation_fence_survives_crash_and_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, _alice, bob = _revocation_fixture(tmp_path)
    carol = _new_cfg(tmp_path, "carol")
    tn.init(authority.yaml_path)
    authority = tn.current_config()
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        carol.device.device_identity,
        cfg=authority,
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority.device.device_identity,
        cfg=carol,
    )

    def crash_before_intent(**_kwargs):
        raise OSError("injected crash after admission fence")

    original_prepare = tn.admin._prepare_hibe_revocation
    monkeypatch.setattr(tn.admin, "_prepare_hibe_revocation", crash_before_intent)
    with pytest.raises(OSError, match="after admission fence"):
        tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
        )
    monkeypatch.setattr(tn.admin, "_prepare_hibe_revocation", original_prepare)
    tn.flush_and_close()
    tn.init(authority.yaml_path)
    restarted = tn.current_config()

    with pytest.raises(tn.trust.TrustError) as fenced:
        tn.admin.grant_reader(
            "default",
            reader_did=carol.device.device_identity,
            out_path=tmp_path / "old-proof.tnpkg",
            proof=proof,
            cfg=restarted,
        )
    assert fenced.value.reason is tn.trust.TrustReason.CHALLENGE_REPLAYED
    assert not (tmp_path / "old-proof.tnpkg").exists()


def test_challenge_issuance_racing_revoke_waits_and_uses_new_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, _alice, bob = _revocation_fixture(tmp_path)
    carol = _new_cfg(tmp_path, "carol")
    tn.init(authority.yaml_path)
    authority = tn.current_config()
    entered_prepare = threading.Event()
    release_prepare = threading.Event()
    original_prepare = tn.admin._prepare_hibe_revocation

    def paused_prepare(**kwargs):
        entered_prepare.set()
        assert release_prepare.wait(timeout=10)
        return original_prepare(**kwargs)

    monkeypatch.setattr(tn.admin, "_prepare_hibe_revocation", paused_prepare)

    with ThreadPoolExecutor(max_workers=2) as executor:
        revoke_future = executor.submit(
            tn.admin.revoke_reader,
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
        )
        assert entered_prepare.wait(timeout=10)
        challenge_future = executor.submit(
            tn.admin.issue_hibe_reader_challenge,
            "default",
            carol.device.device_identity,
            cfg=authority,
        )
        time.sleep(0.2)
        assert not challenge_future.done(), "challenge issuance bypassed the lifecycle cutoff"
        release_prepare.set()
        revoke_future.result(timeout=20)
        challenge = challenge_future.result(timeout=20)

    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority.device.device_identity,
        cfg=carol,
    )
    result = tn.admin.grant_reader(
        "default",
        reader_did=carol.device.device_identity,
        out_path=tmp_path / "carol.tnpkg",
        proof=proof,
        cfg=authority,
    )
    assert result.kit_path == tmp_path / "carol.tnpkg"
    assert result.kit_path.exists()


def test_pre_cutoff_grant_racing_revoke_is_fenced_and_not_overwritten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, alice, bob = _revocation_fixture(tmp_path)
    carol = _new_cfg(tmp_path, "carol")
    tn.init(authority.yaml_path)
    authority = tn.current_config()
    challenge = tn.admin.issue_hibe_reader_challenge(
        "default",
        carol.device.device_identity,
        cfg=authority,
    )
    proof = tn.admin.create_hibe_reader_proof(
        challenge,
        expected_authority_did=authority.device.device_identity,
        cfg=carol,
    )
    entered_replace = threading.Event()
    release_replace = threading.Event()
    original_replace = tn.admin._hibe_grants_replace

    def paused_replace(cfg, group: str, grants: list[dict[str, object]]) -> None:
        entered_replace.set()
        assert release_replace.wait(timeout=10)
        original_replace(cfg, group, grants)

    monkeypatch.setattr(tn.admin, "_hibe_grants_replace", paused_replace)

    def run_revoke():
        return tn.admin.revoke_reader(
            "default",
            bob.device.device_identity,
            out_dir=tmp_path / "regrant",
            cfg=authority,
        )

    def run_grant():
        return tn.admin.grant_reader(
            "default",
            reader_did=carol.device.device_identity,
            out_path=tmp_path / "carol.tnpkg",
            proof=proof,
            cfg=authority,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        revoke_future = executor.submit(run_revoke)
        assert entered_replace.wait(timeout=10)
        grant_future = executor.submit(run_grant)
        # Give the unprotected implementation a chance to commit the racing
        # grant in the revoke snapshot/replace window. With the lifecycle lock,
        # this simply waits outside the transaction.
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not (tmp_path / "carol.tnpkg").exists():
            time.sleep(0.01)
        release_replace.set()
        revoke_result = revoke_future.result(timeout=20)
        with pytest.raises(tn.trust.TrustError) as grant_failure:
            grant_future.result(timeout=20)

    assert revoke_result.path_epoch == 1
    assert grant_failure.value.reason is tn.trust.TrustReason.CHALLENGE_REPLAYED
    assert not (tmp_path / "carol.tnpkg").exists()
    registry = json.loads((authority.keystore / "default.hibe.grants").read_text())
    assert {item["reader_did"] for item in registry} == {alice.device.device_identity}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
