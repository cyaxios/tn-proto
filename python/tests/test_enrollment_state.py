from __future__ import annotations

import base64
import hashlib
import io
import inspect
import json
import multiprocessing
import os
import zipfile
from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, get_type_hints

import pytest

from tn import admin
from tn.absorb import absorb
from tn.canonical import _canonical_bytes
from tn.config import LoadedConfig, load, load_or_create
from tn.conventions import enrollment_dir, pending_offers_dir
from tn.enrollment import MAX_ENROLLMENT_ARTIFACT_BYTES, EnrollmentStore
from tn.key_binding import EnrollmentChallengeV1, KeyBindingProofV1
from tn.packaging import Package, sign
from tn.signing import DeviceKey
from tn.tnpkg import TnpkgManifest, _write_tnpkg, sign_manifest_with_body
from tn.trust import TrustError, TrustReason


UTC = timezone.utc


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _challenge_digest(challenge: EnrollmentChallengeV1) -> str:
    return _digest(_canonical_bytes(challenge._wire_value(include_signature=True)))


def _state_files(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _flip_stored_member_byte(artifact: bytes, member: str) -> bytes:
    """Corrupt one STORED member without updating its central-directory CRC."""
    with zipfile.ZipFile(io.BytesIO(artifact), "r") as archive:
        info = archive.getinfo(member)
    assert info.compress_type == zipfile.ZIP_STORED
    name_length = int.from_bytes(artifact[info.header_offset + 26 : info.header_offset + 28], "little")
    extra_length = int.from_bytes(artifact[info.header_offset + 28 : info.header_offset + 30], "little")
    payload_offset = info.header_offset + 30 + name_length + extra_length
    assert info.file_size > 0
    corrupted = bytearray(artifact)
    corrupted[payload_offset] ^= 1
    return bytes(corrupted)


def _deeply_nested_manifest_artifact() -> bytes:
    nested_manifest = (
        b'{"kind":"offer","nested":'
        + b"[" * 5000
        + b"0"
        + b"]" * 5000
        + b"}"
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", nested_manifest)
    return output.getvalue()


def _deeply_nested_offer_body_artifact(
    directory: Path,
    cfg: LoadedConfig,
    reader: DeviceKey,
) -> bytes:
    nested_package = (
        b'{"payload":{"nested":'
        + b"[" * 5000
        + b"0"
        + b"]" * 5000
        + b"}}"
    )
    body = {"body/package.json": nested_package}
    manifest = TnpkgManifest(
        kind="offer",
        publisher_identity=reader.device_identity,
        recipient_identity=cfg.device.device_identity,
        ceremony_id=cfg.ceremony_id,
        as_of=_timestamp(datetime.now(UTC)),
        scope="default",
        event_count=1,
    )
    sign_manifest_with_body(manifest, body, reader.signing_key())
    path = directory / "nested-offer-body.tnpkg"
    _write_tnpkg(path, manifest, body)
    return path.read_bytes()


def _make_offer_artifact(
    directory: Path,
    cfg: LoadedConfig,
    reader: DeviceKey,
    *,
    challenge: EnrollmentChallengeV1 | None,
    group: str = "default",
    public_key_seed: bytes = b"reader-x25519-a",
    nonce_seed: bytes = b"proof-nonce-a",
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    payload_marker: str | None = None,
    extra_body: bytes | None = None,
    compress: bool = False,
) -> tuple[bytes, KeyBindingProofV1]:
    if challenge is not None:
        issued_at = issued_at or challenge.issued_at
        expires_at = expires_at or challenge.expires_at
        challenge_digest: str | None = _challenge_digest(challenge)
    else:
        issued_at = issued_at or datetime.now(UTC)
        expires_at = expires_at or issued_at + timedelta(minutes=10)
        challenge_digest = None

    public_key = hashlib.sha256(public_key_seed).digest()
    proof = KeyBindingProofV1(
        version=1,
        purpose="jwe-reader",
        subject_did=reader.device_identity,
        audience_did=cfg.device.device_identity,
        ceremony_id=cfg.ceremony_id,
        group=group,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce_b64=base64.b64encode(hashlib.sha256(nonce_seed).digest()).decode("ascii"),
        binding={
            "algorithm": "X25519",
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
            "challenge_digest": challenge_digest,
        },
        signature_b64="",
    ).sign(reader)
    payload: dict[str, Any] = {
        "key_binding_proof": proof._wire_value(include_signature=True),
        "x25519_pub_b64": base64.b64encode(public_key).decode("ascii"),
    }
    if payload_marker is not None:
        payload["marker"] = payload_marker
    package = sign(
        Package(
            package_version=1,
            package_kind="offer",
            ceremony_id=cfg.ceremony_id,
            group=group,
            group_epoch=0,
            device_identity=reader.device_identity,
            signer_verify_pub_b64="",
            recipient_identity=cfg.device.device_identity,
            payload=payload,
            compiled_at=_timestamp(issued_at),
        ),
        reader.signing_key(),
    )
    body = {
        "body/package.json": json.dumps(
            asdict(package), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    }
    if extra_body is not None:
        body["body/padding.bin"] = extra_body
    manifest = TnpkgManifest(
        kind="offer",
        publisher_identity=reader.device_identity,
        recipient_identity=cfg.device.device_identity,
        ceremony_id=cfg.ceremony_id,
        as_of=_timestamp(issued_at),
        scope=group,
        event_count=1,
    )
    sign_manifest_with_body(manifest, body, reader.signing_key())
    path = directory / f"offer-{os.urandom(6).hex()}.tnpkg"
    if compress:
        manifest_bytes = (
            json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", manifest_bytes)
            for name in sorted(body):
                archive.writestr(name, body[name])
    else:
        _write_tnpkg(path, manifest, body)
    return path.read_bytes(), proof


def _store(tmp_path: Path) -> tuple[LoadedConfig, EnrollmentStore, DeviceKey, Path]:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    state_root = tmp_path / "private-enrollment-state"
    reader = DeviceKey.generate()
    return cfg, EnrollmentStore(cfg, cfg.device, state_root), reader, state_root


def _approval_worker(
    yaml_path: str,
    state_root: str,
    offer_digest: str,
    now_text: str,
    queue: multiprocessing.Queue[tuple[str, str, str]],
) -> None:
    cfg = load(Path(yaml_path))
    store = EnrollmentStore(cfg, cfg.device, Path(state_root))
    now = datetime.fromisoformat(now_text)
    try:
        accepted = store.approve_and_reconcile(offer_digest, now=now)
    except TrustError as exc:
        queue.put(("error", exc.reason.value, ""))
    else:
        queue.put(("ok", accepted.offer_digest, accepted.artifact_digest))


def _run_approval_race(
    cfg: LoadedConfig,
    state_root: Path,
    digests: list[str],
    now: datetime,
) -> list[tuple[str, str, str]]:
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_approval_worker,
            args=(str(cfg.yaml_path), str(state_root), digest, now.isoformat(), queue),
        )
        for digest in digests
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in processes]
    queue.close()
    return results


def test_issue_challenge_is_signed_scoped_persisted_and_preauthorized(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    store.preauthorize(reader.device_identity, "default")

    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))

    assert challenge.publisher_did == cfg.device.device_identity
    assert challenge.expected_reader_did == reader.device_identity
    assert challenge.ceremony_id == cfg.ceremony_id
    assert challenge.group == "default"
    assert challenge.expires_at - challenge.issued_at == timedelta(minutes=5)
    challenge_path = state_root / "challenges" / f"{challenge.challenge_id}.json"
    assert challenge_path.is_file()
    persisted = json.loads(challenge_path.read_text(encoding="utf-8"))
    assert persisted["challenge_digest"] == _challenge_digest(challenge)
    assert persisted["challenge"]["signature_b64"] == challenge.signature_b64


def test_stage_and_reconcile_retain_exact_artifact_and_exact_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    store.preauthorize(reader.device_identity, "default")
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    artifact, proof = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)

    pending = store.stage_offer(artifact, cfg.device.device_identity, now)
    accepted = store.reconcile(pending, now=now)

    assert pending.ceremony_id == cfg.ceremony_id
    assert pending.group == "default"
    assert pending.reader_did == reader.device_identity
    assert pending.artifact_path.read_bytes() == artifact
    assert hashlib.sha256(reader.device_identity.encode()).hexdigest() in str(pending.artifact_path)
    assert accepted.offer_digest == _digest(
        _canonical_bytes(proof._wire_value(include_signature=True))
    )
    assert accepted.artifact_digest == _digest(artifact)
    assert accepted.binding.proof_digest == accepted.offer_digest
    assert accepted.binding == pending.verified
    with pytest.raises(FrozenInstanceError):
        pending.group = "changed"

    after_first = _state_files(state_root)
    replayed = store.stage_offer(artifact, cfg.device.device_identity, now)
    replayed_accepted = store.reconcile(replayed, now=now)
    assert replayed_accepted == accepted
    assert _state_files(state_root) == after_first
    assert len(list((state_root / "consumed").glob("*.json"))) == 1
    assert len(list((state_root / "accepted").glob("*.json"))) == 1

    after_expiry = challenge.expires_at + timedelta(hours=1)
    expired_replay = store.stage_offer(
        artifact,
        cfg.device.device_identity,
        after_expiry,
    )
    assert store.reconcile(expired_replay, now=after_expiry) == accepted
    assert _state_files(state_root) == after_first


def test_first_promotion_durably_links_consumed_and_accepted_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn._keystore_backend as backend_module

    cfg, store, reader, state_root = _store(tmp_path)
    store.preauthorize(reader.device_identity, "default")
    challenge = store.issue_challenge(
        reader.device_identity,
        "default",
        timedelta(minutes=5),
    )
    now = challenge.issued_at + timedelta(seconds=1)
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    pending = store.stage_offer(artifact, cfg.device.device_identity, now)
    synced: list[Path] = []
    monkeypatch.setattr(
        backend_module,
        "_fsync_directory",
        lambda path: synced.append(Path(path)),
    )

    store.reconcile(pending, now=now)

    assert synced == [
        state_root.parent,
        state_root.parent,
        state_root,
        state_root / "consumed",
        state_root.parent,
        state_root,
        state_root / "accepted",
    ]


def test_same_challenge_with_changed_signed_body_is_replay_conflict(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    store.preauthorize(reader.device_identity, "default")
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    first, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    pending = store.stage_offer(first, cfg.device.device_identity, now)
    store.reconcile(pending, now=now)
    before = _state_files(state_root)
    changed, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        public_key_seed=b"different-reader-key",
        nonce_seed=b"proof-nonce-a",
    )

    with pytest.raises(TrustError) as raised:
        store.stage_offer(changed, cfg.device.device_identity, now)

    assert raised.value.reason is TrustReason.REPLAY_CONFLICT
    assert _state_files(state_root) == before


def test_consumed_challenge_conflict_wins_over_expiry(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    store.preauthorize(reader.device_identity, "default")
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    first, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    store.reconcile(
        store.stage_offer(first, cfg.device.device_identity, now),
        now=now,
    )
    before = _state_files(state_root)
    conflicting, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        public_key_seed=b"post-expiry-conflicting-key",
        nonce_seed=b"proof-nonce-a",
    )

    with pytest.raises(TrustError) as raised:
        store.stage_offer(
            conflicting,
            cfg.device.device_identity,
            challenge.expires_at + timedelta(hours=1),
        )

    assert raised.value.reason is TrustReason.REPLAY_CONFLICT
    assert _state_files(state_root) == before


def test_consumed_challenge_without_matching_artifact_is_challenge_replayed(
    tmp_path: Path,
) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    consumed_dir = state_root / "consumed"
    consumed_dir.mkdir(parents=True, exist_ok=True)
    (consumed_dir / f"{challenge.challenge_id}.json").write_text(
        json.dumps({"version": 1, "challenge_id": challenge.challenge_id}),
        encoding="utf-8",
    )
    before = _state_files(state_root)

    with pytest.raises(TrustError) as raised:
        store.stage_offer(artifact, cfg.device.device_identity, now)

    assert raised.value.reason is TrustReason.CHALLENGE_REPLAYED
    assert _state_files(state_root) == before


def test_partial_consumed_marker_wins_over_challenge_expiry(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        expires_at=challenge.expires_at + timedelta(hours=2),
    )
    consumed_dir = state_root / "consumed"
    consumed_dir.mkdir(parents=True, exist_ok=True)
    (consumed_dir / f"{challenge.challenge_id}.json").write_text(
        json.dumps({"version": 1, "challenge_id": challenge.challenge_id}),
        encoding="utf-8",
    )
    before = _state_files(state_root)

    with pytest.raises(TrustError) as raised:
        store.stage_offer(
            artifact,
            cfg.device.device_identity,
            challenge.expires_at + timedelta(hours=1),
        )

    assert raised.value.reason is TrustReason.CHALLENGE_REPLAYED
    assert _state_files(state_root) == before


def test_expired_challenge_rejects_without_mutating_pending_state(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(seconds=1))
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        expires_at=challenge.expires_at + timedelta(minutes=5),
    )
    before = _state_files(state_root)

    with pytest.raises(TrustError) as raised:
        store.stage_offer(
            artifact,
            cfg.device.device_identity,
            challenge.expires_at + timedelta(seconds=1),
        )

    assert raised.value.reason is TrustReason.CHALLENGE_EXPIRED
    assert _state_files(state_root) == before


def test_malformed_offer_does_not_create_enrollment_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    state_root = tmp_path / "never-created"
    store = EnrollmentStore(cfg, cfg.device, state_root)

    with pytest.raises(TrustError):
        store.stage_offer(
            b"not a signed tnpkg",
            cfg.device.device_identity,
            datetime.now(UTC),
        )

    assert not state_root.exists()


def test_direct_oversized_prefixed_offer_is_rejected_without_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    issued_at = datetime.now(UTC)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    oversized = (
        b"SFX"
        * ((MAX_ENROLLMENT_ARTIFACT_BYTES - len(artifact)) // 3 + 1)
        + artifact
    )
    state_root = tmp_path / "never-created-oversized"
    store = EnrollmentStore(cfg, cfg.device, state_root)

    with pytest.raises(TrustError, match="maximum enrollment artifact size") as raised:
        store.stage_offer(oversized, cfg.device.device_identity, issued_at)

    assert raised.value.reason is TrustReason.STATEMENT_INVALID
    assert len(oversized) > MAX_ENROLLMENT_ARTIFACT_BYTES
    assert not state_root.exists()


def test_store_normalizes_body_crc_failure_without_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    now = datetime.now(UTC)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    corrupted = _flip_stored_member_byte(artifact, "body/package.json")
    state_root = tmp_path / "crc-direct-state"
    store = EnrollmentStore(cfg, cfg.device, state_root)

    with pytest.raises(TrustError, match="ZIP member") as raised:
        store.stage_offer(corrupted, cfg.device.device_identity, now)

    assert raised.value.reason is TrustReason.STATEMENT_INVALID
    assert not state_root.exists()


def test_absorb_normalizes_body_crc_failure_without_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    now = datetime.now(UTC)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    corrupted = _flip_stored_member_byte(artifact, "body/package.json")

    result = absorb(cfg, corrupted)

    assert result.status == "rejected"
    assert "ZIP member" in result.reason
    assert not enrollment_dir(cfg.yaml_path).exists()


def test_store_normalizes_deeply_nested_manifest_without_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    state_root = tmp_path / "nested-manifest-direct-state"
    store = EnrollmentStore(cfg, cfg.device, state_root)

    with pytest.raises(TrustError, match="nesting") as raised:
        store.stage_offer(
            _deeply_nested_manifest_artifact(),
            cfg.device.device_identity,
            datetime.now(UTC),
        )

    assert raised.value.reason is TrustReason.STATEMENT_INVALID
    assert not state_root.exists()


def test_absorb_normalizes_deeply_nested_manifest_without_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")

    result = absorb(cfg, _deeply_nested_manifest_artifact())

    assert result.status == "rejected"
    assert "nesting" in result.reason
    assert not enrollment_dir(cfg.yaml_path).exists()


def test_store_normalizes_deeply_nested_offer_body_without_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    artifact = _deeply_nested_offer_body_artifact(tmp_path, cfg, DeviceKey.generate())
    state_root = tmp_path / "nested-body-direct-state"
    store = EnrollmentStore(cfg, cfg.device, state_root)

    with pytest.raises(TrustError, match="offer package JSON nesting") as raised:
        store.stage_offer(artifact, cfg.device.device_identity, datetime.now(UTC))

    assert raised.value.reason is TrustReason.STATEMENT_INVALID
    assert not state_root.exists()


def test_absorb_normalizes_deeply_nested_offer_body_without_state(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    artifact = _deeply_nested_offer_body_artifact(tmp_path, cfg, DeviceKey.generate())

    result = absorb(cfg, artifact)

    assert result.status == "rejected"
    assert "offer package JSON nesting" in result.reason
    assert not enrollment_dir(cfg.yaml_path).exists()


def test_absorb_rejects_oversized_prefixed_offer_before_unbounded_reread(
    tmp_path: Path,
) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    issued_at = datetime.now(UTC)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    oversized = (
        b"SFX"
        * ((MAX_ENROLLMENT_ARTIFACT_BYTES - len(artifact)) // 3 + 1)
        + artifact
    )
    source = tmp_path / "oversized-prefixed-offer.tnpkg"
    source.write_bytes(oversized)

    result = absorb(cfg, source)

    assert result.status == "rejected"
    assert "maximum enrollment artifact size" in result.reason
    assert len(oversized) > MAX_ENROLLMENT_ARTIFACT_BYTES
    assert not enrollment_dir(cfg.yaml_path).exists()


def _compressed_oversized_offer(
    tmp_path: Path,
    cfg: LoadedConfig,
    reader: DeviceKey,
    now: datetime,
) -> bytes:
    incompressible_prefix = hashlib.shake_256(b"enrollment-padding").digest(512 * 1024)
    padding = incompressible_prefix + b"\0" * (1536 * 1024)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        extra_body=padding,
        compress=True,
    )
    assert len(artifact) < MAX_ENROLLMENT_ARTIFACT_BYTES
    return artifact


def test_store_preflight_rejects_compressed_offer_before_body_inflation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    now = datetime.now(UTC)
    artifact = _compressed_oversized_offer(tmp_path, cfg, reader, now)
    state_root = tmp_path / "compressed-direct-state"
    store = EnrollmentStore(cfg, cfg.device, state_root)
    original_read = zipfile.ZipFile.read
    read_members: list[str] = []

    def guard_body_read(archive: zipfile.ZipFile, name: str, *args: Any, **kwargs: Any) -> bytes:
        read_members.append(name)
        if name == "body/padding.bin":
            raise AssertionError("oversized enrollment body was inflated")
        return original_read(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", guard_body_read)
    with pytest.raises(TrustError, match="ZIP_STORED"):
        store.stage_offer(artifact, cfg.device.device_identity, now)

    assert "body/padding.bin" not in read_members
    assert not state_root.exists()


def test_absorb_preflight_rejects_compressed_offer_before_body_inflation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    now = datetime.now(UTC)
    artifact = _compressed_oversized_offer(tmp_path, cfg, reader, now)
    source = tmp_path / "compressed-oversized-offer.tnpkg"
    source.write_bytes(artifact)
    original_read = zipfile.ZipFile.read
    read_members: list[str] = []

    def guard_body_read(archive: zipfile.ZipFile, name: str, *args: Any, **kwargs: Any) -> bytes:
        read_members.append(name)
        if name == "body/padding.bin":
            raise AssertionError("oversized enrollment body was inflated")
        return original_read(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", guard_body_read)
    result = absorb(cfg, source)

    assert result.status == "rejected"
    assert "ZIP_STORED" in result.reason
    assert "body/padding.bin" not in read_members
    assert not enrollment_dir(cfg.yaml_path).exists()


def test_unsolicited_per_artifact_quota_rejects_without_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    now = datetime.now(UTC)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    state_root = tmp_path / "unsolicited-per-artifact"
    store = EnrollmentStore(cfg, cfg.device, state_root)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_OFFER_BYTES", len(artifact) - 1)

    with pytest.raises(TrustError, match="unsolicited offer size") as raised:
        store.stage_offer(artifact, cfg.device.device_identity, now)

    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert not state_root.exists()


def test_unsolicited_count_quota_preserves_exact_replay_and_challenged_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, _, state_root = _store(tmp_path)
    now = datetime.now(UTC)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_PENDING_COUNT", 2)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_PENDING_BYTES", 10**7)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_OFFER_BYTES", 10**6)
    retained: list[tuple[bytes, Any]] = []
    for index in range(2):
        reader = DeviceKey.generate()
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=None,
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            nonce_seed=f"unsolicited-{index}".encode(),
        )
        retained.append((artifact, store.stage_offer(artifact, cfg.device.device_identity, now)))

    at_quota = _state_files(state_root)
    third_reader = DeviceKey.generate()
    third_artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        third_reader,
        challenge=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        nonce_seed=b"unsolicited-third",
    )
    with pytest.raises(TrustError, match="unsolicited pending offer count") as raised:
        store.stage_offer(third_artifact, cfg.device.device_identity, now)
    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert _state_files(state_root) == at_quota

    replayed = store.stage_offer(retained[0][0], cfg.device.device_identity, now)
    assert replayed == retained[0][1]
    assert _state_files(state_root) == at_quota

    challenged_reader = DeviceKey.generate()
    store.preauthorize(challenged_reader.device_identity, "default")
    challenge = store.issue_challenge(
        challenged_reader.device_identity,
        "default",
        timedelta(minutes=5),
    )
    challenged_artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        challenged_reader,
        challenge=challenge,
        nonce_seed=b"challenged-reserved-path",
    )
    challenged = store.stage_offer(
        challenged_artifact,
        cfg.device.device_identity,
        challenge.issued_at + timedelta(seconds=1),
    )
    assert challenged.verified.challenge_digest is not None


def test_unsolicited_aggregate_quota_rejects_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, _, state_root = _store(tmp_path)
    now = datetime.now(UTC)
    artifacts: list[bytes] = []
    for index in range(2):
        reader = DeviceKey.generate()
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=None,
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            nonce_seed=f"aggregate-{index}".encode(),
        )
        artifacts.append(artifact)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_PENDING_COUNT", 10)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_OFFER_BYTES", 10**6)
    monkeypatch.setattr(
        enrollment_module,
        "MAX_UNSOLICITED_PENDING_BYTES",
        len(artifacts[0]) + len(artifacts[1]) - 1,
    )
    store.stage_offer(artifacts[0], cfg.device.device_identity, now)
    before = _state_files(state_root)

    with pytest.raises(TrustError, match="unsolicited pending offer bytes") as raised:
        store.stage_offer(artifacts[1], cfg.device.device_identity, now)

    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert _state_files(state_root) == before


def test_accepted_unsolicited_offer_frees_quota_without_deleting_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, _, state_root = _store(tmp_path)
    now = datetime.now(UTC)
    artifacts: list[bytes] = []
    for index in range(2):
        reader = DeviceKey.generate()
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=None,
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            nonce_seed=f"accepted-capacity-{index}".encode(),
        )
        artifacts.append(artifact)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_PENDING_COUNT", 1)
    monkeypatch.setattr(enrollment_module, "MAX_UNSOLICITED_OFFER_BYTES", 10**6)
    monkeypatch.setattr(
        enrollment_module,
        "MAX_UNSOLICITED_PENDING_BYTES",
        max(map(len, artifacts)) + 1,
    )
    first = store.stage_offer(artifacts[0], cfg.device.device_identity, now)
    first_path = first.artifact_path
    store.approve_and_reconcile(first.offer_digest, now=now)

    second = store.stage_offer(artifacts[1], cfg.device.device_identity, now)

    assert first_path.is_file()
    assert first_path.read_bytes() == artifacts[0]
    assert second.artifact_path.is_file()
    assert len(list((state_root / "offers").rglob("*.tnpkg"))) == 2


def test_challenged_variant_quota_preserves_replay_and_other_challenges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, _, state_root = _store(tmp_path)
    reader = DeviceKey.generate()
    challenge = store.issue_challenge(
        reader.device_identity,
        "default",
        timedelta(minutes=5),
    )
    now = challenge.issued_at + timedelta(seconds=1)
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_VARIANTS_PER_CHALLENGE", 2)
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_PENDING_COUNT", 100)
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_PENDING_BYTES", 10**7)

    retained: list[tuple[bytes, Any]] = []
    for index in range(2):
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=challenge,
            public_key_seed=f"challenge-key-{index}".encode(),
            nonce_seed=f"challenge-proof-{index}".encode(),
        )
        retained.append(
            (artifact, store.stage_offer(artifact, cfg.device.device_identity, now))
        )

    third, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        public_key_seed=b"challenge-key-third",
        nonce_seed=b"challenge-proof-third",
    )
    at_quota = _state_files(state_root)
    with pytest.raises(TrustError, match="variants for challenge") as raised:
        store.stage_offer(third, cfg.device.device_identity, now)
    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert _state_files(state_root) == at_quota

    replayed = store.stage_offer(retained[0][0], cfg.device.device_identity, now)
    assert replayed == retained[0][1]
    assert _state_files(state_root) == at_quota

    other_reader = DeviceKey.generate()
    other_challenge = store.issue_challenge(
        other_reader.device_identity,
        "default",
        timedelta(minutes=5),
    )
    other_artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        other_reader,
        challenge=other_challenge,
        nonce_seed=b"reserved-other-challenge",
    )
    other = store.stage_offer(
        other_artifact,
        cfg.device.device_identity,
        other_challenge.issued_at + timedelta(seconds=1),
    )
    assert other.verified.challenge_digest is not None


def test_challenged_pending_count_quota_rejects_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, _, state_root = _store(tmp_path)
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_VARIANTS_PER_CHALLENGE", 4)
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_PENDING_COUNT", 2)
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_PENDING_BYTES", 10**7)
    candidates: list[tuple[bytes, datetime]] = []
    for index in range(3):
        reader = DeviceKey.generate()
        challenge = store.issue_challenge(
            reader.device_identity,
            "default",
            timedelta(minutes=5),
        )
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=challenge,
            nonce_seed=f"challenged-count-{index}".encode(),
        )
        candidates.append((artifact, challenge.issued_at + timedelta(seconds=1)))

    for artifact, now in candidates[:2]:
        store.stage_offer(artifact, cfg.device.device_identity, now)
    at_quota = _state_files(state_root)

    with pytest.raises(TrustError, match="challenged pending offer count") as raised:
        store.stage_offer(candidates[2][0], cfg.device.device_identity, candidates[2][1])

    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert _state_files(state_root) == at_quota


def test_challenged_pending_bytes_quota_rejects_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, _, state_root = _store(tmp_path)
    candidates: list[tuple[bytes, datetime]] = []
    for index in range(2):
        reader = DeviceKey.generate()
        challenge = store.issue_challenge(
            reader.device_identity,
            "default",
            timedelta(minutes=5),
        )
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=challenge,
            nonce_seed=f"challenged-bytes-{index}".encode(),
        )
        candidates.append((artifact, challenge.issued_at + timedelta(seconds=1)))
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_VARIANTS_PER_CHALLENGE", 4)
    monkeypatch.setattr(enrollment_module, "MAX_CHALLENGED_PENDING_COUNT", 10)
    monkeypatch.setattr(
        enrollment_module,
        "MAX_CHALLENGED_PENDING_BYTES",
        len(candidates[0][0]) + len(candidates[1][0]) - 1,
    )
    store.stage_offer(candidates[0][0], cfg.device.device_identity, candidates[0][1])
    before = _state_files(state_root)

    with pytest.raises(TrustError, match="challenged pending offer bytes") as raised:
        store.stage_offer(candidates[1][0], cfg.device.device_identity, candidates[1][1])

    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert _state_files(state_root) == before


def test_reconcile_isolates_losing_challenge_variant_and_accepts_unrelated_offer(
    tmp_path: Path,
) -> None:
    from tn.reconcile import _reconcile

    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    store = EnrollmentStore(cfg, cfg.device)
    competing_reader = DeviceKey.generate()
    store.preauthorize(competing_reader.device_identity, "default")
    competing_challenge = store.issue_challenge(
        competing_reader.device_identity,
        "default",
        timedelta(minutes=5),
    )
    now = competing_challenge.issued_at + timedelta(seconds=1)
    competing: list[Any] = []
    for index in range(2):
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            competing_reader,
            challenge=competing_challenge,
            public_key_seed=f"competing-key-{index}".encode(),
            nonce_seed=f"competing-proof-{index}".encode(),
        )
        competing.append(store.stage_offer(artifact, cfg.device.device_identity, now))
    store.reconcile(competing[0], now=now)

    unrelated_reader = DeviceKey.generate()
    store.preauthorize(unrelated_reader.device_identity, "default")
    unrelated_challenge = store.issue_challenge(
        unrelated_reader.device_identity,
        "default",
        timedelta(minutes=5),
    )
    unrelated_artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        unrelated_reader,
        challenge=unrelated_challenge,
        nonce_seed=b"unrelated-after-conflict",
    )
    unrelated = store.stage_offer(
        unrelated_artifact,
        cfg.device.device_identity,
        unrelated_challenge.issued_at + timedelta(seconds=1),
    )

    with pytest.raises(TrustError) as fail_closed:
        store.pending_offers(now=unrelated_challenge.issued_at + timedelta(seconds=2))
    assert fail_closed.value.reason is TrustReason.REPLAY_CONFLICT

    result = _reconcile(cfg)

    assert any(
        accepted.offer_digest == unrelated.offer_digest
        for accepted in result.accepted_offers
    )
    assert any(
        competing[1].artifact_path.name in conflict and "replay_conflict" in conflict
        for conflict in result.conflicts
    )


def test_non_null_digest_without_retained_challenge_is_challenge_missing(
    tmp_path: Path,
) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    reader = DeviceKey.generate()
    issuing_store = EnrollmentStore(cfg, cfg.device, tmp_path / "issuer-state")
    challenge = issuing_store.issue_challenge(
        reader.device_identity,
        "default",
        timedelta(minutes=5),
    )
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    receiving_root = tmp_path / "receiver-state"
    receiving_store = EnrollmentStore(cfg, cfg.device, receiving_root)

    with pytest.raises(TrustError) as raised:
        receiving_store.stage_offer(
            artifact,
            cfg.device.device_identity,
            challenge.issued_at + timedelta(seconds=1),
        )

    assert raised.value.reason is TrustReason.CHALLENGE_MISSING
    assert list((receiving_root / "offers").rglob("*.tnpkg")) == []


def test_same_reader_in_two_groups_has_distinct_retained_paths(tmp_path: Path) -> None:
    cfg, _, reader, state_root = _store(tmp_path)
    cfg = admin.ensure_group(cfg, "finance", cipher="jwe")
    store = EnrollmentStore(cfg, cfg.device, state_root)
    pendings = []
    for group in ("default", "finance"):
        store.preauthorize(reader.device_identity, group)
        challenge = store.issue_challenge(reader.device_identity, group, timedelta(minutes=5))
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=challenge,
            group=group,
            nonce_seed=group.encode(),
        )
        pendings.append(
            store.stage_offer(
                artifact,
                cfg.device.device_identity,
                challenge.issued_at + timedelta(seconds=1),
            )
        )

    assert pendings[0].artifact_path != pendings[1].artifact_path
    assert pendings[0].artifact_path.read_bytes() != pendings[1].artifact_path.read_bytes()
    assert {pending.group for pending in pendings} == {"default", "finance"}


def test_signed_separator_components_cannot_escape_the_private_state_root(
    tmp_path: Path,
) -> None:
    cfg, _, reader, state_root = _store(tmp_path)
    malicious_group = "../outside\\nested"
    cfg.groups[malicious_group] = cfg.groups["default"]
    store = EnrollmentStore(cfg, cfg.device, state_root)
    store.preauthorize(reader.device_identity, malicious_group)
    challenge = store.issue_challenge(
        reader.device_identity,
        malicious_group,
        timedelta(minutes=5),
    )
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        group=malicious_group,
    )

    pending = store.stage_offer(
        artifact,
        cfg.device.device_identity,
        challenge.issued_at + timedelta(seconds=1),
    )

    relative = pending.artifact_path.relative_to(state_root)
    assert ".." not in relative.parts
    assert all("/" not in part and "\\" not in part for part in relative.parts)
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize(
    "dangerous_scope",
    [
        "CON",
        "AUX",
        "NUL",
        "COM1",
        "scope.",
        "scope ",
        "alpha/beta",
        "alpha\\beta",
        "../outside",
    ],
)
def test_signed_scope_components_use_fixed_lowercase_hashes(
    tmp_path: Path,
    dangerous_scope: str,
) -> None:
    cfg, _, reader, state_root = _store(tmp_path)
    cfg.ceremony_id = dangerous_scope
    cfg.groups[dangerous_scope] = cfg.groups["default"]
    store = EnrollmentStore(cfg, cfg.device, state_root)
    store.preauthorize(reader.device_identity, dangerous_scope)
    challenge = store.issue_challenge(
        reader.device_identity,
        dangerous_scope,
        timedelta(minutes=5),
    )
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        group=dangerous_scope,
    )

    pending = store.stage_offer(
        artifact,
        cfg.device.device_identity,
        challenge.issued_at + timedelta(seconds=1),
    )

    expected = "sha256-" + hashlib.sha256(dangerous_scope.encode("utf-8")).hexdigest()
    relative = pending.artifact_path.relative_to(state_root)
    assert relative.parts[1:3] == (expected, expected)
    assert expected == expected.lower()
    assert len(expected) == 71


def test_case_distinct_scope_components_do_not_alias_on_windows(tmp_path: Path) -> None:
    cfg, _, reader, state_root = _store(tmp_path)
    cfg.ceremony_id = "CaseSensitiveCeremony"
    groups = ("Finance", "finance")
    for group in groups:
        cfg.groups[group] = cfg.groups["default"]
    store = EnrollmentStore(cfg, cfg.device, state_root)
    paths: list[Path] = []

    for group in groups:
        store.preauthorize(reader.device_identity, group)
        challenge = store.issue_challenge(reader.device_identity, group, timedelta(minutes=5))
        artifact, _ = _make_offer_artifact(
            tmp_path,
            cfg,
            reader,
            challenge=challenge,
            group=group,
            nonce_seed=group.encode("utf-8"),
        )
        pending = store.stage_offer(
            artifact,
            cfg.device.device_identity,
            challenge.issued_at + timedelta(seconds=1),
        )
        paths.append(pending.artifact_path)

    group_components = [path.relative_to(state_root).parts[2] for path in paths]
    assert group_components == [
        "sha256-" + hashlib.sha256(group.encode("utf-8")).hexdigest()
        for group in groups
    ]
    assert group_components[0] != group_components[1]


def test_unsolicited_offer_stays_pending_until_exact_digest_approval(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    now = datetime.now(UTC)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    pending = store.stage_offer(artifact, cfg.device.device_identity, now)
    before = _state_files(state_root)

    with pytest.raises(TrustError) as raised:
        store.reconcile(pending, now=now)

    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    assert _state_files(state_root) == before
    accepted = store.approve_and_reconcile(pending.offer_digest, now=now)
    assert accepted.offer_digest == pending.offer_digest
    approval = next((state_root / "approvals").glob("*.json"))
    assert json.loads(approval.read_text(encoding="utf-8"))["offer_digest"] == (
        pending.offer_digest
    )
    assert list((state_root / "consumed").glob("*.json")) == []


def test_exact_approval_recovers_acceptance_after_write_failure_and_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, reader, state_root = _store(tmp_path)
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(minutes=5)
    artifact, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    pending = store.stage_offer(artifact, cfg.device.device_identity, issued_at)
    real_atomic_write = enrollment_module.atomic_write_bytes

    def fail_accepted_write(path: Path, data: bytes) -> None:
        if Path(path).parent == state_root / "accepted":
            raise OSError("simulated failure after durable approval")
        real_atomic_write(path, data)

    with monkeypatch.context() as patcher:
        patcher.setattr(enrollment_module, "atomic_write_bytes", fail_accepted_write)
        with pytest.raises(OSError, match="after durable approval"):
            store.approve_and_reconcile(pending.offer_digest, now=issued_at)

    assert len(list((state_root / "approvals").glob("*.json"))) == 1
    assert not (state_root / "accepted").exists()

    accepted = store.approve_and_reconcile(
        pending.offer_digest,
        now=expires_at + timedelta(hours=1),
    )

    assert accepted.offer_digest == pending.offer_digest
    assert accepted.artifact_digest == _digest(artifact)
    assert len(list((state_root / "accepted").glob("*.json"))) == 1


def test_durable_approval_never_authorizes_different_artifact_after_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tn.enrollment as enrollment_module

    cfg, store, reader, state_root = _store(tmp_path)
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(minutes=5)
    artifact, proof = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    pending = store.stage_offer(artifact, cfg.device.device_identity, issued_at)
    real_atomic_write = enrollment_module.atomic_write_bytes

    def fail_accepted_write(path: Path, data: bytes) -> None:
        if Path(path).parent == state_root / "accepted":
            raise OSError("simulated failure after durable approval")
        real_atomic_write(path, data)

    with monkeypatch.context() as patcher:
        patcher.setattr(enrollment_module, "atomic_write_bytes", fail_accepted_write)
        with pytest.raises(OSError, match="after durable approval"):
            store.approve_and_reconcile(pending.offer_digest, now=issued_at)

    replacement, replacement_proof = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=None,
        issued_at=issued_at,
        expires_at=expires_at,
        payload_marker="different signed container",
    )
    assert _digest(_canonical_bytes(proof._wire_value(include_signature=True))) == _digest(
        _canonical_bytes(replacement_proof._wire_value(include_signature=True))
    )
    assert replacement != artifact
    pending.artifact_path.write_bytes(replacement)
    before = _state_files(state_root)

    with pytest.raises(TrustError) as raised:
        store.approve_and_reconcile(
            pending.offer_digest,
            now=expires_at + timedelta(hours=1),
        )

    assert raised.value.reason is TrustReason.REPLAY_CONFLICT
    assert _state_files(state_root) == before
    assert not (state_root / "accepted").exists()


def test_reconcile_reverifies_retained_bytes_before_any_promotion_mutation(
    tmp_path: Path,
) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    store.preauthorize(reader.device_identity, "default")
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    pending = store.stage_offer(artifact, cfg.device.device_identity, now)
    pending.artifact_path.write_bytes(b"not the retained signed artifact")
    before = _state_files(state_root)

    with pytest.raises((TrustError, ValueError)):
        store.reconcile(pending, now=now)

    assert _state_files(state_root) == before
    assert not (state_root / "accepted").exists()
    assert not (state_root / "consumed").exists()


def test_failed_atomic_offer_write_leaves_no_target_or_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tn._keystore_backend as backend

    cfg, store, reader, state_root = _store(tmp_path)
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    before = _state_files(state_root)

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("simulated crash before atomic replace")

    monkeypatch.setattr(backend.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated crash"):
        store.stage_offer(artifact, cfg.device.device_identity, now)

    assert _state_files(state_root) == before
    assert list((state_root / "offers").rglob("*.tnpkg")) == []
    assert list(state_root.rglob("*.tmp.*")) == []


def test_admin_reconcile_enrollment_exposes_auto_and_explicit_approval(
    tmp_path: Path,
) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    store = EnrollmentStore(cfg, cfg.device)
    reader = DeviceKey.generate()
    store.preauthorize(reader.device_identity, "default")
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    pending = store.stage_offer(artifact, cfg.device.device_identity, now)

    automatic = admin.reconcile_enrollment(
        pending.offer_digest,
        approve=False,
        cfg=cfg,
        now=now,
    )
    assert automatic.offer_digest == pending.offer_digest

    other_reader = DeviceKey.generate()
    unsolicited, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        other_reader,
        challenge=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    other_pending = store.stage_offer(unsolicited, cfg.device.device_identity, now)
    with pytest.raises(TrustError) as raised:
        admin.reconcile_enrollment(
            other_pending.offer_digest,
            approve=False,
            cfg=cfg,
            now=now,
        )
    assert raised.value.reason is TrustReason.UNTRUSTED_PRINCIPAL
    approved = admin.reconcile_enrollment(
        other_pending.offer_digest,
        approve=True,
        cfg=cfg,
        now=now,
    )
    assert approved.offer_digest == other_pending.offer_digest


def test_admin_reconcile_enrollment_has_the_frozen_public_signature() -> None:
    signature = inspect.signature(admin.reconcile_enrollment)
    hints = get_type_hints(admin.reconcile_enrollment)

    assert list(signature.parameters) == ["offer_digest", "approve", "cfg", "now"]
    assert signature.parameters["approve"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["cfg"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
    assert hints["now"] == datetime | None
    assert hints["return"].__name__ == "AcceptedOffer"


def test_absorb_strict_offer_retains_the_complete_signed_artifact(tmp_path: Path) -> None:
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    store = EnrollmentStore(cfg, cfg.device)
    reader = DeviceKey.generate()
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)

    result = absorb(cfg, artifact)

    assert result.status == "offer_stashed", result.reason
    retained = list((enrollment_dir(cfg.yaml_path) / "offers").rglob("*.tnpkg"))
    assert len(retained) == 1
    assert retained[0].read_bytes() == artifact
    assert not pending_offers_dir(cfg.yaml_path).exists()


@pytest.mark.skipif(os.name != "nt", reason="spawn semantics are the Windows deployment boundary")
def test_multiprocess_identical_approval_calls_converge(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    artifact, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    pending = store.stage_offer(artifact, cfg.device.device_identity, now)

    results = _run_approval_race(
        cfg,
        state_root,
        [pending.offer_digest, pending.offer_digest],
        now,
    )

    assert results == [
        ("ok", pending.offer_digest, _digest(artifact)),
        ("ok", pending.offer_digest, _digest(artifact)),
    ]
    assert len(list((state_root / "consumed").glob("*.json"))) == 1
    assert len(list((state_root / "accepted").glob("*.json"))) == 1


@pytest.mark.skipif(os.name != "nt", reason="spawn semantics are the Windows deployment boundary")
def test_multiprocess_conflicting_approval_calls_have_one_winner(tmp_path: Path) -> None:
    cfg, store, reader, state_root = _store(tmp_path)
    challenge = store.issue_challenge(reader.device_identity, "default", timedelta(minutes=5))
    now = challenge.issued_at + timedelta(seconds=1)
    first, _ = _make_offer_artifact(tmp_path, cfg, reader, challenge=challenge)
    second, _ = _make_offer_artifact(
        tmp_path,
        cfg,
        reader,
        challenge=challenge,
        public_key_seed=b"conflicting-key",
        nonce_seed=b"proof-nonce-a",
    )
    pending_a = store.stage_offer(first, cfg.device.device_identity, now)
    pending_b = store.stage_offer(second, cfg.device.device_identity, now)

    results = _run_approval_race(
        cfg,
        state_root,
        [pending_a.offer_digest, pending_b.offer_digest],
        now,
    )

    assert [result[0] for result in results].count("ok") == 1
    assert ("error", TrustReason.REPLAY_CONFLICT.value, "") in results
    assert len(list((state_root / "approvals").glob("*.json"))) == 1
    assert len(list((state_root / "consumed").glob("*.json"))) == 1
    assert len(list((state_root / "accepted").glob("*.json"))) == 1
