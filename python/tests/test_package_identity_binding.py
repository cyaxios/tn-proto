from __future__ import annotations

import base64
import hashlib
import json
import warnings
from dataclasses import asdict

import pytest
import tn
import tn.packaging as packaging
from tn.absorb import absorb
from tn.config import load_or_create
from tn.conventions import pending_offers_dir
from tn.enrollment import MAX_ENROLLMENT_ARTIFACT_BYTES
from tn.packaging import Package, dump_tnpkg, sign, verify
from tn.security_audit import TnSecurityWarning
from tn.signing import DeviceKey


def _package(device_identity: str) -> Package:
    return Package(
        package_version=1,
        package_kind="offer",
        ceremony_id="ceremony-a",
        group="default",
        group_epoch=0,
        device_identity=device_identity,
        signer_verify_pub_b64="",
        recipient_identity=DeviceKey.generate().did,
        payload={"example": True},
        compiled_at="2026-07-12T00:00:00+00:00",
    )


def test_verify_requires_signer_key_to_match_complete_device_did() -> None:
    claimed = DeviceKey.generate()
    unrelated = DeviceKey.generate()
    package = sign(_package(claimed.did), unrelated.signing_key())

    assert verify(package) is False


def test_verify_accepts_did_bound_signer() -> None:
    signer = DeviceKey.generate()
    package = sign(_package(signer.did), signer.signing_key())

    assert verify(package) is True


def test_unbound_verifier_is_private_legacy_import_escape_hatch() -> None:
    claimed = DeviceKey.generate()
    unrelated = DeviceKey.generate()
    package = sign(_package(claimed.did), unrelated.signing_key())

    assert packaging._verify_signature_unbound(package) is True
    assert verify(package) is False


def test_legacy_unrelated_signer_requires_explicit_unsafe_import_and_is_unverified(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = load_or_create(tmp_path / "publisher" / "tn.yaml", cipher="jwe")
    claimed = DeviceKey.generate()
    unrelated = DeviceKey.generate()
    package = _package(claimed.did)
    package.recipient_identity = cfg.device.did
    package = sign(package, unrelated.signing_key())
    path = tmp_path / "legacy-offer.tnpkg"
    dump_tnpkg(package, path)

    rejected = absorb(cfg, path)
    assert rejected.status == "rejected"
    assert not pending_offers_dir(cfg.yaml_path).exists()

    events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        tn,
        "info",
        lambda event_type, **fields: events.append((event_type, fields)),
    )
    with pytest.warns(TnSecurityWarning) as caught:
        accepted = absorb(cfg, path, unsafe_legacy_signer=True)

    assert accepted.status == "offer_stashed"
    records = list(pending_offers_dir(cfg.yaml_path).glob("*.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert record["verified"] is False
    artifact_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    notice = caught[0].message.notice
    assert notice.artifact_digest == artifact_digest
    assert events == [
        (
            "tn.security.unsafe_operation",
            {
                "artifact_digest": artifact_digest,
                "group": "default",
                "operation": "legacy_package_import",
                "relaxations": ["legacy_signer_mismatch"],
                "subject_did": claimed.did,
            },
        )
    ]


def test_unsafe_legacy_import_cannot_downgrade_a_malformed_signature(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = load_or_create(tmp_path / "publisher" / "tn.yaml", cipher="jwe")
    claimed = DeviceKey.generate()
    unrelated = DeviceKey.generate()
    package = _package(claimed.did)
    package.recipient_identity = cfg.device.did
    package = sign(package, unrelated.signing_key())
    package.sig_b64 = base64.b64encode(b"\x00" * 64).decode("ascii")
    path = tmp_path / "malformed-legacy-offer.tnpkg"
    dump_tnpkg(package, path)
    events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        tn,
        "info",
        lambda event_type, **fields: events.append((event_type, fields)),
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = absorb(cfg, path, unsafe_legacy_signer=True)

    assert result.status == "rejected"
    assert not any(isinstance(item.message, TnSecurityWarning) for item in caught)
    assert events == []
    assert not pending_offers_dir(cfg.yaml_path).exists()


def _oversized_signed_flat_offer(cfg) -> bytes:
    signer = DeviceKey.generate()
    package = _package(signer.did)
    package.recipient_identity = cfg.device.did
    package.payload = {
        "padding": "x" * MAX_ENROLLMENT_ARTIFACT_BYTES,
        "x25519_pub_b64": base64.b64encode(b"k" * 32).decode("ascii"),
    }
    package = sign(package, signer.signing_key())
    encoded = json.dumps(asdict(package), sort_keys=True).encode("utf-8")
    assert len(encoded) > MAX_ENROLLMENT_ARTIFACT_BYTES
    return encoded


def test_flat_legacy_file_is_size_bounded_before_decode(tmp_path) -> None:
    cfg = load_or_create(tmp_path / "publisher" / "tn.yaml", cipher="jwe")
    source = tmp_path / "oversized-flat.tnpkg"
    source.write_bytes(_oversized_signed_flat_offer(cfg))

    result = absorb(cfg, source)

    assert result.status == "rejected"
    assert "maximum enrollment artifact size" in result.reason
    assert not pending_offers_dir(cfg.yaml_path).exists()


def test_flat_legacy_bytes_are_size_bounded_before_decode(tmp_path) -> None:
    cfg = load_or_create(tmp_path / "publisher" / "tn.yaml", cipher="jwe")
    source = _oversized_signed_flat_offer(cfg)

    result = absorb(cfg, source)

    assert result.status == "rejected"
    assert "maximum enrollment artifact size" in result.reason
    assert not pending_offers_dir(cfg.yaml_path).exists()
