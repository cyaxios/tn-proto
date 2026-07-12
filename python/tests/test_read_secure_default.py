from __future__ import annotations

import importlib
import inspect
import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import tn
from tn._entry import Entry, VerifyError
from tn.read import _ReadIterator
from tn.signing import DeviceKey
from tn.chain import ZERO_HASH, _compute_row_hash
from tn.signing import _signature_b64


def _envelope(device: DeviceKey, **overrides: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "timestamp": "2026-07-12T12:00:00.000000Z",
        "event_type": "order.created",
        "level": "info",
        "device_identity": device.did,
        "sequence": 1,
        "event_id": "01J00000000000000000000000",
        "run_id": "run-secure-read",
        "prev_hash": "sha256:" + "0" * 64,
        "row_hash": "sha256:" + "1" * 64,
        "signature": "signed",
        "amount": 4999,
    }
    envelope.update(overrides)
    return envelope


def _triple(
    device: DeviceKey,
    *,
    valid: dict[str, Any] | None = None,
    envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "envelope": envelope or _envelope(device),
        "plaintext": {},
        "valid": valid
        or {
            "signature": True,
            "row_hash": True,
            "chain": True,
        },
    }


@pytest.fixture()
def read_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Bind the public reader to one immutable receiver-local fake source."""

    device = DeviceKey.generate()
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    keystore = tmp_path / ".tn" / "keys"
    keystore.mkdir(parents=True)
    log_path = tmp_path / "local.ndjson"
    cfg = SimpleNamespace(
        yaml_path=yaml_path,
        keystore=keystore,
        device=device,
        sign=True,
        chain=True,
        resolve_log_path=lambda: log_path,
    )
    rows: list[dict[str, Any]] = [_triple(device)]

    read_impl = importlib.import_module("tn._read_impl")
    read_module = importlib.import_module("tn.read")
    monkeypatch.setattr(tn, "_maybe_autoinit_load_only", lambda: None)
    monkeypatch.setattr(tn, "current_config", lambda: cfg)
    monkeypatch.setattr(read_module, "_resolve_read_source", lambda *args: None)
    monkeypatch.setattr(
        read_impl,
        "_read_raw_inner",
        lambda *args, **kwargs: iter(rows),
    )
    return SimpleNamespace(device=device, cfg=cfg, rows=rows)


def test_read_default_is_auto_and_preserves_iterator_and_entry_shape(read_harness) -> None:
    parameter = inspect.signature(tn.read).parameters["verify"]
    assert parameter.default == "auto"

    result = tn.read()
    assert isinstance(result, _ReadIterator)
    assert result.stats.yielded == 0

    entries = list(result)
    assert len(entries) == 1
    assert isinstance(entries[0], Entry)
    assert entries[0].event_type == "order.created"
    assert entries[0].fields == {"amount": 4999}
    assert result.stats.yielded == 1


def test_default_raise_uses_stable_primary_and_full_reasons(read_harness) -> None:
    read_harness.rows[:] = [
        _triple(
            read_harness.device,
            valid={"signature": False, "row_hash": False, "chain": False},
        ),
    ]

    result = tn.read()
    with pytest.raises(VerifyError) as raised:
        list(result)

    assert raised.value.reason == "row_hash_invalid"
    assert raised.value.reasons == [
        "row_hash_invalid",
        "chain_invalid",
        "signature_invalid",
    ]
    assert raised.value.failed_checks == raised.value.reasons
    assert raised.value.sequence == 1
    assert raised.value.event_type == "order.created"


def test_skip_preserves_stats_callback_and_full_raw_reason_metadata(read_harness) -> None:
    read_harness.rows[:] = [
        _triple(
            read_harness.device,
            valid={"signature": False, "row_hash": False, "chain": False},
        ),
    ]
    seen: list[tuple[dict[str, Any], str]] = []

    result = tn.read(
        verify="skip",
        raw=True,
        on_skip=lambda envelope, reason: seen.append((envelope, reason)),
    )
    assert list(result) == []
    assert result.stats.yielded == 0
    assert result.stats.skipped_verify == 1
    assert result.stats.skipped_reasons == ["row_hash_invalid"]
    assert len(seen) == 1
    assert seen[0][1] == "row_hash_invalid"
    assert seen[0][0]["_valid"]["reasons"] == [
        "row_hash_invalid",
        "chain_invalid",
        "signature_invalid",
    ]


def test_disabled_mode_never_claims_authentication_or_authorization(read_harness) -> None:
    rows = list(tn.read(verify=False, raw=True))
    assert len(rows) == 1
    assert rows[0]["_valid"]["writer_authenticated"] is False
    assert rows[0]["_valid"]["writer_authorized"] is False
    assert rows[0]["_valid"]["reasons"] == []


def test_invalid_present_signature_is_not_excused_by_unauthenticated_override(
    read_harness,
) -> None:
    read_harness.rows[:] = [
        _triple(
            read_harness.device,
            valid={"signature": False, "row_hash": True, "chain": True},
        ),
    ]

    with pytest.raises(VerifyError) as raised:
        list(
            tn.read(
                require_signature=False,
                allow_unauthenticated=True,
            ),
        )
    assert raised.value.reason == "signature_invalid"


def test_absent_signature_under_signed_local_profile_is_signature_required(
    read_harness,
) -> None:
    read_harness.rows[:] = [
        _triple(
            read_harness.device,
            envelope=_envelope(read_harness.device, signature=""),
            valid={"signature": False, "row_hash": True, "chain": True},
        ),
    ]

    with pytest.raises(VerifyError) as raised:
        list(tn.read())
    assert raised.value.reason == "signature_required"
    assert raised.value.reasons == ["signature_required"]


def test_true_and_false_remain_compatibility_aliases(read_harness) -> None:
    read_harness.rows[:] = [
        _triple(
            read_harness.device,
            valid={"signature": False, "row_hash": False, "chain": False},
        ),
    ]

    with pytest.raises(VerifyError):
        list(tn.read(verify=True))
    rows = list(tn.read(verify=False, raw=True))
    assert rows[0]["_valid"]["writer_authenticated"] is False
    assert rows[0]["_valid"]["writer_authorized"] is False


def test_secure_read_is_a_strict_wrapper_without_weakening_keywords(read_harness) -> None:
    secure_read = getattr(tn, "secure_read", None)
    assert callable(secure_read)
    assert "verify" not in inspect.signature(secure_read).parameters
    assert "require_signature" not in inspect.signature(secure_read).parameters
    assert "allow_unauthenticated" not in inspect.signature(secure_read).parameters
    assert "allow_unknown_writers" not in inspect.signature(secure_read).parameters
    assert isinstance(secure_read(), _ReadIterator)
    with pytest.raises(TypeError):
        secure_read(verify=False)


@pytest.mark.parametrize("rejection", ["row_hash", "signature", "writer"])
def test_security_rejection_happens_before_group_decrypt(
    rejection: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SpyCipher:
        calls = 0

        def decrypt(self, ciphertext: bytes, aad: bytes) -> bytes:
            del ciphertext, aad
            self.calls += 1
            return json.dumps({"secret": "must-not-surface"}).encode()

    local_device = DeviceKey.generate()
    writer = DeviceKey.generate() if rejection == "writer" else local_device
    cipher = SpyCipher()
    ciphertext = b"sealed-placeholder"
    group_wire = {
        "ciphertext": base64.standard_b64encode(ciphertext).decode("ascii"),
        "field_hashes": {},
    }
    row_hash = _compute_row_hash(
        device_identity=writer.did,
        timestamp="2026-07-12T12:00:00.000000Z",
        event_id="01J00000000000000000000001",
        event_type="secret.created",
        level="info",
        prev_hash=ZERO_HASH,
        public_fields={},
        groups={"default": {"ciphertext": ciphertext, "field_hashes": {}}},
    )
    if rejection == "row_hash":
        row_hash = "sha256:" + "f" * 64
    signature = _signature_b64(writer.sign(row_hash.encode("ascii")))
    if rejection == "signature":
        signature = _signature_b64(DeviceKey.generate().sign(row_hash.encode("ascii")))
    envelope = {
        "timestamp": "2026-07-12T12:00:00.000000Z",
        "event_type": "secret.created",
        "level": "info",
        "device_identity": writer.did,
        "sequence": 1,
        "event_id": "01J00000000000000000000001",
        "prev_hash": ZERO_HASH,
        "row_hash": row_hash,
        "signature": signature,
        "default": group_wire,
    }
    log_path = tmp_path / "local.ndjson"
    log_path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("{}\n", encoding="utf-8")
    keystore = tmp_path / "keys"
    keystore.mkdir()
    cfg = SimpleNamespace(
        yaml_path=yaml_path,
        keystore=keystore,
        device=local_device,
        sign=True,
        chain=True,
        public_fields=[],
        groups={"default": SimpleNamespace(cipher=cipher)},
        resolve_log_path=lambda: log_path,
    )
    monkeypatch.setattr(tn, "_dispatch_rt", None)
    monkeypatch.setattr(tn, "_maybe_autoinit_load_only", lambda: None)
    monkeypatch.setattr(tn, "current_config", lambda: cfg)

    with pytest.raises(VerifyError):
        list(tn.read())
    assert cipher.calls == 0
