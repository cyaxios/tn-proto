from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from tn import _hibe
from tn.cipher import HibeGroupCipher, JWEGroupCipher


def _snapshot_by_stage(perf_module):
    return {stage: {"count": count, "total_ns": total_ns} for stage, count, total_ns in perf_module.snapshot()}


def _hibe_available() -> bool:
    try:
        _hibe.setup(1)
    except RuntimeError as exc:
        if "HIBE native extension is unavailable" in str(exc):
            return False
        raise
    return True


def test_python_perf_module_records_and_resets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TN_PERF_TRACE", "1")
    perf = importlib.import_module("tn._perf")

    perf.reset()
    assert perf.snapshot() == []

    with perf.time_stage("unit:test_stage"):
        sum(range(16))

    snapshot = _snapshot_by_stage(perf)
    assert snapshot["unit:test_stage"]["count"] == 1
    assert snapshot["unit:test_stage"]["total_ns"] > 0

    perf.reset()
    assert perf.snapshot() == []


def test_jwe_cipher_records_encrypt_and_decrypt_cipher_stages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TN_PERF_TRACE", "1")
    perf = importlib.import_module("tn._perf")
    perf.reset()

    cipher = JWEGroupCipher.create(tmp_path, "default", recipient_dids=["did:self"])
    ciphertext = cipher.encrypt(b"jwe perf payload")
    assert cipher.decrypt(ciphertext) == b"jwe perf payload"

    snapshot = _snapshot_by_stage(perf)
    assert snapshot["emit:group_encrypt.cipher"]["count"] == 1
    assert snapshot["emit:group_encrypt.cipher"]["total_ns"] > 0
    assert snapshot["read:group_decrypt.cipher"]["count"] == 1
    assert snapshot["read:group_decrypt.cipher"]["total_ns"] > 0


def test_hibe_cipher_records_encrypt_and_decrypt_cipher_stages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if not _hibe_available():
        pytest.skip("tn._native was built without the HIBE submodule")

    monkeypatch.setenv("TN_PERF_TRACE", "1")
    perf = importlib.import_module("tn._perf")
    perf.reset()

    cipher = HibeGroupCipher.create(tmp_path, "default")
    ciphertext = cipher.encrypt(b"hibe perf payload")
    assert cipher.decrypt(ciphertext) == b"hibe perf payload"

    snapshot = _snapshot_by_stage(perf)
    assert snapshot["emit:group_encrypt.cipher"]["count"] == 1
    assert snapshot["emit:group_encrypt.cipher"]["total_ns"] > 0
    assert snapshot["read:group_decrypt.cipher"]["count"] >= 1
    assert snapshot["read:group_decrypt.cipher"]["total_ns"] > 0
