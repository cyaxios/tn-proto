from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import tn
import tn.reader
from tn import _hibe


REQUIRED_READ_STAGES = {
    "read:_TOTAL",
    "read:line_parse",
    "read:row_hash_verify",
    "read:signature_verify",
    "read:chain_verify",
    "read:group_decode",
    "read:group_decrypt",
    "read:group_decrypt.cipher",
    "read:group_plaintext_parse",
}


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


@pytest.mark.parametrize("cipher", ["btn", "jwe", "hibe"])
def test_verified_read_records_required_stage_vocabulary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, cipher: str
) -> None:
    if cipher == "hibe" and not _hibe_available():
        pytest.skip("tn._native was built without the HIBE submodule")

    monkeypatch.setenv("TN_PERF_TRACE", "1")
    perf = importlib.import_module("tn._perf")

    root = tmp_path / cipher
    yaml_path = root / "publisher" / "tn.yaml"
    log_path = root / "publisher" / "logs" / "tn.ndjson"

    try:
        tn.init(yaml_path, log_path=log_path, cipher=cipher)
        tn.info("perf_stage.created", payload=f"{cipher}-payload")
        tn.flush_and_close()

        tn.init(yaml_path, log_path=log_path, cipher=cipher)
        cfg = tn.current_config()
        perf.reset()
        entries = list(tn.reader.read(log_path, cfg))
    finally:
        tn.flush_and_close()

    assert len(entries) == 1
    assert entries[0]["valid"] == {"signature": True, "row_hash": True, "chain": True}
    assert entries[0]["plaintext"]["default"]["payload"] == f"{cipher}-payload"

    snapshot = _snapshot_by_stage(perf)
    missing = REQUIRED_READ_STAGES - set(snapshot)
    assert not missing, f"{cipher} missing read perf stages: {sorted(missing)}"
    for stage in REQUIRED_READ_STAGES:
        assert snapshot[stage]["count"] >= 1, (cipher, stage, snapshot[stage])
        assert snapshot[stage]["total_ns"] > 0, (cipher, stage, snapshot[stage])
