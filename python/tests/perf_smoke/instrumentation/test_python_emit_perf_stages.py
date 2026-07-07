from __future__ import annotations

import importlib
from pathlib import Path

import tn


REQUIRED_PYTHON_EMIT_STAGES = {
    "emit:_TOTAL",
    "emit:lock_acquire",
    "emit:field_classify",
    "emit:group_encrypt",
    "emit:group_encrypt.cipher",
    "emit:chain_advance",
    "emit:row_hash",
    "emit:sign",
    "emit:envelope_build",
    "emit:fan_out",
    "emit:file_write",
    "emit:chain_commit",
}

REQUIRED_PYTHON_EMIT_SIZE_METRICS = {
    "emit:group_encrypt.plaintext_bytes",
    "emit:group_encrypt.ciphertext_bytes",
    "emit:envelope.raw_bytes",
    "emit:file_write.raw_bytes",
}


def _snapshot_by_stage(perf_module):
    return {stage: {"count": count, "total_ns": total_ns} for stage, count, total_ns in perf_module.snapshot()}


def _metrics_by_name(perf_module):
    return {
        name: {"count": count, "total": total, "min": min_value, "max": max_value}
        for name, count, total, min_value, max_value in perf_module.snapshot_metrics()
    }


def test_jwe_python_emit_records_write_stages_and_sizes(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TN_PERF_TRACE", "1")
    perf = importlib.import_module("tn._perf")

    yaml_path = tmp_path / "jwe" / "publisher" / "tn.yaml"
    log_path = tmp_path / "jwe" / "publisher" / "logs" / "tn.ndjson"

    try:
        tn.init(yaml_path, log_path=log_path, cipher="jwe")
        perf.reset()
        tn.info("perf_emit.created", payload="jwe-stage-payload", count=1)
    finally:
        tn.flush_and_close()

    snapshot = _snapshot_by_stage(perf)
    missing_stages = REQUIRED_PYTHON_EMIT_STAGES - set(snapshot)
    assert not missing_stages, f"jwe missing emit perf stages: {sorted(missing_stages)}"
    for stage in REQUIRED_PYTHON_EMIT_STAGES:
        assert snapshot[stage]["count"] >= 1, (stage, snapshot[stage])
        assert snapshot[stage]["total_ns"] > 0, (stage, snapshot[stage])

    metrics = _metrics_by_name(perf)
    missing_metrics = REQUIRED_PYTHON_EMIT_SIZE_METRICS - set(metrics)
    assert not missing_metrics, f"jwe missing emit size metrics: {sorted(missing_metrics)}"
    for metric in REQUIRED_PYTHON_EMIT_SIZE_METRICS:
        assert metrics[metric]["count"] >= 1, (metric, metrics[metric])
        assert metrics[metric]["total"] > 0, (metric, metrics[metric])

    assert log_path.exists()
    assert metrics["emit:file_write.raw_bytes"]["total"] == metrics["emit:envelope.raw_bytes"]["total"]
    assert log_path.stat().st_size >= metrics["emit:file_write.raw_bytes"]["total"]
