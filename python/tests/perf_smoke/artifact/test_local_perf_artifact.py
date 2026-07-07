from __future__ import annotations

import json
from pathlib import Path

import pytest

from tn_bench.artifact import create_artifact_layout, write_env_descriptor, write_ndjson
from tn_bench.cells import expand_local_smoke_cells, make_payload_fields
from tn_bench.local_perf import _snapshot_metric_rows
from tn_bench.stats import summarize_operation_rows
from tn_bench.sufficiency import REQUIRED_READ_STAGES, check_required_stages


def test_payload_fields_match_exact_canonical_sizes() -> None:
    for payload_bytes in [64, 256, 1024]:
        fields = make_payload_fields(payload_bytes, seed=f"p{payload_bytes}")
        encoded = json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
        assert len(encoded) == payload_bytes


def test_local_smoke_expands_three_ciphers_payloads_and_recipients() -> None:
    cells = expand_local_smoke_cells(payloads=[64, 256, 1024], recipients=[1, 4, 8])
    assert len(cells) == 27
    assert {cell.cipher for cell in cells} == {"btn", "jwe", "hibe"}
    assert {cell.payload_bytes for cell in cells} == {64, 256, 1024}
    assert {cell.recipients for cell in cells} == {1, 4, 8}
    assert "jwe.r4.p256b.none" in {cell.id for cell in cells}


def test_stats_exclude_warmup_rows() -> None:
    rows = [
        {"cell": "btn.r1.p64b.none", "op": "emit", "trial": 0, "lat_ns": 999, "ok": True},
        {"cell": "btn.r1.p64b.none", "op": "emit", "trial": 1, "lat_ns": 100, "ok": True},
        {"cell": "btn.r1.p64b.none", "op": "emit", "trial": 1, "lat_ns": 300, "ok": True},
    ]
    summary = summarize_operation_rows(rows)
    cell_summary = summary["btn.r1.p64b.none"]["emit"]
    assert cell_summary["count"] == 2
    assert cell_summary["p50_ns"] == 100
    assert cell_summary["p95_ns"] == 300


def test_sufficiency_fails_when_required_stage_is_missing() -> None:
    stage_rows = [
        {
            "schema": "tn-bench-stage/v1",
            "cell": "jwe.r1.p64b.none",
            "op": "read",
            "stage": stage,
            "count": 1,
            "total_ns": 1,
        }
        for stage in sorted(REQUIRED_READ_STAGES - {"read:signature_verify"})
    ]
    with pytest.raises(AssertionError, match="read:signature_verify"):
        check_required_stages("jwe.r1.p64b.none", "read", stage_rows, REQUIRED_READ_STAGES)


def test_artifact_layout_writes_env_and_ndjson(tmp_path: Path) -> None:
    layout = create_artifact_layout(tmp_path / "artifact")
    env = write_env_descriptor(layout, revision="abc123", dirty=True)
    assert env["environment_class"] == "local_windows_smoke"
    assert env["revision"] == "abc123"
    assert env["dirty"] is True

    out = layout.raw_dir / "sample.ndjson"
    write_ndjson(out, [{"a": 1}, {"b": 2}])
    assert [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()] == [
        {"a": 1},
        {"b": 2},
    ]


def test_metric_snapshot_rows_preserve_size_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakePerf:
        @staticmethod
        def snapshot_metrics():
            return [("emit:file_write.raw_bytes", 2, 128, 64, 64)]

    monkeypatch.setattr("tn_bench.local_perf._import_perf_modules", lambda: (FakePerf, None))
    cell = expand_local_smoke_cells(payloads=[64], recipients=[1])[0]

    rows = _snapshot_metric_rows(cell, "emit", 1)

    assert rows == [
        {
            "schema": "tn-bench-metric/v1",
            "cell": cell.id,
            "cipher": cell.cipher,
            "op": "emit",
            "trial": 1,
            "metric": "emit:file_write.raw_bytes",
            "source": "python",
            "count": 2,
            "total": 128,
            "min": 64,
            "max": 64,
            "avg": 64,
        }
    ]
