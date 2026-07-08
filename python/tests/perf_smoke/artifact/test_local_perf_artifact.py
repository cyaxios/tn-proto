from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tn_bench.artifact import create_artifact_layout, write_env_descriptor, write_ndjson
from tn_bench.cells import expand_local_smoke_cells, expand_paper_cells, make_payload_fields
from tn_bench.local_perf import (
    main as local_perf_main,
    _mark_payload_public,
    _remove_stdout_handlers,
    _runtime_metadata_for_cipher,
    _snapshot_metric_rows,
    _stdout_handlers_present,
    _tn_cipher_for_cell,
)
from tn_bench.stats import summarize_operation_rows, summarize_stage_rows
from tn_bench.sufficiency import REQUIRED_READ_STAGES, check_required_stages


def test_payload_fields_match_exact_canonical_sizes() -> None:
    for payload_bytes in [64, 256, 1024, 3072, 4096, 32768]:
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


def test_paper_profile_expands_full_cipher_recipient_matrix() -> None:
    cells = expand_paper_cells(payloads=[1024], recipients=[1, 4])
    ids = {cell.id for cell in cells}

    assert "btn.r4.p1k.clustered.post_rotation" in ids
    assert "btn.r4.p1k.dispersed.pre_rotation" in ids
    assert "jwe.r4.p1k.none" in ids
    assert "hibe.r4.p1k.none" in ids
    assert "plaintext.r0.p1k.none" in ids
    assert "signchain.r0.p1k.none" in ids
    assert {cell.recipients for cell in cells if cell.cipher in {"btn", "jwe", "hibe"}} == {1, 4}


def test_stats_exclude_warmup_rows() -> None:
    rows = [
        {
            "cell": "btn.r1.p64b.none",
            "op": "emit",
            "trial": 0,
            "lat_ns": 999,
            "wire_bytes": 99,
            "payload_bytes": 64,
            "ok": True,
        },
        {
            "cell": "btn.r1.p64b.none",
            "op": "emit",
            "trial": 1,
            "lat_ns": 100,
            "wire_bytes": 500,
            "payload_bytes": 64,
            "ok": True,
        },
        {
            "cell": "btn.r1.p64b.none",
            "op": "emit",
            "trial": 1,
            "lat_ns": 300,
            "wire_bytes": 700,
            "payload_bytes": 64,
            "ok": True,
        },
    ]
    summary = summarize_operation_rows(rows)
    cell_summary = summary["btn.r1.p64b.none"]["emit"]
    assert cell_summary["count"] == 2
    assert cell_summary["p50_ns"] == 100
    assert cell_summary["p95_ns"] == 300
    assert cell_summary["mean_ns"] == 200
    assert cell_summary["stdev_ns"] == 141
    assert cell_summary["payload_bytes"] == 64
    assert cell_summary["wire_bytes_p50"] == 500
    assert cell_summary["wire_bytes_p95"] == 700


def test_stage_summary_reports_aggregate_means_only() -> None:
    rows = [
        {
            "cell": "btn.r1.p64b.none",
            "op": "emit",
            "stage": "emit:file_write",
            "trial": 1,
            "count": 2,
            "total_ns": 100,
        },
        {
            "cell": "btn.r1.p64b.none",
            "op": "emit",
            "stage": "emit:file_write",
            "trial": 2,
            "count": 3,
            "total_ns": 300,
        },
    ]

    summary = summarize_stage_rows(rows)

    file_write = summary["btn.r1.p64b.none"]["emit"]["emit:file_write"]
    assert file_write == {
        "count": 5,
        "trials": 2,
        "total_ns": 400,
        "mean_ns": 80,
    }


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


def test_remove_stdout_handlers_preserves_file_handlers(tmp_path: Path) -> None:
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "handlers": [
                    {
                        "kind": "file.rotating",
                        "name": "main",
                        "path": "./logs/tn.ndjson",
                    },
                    {"kind": "stdout"},
                    {"kind": "stdout", "name": "mirror"},
                ],
                "logs": {"path": "./logs/tn.ndjson"},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    removed = _remove_stdout_handlers(yaml_path)

    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert removed == 2
    assert doc["handlers"] == [
        {
            "kind": "file.rotating",
            "name": "main",
            "path": "./logs/tn.ndjson",
        }
    ]
    assert doc["logs"] == {"path": "./logs/tn.ndjson"}


def test_signchain_cell_uses_btn_runtime_and_public_payload(tmp_path: Path) -> None:
    cell = expand_paper_cells(payloads=[64], recipients=[1])[1]
    assert cell.cipher == "signchain"
    assert _tn_cipher_for_cell(cell) == "btn"

    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "ceremony": {"cipher": "btn"},
                "public_fields": ["event_id"],
                "handlers": [{"kind": "file.rotating", "path": "./logs/tn.ndjson"}],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    _mark_payload_public(yaml_path)

    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert doc["public_fields"] == ["event_id", "payload", "run_id"]
    assert _stdout_handlers_present(yaml_path) is False


def test_runtime_metadata_distinguishes_hibe_dispatch_from_cipher_binding() -> None:
    assert _runtime_metadata_for_cipher("hibe") == {
        "dispatch_path": "python-dispatch",
        "cipher_impl": "tn._native.hibe-rust-binding",
        "runtime_path": "python-dispatch/native-hibe",
    }
    assert _runtime_metadata_for_cipher("jwe")["cipher_impl"] == "joserfc-cryptography"
    assert _runtime_metadata_for_cipher("btn")["dispatch_path"] == "rust-dispatch"


def test_local_perf_records_telemetry_profile_and_otel_handler(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifact"

    rc = local_perf_main(
        [
            "--profile",
            "local-smoke",
            "--payloads",
            "64",
            "--recipients",
            "1",
            "--trials",
            "1",
            "--ops",
            "1",
            "--warmup-trials",
            "0",
            "--tn-profile",
            "telemetry",
            "--otel-handler",
            "null",
            "--out",
            str(out_dir),
        ]
    )

    assert rc == 0
    config = json.loads((out_dir / "raw" / "config.json").read_text(encoding="utf-8"))
    assert config["tn_profile"] == "telemetry"
    assert config["otel_handler"] == "null"

    cell_rows = [
        json.loads(line)
        for line in (out_dir / "raw" / "jwe.r1.p64b.none.ndjson")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    cell_meta = next(row for row in cell_rows if row["schema"] == "tn-bench-cell/v1")
    assert cell_meta["tn_profile"] == "telemetry"
    assert cell_meta["otel_handler"] == "null"
    assert cell_meta["stdout_handlers_present"] is False

    yaml_path = out_dir / "work" / "jwe.r1.p64b.none" / "publisher" / "tn.yaml"
    yaml_doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert yaml_doc["ceremony"]["profile"] == "telemetry"
    assert yaml_doc["ceremony"]["sign"] is False
    assert yaml_doc["ceremony"]["chain"] is False
    assert not _stdout_handlers_present(yaml_path)
