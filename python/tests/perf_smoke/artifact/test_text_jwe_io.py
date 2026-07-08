from __future__ import annotations

import json
from pathlib import Path

from tn_bench.text_jwe_io import (
    DEFAULT_PAYLOADS,
    make_jwe_context,
    make_text_payload,
    open_jwe_payload,
    run_benchmark,
    seal_jwe_payload,
    summarize_io_rows,
)


def test_text_payloads_include_small_1k_and_3k() -> None:
    assert DEFAULT_PAYLOADS == (64, 256, 1024, 3072)

    for payload_bytes in DEFAULT_PAYLOADS:
        payload = make_text_payload(payload_bytes)
        assert len(payload) == payload_bytes
        assert payload.decode("utf-8")


def test_jwe_payload_round_trips_and_records_larger_total_size() -> None:
    context = make_jwe_context()
    payload = make_text_payload(64)

    encrypted = seal_jwe_payload(context, payload)

    assert len(encrypted) > len(payload)
    assert open_jwe_payload(context, encrypted) == payload


def test_summarize_io_rows_excludes_warmup_and_preserves_sizes() -> None:
    rows = [
        {
            "cell": "plain.p64b",
            "mode": "plain",
            "op": "write",
            "trial": 0,
            "lat_ns": 999,
            "payload_bytes": 64,
            "total_bytes": 64,
            "ok": True,
        },
        {
            "cell": "plain.p64b",
            "mode": "plain",
            "op": "write",
            "trial": 1,
            "lat_ns": 100,
            "payload_bytes": 64,
            "total_bytes": 64,
            "ok": True,
        },
        {
            "cell": "plain.p64b",
            "mode": "plain",
            "op": "write",
            "trial": 1,
            "lat_ns": 300,
            "payload_bytes": 64,
            "total_bytes": 64,
            "ok": True,
        },
    ]

    summary = summarize_io_rows(rows)

    write_summary = summary["plain.p64b"]["write"]
    assert write_summary["count"] == 2
    assert write_summary["p50_ns"] == 100
    assert write_summary["p95_ns"] == 300
    assert write_summary["payload_bytes"] == 64
    assert write_summary["total_bytes_p50"] == 64


def test_text_jwe_io_benchmark_writes_raw_rows_and_summary(tmp_path: Path) -> None:
    layout, summary = run_benchmark(
        tmp_path / "artifact",
        payloads=[64],
        trials=2,
        ops_per_trial=2,
        warmup_trials=1,
    )

    assert (layout.work_dir / "plain.p64b").is_dir()
    assert (layout.work_dir / "jwe.p64b").is_dir()

    plain_rows = [
        json.loads(line)
        for line in (layout.raw_dir / "plain.p64b.ndjson").read_text(encoding="utf-8").splitlines()
    ]
    jwe_rows = [
        json.loads(line)
        for line in (layout.raw_dir / "jwe.p64b.ndjson").read_text(encoding="utf-8").splitlines()
    ]

    assert {row["op"] for row in plain_rows} == {"read", "write"}
    assert {row["op"] for row in jwe_rows} == {"decrypt", "encrypt", "read", "write"}
    assert summary["plain.p64b"]["write"]["count"] == 4
    assert summary["jwe.p64b"]["read"]["count"] == 4
    assert summary["jwe.p64b"]["write"]["total_bytes_p50"] > 64
    assert json.loads((layout.stats_dir / "summary.json").read_text(encoding="utf-8")) == summary
