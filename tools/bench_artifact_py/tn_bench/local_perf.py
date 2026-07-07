from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from .artifact import (
    create_artifact_layout,
    git_dirty,
    git_revision,
    write_env_descriptor,
    write_json,
    write_ndjson,
)
from .cells import BenchCell, expand_local_smoke_cells, make_payload_fields
from .stats import summarize_operation_rows
from .sufficiency import REQUIRED_READ_STAGES, check_required_stages


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _import_perf_modules():
    from tn import _perf

    try:
        from tn._native import core as rust_core
    except Exception:  # pragma: no cover - platform-dependent
        rust_core = None
    return _perf, rust_core


def _reset_perf() -> None:
    py_perf, rust_core = _import_perf_modules()
    py_perf.reset()
    if rust_core is not None and hasattr(rust_core, "perf_reset"):
        rust_core.perf_reset()


def _snapshot_stage_rows(cell: BenchCell, op: str, trial: int) -> list[dict[str, Any]]:
    py_perf, rust_core = _import_perf_modules()
    rows: list[dict[str, Any]] = []
    for source, snapshot in [("python", py_perf.snapshot())]:
        for stage, count, total_ns in snapshot:
            rows.append(
                {
                    "schema": "tn-bench-stage/v1",
                    "cell": cell.id,
                    "cipher": cell.cipher,
                    "op": op,
                    "trial": trial,
                    "stage": stage,
                    "source": source,
                    "count": count,
                    "total_ns": total_ns,
                    "avg_ns": total_ns // count if count else 0,
                }
            )
    if rust_core is not None and hasattr(rust_core, "perf_snapshot"):
        for stage, count, total_ns in rust_core.perf_snapshot():
            rows.append(
                {
                    "schema": "tn-bench-stage/v1",
                    "cell": cell.id,
                    "cipher": cell.cipher,
                    "op": op,
                    "trial": trial,
                    "stage": stage,
                    "source": "rust",
                    "count": count,
                    "total_ns": total_ns,
                    "avg_ns": total_ns // count if count else 0,
                }
            )
    return rows


def _snapshot_metric_rows(cell: BenchCell, op: str, trial: int) -> list[dict[str, Any]]:
    py_perf, _rust_core = _import_perf_modules()
    rows: list[dict[str, Any]] = []
    snapshot_metrics = getattr(py_perf, "snapshot_metrics", None)
    if snapshot_metrics is None:
        return rows
    for metric, count, total, min_value, max_value in snapshot_metrics():
        rows.append(
            {
                "schema": "tn-bench-metric/v1",
                "cell": cell.id,
                "cipher": cell.cipher,
                "op": op,
                "trial": trial,
                "metric": metric,
                "source": "python",
                "count": count,
                "total": total,
                "min": min_value,
                "max": max_value,
                "avg": total // count if count else 0,
            }
        )
    return rows


def _last_wire_bytes(log_path: Path) -> int:
    if not log_path.exists():
        return 0
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    return len(lines[-1].encode("utf-8")) + 1 if lines else 0


def _add_extra_recipients(cell: BenchCell, work_dir: Path) -> str:
    import tn
    import tn.admin

    if cell.recipients <= 1:
        return "rust-dispatch" if cell.cipher == "btn" else "python-runtime"

    cfg = tn.current_config()
    recipient_root = work_dir / "recipients"
    recipient_root.mkdir(parents=True, exist_ok=True)

    if cell.cipher == "jwe":
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        for idx in range(2, cell.recipients + 1):
            sk = X25519PrivateKey.generate()
            pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            result = tn.admin.add_recipient(
                "default",
                recipient_did=f"did:example:jwe-r{idx}",
                public_key=pub,
                cfg=cfg,
            )
            if result.updated_cfg is not None:
                cfg = result.updated_cfg
        return "python-runtime"

    if cell.cipher == "hibe":
        for idx in range(2, cell.recipients + 1):
            tn.admin.grant_reader(
                "default",
                reader_did=f"did:example:hibe-r{idx}",
                out_path=recipient_root / f"hibe-r{idx}.tnpkg",
                cfg=cfg,
            )
        return "python-runtime"

    if cell.cipher == "btn":
        for idx in range(2, cell.recipients + 1):
            out_dir = recipient_root / f"btn-r{idx}"
            out_dir.mkdir(parents=True, exist_ok=True)
            tn.admin.add_recipient(
                "default",
                recipient_did=f"did:example:btn-r{idx}",
                out_path=out_dir / "default.btn.mykit",
                raw=True,
                cfg=cfg,
            )
        return "rust-dispatch"

    raise ValueError(f"unknown cipher {cell.cipher!r}")


def _run_cell(layout, cell: BenchCell, *, warmup_trials: int, trials: int, ops: int) -> tuple[list[dict], list[dict], list[dict]]:
    import tn
    import tn.reader

    cell_work = layout.work_dir / cell.id
    publisher = cell_work / "publisher"
    yaml_path = publisher / "tn.yaml"
    log_path = publisher / "logs" / "tn.ndjson"
    payload_fields = make_payload_fields(cell.payload_bytes, seed=cell.id)
    payload_json = json.dumps(payload_fields, separators=(",", ":"), sort_keys=True)

    op_rows: list[dict[str, Any]] = []
    stage_rows: list[dict[str, Any]] = []
    metric_rows: list[dict[str, Any]] = []

    tn.init(yaml_path, log_path=log_path, cipher=cell.cipher)
    runtime_path = _add_extra_recipients(cell, cell_work)

    write_ndjson(
        layout.raw_dir / f"{cell.id}.ndjson",
        [
            {
                "schema": "tn-bench-cell/v1",
                "cell": cell.id,
                "cipher": cell.cipher,
                "recipients": cell.recipients,
                "payload_bytes": cell.payload_bytes,
                "revocation": cell.revocation,
                "runtime_path": runtime_path,
                "status": "ok",
            }
        ],
    )

    def emit_trial(trial: int) -> None:
        _reset_perf()
        for i in range(ops):
            started = time.perf_counter_ns()
            ok = True
            try:
                tn.info("bench.local", **payload_fields)
            except Exception:
                ok = False
                raise
            finally:
                lat_ns = time.perf_counter_ns() - started
            row = {
                "schema": "tn-bench-operation/v1",
                "cell": cell.id,
                "cipher": cell.cipher,
                "op": "emit",
                "trial": trial,
                "i": i,
                "payload_bytes": len(payload_json.encode("utf-8")),
                "wire_bytes": _last_wire_bytes(log_path),
                "lat_ns": lat_ns,
                "ok": ok,
            }
            op_rows.append(row)
            write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", [row])
        emit_stage_rows = _snapshot_stage_rows(cell, "emit", trial)
        stage_rows.extend(emit_stage_rows)
        write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", emit_stage_rows)
        emit_metric_rows = _snapshot_metric_rows(cell, "emit", trial)
        metric_rows.extend(emit_metric_rows)
        write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", emit_metric_rows)

    for _ in range(warmup_trials):
        emit_trial(0)

    if warmup_trials:
        tn.flush_and_close()
        if log_path.exists():
            log_path.unlink()
        tn.init(yaml_path, log_path=log_path, cipher=cell.cipher)

    for trial in range(1, trials + 1):
        emit_trial(trial)

    tn.flush_and_close()

    tn.init(yaml_path, log_path=log_path, cipher=cell.cipher)
    cfg = tn.current_config()
    _reset_perf()
    started = time.perf_counter_ns()
    entries = list(tn.reader.read(log_path, cfg))
    batch_lat_ns = time.perf_counter_ns() - started
    tn.flush_and_close()

    expected_payload = payload_fields["payload"]
    business_entries = [entry for entry in entries if entry["envelope"]["event_type"] == "bench.local"]
    ok = all(
        entry["valid"] == {"signature": True, "row_hash": True, "chain": True}
        and entry["plaintext"]["default"]["payload"] == expected_payload
        for entry in business_entries
    )
    read_trial = 1
    read_batch = {
        "schema": "tn-bench-read-batch/v1",
        "cell": cell.id,
        "cipher": cell.cipher,
        "op": "read_batch",
        "trial": read_trial,
        "batch_events": len(business_entries),
        "batch_lat_ns": batch_lat_ns,
        "payload_bytes": len(payload_json.encode("utf-8")),
        "ok": ok,
    }
    op_rows.append(read_batch)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", [read_batch])

    per_event_ns = batch_lat_ns // max(1, len(business_entries))
    derived_rows = []
    for i, _entry in enumerate(business_entries):
        derived_rows.append(
            {
                "schema": "tn-bench-operation/v1",
                "cell": cell.id,
                "cipher": cell.cipher,
                "op": "read",
                "trial": read_trial,
                "i": i,
                "payload_bytes": len(payload_json.encode("utf-8")),
                "lat_ns": per_event_ns,
                "derived_from_batch": True,
                "ok": ok,
            }
        )
    op_rows.extend(derived_rows)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", derived_rows)

    read_stage_rows = _snapshot_stage_rows(cell, "read", read_trial)
    check_required_stages(cell.id, "read", read_stage_rows, REQUIRED_READ_STAGES)
    stage_rows.extend(read_stage_rows)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", read_stage_rows)
    read_metric_rows = _snapshot_metric_rows(cell, "read", read_trial)
    metric_rows.extend(read_metric_rows)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", read_metric_rows)

    return op_rows, stage_rows, metric_rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="local-smoke", choices=["local-smoke"])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--ops", type=int, default=50)
    parser.add_argument("--warmup-trials", type=int, default=1)
    parser.add_argument("--payloads", default="64,256,1024")
    parser.add_argument("--recipients", default="1,4,8")
    parser.add_argument("--btn-stress", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    os.environ.setdefault("TN_PERF_TRACE", "1")
    root = _repo_root()
    revision = git_revision(root)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    artifact_root = Path(args.out) if args.out else root / "artifacts" / f"bench-artifact-local-{revision}-{stamp}"
    layout = create_artifact_layout(artifact_root)
    write_env_descriptor(layout, revision=revision, dirty=git_dirty(root), argv=sys.argv if argv is None else ["tn_bench.local_perf", *argv])

    payloads = [int(v) for v in args.payloads.split(",") if v]
    recipients = [int(v) for v in args.recipients.split(",") if v]
    cells = expand_local_smoke_cells(payloads=payloads, recipients=recipients, btn_stress=args.btn_stress)
    write_json(layout.raw_dir / "cells.json", [cell.__dict__ | {"id": cell.id} for cell in cells])

    all_ops: list[dict[str, Any]] = []
    all_stages: list[dict[str, Any]] = []
    all_metrics: list[dict[str, Any]] = []
    for cell in cells:
        ops, stages, metrics = _run_cell(
            layout,
            cell,
            warmup_trials=args.warmup_trials,
            trials=args.trials,
            ops=args.ops,
        )
        all_ops.extend(ops)
        all_stages.extend(stages)
        all_metrics.extend(metrics)

    write_json(layout.stats_dir / "summary.json", summarize_operation_rows(all_ops))
    write_json(layout.stats_dir / "stage-summary.json", all_stages)
    write_json(layout.stats_dir / "metric-summary.json", all_metrics)
    print(f"artifact: {layout.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
