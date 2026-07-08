from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from .artifact import (
    create_artifact_layout,
    git_dirty,
    git_revision,
    write_env_descriptor,
    write_json,
    write_ndjson,
)
from .cells import BenchCell, expand_local_smoke_cells, expand_paper_cells, make_payload_fields
from .stats import summarize_operation_rows, summarize_stage_rows
from .sufficiency import (
    REQUIRED_EMIT_STAGES,
    REQUIRED_READ_STAGES,
    check_required_stages,
)

TN_PROFILES = ("transaction", "audit", "secure_log", "telemetry", "stdout")
OTEL_HANDLER_MODES = ("none", "null")


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


def _remove_stdout_handlers(yaml_path: Path) -> int:
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    handlers = doc.get("handlers")
    if not isinstance(handlers, list):
        return 0

    kept = [
        handler
        for handler in handlers
        if not (
            isinstance(handler, dict)
            and str(handler.get("kind", "")).strip().lower() == "stdout"
        )
    ]
    removed = len(handlers) - len(kept)
    if removed:
        doc["handlers"] = kept
        yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return removed


def _stdout_handlers_present(yaml_path: Path) -> bool:
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    handlers = doc.get("handlers")
    if not isinstance(handlers, list):
        return False
    return any(
        isinstance(handler, dict)
        and str(handler.get("kind", "")).strip().lower() == "stdout"
        for handler in handlers
    )


def _mark_payload_public(yaml_path: Path) -> None:
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    public_fields = list(doc.get("public_fields") or [])
    for field_name in ("payload", "run_id"):
        if field_name not in public_fields:
            public_fields.append(field_name)
    doc["public_fields"] = public_fields
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _tn_cipher_for_cell(cell: BenchCell) -> str:
    if cell.cipher == "signchain":
        return "btn"
    return cell.cipher


def _runtime_metadata_for_cipher(actual_cipher: str) -> dict[str, str]:
    if actual_cipher == "btn":
        return {
            "dispatch_path": "rust-dispatch",
            "cipher_impl": "tn_core/tn_btn-rust",
            "runtime_path": "rust-dispatch",
        }
    if actual_cipher == "hibe":
        return {
            "dispatch_path": "python-dispatch",
            "cipher_impl": "tn._native.hibe-rust-binding",
            "runtime_path": "python-dispatch/native-hibe",
        }
    if actual_cipher == "jwe":
        return {
            "dispatch_path": "python-dispatch",
            "cipher_impl": "joserfc-cryptography",
            "runtime_path": "python-dispatch/joserfc",
        }
    if actual_cipher == "none":
        return {
            "dispatch_path": "plaintext-file",
            "cipher_impl": "none",
            "runtime_path": "plaintext-file",
        }
    raise ValueError(f"unknown cipher {actual_cipher!r}")


def _otel_extra_handlers(mode: str):
    if mode == "none":
        return None
    if mode == "null":
        from tn.handlers.otel import OpenTelemetryHandler

        return [OpenTelemetryHandler("otel")]
    raise ValueError(f"unknown otel handler mode {mode!r}")


def _init_tn_for_benchmark(
    yaml_path: Path,
    *,
    log_path: Path,
    actual_cipher: str,
    tn_profile: str,
    otel_handler: str,
) -> None:
    import tn

    tn.init(
        yaml_path,
        log_path=log_path,
        cipher=actual_cipher,
        profile=tn_profile,
        stdout=False,
        extra_handlers=_otel_extra_handlers(otel_handler),
    )


def _apply_tn_profile_to_yaml(yaml_path: Path, tn_profile: str) -> bool:
    import tn._profiles as profiles

    prof = profiles.get(tn_profile)
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    ceremony = doc.setdefault("ceremony", {})
    before = json.dumps(ceremony, sort_keys=True, default=str)
    ceremony["profile"] = tn_profile
    ceremony["sign"] = bool(prof.signs)
    ceremony["chain"] = bool(prof.chains)
    after = json.dumps(ceremony, sort_keys=True, default=str)
    if before == after:
        return False
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return True


def _validity_ok_for_profile(valid: dict[str, Any], tn_profile: str) -> bool:
    if tn_profile in {"telemetry", "stdout"}:
        return True
    return valid == {"signature": True, "row_hash": True, "chain": True}


def _required_emit_stages_for_profile(tn_profile: str) -> set[str]:
    if tn_profile in {"telemetry", "stdout"}:
        return REQUIRED_EMIT_STAGES - {"emit:row_hash", "emit:sign"}
    return REQUIRED_EMIT_STAGES


def _required_read_stages_for_profile(tn_profile: str) -> set[str]:
    if tn_profile in {"telemetry", "stdout"}:
        return REQUIRED_READ_STAGES - {
            "read:row_hash_verify",
            "read:signature_verify",
            "read:chain_verify",
        }
    return REQUIRED_READ_STAGES


def _add_extra_recipients(cell: BenchCell, work_dir: Path) -> dict[str, Any]:
    import tn
    import tn.admin

    actual_cipher = _tn_cipher_for_cell(cell)
    runtime_metadata = _runtime_metadata_for_cipher(actual_cipher)
    setup: dict[str, Any] = {
        **runtime_metadata,
        "added_recipients": [],
        "leaf_indices": [],
        "revoked_leaf_indices": [],
        "rotation_result": None,
    }
    if cell.recipients <= 1:
        return setup

    cfg = tn.current_config()
    recipient_root = work_dir / "recipients"
    recipient_root.mkdir(parents=True, exist_ok=True)

    if actual_cipher == "jwe":
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        for idx in range(2, cell.recipients + 1):
            did = f"did:example:jwe-r{idx}"
            sk = X25519PrivateKey.generate()
            pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            result = tn.admin.add_recipient(
                "default",
                recipient_did=did,
                public_key=pub,
                cfg=cfg,
            )
            if result.updated_cfg is not None:
                cfg = result.updated_cfg
            setup["added_recipients"].append(did)
        return setup

    if actual_cipher == "hibe":
        for idx in range(2, cell.recipients + 1):
            did = f"did:example:hibe-r{idx}"
            tn.admin.grant_reader(
                "default",
                reader_did=did,
                out_path=recipient_root / f"hibe-r{idx}.tnpkg",
                cfg=cfg,
            )
            setup["added_recipients"].append(did)
        return setup

    if actual_cipher == "btn":
        for idx in range(2, cell.recipients + 1):
            did = f"did:example:btn-r{idx}"
            out_dir = recipient_root / f"btn-r{idx}"
            out_dir.mkdir(parents=True, exist_ok=True)
            result = tn.admin.add_recipient(
                "default",
                recipient_did=did,
                out_path=out_dir / "default.btn.mykit",
                raw=True,
                cfg=cfg,
            )
            setup["added_recipients"].append(did)
            if result.leaf_index is not None:
                setup["leaf_indices"].append(int(result.leaf_index))
        return setup

    raise ValueError(f"unknown cipher {cell.cipher!r}")


def _btn_revocation_targets(leaf_indices: list[int], revocation: str) -> list[int]:
    leaves = sorted(leaf_indices)
    if revocation == "none" or not leaves:
        return []
    revoke_count = max(1, len(leaves) // 4)
    if revocation == "clustered":
        return leaves[:revoke_count]
    if revocation == "dispersed":
        if revoke_count == 1:
            return [leaves[len(leaves) // 2]]
        indexes = {
            round(i * (len(leaves) - 1) / (revoke_count - 1))
            for i in range(revoke_count)
        }
        return [leaves[idx] for idx in sorted(indexes)]
    raise ValueError(f"unknown BTN revocation state {revocation!r}")


def _apply_btn_revocation_and_rotation(cell: BenchCell, setup: dict[str, Any]) -> None:
    if cell.cipher != "btn":
        return

    import tn
    import tn.admin

    revoked = _btn_revocation_targets(setup["leaf_indices"], cell.revocation)
    for leaf in revoked:
        tn.admin.revoke_recipient("default", leaf_index=leaf)
    setup["revoked_leaf_indices"] = revoked

    if cell.rotation == "post_rotation":
        result = tn.admin.rotate("default")
        setup["rotation_result"] = {
            "cipher": result.cipher,
            "generation": result.generation,
            "cipher_actually_rotated": result.cipher_actually_rotated,
            "prior_epoch": result.prior_epoch,
            "new_epoch": result.new_epoch,
            "renewed_recipients": result.renewed_recipients,
            "renewal_output_dir": str(result.renewal_output_dir)
            if result.renewal_output_dir is not None
            else None,
        }


def _append_line_timed(path: Path, line: str) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter_ns()
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(line)
    return time.perf_counter_ns() - started


def _run_plaintext_cell(
    layout,
    cell: BenchCell,
    *,
    warmup_trials: int,
    trials: int,
    ops: int,
    tn_profile: str,
    otel_handler: str,
) -> tuple[list[dict], list[dict], list[dict]]:
    cell_work = layout.work_dir / cell.id
    log_path = cell_work / "plain.ndjson"
    payload_fields = make_payload_fields(cell.payload_bytes, seed=cell.id)
    payload_json = json.dumps(payload_fields, separators=(",", ":"), sort_keys=True)
    line = json.dumps(
        {"event_type": "bench.local", **payload_fields},
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    line_bytes = len(line.encode("utf-8"))
    payload_bytes = len(payload_json.encode("utf-8"))

    op_rows: list[dict[str, Any]] = []
    stage_rows: list[dict[str, Any]] = []
    metric_rows: list[dict[str, Any]] = []
    runtime_metadata = _runtime_metadata_for_cipher("none")

    write_ndjson(
        layout.raw_dir / f"{cell.id}.ndjson",
        [
            {
                "schema": "tn-bench-cell/v1",
                "cell": cell.id,
                "cipher": cell.cipher,
                "actual_cipher": "none",
                "recipients": cell.recipients,
                "payload_bytes": cell.payload_bytes,
                "revocation": cell.revocation,
                "rotation": cell.rotation,
                "runtime_path": runtime_metadata["runtime_path"],
                "dispatch_path": runtime_metadata["dispatch_path"],
                "cipher_impl": runtime_metadata["cipher_impl"],
                "tn_profile": tn_profile,
                "otel_handler": otel_handler,
                "stdout_handlers_present": False,
                "status": "ok",
            }
        ],
    )

    def emit_trial(trial: int) -> None:
        for i in range(ops):
            lat_ns = _append_line_timed(log_path, line)
            row = {
                "schema": "tn-bench-operation/v1",
                "cell": cell.id,
                "cipher": cell.cipher,
                "op": "emit",
                "trial": trial,
                "i": i,
                "payload_bytes": payload_bytes,
                "wire_bytes": line_bytes,
                "lat_ns": lat_ns,
                "ok": True,
            }
            op_rows.append(row)
            write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", [row])

    for _ in range(warmup_trials):
        emit_trial(0)

    if warmup_trials and log_path.exists():
        log_path.unlink()

    for trial in range(1, trials + 1):
        emit_trial(trial)

    started = time.perf_counter_ns()
    lines = log_path.read_text(encoding="utf-8").splitlines() if log_path.exists() else []
    parsed = [json.loads(raw) for raw in lines if raw]
    batch_lat_ns = time.perf_counter_ns() - started
    ok = all(row.get("payload") == payload_fields["payload"] for row in parsed)
    read_trial = 1
    read_batch = {
        "schema": "tn-bench-read-batch/v1",
        "cell": cell.id,
        "cipher": cell.cipher,
        "op": "read_batch",
        "trial": read_trial,
        "batch_events": len(parsed),
        "batch_lat_ns": batch_lat_ns,
        "payload_bytes": payload_bytes,
        "wire_bytes": line_bytes,
        "ok": ok,
    }
    op_rows.append(read_batch)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", [read_batch])

    per_event_ns = batch_lat_ns // max(1, len(parsed))
    read_rows = [
        {
            "schema": "tn-bench-operation/v1",
            "cell": cell.id,
            "cipher": cell.cipher,
            "op": "read",
            "trial": read_trial,
            "i": i,
            "payload_bytes": payload_bytes,
            "wire_bytes": line_bytes,
            "lat_ns": per_event_ns,
            "derived_from_batch": True,
            "ok": ok,
        }
        for i, _row in enumerate(parsed)
    ]
    op_rows.extend(read_rows)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", read_rows)
    return op_rows, stage_rows, metric_rows


def _run_cell(
    layout,
    cell: BenchCell,
    *,
    warmup_trials: int,
    trials: int,
    ops: int,
    tn_profile: str,
    otel_handler: str,
) -> tuple[list[dict], list[dict], list[dict]]:
    if cell.cipher == "plaintext":
        return _run_plaintext_cell(
            layout,
            cell,
            warmup_trials=warmup_trials,
            trials=trials,
            ops=ops,
            tn_profile=tn_profile,
            otel_handler=otel_handler,
        )

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

    actual_cipher = _tn_cipher_for_cell(cell)
    _init_tn_for_benchmark(
        yaml_path,
        log_path=log_path,
        actual_cipher=actual_cipher,
        tn_profile=tn_profile,
        otel_handler=otel_handler,
    )
    if _apply_tn_profile_to_yaml(yaml_path, tn_profile):
        tn.flush_and_close()
        _init_tn_for_benchmark(
            yaml_path,
            log_path=log_path,
            actual_cipher=actual_cipher,
            tn_profile=tn_profile,
            otel_handler=otel_handler,
        )
    if cell.cipher == "signchain":
        tn.flush_and_close()
        _mark_payload_public(yaml_path)
        _init_tn_for_benchmark(
            yaml_path,
            log_path=log_path,
            actual_cipher=actual_cipher,
            tn_profile=tn_profile,
            otel_handler=otel_handler,
        )
    if _remove_stdout_handlers(yaml_path):
        tn.flush_and_close()
        _init_tn_for_benchmark(
            yaml_path,
            log_path=log_path,
            actual_cipher=actual_cipher,
            tn_profile=tn_profile,
            otel_handler=otel_handler,
        )
    setup = _add_extra_recipients(cell, cell_work)
    _apply_btn_revocation_and_rotation(cell, setup)

    write_ndjson(
        layout.raw_dir / f"{cell.id}.ndjson",
        [
            {
                "schema": "tn-bench-cell/v1",
                "cell": cell.id,
                "cipher": cell.cipher,
                "actual_cipher": actual_cipher,
                "recipients": cell.recipients,
                "payload_bytes": cell.payload_bytes,
                "revocation": cell.revocation,
                "rotation": cell.rotation,
                "runtime_path": setup["runtime_path"],
                "dispatch_path": setup["dispatch_path"],
                "cipher_impl": setup["cipher_impl"],
                "tn_profile": tn_profile,
                "otel_handler": otel_handler,
                "added_recipients": setup["added_recipients"],
                "leaf_indices": setup["leaf_indices"],
                "revoked_leaf_indices": setup["revoked_leaf_indices"],
                "rotation_result": setup["rotation_result"],
                "stdout_handlers_present": _stdout_handlers_present(yaml_path),
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
        _init_tn_for_benchmark(
            yaml_path,
            log_path=log_path,
            actual_cipher=actual_cipher,
            tn_profile=tn_profile,
            otel_handler=otel_handler,
        )

    for trial in range(1, trials + 1):
        emit_trial(trial)

    # Sufficiency gate: every cipher must produce the same emit stage
    # vocabulary (btn via Rust counters, jwe via Python counters, hibe via
    # whichever runtime served the cell). Warmup rows (trial 0) are kept in
    # the artifact but don't count toward the gate.
    measured_emit_stage_rows = [
        row
        for row in stage_rows
        if row.get("op") == "emit" and int(row.get("trial", 0)) >= 1
    ]
    if cell.cipher in {"btn", "jwe", "hibe"}:
        check_required_stages(
            cell.id,
            "emit",
            measured_emit_stage_rows,
            _required_emit_stages_for_profile(tn_profile),
        )

    tn.flush_and_close()

    _init_tn_for_benchmark(
        yaml_path,
        log_path=log_path,
        actual_cipher=actual_cipher,
        tn_profile=tn_profile,
        otel_handler=otel_handler,
    )
    cfg = tn.current_config()
    _reset_perf()
    started = time.perf_counter_ns()
    entries = list(tn.reader.read(log_path, cfg))
    batch_lat_ns = time.perf_counter_ns() - started
    tn.flush_and_close()

    expected_payload = payload_fields["payload"]
    business_entries = [entry for entry in entries if entry["envelope"]["event_type"] == "bench.local"]
    if cell.cipher == "signchain":
        ok = all(
            _validity_ok_for_profile(entry["valid"], tn_profile)
            and entry["envelope"].get("payload") == expected_payload
            and "default" not in entry["plaintext"]
            for entry in business_entries
        )
    else:
        ok = all(
            _validity_ok_for_profile(entry["valid"], tn_profile)
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
    if cell.cipher in {"btn", "jwe", "hibe"}:
        check_required_stages(
            cell.id,
            "read",
            read_stage_rows,
            _required_read_stages_for_profile(tn_profile),
        )
    stage_rows.extend(read_stage_rows)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", read_stage_rows)
    read_metric_rows = _snapshot_metric_rows(cell, "read", read_trial)
    metric_rows.extend(read_metric_rows)
    write_ndjson(layout.raw_dir / f"{cell.id}.ndjson", read_metric_rows)

    return op_rows, stage_rows, metric_rows


def _write_no_stdout_manifest(layout, cells: list[BenchCell]) -> dict[str, Any]:
    checked_cells: list[dict[str, Any]] = []
    for cell in cells:
        if cell.cipher == "plaintext":
            checked_cells.append(
                {
                    "cell": cell.id,
                    "path": "plaintext-file-baseline",
                    "stdout_handlers_present": False,
                }
            )
            continue
        yaml_path = layout.work_dir / cell.id / "publisher" / "tn.yaml"
        checked_cells.append(
            {
                "cell": cell.id,
                "path": str(yaml_path),
                "stdout_handlers_present": _stdout_handlers_present(yaml_path)
                if yaml_path.exists()
                else True,
            }
        )
    manifest = {
        "schema": "tn-bench-no-stdout-manifest/v1",
        "tn_no_stdout": os.environ.get("TN_NO_STDOUT", ""),
        "checked_cells": checked_cells,
        "ok": all(not cell["stdout_handlers_present"] for cell in checked_cells),
    }
    write_json(layout.raw_dir / "no-stdout-manifest.json", manifest)
    return manifest


def _parse_csv_ints(value: str) -> list[int]:
    return [int(v) for v in value.split(",") if v]


def _default_payloads_for_profile(profile: str) -> list[int]:
    if profile == "paper":
        return [64, 256, 1024, 3072, 4096, 32768]
    return [64, 256, 1024]


def _default_recipients_for_profile(profile: str) -> list[int]:
    if profile == "paper":
        return [1, 4, 8, 32]
    return [1, 4, 8]


def _cells_for_profile(
    profile: str,
    *,
    payloads: list[int],
    recipients: list[int],
    btn_stress: bool,
) -> list[BenchCell]:
    if profile == "paper":
        return expand_paper_cells(payloads=payloads, recipients=recipients)
    return expand_local_smoke_cells(
        payloads=payloads,
        recipients=recipients,
        btn_stress=btn_stress,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="local-smoke", choices=["local-smoke", "paper"])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--ops", type=int, default=50)
    parser.add_argument("--warmup-trials", type=int, default=1)
    parser.add_argument("--payloads", default="")
    parser.add_argument("--recipients", default="")
    parser.add_argument("--btn-stress", action="store_true")
    parser.add_argument("--tn-profile", choices=TN_PROFILES, default="transaction")
    parser.add_argument("--otel-handler", choices=OTEL_HANDLER_MODES, default="none")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    os.environ.setdefault("TN_PERF_TRACE", "1")
    os.environ.setdefault("TN_NO_STDOUT", "1")
    root = _repo_root()
    revision = git_revision(root)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    artifact_root = Path(args.out) if args.out else root / "artifacts" / f"bench-artifact-local-{revision}-{stamp}"
    layout = create_artifact_layout(artifact_root)
    write_env_descriptor(layout, revision=revision, dirty=git_dirty(root), argv=sys.argv if argv is None else ["tn_bench.local_perf", *argv])

    payloads = _parse_csv_ints(args.payloads) if args.payloads else _default_payloads_for_profile(args.profile)
    recipients = (
        _parse_csv_ints(args.recipients)
        if args.recipients
        else _default_recipients_for_profile(args.profile)
    )
    cells = _cells_for_profile(
        args.profile,
        payloads=payloads,
        recipients=recipients,
        btn_stress=args.btn_stress,
    )
    write_json(
        layout.raw_dir / "config.json",
        {
            "schema": "tn-bench-config/v1",
            "profile": args.profile,
            "payloads": payloads,
            "recipients": recipients,
            "trials": args.trials,
            "ops": args.ops,
            "warmup_trials": args.warmup_trials,
            "btn_stress": bool(args.btn_stress),
            "tn_profile": args.tn_profile,
            "otel_handler": args.otel_handler,
            "cell_count": len(cells),
            "read_sampling": "batch-derived per-event rows",
            "stage_sampling": "aggregate counters; stage summary reports means only",
        },
    )
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
            tn_profile=args.tn_profile,
            otel_handler=args.otel_handler,
        )
        all_ops.extend(ops)
        all_stages.extend(stages)
        all_metrics.extend(metrics)

    no_stdout_manifest = _write_no_stdout_manifest(layout, cells)
    if not no_stdout_manifest["ok"]:
        raise AssertionError("stdout handlers remain in benchmark cell yaml")

    write_json(layout.stats_dir / "summary.json", summarize_operation_rows(all_ops))
    write_json(layout.stats_dir / "stage-summary.json", summarize_stage_rows(all_stages))
    write_json(layout.stats_dir / "metric-summary.json", all_metrics)
    print(f"artifact: {layout.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
