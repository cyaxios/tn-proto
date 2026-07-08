from __future__ import annotations

import argparse
import math
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tn.cipher import _jwe_open, _jwe_seal

from .artifact import (
    ArtifactLayout,
    create_artifact_layout,
    git_dirty,
    git_revision,
    write_env_descriptor,
    write_json,
    write_ndjson,
)
from .cells import payload_label

DEFAULT_PAYLOADS = (64, 256, 1024, 3072)
DEFAULT_TRIALS = 3
DEFAULT_OPS_PER_TRIAL = 100
DEFAULT_WARMUP_TRIALS = 1
SCHEMA = "tn-bench-text-jwe-io/v1"


@dataclass(frozen=True)
class JweContext:
    private_key: X25519PrivateKey
    public_key: bytes


def _payload_label(payload_bytes: int) -> str:
    if payload_bytes == 3072:
        return "p3k"
    return payload_label(payload_bytes)


def make_text_payload(payload_bytes: int) -> bytes:
    if payload_bytes <= 0:
        raise ValueError("payload_bytes must be positive")
    return b"x" * payload_bytes


def make_jwe_context() -> JweContext:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return JweContext(private_key=private_key, public_key=public_key)


def seal_jwe_payload(context: JweContext, payload: bytes) -> bytes:
    return _jwe_seal([context.public_key], payload, b"")


def open_jwe_payload(context: JweContext, encrypted: bytes) -> bytes:
    return _jwe_open(encrypted, context.private_key, b"")


def _percentile(sorted_values: list[int], p: float) -> int:
    if not sorted_values:
        return 0
    rank = max(1, int(math.ceil(p * len(sorted_values))))
    return sorted_values[min(rank - 1, len(sorted_values) - 1)]


def _mean(values: list[int]) -> int:
    if not values:
        return 0
    return int(round(sum(values) / len(values)))


def _stdev(values: list[int]) -> int:
    if len(values) < 2:
        return 0
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    return int(round(math.sqrt(variance)))


def _summarize_ints(values: list[int], suffix: str = "") -> dict[str, int]:
    sorted_values = sorted(values)
    return {
        f"min{suffix}": sorted_values[0] if sorted_values else 0,
        f"p50{suffix}": _percentile(sorted_values, 0.50),
        f"p95{suffix}": _percentile(sorted_values, 0.95),
        f"p99{suffix}": _percentile(sorted_values, 0.99),
        f"max{suffix}": sorted_values[-1] if sorted_values else 0,
        f"mean{suffix}": _mean(sorted_values),
        f"stdev{suffix}": _stdev(sorted_values),
    }


def _summarize_total_bytes(values: list[int]) -> dict[str, int]:
    summary = _summarize_ints(values)
    return {f"total_bytes_{key}": value for key, value in summary.items()}


def summarize_io_rows(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, dict[str, int]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if int(row.get("trial", 0)) == 0:
            continue
        grouped[(str(row["cell"]), str(row["op"]))].append(row)

    out: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for (cell, op), items in grouped.items():
        latencies = [int(item["lat_ns"]) for item in items]
        total_sizes = [int(item["total_bytes"]) for item in items]
        payload_sizes = {int(item["payload_bytes"]) for item in items}
        out[cell][op] = {
            "count": len(items),
            "failures": sum(1 for item in items if not item.get("ok", False)),
            "payload_bytes": payload_sizes.pop() if len(payload_sizes) == 1 else 0,
            **_summarize_ints(latencies, "_ns"),
            **_summarize_total_bytes(total_sizes),
        }
    return {cell: dict(ops) for cell, ops in out.items()}


def _base_row(
    *,
    cell: str,
    mode: str,
    op: str,
    trial: int,
    sample: int,
    payload_bytes: int,
    total_bytes: int,
    lat_ns: int,
    ok: bool,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "cell": cell,
        "mode": mode,
        "op": op,
        "trial": trial,
        "sample": sample,
        "payload_bytes": payload_bytes,
        "total_bytes": total_bytes,
        "lat_ns": lat_ns,
        "ok": ok,
    }


def _write_timed(path: Path, data: bytes) -> int:
    start = time.perf_counter_ns()
    path.write_bytes(data)
    return time.perf_counter_ns() - start


def _read_timed(path: Path) -> tuple[bytes, int]:
    start = time.perf_counter_ns()
    data = path.read_bytes()
    return data, time.perf_counter_ns() - start


def _benchmark_payload(
    layout: ArtifactLayout,
    *,
    payload_bytes: int,
    trials: int,
    ops_per_trial: int,
    warmup_trials: int,
) -> list[dict[str, Any]]:
    payload = make_text_payload(payload_bytes)
    context = make_jwe_context()
    encrypted_seed = seal_jwe_payload(context, payload)
    rows: list[dict[str, Any]] = []

    plain_cell = f"plain.{_payload_label(payload_bytes)}"
    plain_dir = layout.work_dir / plain_cell
    plain_dir.mkdir(parents=True, exist_ok=True)

    jwe_cell = f"jwe.{_payload_label(payload_bytes)}"
    jwe_dir = layout.work_dir / jwe_cell
    jwe_dir.mkdir(parents=True, exist_ok=True)

    total_trials = warmup_trials + trials
    for trial in range(total_trials):
        for sample in range(ops_per_trial):
            plain_path = plain_dir / f"trial-{trial:03d}-sample-{sample:05d}.txt"
            lat_ns = _write_timed(plain_path, payload)
            rows.append(
                _base_row(
                    cell=plain_cell,
                    mode="plain",
                    op="write",
                    trial=trial,
                    sample=sample,
                    payload_bytes=payload_bytes,
                    total_bytes=len(payload),
                    lat_ns=lat_ns,
                    ok=True,
                )
            )

            read_back, lat_ns = _read_timed(plain_path)
            rows.append(
                _base_row(
                    cell=plain_cell,
                    mode="plain",
                    op="read",
                    trial=trial,
                    sample=sample,
                    payload_bytes=payload_bytes,
                    total_bytes=len(read_back),
                    lat_ns=lat_ns,
                    ok=read_back == payload,
                )
            )

            start = time.perf_counter_ns()
            encrypted = seal_jwe_payload(context, payload)
            lat_ns = time.perf_counter_ns() - start
            rows.append(
                _base_row(
                    cell=jwe_cell,
                    mode="jwe",
                    op="encrypt",
                    trial=trial,
                    sample=sample,
                    payload_bytes=payload_bytes,
                    total_bytes=len(encrypted),
                    lat_ns=lat_ns,
                    ok=True,
                )
            )

            start = time.perf_counter_ns()
            decrypted = open_jwe_payload(context, encrypted)
            lat_ns = time.perf_counter_ns() - start
            rows.append(
                _base_row(
                    cell=jwe_cell,
                    mode="jwe",
                    op="decrypt",
                    trial=trial,
                    sample=sample,
                    payload_bytes=payload_bytes,
                    total_bytes=len(encrypted),
                    lat_ns=lat_ns,
                    ok=decrypted == payload,
                )
            )

            jwe_path = jwe_dir / f"trial-{trial:03d}-sample-{sample:05d}.jwe.json"
            lat_ns = _write_timed(jwe_path, encrypted_seed)
            rows.append(
                _base_row(
                    cell=jwe_cell,
                    mode="jwe",
                    op="write",
                    trial=trial,
                    sample=sample,
                    payload_bytes=payload_bytes,
                    total_bytes=len(encrypted_seed),
                    lat_ns=lat_ns,
                    ok=True,
                )
            )

            read_back, lat_ns = _read_timed(jwe_path)
            rows.append(
                _base_row(
                    cell=jwe_cell,
                    mode="jwe",
                    op="read",
                    trial=trial,
                    sample=sample,
                    payload_bytes=payload_bytes,
                    total_bytes=len(read_back),
                    lat_ns=lat_ns,
                    ok=read_back == encrypted_seed,
                )
            )

    write_ndjson(layout.raw_dir / f"{plain_cell}.ndjson", [row for row in rows if row["cell"] == plain_cell])
    write_ndjson(layout.raw_dir / f"{jwe_cell}.ndjson", [row for row in rows if row["cell"] == jwe_cell])
    return rows


def run_benchmark(
    root: Path,
    *,
    payloads: Sequence[int] = DEFAULT_PAYLOADS,
    trials: int = DEFAULT_TRIALS,
    ops_per_trial: int = DEFAULT_OPS_PER_TRIAL,
    warmup_trials: int = DEFAULT_WARMUP_TRIALS,
) -> tuple[ArtifactLayout, dict[str, dict[str, dict[str, int]]]]:
    layout = create_artifact_layout(root)
    rows: list[dict[str, Any]] = []
    for payload_bytes in payloads:
        rows.extend(
            _benchmark_payload(
                layout,
                payload_bytes=int(payload_bytes),
                trials=trials,
                ops_per_trial=ops_per_trial,
                warmup_trials=warmup_trials,
            )
        )

    summary = summarize_io_rows(rows)
    write_json(
        layout.raw_dir / "config.json",
        {
            "schema": "tn-bench-text-jwe-io-config/v1",
            "payloads": [int(payload) for payload in payloads],
            "trials": trials,
            "ops_per_trial": ops_per_trial,
            "warmup_trials": warmup_trials,
            "modes": ["plain", "jwe"],
            "plain_ops": ["write", "read"],
            "jwe_ops": ["encrypt", "decrypt", "write", "read"],
            "io_scope": "file timers include only Path.write_bytes/Path.read_bytes",
            "jwe_scope": "JWE encrypt/decrypt timers are recorded separately from file IO",
        },
    )

    repo_root = Path.cwd()
    write_env_descriptor(
        layout,
        revision=git_revision(repo_root),
        dirty=git_dirty(repo_root),
        argv=sys.argv,
    )
    write_json(layout.stats_dir / "summary.json", summary)
    return layout, summary


def _parse_payloads(value: str) -> tuple[int, ...]:
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark plain text vs JWE text file IO.")
    parser.add_argument("--out", type=Path, required=True, help="Artifact output directory.")
    parser.add_argument("--payloads", default="64,256,1024,3072", help="Comma-separated byte sizes.")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--ops", type=int, default=DEFAULT_OPS_PER_TRIAL)
    parser.add_argument("--warmup-trials", type=int, default=DEFAULT_WARMUP_TRIALS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    layout, _summary = run_benchmark(
        args.out,
        payloads=_parse_payloads(args.payloads),
        trials=args.trials,
        ops_per_trial=args.ops,
        warmup_trials=args.warmup_trials,
    )
    print(layout.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
