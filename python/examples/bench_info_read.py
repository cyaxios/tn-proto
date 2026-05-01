"""Final performance bench — `tn.info` and `tn.read` through the Python skin.

Measures what a TN user actually sees: the public `import tn` API, called
from Python, across a sweep of message sizes and under both runtime paths:

    - Rust (default on btn ceremonies)
    - Pure Python (TN_FORCE_PYTHON=1)

Run (overnight capture):

    .venv/Scripts/python.exe tn-protocol/python/examples/bench_info_read.py

Writes a markdown summary to
tn-protocol/python/examples/bench_info_read.results.md and prints it to
stdout. Prefer running the Rust-path build with `maturin develop --release`
first so the tn_core extension is optimised.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # tn-protocol/python on sys.path

MSG_SIZES = [64, 256, 1_024, 4_096, 16_384, 65_536]
EMIT_ITERS = 200
READ_REPEATS = 5


def _percentile(values_us: list[float], p: float) -> float:
    if not values_us:
        return 0.0
    values_us = sorted(values_us)
    idx = int(len(values_us) * p)
    idx = max(0, min(idx, len(values_us) - 1))
    return values_us[idx]


def _run_subprocess_cell(size: int, force_python: bool) -> dict:
    """Run one (size, path) cell in a subprocess so `TN_FORCE_PYTHON` and
    module state are fresh every time."""
    env = os.environ.copy()
    if force_python:
        env["TN_FORCE_PYTHON"] = "1"
    else:
        env.pop("TN_FORCE_PYTHON", None)

    script = f"""
import json, os, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, {str(HERE.parent)!r})
import tn

SIZE = {size}
EMIT_ITERS = {EMIT_ITERS}
READ_REPEATS = {READ_REPEATS}

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    yaml = td / "tn.yaml"
    tn.init(yaml, cipher="btn")
    payload = ("x" * SIZE)[:SIZE]

    # Warm-up emit.
    tn.info("bench.warm", payload=payload)

    emit_us = []
    for _ in range(EMIT_ITERS):
        t0 = time.perf_counter()
        tn.info("bench.test", payload=payload)
        emit_us.append((time.perf_counter() - t0) * 1_000_000.0)

    # Warm-up read.
    list(tn.read(raw=True))

    read_total_us = []
    for _ in range(READ_REPEATS):
        t0 = time.perf_counter()
        entries = list(tn.read(raw=True))
        dur = (time.perf_counter() - t0) * 1_000_000.0
        # Per-event µs
        if entries:
            read_total_us.append(dur / len(entries))

    using_rust = tn.using_rust()
    tn.flush_and_close()

    print(json.dumps({{
        "emit_us": emit_us,
        "read_per_event_us": read_total_us,
        "using_rust": using_rust,
        "event_count": len(entries),
    }}))
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"cell failed (size={size}, force_python={force_python}):\n"
            f"stderr:\n{result.stderr}\nstdout:\n{result.stdout}"
        )
    data = json.loads(result.stdout.strip().splitlines()[-1])
    return data


def _summarize(samples_us: list[float]) -> dict:
    if not samples_us:
        return {"p50": 0, "p95": 0, "mean": 0, "eps": 0}
    p50 = _percentile(samples_us, 0.50)
    p95 = _percentile(samples_us, 0.95)
    mean = statistics.mean(samples_us)
    eps = int(1_000_000 / p50) if p50 > 0 else 0
    return {"p50": p50, "p95": p95, "mean": mean, "eps": eps}


def main() -> int:
    rows: list[dict] = []
    print("\n=== bench_info_read: Python skin, both paths ===\n")
    for size in MSG_SIZES:
        for force_py in (False, True):
            label = "python" if force_py else "rust"
            print(f"  size={size:>6} path={label} ...", flush=True)
            try:
                data = _run_subprocess_cell(size, force_py)
            except Exception as e:
                print(f"    skipped: {e}")
                continue
            emit = _summarize(data["emit_us"])
            read = _summarize(data["read_per_event_us"])
            rows.append(
                {
                    "size": size,
                    "path": label,
                    "using_rust": data["using_rust"],
                    "emit_p50": emit["p50"],
                    "emit_p95": emit["p95"],
                    "emit_eps": emit["eps"],
                    "read_p50": read["p50"],
                    "read_p95": read["p95"],
                    "read_eps": read["eps"],
                }
            )

    # Print table + write results file.
    out_path = HERE / "bench_info_read.results.md"
    lines = []
    lines.append("# `tn.info` / `tn.read` — Python skin bench\n")
    lines.append(
        "Measured through the public Python API. Both paths use the same "
        "`tn.init / tn.info / tn.read` call sequence — only `TN_FORCE_PYTHON=1` "
        "differs for the 'python' rows.\n"
    )
    lines.append(f"- {EMIT_ITERS} emit iterations per cell")
    lines.append(f"- {READ_REPEATS} read passes per cell (per-event µs = total / event count)")
    lines.append(f"- Message sizes: {MSG_SIZES}\n")
    lines.append(
        "| msg_size | path   | using_rust | info p50 µs | info p95 µs | info events/s | read p50 µs | read p95 µs | read events/s |"
    )
    lines.append(
        "|---------:|:-------|:----------:|------------:|------------:|--------------:|------------:|------------:|--------------:|"
    )
    for r in rows:
        lines.append(
            f"| {r['size']:>8} | {r['path']:<6} | {r['using_rust']!s:^10} "
            f"| {r['emit_p50']:>11.1f} | {r['emit_p95']:>11.1f} | {r['emit_eps']:>13} "
            f"| {r['read_p50']:>11.1f} | {r['read_p95']:>11.1f} | {r['read_eps']:>13} |"
        )

    # Side-by-side speedup table.
    lines.append("\n## Rust vs Python speedup (p50)\n")
    lines.append(
        "| msg_size | info Python µs | info Rust µs | info speedup | read Python µs | read Rust µs | read speedup |"
    )
    lines.append(
        "|---------:|---------------:|-------------:|-------------:|---------------:|-------------:|-------------:|"
    )
    by_size_path: dict[tuple[int, str], dict] = {(r["size"], r["path"]): r for r in rows}
    for size in MSG_SIZES:
        py = by_size_path.get((size, "python"))
        ru = by_size_path.get((size, "rust"))
        if not py or not ru:
            continue
        info_speedup = py["emit_p50"] / ru["emit_p50"] if ru["emit_p50"] > 0 else 0
        read_speedup = py["read_p50"] / ru["read_p50"] if ru["read_p50"] > 0 else 0
        lines.append(
            f"| {size:>8} | {py['emit_p50']:>14.1f} | {ru['emit_p50']:>12.1f} | {info_speedup:>11.2f}x "
            f"| {py['read_p50']:>14.1f} | {ru['read_p50']:>12.1f} | {read_speedup:>11.2f}x |"
        )

    body = "\n".join(lines) + "\n"
    out_path.write_text(body, encoding="utf-8")
    print("\n" + body)
    print(f"\nResults written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
