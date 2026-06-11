"""TN end-to-end perf harness.

Drives a representative TN e2e (init -> warmup -> measured emits -> read
-> export project_seed -> absorb into a fresh dir) with the Rust
stage-timer instrumentation enabled (TN_PERF_TRACE), and prints:

  1. wall-clock per top-level operation (ms), and
  2. the per-emit-stage breakdown from the Rust core's perf snapshot
     (count, total ms, avg us/op), sorted slowest-first.

The stage timers live in crypto/tn-core/src/perf.rs and are exposed to
Python as tn_core._core.perf_snapshot() / perf_reset(). This harness
just drives them; setting TN_PERF_TRACE before Runtime.init turns them
on (this module does that for you).

Run inside a venv that has tn-protocol + the tn_core/tn_btn extensions:

    python python/tools/perf_e2e.py          # default 500 emits
    PERF_N=2000 python python/tools/perf_e2e.py
    TN_NO_STDOUT=1 python python/tools/perf_e2e.py   # quieter / cleaner
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

os.environ["TN_PERF_TRACE"] = "1"  # must be set before Runtime.init

import tn  # noqa: E402
from tn._native import core as core  # noqa: E402

N = int(os.environ.get("PERF_N", "500"))
WARMUP = 25


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def main() -> None:
    ws = Path(tempfile.mkdtemp(prefix="tn-perf-"))
    results: list[tuple[str, float, str]] = []

    t0 = time.perf_counter()
    tn.init("bench", project_dir=ws, link=False)
    results.append(("init", _ms(t0), "1 call"))

    for i in range(WARMUP):
        tn.info("bench.warmup", i=i)
    core.perf_reset()  # drop warmup from the measured window

    t0 = time.perf_counter()
    for i in range(N):
        tn.info("bench.event", i=i, amount=100, currency="USD", note="hello perf")
    emit_total = _ms(t0)
    results.append((f"emit x{N}", emit_total, f"{emit_total / N * 1000:.1f} us/emit"))
    snap = core.perf_snapshot()  # capture emit-stage counters before later steps

    try:
        t0 = time.perf_counter()
        rows = list(tn.read())
        results.append(("read all", _ms(t0), f"{len(rows)} entries"))
    except Exception as exc:  # noqa: BLE001
        results.append(("read all", -1.0, f"SKIPPED: {type(exc).__name__}: {exc}"))

    seed = ws / "backup.tnpkg"
    try:
        t0 = time.perf_counter()
        tn.export(str(seed), kind="project_seed", confirm_includes_secrets=True)
        results.append(("export project_seed", _ms(t0), f"{seed.stat().st_size} bytes"))
    except Exception as exc:  # noqa: BLE001
        results.append(("export project_seed", -1.0, f"SKIPPED: {type(exc).__name__}: {exc}"))

    if seed.exists():
        dst = Path(tempfile.mkdtemp(prefix="tn-perf-absorb-"))
        cwd = os.getcwd()
        try:
            t0 = time.perf_counter()
            os.chdir(dst)
            try:
                tn.absorb(str(seed))
            finally:
                os.chdir(cwd)
            results.append(("absorb project_seed", _ms(t0), "into fresh dir"))
        except Exception as exc:  # noqa: BLE001
            os.chdir(cwd)
            results.append(("absorb project_seed", -1.0, f"SKIPPED: {type(exc).__name__}: {exc}"))

    print("\n=== top-level e2e timings (wall clock) ===")
    print(f"{'operation':<24} {'ms':>10}   note")
    for name, ms, note in results:
        ms_s = f"{ms:.2f}" if ms >= 0 else "n/a"
        print(f"{name:<24} {ms_s:>10}   {note}")

    print(f"\n=== emit per-stage breakdown (Rust core, {N} emits) ===")
    print(f"{'stage':<34} {'count':>7} {'total_ms':>10} {'avg_us':>10}")
    for stage, count, total_ns in sorted(snap, key=lambda r: r[2], reverse=True):
        total_ms = total_ns / 1e6
        avg_us = (total_ns / count) / 1e3 if count else 0.0
        print(f"{stage:<34} {count:>7} {total_ms:>10.2f} {avg_us:>10.2f}")


if __name__ == "__main__":
    main()
