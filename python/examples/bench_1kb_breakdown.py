"""Where does the time go for a 1 KB message, through the Python skin?

Times each phase of tn.info / tn.read independently so you can see what the
18-19k events/s `tn.info` number and the 5k events/s `tn.read` number are
actually made of.

Run:

    .venv/Scripts/python.exe tn-protocol/python/examples/bench_1kb_breakdown.py
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tn_core import Runtime as _RustRuntime  # type: ignore[import-not-found]

import tn  # type: ignore[import-not-found]

MSG_SIZE = 1024
N_EMIT = 200
N_READ_PASSES = 20  # total reads we'll time; each read pass covers N_EMIT entries


def _p50(xs_us: list[float]) -> float:
    xs = sorted(xs_us)
    return xs[len(xs) // 2] if xs else 0.0


def _p95(xs_us: list[float]) -> float:
    xs = sorted(xs_us)
    return xs[int(len(xs) * 0.95)] if xs else 0.0


def main() -> int:
    results = []

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        yaml_path = td / "tn.yaml"

        # --- Set up a fresh btn ceremony via the tn Python API ---
        tn.init(yaml_path, cipher="btn")
        assert tn.using_rust(), "bench requires the Rust path"
        payload = "x" * MSG_SIZE

        # ================================================================
        # EMIT BREAKDOWN
        # ================================================================

        # Phase 1: tn.info through the full public skin
        # (includes context merge, DispatchRuntime hop, PyO3 Py->Rust, Rust pipeline, PyO3 Rust->Py)
        for _ in range(10):
            tn.info("bench.warm", payload=payload)  # warm-up
        skin_info_us = []
        for _ in range(N_EMIT):
            t0 = time.perf_counter()
            tn.info("bench.skin", payload=payload)
            skin_info_us.append((time.perf_counter() - t0) * 1e6)
        results.append(("tn.info (full skin)", skin_info_us))

        # Phase 2: direct PyO3 Runtime.emit (skip the tn.info dispatcher)
        # Opens a second Runtime pointing at the same yaml.
        rt_direct = _RustRuntime.init(str(yaml_path))
        for _ in range(10):
            rt_direct.emit("info", "bench.warm", {"payload": payload})
        direct_emit_us = []
        for _ in range(N_EMIT):
            t0 = time.perf_counter()
            rt_direct.emit("info", "bench.direct", {"payload": payload})
            direct_emit_us.append((time.perf_counter() - t0) * 1e6)
        results.append(("PyRuntime.emit (no tn.info wrapper)", direct_emit_us))

        # Phase 3: Python tn.info when FORCE_PYTHON — proxy for Python pipeline.
        # We can't flip that in-process after init, so skip; the earlier bench
        # already captured this (~164 us at 1 KB). Note it for comparison.

        # ================================================================
        # READ BREAKDOWN
        # ================================================================

        # Make sure the log has exactly N_EMIT events (it has warmups too).
        # We'll time reads as "total_us / entries_count" so count doesn't matter.

        # Phase R1: full tn.read(raw=True) — through the skin
        # (PyRuntime.read -> PyO3 convert to Py list of dicts -> _rust_entries_with_valid -> yield loop)
        list(tn.read(raw=True))  # warm-up
        skin_read_per_event_us = []
        for _ in range(N_READ_PASSES):
            t0 = time.perf_counter()
            entries = list(tn.read(raw=True))
            total_us = (time.perf_counter() - t0) * 1e6
            skin_read_per_event_us.append(total_us / len(entries))
        results.append(("tn.read (full skin, list()'d)", skin_read_per_event_us))

        # Phase R2: direct PyRuntime.read — skips _rust_entries_with_valid and the generator wrapper
        rt_direct.read()  # warm-up
        direct_read_per_event_us = []
        for _ in range(N_READ_PASSES):
            t0 = time.perf_counter()
            direct_entries = rt_direct.read()
            total_us = (time.perf_counter() - t0) * 1e6
            direct_read_per_event_us.append(total_us / len(direct_entries))
        results.append(("PyRuntime.read (PyO3 call + PyO3 dict build)", direct_read_per_event_us))

        # Phase R3: How big was the overhead between R1 and R2?
        # That's the `_rust_entries_with_valid` cost (chain walk + adds `valid` dict per entry).
        # Derived, not measured directly below.

        # Phase R4: PyO3-level cost WITHOUT plaintext construction.
        # We don't have a knob to skip plaintext; but we can time the same pass
        # and include an assertion that decodes were done.
        # Use this as reference: the actual decrypt+PyO3 conversion per entry.

        # ================================================================
        # ISOLATE PyO3 BOUNDARY COST
        # ================================================================

        # Phase X1: Just the PyO3 call overhead — call a cheap method many times.
        # `rt_direct.did()` returns a &str, no conversion cost to speak of.
        for _ in range(100):
            rt_direct.did()
        py03_call_us = []
        for _ in range(N_EMIT):
            t0 = time.perf_counter()
            rt_direct.did()
            py03_call_us.append((time.perf_counter() - t0) * 1e6)
        results.append(("PyO3 call overhead (rt.did())", py03_call_us))

        tn.flush_and_close()

    # =================== Print breakdown ===================
    lines = []
    lines.append(f"\n=== Per-event breakdown for {MSG_SIZE}-byte messages ===\n")
    lines.append(f"{'Phase':<46} | {'p50 us':>8} | {'p95 us':>8} | {'events/s':>10}")
    lines.append("-" * 82)
    for name, xs in results:
        p50 = _p50(xs)
        p95 = _p95(xs)
        eps = int(1_000_000 / p50) if p50 > 0 else 0
        lines.append(f"{name:<46} | {p50:>8.1f} | {p95:>8.1f} | {eps:>10}")
    lines.append("")

    # Derived deltas
    by_name = {n: _p50(xs) for n, xs in results}
    skin_info = by_name["tn.info (full skin)"]
    direct_info = by_name["PyRuntime.emit (no tn.info wrapper)"]
    skin_read = by_name["tn.read (full skin, list()'d)"]
    direct_read = by_name["PyRuntime.read (PyO3 call + PyO3 dict build)"]
    call_ovh = by_name["PyO3 call overhead (rt.did())"]

    lines.append("=== Derived ===\n")
    lines.append(f"tn.info wrapper overhead         : {skin_info - direct_info:>6.1f} us")
    lines.append("  (Python: context merge, DispatchRuntime hop, kwargs -> dict)")
    lines.append("")
    lines.append(f"_rust_entries_with_valid wrap    : {skin_read - direct_read:>6.1f} us/event")
    lines.append("  (Python: chain walk + build 'valid' dict per entry, generator yield)")
    lines.append("")
    lines.append(f"PyO3 minimal call overhead       : {call_ovh:>6.1f} us")
    lines.append("")
    lines.append("Accounting (1 KB, Rust path):")
    lines.append(f"  direct PyRuntime.emit          : {direct_info:>6.1f} us")
    lines.append(f"  + tn.info wrapper              : +{skin_info - direct_info:>5.1f} us")
    lines.append(f"  = tn.info full skin            : {skin_info:>6.1f} us")
    lines.append("")
    lines.append(f"  direct PyRuntime.read / entry  : {direct_read:>6.1f} us")
    lines.append(f"  + _rust_entries_with_valid     : +{skin_read - direct_read:>5.1f} us")
    lines.append(f"  = tn.read full skin / entry    : {skin_read:>6.1f} us")
    lines.append("")
    lines.append("Note: PyRuntime.read includes PyO3 dict-building for every envelope and")
    lines.append("plaintext field, which is substantial for the 'read' path. In contrast,")
    lines.append("emit only builds a 3-key receipt dict on return.")

    body = "\n".join(lines)
    print(body)
    out_path = HERE / "bench_1kb_breakdown.results.md"
    out_path.write_text(
        "# 1 KB message — where does the time go?\n\n```\n" + body + "\n```\n", encoding="utf-8"
    )
    print(f"\nSaved to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
