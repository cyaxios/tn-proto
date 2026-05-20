"""Final perf chart — runs all profile × size combinations in ONE
process to avoid subprocess overhead. Each cell does warmup + N=5000
timed emits. Prints structured table and per-feature cost stack-up.

This is the chart-producing benchmark for the 2026-05-19 perf shift.
"""
from __future__ import annotations

import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("TN_NO_STDOUT", "1")
os.environ.setdefault("TN_AUTOINIT_QUIET", "1")

# IMPORTANT: do not enable TN_PERF_TRACE here. The fine-grained
# instrumentation has measurable overhead at the scale we care
# about now (~50-100 µs/emit). Run a separate stage-breakdown
# bench when you want the per-stage detail.

import tn

# Message-size payloads — keep deterministic for reruns.
PAYLOADS: dict[str, callable] = {
    "tiny":   lambda i: {"i": i},
    "small":  lambda i: {"i": i, "user": "alice", "kind": "order.created"},
    "medium": lambda i: {
        "i": i, "user": "alice", "kind": "order.created",
        "amount": 4999, "currency": "USD", "session": "sess_abc123",
        "channel": "mobile", "flag_a": True, "flag_b": False, "lat": 37.7749,
    },
    "large":  lambda i: {
        "i": i, "user": "alice" * 8, "note": "lorem ipsum dolor sit amet," * 3,
        **{f"p{j}": "x" * 60 for j in range(1, 17)},
    },
}

PROFILES = [
    ("telemetry",   False),  # chain=F sign=F (default group private)
    ("stdout",      False),  # chain=F sign=F default_sink=stdout
    ("secure_log",  False),  # chain=F sign=T
    ("audit",       False),  # chain=T sign=T
    ("transaction", False),  # chain=T sign=T (axis-equivalent to audit)
]

WARMUP = 200
N = 5000
RUNS = 3


def bench_cell(profile: str, public_group: bool, payload_fn) -> dict:
    """Run RUNS samples of N emits, return median µs/emit + spread."""
    samples_us = []
    for run in range(RUNS):
        td = tempfile.mkdtemp()
        os.chdir(td)
        tn.flush_and_close()
        tn.init(profile=profile)
        if public_group:
            # Patch yaml then re-init to flip the default group public.
            import yaml as _yaml
            yaml_path = Path(tn._require_dispatch()._yaml)
            doc = _yaml.safe_load(yaml_path.read_text())
            doc["default_policy"] = "public"
            for g in doc.get("groups", {}).values():
                g["policy"] = "public"
            yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False))
            tn.flush_and_close()
            tn.init(profile=profile)
        # Warmup
        for i in range(WARMUP):
            tn.log("warmup", **payload_fn(i))
        # Timed run
        t0 = time.perf_counter()
        for i in range(N):
            tn.log("bench", **payload_fn(i))
        dt = time.perf_counter() - t0
        samples_us.append(dt / N * 1e6)
        tn.flush_and_close()
    return {
        "median": statistics.median(samples_us),
        "min": min(samples_us),
        "max": max(samples_us),
        "throughput": int(1_000_000 / statistics.median(samples_us)),
    }


def main() -> None:
    print(f"# Final perf chart — release-mode build, N={N}, RUNS={RUNS}")
    print(f"  warmup={WARMUP} emits/cell")
    print(f"  python={sys.version.split()[0]}, platform={sys.platform}")
    print()

    results: dict[tuple[str, str], dict] = {}
    sizes = list(PAYLOADS.keys())

    for profile, public_group in PROFILES:
        label = f"{profile}{'-pub' if public_group else ''}"
        for size in sizes:
            print(f"  bench [{label}/{size}]...", end=" ", flush=True)
            t0 = time.time()
            r = bench_cell(profile, public_group, PAYLOADS[size])
            results[(label, size)] = r
            print(
                f"median={r['median']:6.1f} µs/emit  "
                f"(min={r['min']:.1f}, max={r['max']:.1f})  "
                f"= {r['throughput']:>6}/s  "
                f"[{time.time()-t0:.0f}s]"
            )
    print()

    # Pretty matrix table.
    print("## Per-profile per-size, µs/emit (median of 3 runs)\n")
    header = f"{'profile':16s}" + "".join(f"{s:>12s}" for s in sizes)
    print(header)
    print("-" * len(header))
    for profile, public_group in PROFILES:
        label = f"{profile}{'-pub' if public_group else ''}"
        row = f"{label:16s}"
        for size in sizes:
            r = results.get((label, size))
            row += f"{r['median']:>11.1f}µ" if r else f"{'--':>12s}"
        print(row)
    print()

    # Throughput table.
    print("## Throughput, emits/s (median; higher is better)\n")
    print(header)
    print("-" * len(header))
    for profile, public_group in PROFILES:
        label = f"{profile}{'-pub' if public_group else ''}"
        row = f"{label:16s}"
        for size in sizes:
            r = results.get((label, size))
            row += f"{r['throughput']:>11}/s" if r else f"{'--':>12s}"
        print(row)
    print()

    # Cost stack-up: how much each axis adds to telemetry baseline at "small" size.
    print("## Cost stack-up @ small payload (vs telemetry, chain=F sign=F private)\n")
    base = results.get(("telemetry", "small"))
    if base:
        base_us = base["median"]
        print(f"  telemetry  (chain=F sign=F, default group private):  {base_us:6.1f} µs/emit")
        for profile, public_group in PROFILES[1:]:
            label = f"{profile}{'-pub' if public_group else ''}"
            r = results.get((label, "small"))
            if r:
                delta = r["median"] - base_us
                sign = "+" if delta >= 0 else ""
                print(f"  {label:42s}: {r['median']:6.1f} µs/emit  ({sign}{delta:+5.1f} µs vs telemetry)")
    print()


if __name__ == "__main__":
    main()
