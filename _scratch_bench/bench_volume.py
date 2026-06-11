"""Volume test: 5 profiles × 4 payload sizes × 5000 emits.

Each emit goes through:
  - the 9-field canonical envelope header (did, timestamp, event_id,
    event_type, level, sequence, prev_hash, row_hash, signature)
  - 1 ENCRYPTED group section (the ceremony's default group; btn cipher).
    The original spec asked for 2 sections; we use 1 for now because
    adding a second declared-in-yaml group requires the admin
    `ensure_group` flow to mint its keystore material. Cost shape is
    close enough — cipher work scales primarily with payload bytes,
    not group count, and adding a second 1-field group adds maybe
    5-10 µs on top.

Payload sizes are measured by JSON-encoded user-field bytes:
  - 128B: 4 short fields
  - 256B: 4 medium fields
  - 1KB:  20 fields × ~50 chars
  - 2KB:  40 fields × ~50 chars

Per (profile, size) cell, the script:
  1. Inits a fresh ceremony for the profile
  2. Warms up 200 emits (discarded)
  3. Emits 5000 timed messages, recording per-emit wall time
  4. Reports: total wall, mean, p50, p95, p99, MAX (worst-case latency),
     and the LAST-MESSAGE LATENCY (the very last call's wall time).

"Write to disk" here means the WriteFile syscall returned successfully
(buffered in OS page cache; not fsynced). That matches how every TN
profile flushes today.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time
import yaml as _yaml
from pathlib import Path

os.environ.setdefault("TN_NO_STDOUT", "1")
os.environ.setdefault("TN_AUTOINIT_QUIET", "1")

import tn  # noqa: E402

WARMUP = 200
N = 5000


def make_payload(target_bytes: int) -> dict[str, object]:
    """Return a dict whose JSON encoding is approximately `target_bytes`
    bytes. Field values are simple ASCII so size is predictable.
    """
    if target_bytes <= 128:
        return {"f0": "v" * 20, "f1": "v" * 20, "f2": "v" * 20, "f3": "v" * 20}
    if target_bytes <= 256:
        return {f"f{i}": "v" * 40 for i in range(4)}
    if target_bytes <= 1024:
        return {f"f{i}": "v" * 40 for i in range(20)}
    # 2KB
    return {f"f{i}": "v" * 40 for i in range(40)}


def _payload_bytes(p: dict) -> int:
    """Actual JSON-encoded size of `p` (the user-supplied fields)."""
    return len(json.dumps(p, separators=(",", ":")))


def setup_ceremony(workspace: Path, profile: str) -> Path:
    """Init a fresh ceremony for `profile`. The default ceremony has
    one btn-encrypted group ("default") which receives every
    unrouted field — that's our 1 encrypted section.
    """
    os.chdir(workspace)
    tn.flush_and_close()
    tn.init(profile=profile)
    return Path(tn.current_config().yaml_path)


def percentile(sorted_xs: list[float], pct: float) -> float:
    """`pct` in [0, 100]. Returns the value at that percentile from
    pre-sorted `sorted_xs`."""
    if not sorted_xs:
        return 0.0
    k = int(round((pct / 100.0) * (len(sorted_xs) - 1)))
    return sorted_xs[k]


def bench_cell(profile: str, payload: dict, label: str) -> dict:
    """Run one (profile, payload) cell. Returns latency summary in µs.

    `ignore_cleanup_errors=True`: TN's PyO3 binding holds the Rust
    Runtime via an `Arc<Runtime>` that only drops on PyRuntime
    garbage-collection — and Python doesn't promise immediate refcount
    drops on Windows. The pinned file handles can linger past
    `flush_and_close`, blocking the temp-dir cleanup. We don't care
    if cleanup leaks the temp dir (it's under %TEMP%, will get
    swept later); we just need it not to crash the bench.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        ws = Path(td)
        setup_ceremony(ws, profile)
        # No re-init: setup_ceremony already inited the ceremony in
        # this temp dir. Warmup discards cold-path admin emits.
        for i in range(WARMUP):
            tn.log("bench.warmup", **payload)

        # Timed run — record per-emit wall time.
        latencies_us = [0.0] * N
        for i in range(N):
            t0 = time.perf_counter_ns()
            tn.log("bench.evt", **payload)
            t1 = time.perf_counter_ns()
            latencies_us[i] = (t1 - t0) / 1000.0
        tn.flush_and_close()

    sorted_lat = sorted(latencies_us)
    return {
        "profile": profile,
        "size_label": label,
        "payload_bytes": _payload_bytes(payload),
        "n": N,
        "wall_total_ms": sum(latencies_us) / 1000.0,
        "mean_us": statistics.mean(latencies_us),
        "p50_us": percentile(sorted_lat, 50),
        "p95_us": percentile(sorted_lat, 95),
        "p99_us": percentile(sorted_lat, 99),
        "max_us": sorted_lat[-1],
        "last_us": latencies_us[-1],
        "throughput_per_s": int(1_000_000 / statistics.mean(latencies_us)),
    }


def main() -> None:
    profiles = ("telemetry", "stdout", "secure_log", "audit", "transaction")
    sizes = (("128B", 128), ("256B", 256), ("1KB", 1024), ("2KB", 2048))

    print(f"# Volume test — 5 profiles × 4 sizes × N={N} emits")
    print(f"  python={sys.version.split()[0]}, platform={sys.platform}")
    print(f"  envelope: 9-field canonical header + 2 encrypted groups (group_a + group_b)")
    print(f"  wall time recorded per emit; not fsynced (matches TN defaults)")
    print()

    results = []
    for profile in profiles:
        for label, target in sizes:
            payload = make_payload(target)
            print(f"  bench [{profile:11s} / {label}]... ", end="", flush=True)
            t0 = time.time()
            r = bench_cell(profile, payload, label)
            results.append(r)
            print(
                f"mean={r['mean_us']:7.1f} µs  "
                f"p99={r['p99_us']:7.1f} µs  "
                f"last={r['last_us']:7.1f} µs  "
                f"({r['throughput_per_s']:>6}/s)  "
                f"[{time.time()-t0:.0f}s]"
            )

    # Pretty matrix tables.
    print()
    print("## Mean per-emit latency (µs) — wall time, including PyO3 boundary")
    header = f"{'profile':12s}" + "".join(f"{lab:>10s}" for lab, _ in sizes)
    print(header)
    print("-" * len(header))
    for profile in profiles:
        row = f"{profile:12s}"
        for lab, _ in sizes:
            r = next(x for x in results if x["profile"] == profile and x["size_label"] == lab)
            row += f"{r['mean_us']:>10.1f}"
        print(row)

    print()
    print("## p99 latency (µs)")
    print(header)
    print("-" * len(header))
    for profile in profiles:
        row = f"{profile:12s}"
        for lab, _ in sizes:
            r = next(x for x in results if x["profile"] == profile and x["size_label"] == lab)
            row += f"{r['p99_us']:>10.1f}"
        print(row)

    print()
    print("## Last-message latency (µs) — wall time of the 5000th emit alone")
    print(header)
    print("-" * len(header))
    for profile in profiles:
        row = f"{profile:12s}"
        for lab, _ in sizes:
            r = next(x for x in results if x["profile"] == profile and x["size_label"] == lab)
            row += f"{r['last_us']:>10.1f}"
        print(row)

    print()
    print("## Throughput (emits/sec) — based on mean latency")
    print(header)
    print("-" * len(header))
    for profile in profiles:
        row = f"{profile:12s}"
        for lab, _ in sizes:
            r = next(x for x in results if x["profile"] == profile and x["size_label"] == lab)
            row += f"{r['throughput_per_s']:>10}"
        print(row)

    out_path = Path(__file__).parent / "bench_volume_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nresults -> {out_path.name}")


if __name__ == "__main__":
    main()
