"""Comprehensive perf matrix: profile × message-size × N=5000 × 3 runs.

For each (profile, size) combination, runs N=5000 emits in a fresh
subprocess, repeats 3 times, takes the median. Writes structured JSON
output alongside human-readable tables so we can chart the cost
stackup later.

Profiles tested:
  - telemetry  (chain=F sign=F default_sink=stdout) — public group
  - telemetry-priv (same, default group PRIVATE — btn cipher on)
  - secure_log (chain=F sign=T)
  - audit      (chain=T sign=T)
  - transaction(chain=T sign=T) — same axes as audit, here for parity

Message sizes:
  - tiny:   1 field (the smallest TN entry that does any real work)
  - small:  3 fields (one int, one short string, one timestamp-ish)
  - medium: 10 fields (mix of int / string / float / bool)
  - large:  20 fields (mostly strings ~60-80 chars each)

Why not larger sizes: TN's payload is encrypted into a single ciphertext
per group, so payload bytes scale linearly with field count.  Larger
sizes mostly exercise the cipher's tolerance of large plaintext which
isn't where the per-emit overhead lives. Use 20-field as the "real-
world heavy" upper bound.
"""
from __future__ import annotations

import json
import statistics
import subprocess
import sys
import textwrap
import time
from pathlib import Path

PY = sys.executable
N = 5000          # emits per run
WARMUP = 200      # discard the first N to drop cold-start admin emits
RUNS = 3          # take median across this many runs

# Build the field payloads. Keep them deterministic so reruns are
# comparable. Values must be JSON-native scalars (strings get
# enclosed in the env-var passed to subprocess, so keep them ASCII).
_PAYLOADS: dict[str, str] = {
    "tiny": "{'i': i}",
    "small": "{'i': i, 'user': 'alice', 'kind': 'order.created'}",
    "medium": (
        "{'i': i, 'user': 'alice', 'kind': 'order.created', "
        "'amount': 4999, 'currency': 'USD', 'session': 'sess_abc123', "
        "'channel': 'mobile', 'flag_a': True, 'flag_b': False, 'lat': 37.7749}"
    ),
    "large": (
        "{'i': i, 'user': 'alice'*8, 'note': 'lorem ipsum dolor sit amet,'*3, "
        "'p1': 'aaa'*20, 'p2': 'bbb'*20, 'p3': 'ccc'*20, 'p4': 'ddd'*20, "
        "'p5': 'eee'*20, 'p6': 'fff'*20, 'p7': 'ggg'*20, 'p8': 'hhh'*20, "
        "'p9': 'iii'*20, 'p10': 'jjj'*20, 'p11': 'kkk'*20, 'p12': 'lll'*20, "
        "'p13': 'mmm'*20, 'p14': 'nnn'*20, 'p15': 'ooo'*20, 'p16': 'ppp'*20}"
    ),
}


def _bench_code(profile: str, public_group: bool, fields_expr: str, n: int, warmup: int) -> str:
    """Return the bench script body for one (profile, size) run."""
    patch_block = ""
    if public_group:
        patch_block = textwrap.dedent("""
            import yaml as _yaml
            from pathlib import Path as _Path
            _yp = _Path(tn._require_dispatch()._yaml)
            _doc = _yaml.safe_load(_yp.read_text())
            _doc['default_policy'] = 'public'
            for _g in _doc.get('groups', {}).values():
                _g['policy'] = 'public'
            _yp.write_text(_yaml.safe_dump(_doc, sort_keys=False))
            tn.flush_and_close()
            tn.init(profile={profile!r})
        """).format(profile=profile)

    return textwrap.dedent(f"""
        import os, tempfile, time
        os.environ['TN_NO_STDOUT'] = '1'
        os.environ['TN_AUTOINIT_QUIET'] = '1'
        td = tempfile.mkdtemp(); os.chdir(td)
        import tn
        tn.init(profile={profile!r})
        {patch_block}
        # Warmup
        for i in range({warmup}):
            tn.log('warmup', **{fields_expr})
        # Measured run
        t0 = time.perf_counter()
        for i in range({n}):
            tn.log('bench', **{fields_expr})
        dt = time.perf_counter() - t0
        tn.flush_and_close()
        print(dt)
    """).strip()


def run_one(profile: str, public_group: bool, size: str, fields_expr: str) -> float:
    """Run one (profile, size) cell once. Returns wall seconds for N emits."""
    code = _bench_code(profile, public_group, fields_expr, N, WARMUP)
    proc = subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"{profile}/{size}/{public_group}: {proc.stderr[-500:]}")
    return float(proc.stdout.strip().splitlines()[-1])


def run_cell(profile: str, public_group: bool, size: str, fields_expr: str) -> dict:
    """Run RUNS iterations of one cell, return median + spread stats."""
    samples = []
    for r in range(RUNS):
        try:
            samples.append(run_one(profile, public_group, size, fields_expr))
        except Exception as e:
            print(f"  [{profile}/{size}/pub={public_group}] run {r+1} FAILED: {e}")
            return {"failed": str(e)}
    samples_us_per = [s / N * 1e6 for s in samples]
    return {
        "profile": profile,
        "public_group": public_group,
        "size": size,
        "n": N,
        "runs": RUNS,
        "median_us_per_emit": statistics.median(samples_us_per),
        "min_us_per_emit": min(samples_us_per),
        "max_us_per_emit": max(samples_us_per),
        "throughput_per_s_median": int(1_000_000 / statistics.median(samples_us_per)),
    }


def main() -> None:
    print(f"# Full perf matrix — profiles × sizes × N={N} × {RUNS} runs (median)")
    print(f"  warmup={WARMUP}, started at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    scenarios = [
        # (label, profile, public_group)
        ("telemetry-pub", "telemetry", True),
        ("telemetry-priv", "telemetry", False),
        ("stdout", "stdout", False),
        ("secure_log", "secure_log", False),
        ("audit", "audit", False),
        ("transaction", "transaction", False),
    ]
    sizes = list(_PAYLOADS.items())

    results = []
    for label, profile, public in scenarios:
        for size, fields_expr in sizes:
            print(f"  [{label}/{size}] running {RUNS}×{N} emits...", flush=True)
            t0 = time.time()
            r = run_cell(profile, public, size, fields_expr)
            r["label"] = label
            results.append(r)
            if "failed" not in r:
                print(
                    f"    median = {r['median_us_per_emit']:7.1f} µs/emit  "
                    f"({r['throughput_per_s_median']:>7} emits/s)  "
                    f"[{(time.time()-t0):.1f}s]"
                )

    # Write structured output.
    out_path = Path(__file__).parent / "bench_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out_path.name}")
    print()

    # Pretty table.
    sizes_keys = [s for s, _ in sizes]
    header = f"{'profile':16s}" + "".join(f"{s:>14s}" for s in sizes_keys) + f"  {'tput@small':>11s}"
    print(header)
    print("-" * len(header))
    for label, _, _ in scenarios:
        row = f"{label:16s}"
        tput = None
        for size in sizes_keys:
            r = next((x for x in results if x.get("label") == label and x.get("size") == size), None)
            if r is None or "failed" in r:
                row += f"{'--':>14s}"
            else:
                row += f"{r['median_us_per_emit']:>11.1f} µs"
                if size == "small":
                    tput = r["throughput_per_s_median"]
        row += f"  {f'{tput:>9}/s' if tput else '--':>11s}"
        print(row)


if __name__ == "__main__":
    main()
