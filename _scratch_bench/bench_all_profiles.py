"""Per-profile perf snapshot after all the lifts.

Runs each of the 5 profiles in a fresh subprocess to get a clean
post-fix performance number. Catches any profile-specific regressions
the telemetry-only bench would have missed.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

PY = sys.executable
N = 1000
WARMUP = 50


def run(profile: str) -> None:
    code = textwrap.dedent(f"""
        import os, tempfile, time
        os.environ['TN_NO_STDOUT'] = '1'
        os.environ['TN_AUTOINIT_QUIET'] = '1'
        os.environ['TN_PERF_TRACE'] = '1'
        td = tempfile.mkdtemp(); os.chdir(td)
        import tn
        tn.init(profile={profile!r})
        from tn_core._core import perf_snapshot, perf_reset
        for i in range({WARMUP}):
            tn.log('warmup', i=i)
        perf_reset()
        t0 = time.perf_counter()
        for i in range({N}):
            tn.log('bench', i=i)
        wall = time.perf_counter() - t0
        tn.flush_and_close()
        snap = sorted(perf_snapshot(), key=lambda r: -r[2])
        rust_total_ns = next((ns for s, _c, ns in snap if s == 'emit:_TOTAL'), 0)
        rust_per = rust_total_ns / {N} / 1000.0
        wall_per = wall / {N} * 1000.0
        py_per = wall_per - rust_per / 1000.0
        print(f'profile={profile:12s}  wall={{wall_per:6.3f}} ms/emit  rust={{rust_per:7.1f}} us  py_overhead={{py_per:6.3f}} ms')
        print(f'  top stages:')
        for stage, count, total_ns in snap[:6]:
            print(f'    {{stage:28s}}  {{total_ns/count/1000.0:7.2f}} us/emit')
    """)
    proc = subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        print(f"FAILED [{profile}]:\n{proc.stderr}")
        return
    print(proc.stdout)


def main() -> None:
    print(f"# Per-profile perf snapshot (N={N})\n")
    for profile in ("telemetry", "stdout", "secure_log", "audit", "transaction"):
        run(profile)


if __name__ == "__main__":
    main()
