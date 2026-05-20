"""Run TN emits with stage instrumentation on; dump per-stage breakdown.

Sets TN_PERF_TRACE=1 in the child subprocess BEFORE importing tn so the
Runtime picks up the env var at init. Each scenario gets a fresh
subprocess + fresh ceremony.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap

PY = sys.executable


def run_scenario(label: str, profile: str, N: int, warmup: int = 50) -> None:
    code = textwrap.dedent(f"""
        import os
        os.environ['TN_NO_STDOUT'] = '1'
        os.environ['TN_AUTOINIT_QUIET'] = '1'
        os.environ['TN_PERF_TRACE'] = '1'
        import tempfile, time
        td = tempfile.mkdtemp(); os.chdir(td)
        import tn
        from tn_core._core import perf_snapshot, perf_reset

        tn.init(profile={profile!r})
        # Warmup emits — discard so steady-state numbers aren't polluted by
        # cold-path setup (e.g. first emit triggers admin tn.ceremony.init).
        for i in range({warmup}):
            tn.log('warmup', i=i)
        perf_reset()

        t0 = time.perf_counter()
        for i in range({N}):
            tn.log('bench', i=i)
        wall_total_s = time.perf_counter() - t0
        tn.flush_and_close()

        snap = sorted(perf_snapshot(), key=lambda r: -r[2])
        total_emit_ns = next((ns for s, _c, ns in snap if s == 'emit:_TOTAL'), 0)
        print(f'--- {label} ---')
        print(f'wall total      : {{wall_total_s*1000:8.2f}} ms over {N} emits = {{wall_total_s/{N}*1000:6.3f}} ms/emit')
        if total_emit_ns:
            print(f'emit:_TOTAL sum : {{total_emit_ns/1e6:8.2f}} ms                = {{total_emit_ns/{N}/1000:6.3f}} us/emit (avg, inside Rust)')
        print(f'  {{\"stage\":28s}}  {{\"count\":>6s}}  {{\"total_ms\":>10s}}  {{\"avg_us\":>10s}}  {{\"%total\":>7s}}')
        for stage, count, total_ns in snap:
            avg_us = (total_ns/count)/1000.0 if count else 0.0
            pct = 100.0 * total_ns / total_emit_ns if total_emit_ns else 0.0
            print(f'  {{stage:28s}}  {{count:>6d}}  {{total_ns/1e6:>10.2f}}  {{avg_us:>10.2f}}  {{pct:>6.1f}}%')
    """)
    proc = subprocess.run(
        [PY, "-c", code],
        capture_output=True, text=True, timeout=600,
    )
    print(proc.stdout, end="")
    if proc.returncode != 0:
        print("STDERR:", proc.stderr)


def main() -> None:
    N = 1000
    print(f"# TN stage breakdown — N={N} emits per scenario\n")
    # chain=False profiles surface the structural floor.
    run_scenario("telemetry (chain=F, sign=F)", "telemetry", N)
    print()
    run_scenario("secure_log (chain=F, sign=T)", "secure_log", N)
    print()
    # chain=True surfaces the lock + tip-refresh cost on top.
    run_scenario("transaction (chain=T, sign=T)", "transaction", N)


if __name__ == "__main__":
    main()
