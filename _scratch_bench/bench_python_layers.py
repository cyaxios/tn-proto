"""Strip TN's Python layers one at a time to see how much each adds.

Layers (outermost → innermost):
  A. tn.log('evt', i=i)              # full public verb path
  B. _emit_with_splice('info', ...)  # skip the verb wrapper + _surface_log_emit
  C. _emit_via(rt, ...)              # skip context/merge dance — handed-in rt
  D. dispatch.emit(level, et, fields, sign=None)
                                      # skip _coerce_for_wire + _splice_agent_policy
  E. rt._rt.emit(level, et, fields, None, None, sign)
                                      # PyO3 -> Rust, no Python wrapping at all
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

PY = sys.executable
N = 1000
WARMUP = 50


def run(label: str, body: str) -> None:
    code = textwrap.dedent(f"""
        import os, sys, time, tempfile
        os.environ['TN_NO_STDOUT'] = '1'
        os.environ['TN_AUTOINIT_QUIET'] = '1'
        os.environ['TN_PERF_TRACE'] = '1'
        td = tempfile.mkdtemp(); os.chdir(td)
        import tn
        from tn_core._core import perf_snapshot, perf_reset
        tn.init(profile='telemetry')

        # Warmup with the public path so admin events fire ahead of time.
        for i in range({WARMUP}):
            tn.log('warmup', i=i)
        perf_reset()

    """) + body + textwrap.dedent(f"""
        snap = sorted(perf_snapshot(), key=lambda r: -r[2])
        rust_total_ns = next((ns for s, _c, ns in snap if s == 'emit:_TOTAL'), 0)
        py_total_s = dt
        py_per = py_total_s / {N} * 1e3
        rust_per_us = rust_total_ns / {N} / 1000.0
        py_overhead_per_us = py_per * 1000.0 - rust_per_us
        print(f"{label:50s}  total={{py_total_s*1000:7.1f}} ms  py/emit={{py_per:6.3f}} ms  rust/emit={{rust_per_us:7.1f}} us  py_overhead={{py_overhead_per_us:7.1f}} us")
    """)
    proc = subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        print(f"FAILED [{label}]:\n{proc.stderr}")
        return
    print(proc.stdout.strip())


def main() -> None:
    print(f"# Python-layer peel (telemetry profile, N={N} emits)\n")

    # Layer A — full public verb.
    run("A. tn.log('bench', i=i)", textwrap.dedent(f"""
        t0 = time.perf_counter()
        for i in range({N}):
            tn.log('bench', i=i)
        dt = time.perf_counter() - t0
    """))

    # Layer B — go straight through _emit_with_splice, skipping the
    # verb wrapper (_reject_extra_positionals, _surface_log_emit,
    # _maybe_autoinit per-call check, late imports).
    run("B. _emit_with_splice('', et, fields, None)", textwrap.dedent(f"""
        from tn import _emit_with_splice
        t0 = time.perf_counter()
        for i in range({N}):
            _emit_with_splice('', 'bench', {{'i': i}}, None)
        dt = time.perf_counter() - t0
    """))

    # Layer C — call _emit_via directly with the singleton; skips the
    # _require_dispatch lookup inside _emit_with_splice. Otherwise
    # identical (still does context-merge, run_id auto-inject,
    # coerce-for-wire, splice-agent-policy).
    run("C. _emit_via(rt, '', et, fields, None)", textwrap.dedent(f"""
        from tn import _emit_via, _require_dispatch
        rt = _require_dispatch()
        t0 = time.perf_counter()
        for i in range({N}):
            _emit_via(rt, '', 'bench', {{'i': i}}, None)
        dt = time.perf_counter() - t0
    """))

    # Layer D — call dispatch.emit directly. Skips _emit_via's
    # context merge, run_id auto-inject, _coerce_for_wire, agent
    # policy splice. The dict goes straight into PyO3.
    run("D. dispatch.emit('', et, fields, sign=None)", textwrap.dedent(f"""
        from tn import _require_dispatch
        rt = _require_dispatch()
        t0 = time.perf_counter()
        for i in range({N}):
            rt.emit('', 'bench', {{'i': i, 'run_id': 'r'}}, sign=None)
        dt = time.perf_counter() - t0
    """))

    # Layer E — go straight to the PyO3 Rust call. Bypasses
    # DispatchRuntime.emit and its _fan_out_python_handlers call.
    run("E. rt._rt.emit('', et, fields, None, None, None)", textwrap.dedent(f"""
        from tn import _require_dispatch
        rt = _require_dispatch()
        rust_rt = rt._rt
        t0 = time.perf_counter()
        for i in range({N}):
            rust_rt.emit('', 'bench', {{'i': i, 'run_id': 'r'}}, None, None, None)
        dt = time.perf_counter() - t0
    """))


if __name__ == "__main__":
    main()
