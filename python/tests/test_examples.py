"""Run every example end-to-end and check its output.

Each example is also a pytest-style test: it prints a few markers that
prove the scenario worked. The test harness runs each as a subprocess
in a clean interpreter so nothing leaks state between them.

Fail-fast: if any example exits non-zero or doesn't print the expected
marker, the whole suite fails.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY_PKG = HERE.parent
EXAMPLES_DIR = PY_PKG / "examples"

# ex03 + ex05 demonstrate btn-cipher recipient management and need the
# Rust extension (tn_core / tn_btn). When the extension isn't built they
# print a SKIP marker and exit 0 — so we recognize that as "skipped" rather
# than a failure.
sys.path.insert(0, str(PY_PKG))

_EXPECTATIONS: list[tuple[str, list[str]]] = [
    # (filename, [substrings that MUST appear in the captured stdout])
    (
        "ex01_hello.py",
        [
            "I am: did:key:",
            "app.booted",
            "page.view",
            "auth.retry",
            # ex01 now uses tn.read() flat shape; check for the friendly
            # printout instead of the audit-grade `sig=ok`.
            "[info   ]",
            "fields=",
        ],
    ),
    (
        "ex02_reading.py",
        [
            "envelope shape",
            "event_type=page.view",
            "sig=ok",
            "chain=ok",
            "row_hash_recomputes=ok",
            "verify   = True",
        ],
    ),
    (
        "ex03_groups.py",
        [
            # Either the SKIP marker (no Rust ext) or the full success markers.
            # We check for ONE of these alternatives via _check_markers below.
            "groups now defined:",
            "as publisher",
            "alice@example.com",
            "as partner",
            "[encrypted,",
        ],
    ),
    (
        "ex05_rotate.py",
        [
            "minted leaf",
            "[ok] analyst's old kit still decrypts data written BEFORE revocation",
            "[ok] analyst's kit cannot decrypt data written AFTER revocation",
            "revocation chain entries in the log:",
        ],
    ),
    (
        "ex06_multi_handler.py",
        [
            "tn.ndjson",
            "6 line(s)",
            "auth.ndjson",
            "pages.ndjson",
            "2 line(s)",
            "fan-out works as configured.",
        ],
    ),
    (
        "ex07_context.py",
        [
            "req-0",
            "req-1",
            "req-2",
            "req-3",
            "context isolation works across concurrent tasks.",
        ],
    ),
]


def _run_example(name: str) -> tuple[int, str]:
    # Run in a fresh interpreter with PY_PKG on sys.path so `import tn`
    # resolves to this project (not any system-installed tn package).
    proc = subprocess.run(
        [sys.executable, str(EXAMPLES_DIR / name)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env={
            **__import__("os").environ,
            "PYTHONPATH": str(PY_PKG),
            "PYTHONIOENCODING": "utf-8",
        },
    )
    return proc.returncode, proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")


_RUST_EXAMPLES: frozenset[str] = frozenset({"ex03_groups.py", "ex05_rotate.py"})


def test_all_examples():
    failures: list[str] = []
    for name, markers in _EXPECTATIONS:
        rc, output = _run_example(name)
        if rc == 0 and name in _RUST_EXAMPLES and "SKIP:" in output:
            # Example self-skipped because the Rust extension isn't built.
            print(f"  [skip] {name} — Rust ext not built (SKIP marker)")
            continue
        missing = [m for m in markers if m not in output]
        status = "ok" if rc == 0 and not missing else "FAIL"
        print(f"  [{status}] {name}")
        if rc != 0:
            failures.append(f"{name}: exit code {rc}\n--- output ---\n{output}")
        elif missing:
            failures.append(f"{name}: missing markers {missing}\n--- output ---\n{output}")

    if failures:
        print("\n".join(failures))
        raise SystemExit(1)
    print("\nall examples passed.")


if __name__ == "__main__":
    test_all_examples()
