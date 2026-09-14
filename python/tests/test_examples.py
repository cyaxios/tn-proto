"""Run the event stream examples end-to-end and check their output.

Each example is also a pytest-style test: it prints a few markers that
prove the scenario worked. The test harness runs each as a subprocess
in a clean interpreter so nothing leaks state between them.

Fail-fast: if any example exits non-zero or doesn't print the expected
marker, the whole suite fails.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY_PKG = HERE.parent
EXAMPLES_DIR = PY_PKG / "examples"

_EXPECTATIONS: list[tuple[str, list[str]]] = [
    # (filename, [substrings that MUST appear in the captured stdout])
    (
        "ex01_hello.py",
        [
            "I am: did:key:",
            "app.booted",
            "page.view",
            "auth.retry",
            "[info   ]",
            "fields=",
        ],
    ),
    (
        "ex02_reading.py",
        [
            "envelope shape",
            "event_type=page.view",
            # The main log contains the four application events.
            "all 4 rows pass: signature, row_hash, chain",
            "verify   = True",
        ],
    ),
    (
        "ex03_groups.py",
        [
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
    (
        "ex08_stdout.py",
        ["default-on:", "stdout=False:", "file contains 4 event(s)"],
    ),
]


def _run_example(name: str, *, stdout_format: str = "pretty") -> tuple[int, str]:
    # Run in a fresh interpreter with PY_PKG on sys.path so `import tn`
    # resolves to this project (not any system-installed tn package).
    with tempfile.TemporaryDirectory(prefix="tn-example-state-") as state_dir:
        env = {
            **os.environ,
            "PYTHONPATH": str(PY_PKG),
            "PYTHONIOENCODING": "utf-8",
            "TN_STATE_DIR": state_dir,
            "TN_IDENTITY_DIR": str(Path(state_dir) / "identity"),
            "TN_NO_LINK": "1",
            "TN_STDOUT_FORMAT": stdout_format,
            "TN_STDOUT_INCLUDE_ADMIN": "0",
        }
        env.pop("TN_NO_STDOUT", None)
        proc = subprocess.run(
            [sys.executable, str(EXAMPLES_DIR / name)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            env=env,
        )
    if name == "ex08_stdout.py" and proc.returncode == 0:
        assert "silent.event" not in proc.stdout
        if stdout_format == "json":
            envelopes = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]
            events = [item["event_type"] for item in envelopes]
            assert events == ["app.booted", "order.created", "auth.retry"]
        else:
            for event in ("app.booted", "order.created", "auth.retry"):
                assert event in proc.stdout
    return proc.returncode, proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")


def test_stdout_json():
    rc, output = _run_example("ex08_stdout.py", stdout_format="json")
    assert rc == 0, output
    assert "file contains 4 event(s)" in output


def test_all_examples():
    failures: list[str] = []
    for name, markers in _EXPECTATIONS:
        rc, output = _run_example(name)
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
