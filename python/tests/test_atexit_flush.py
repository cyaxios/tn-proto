"""tn.init() registers an atexit hook so handlers drain on normal
interpreter shutdown without the caller having to call
tn.flush_and_close().

Test strategy: spawn a Python subprocess that does only tn.init() +
tn.info() + sys.exit(0). Then in the parent, read the log file and
assert the events landed. If atexit didn't drain, the events would
still be in the runtime's in-memory state when the subprocess died
and the on-disk log would be empty (or partial).

Companion to the usability cleanup in #35.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path


def _run_subprocess(script: str, cwd: Path) -> subprocess.CompletedProcess:
    """Run ``python -c <script>`` in cwd. Captures stdout+stderr.

    Isolation: TN_HOME is pointed at ``cwd/.tn-home`` so the subprocess
    never finds the developer's real ``~/.tn/tn.yaml`` via the
    discovery chain. Without this, the test passes locally but the
    log file ends up in the developer's home dir instead of tmp_path.
    """
    env = dict(os.environ)
    env["TN_NO_STDOUT"] = "1"
    env["TN_HOME"] = str(cwd / ".tn-home")
    # Drop any inherited TN_YAML that would short-circuit discovery.
    env.pop("TN_YAML", None)
    # Make the in-repo tn package win over any installed wheel — same
    # rule conftest.py uses for the test suite itself.
    repo_python_dir = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = str(repo_python_dir) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_atexit_drains_without_explicit_flush(tmp_path: Path) -> None:
    """A subprocess that calls tn.init() + tn.info() + sys.exit(0)
    should have its log entries on disk when we read them from the
    parent — the atexit hook must drain even if the user never calls
    flush_and_close()."""
    script = textwrap.dedent(
        """
        import sys
        import tn
        tn.init()
        tn.info("user.action", actor="alice", amount=42)
        tn.info("user.action", actor="bob", amount=99)
        sys.exit(0)
        """
    )
    result = _run_subprocess(script, tmp_path)
    assert result.returncode == 0, (
        f"subprocess failed: rc={result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    # Find the log file the subprocess produced. Fresh init uses the
    # cwd-named Project root.
    log_path = tmp_path / ".tn" / tmp_path.name / "logs" / "default.ndjson"
    assert log_path.exists(), (
        f"log file missing - atexit didn't drain. "
        f"stderr from subprocess:\n{result.stderr}"
    )

    # Count the user.action events. We don't decrypt; we just confirm
    # both envelopes made it to disk.
    user_event_count = sum(
        1
        for line in log_path.read_text().splitlines()
        if line.strip() and json.loads(line).get("event_type") == "user.action"
    )
    assert user_event_count == 2, (
        f"expected 2 user.action events, found {user_event_count}. "
        f"atexit may not have drained the second event before exit."
    )


def test_explicit_flush_still_works(tmp_path: Path) -> None:
    """Calling tn.flush_and_close() explicitly continues to work and
    doesn't double-close when atexit fires afterward."""
    script = textwrap.dedent(
        """
        import sys
        import tn
        tn.init()
        tn.info("user.action", marker="alpha")
        tn.flush_and_close()
        # If this triggers a double-close or atexit conflict, the
        # subprocess exits non-zero or prints to stderr.
        sys.exit(0)
        """
    )
    result = _run_subprocess(script, tmp_path)
    assert result.returncode == 0, (
        f"explicit flush+atexit conflict: rc={result.returncode}\n"
        f"stderr: {result.stderr}"
    )
    # No stderr noise from atexit running after explicit close.
    assert "Exception" not in result.stderr, (
        f"atexit raised after explicit flush_and_close:\n{result.stderr}"
    )
