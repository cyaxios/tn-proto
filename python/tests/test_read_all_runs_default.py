"""Document the actual tn.read() default + pin it against drift.

Covers DX review #7: the README previously said `tn.read()` defaults
to *this run only*. The implementation has defaulted to
`all_runs=True` since 0.4.1a3. The README has been updated to match
reality; this test pins both the signature default and the runtime
behaviour so any future flip ships with a coordinated doc update.
"""
from __future__ import annotations

import inspect
import json
import subprocess
import sys
import textwrap
from pathlib import Path


def test_read_signature_default_is_all_runs_true():
    import tn

    sig = inspect.signature(tn.read)
    assert sig.parameters["all_runs"].default is True, (
        "If you intentionally change this default, also update the "
        "README's 'Reading: all runs, this run, admin' section."
    )


def _write_entry_in_subprocess(tmp_path: Path, marker: str) -> None:
    script = tmp_path / f"emit_{marker}.py"
    script.write_text(textwrap.dedent(f"""
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        tn.info("run.evt", marker={marker!r})
        tn.flush_and_close()
    """).strip())
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, rc.stderr


def _read_in_subprocess(tmp_path: Path, kwargs: str) -> list[str]:
    script = tmp_path / "reader.py"
    script.write_text(textwrap.dedent(f"""
        import os, json
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        markers = [
            e.fields.get("marker") for e in tn.read({kwargs})
            if e.event_type == "run.evt"
        ]
        print(json.dumps(markers))
    """).strip())
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, rc.stderr
    return json.loads(rc.stdout.decode().strip().splitlines()[-1])


def test_default_read_sees_previous_runs(tmp_path: Path):
    """Process A writes; process B's bare tn.read() sees A's entry."""
    _write_entry_in_subprocess(tmp_path, marker="run-A")
    markers = _read_in_subprocess(tmp_path, "")
    assert "run-A" in markers, (
        "tn.read() default (all_runs=True) must include entries from "
        "previous process runs. The README documents this behaviour; "
        "if it changes, update both the docs and this test."
    )


def test_all_runs_false_restricts_to_current_run(tmp_path: Path):
    """Process A writes; process B's tn.read(all_runs=False) is empty
    for A's marker (B emitted no run.evt of its own)."""
    _write_entry_in_subprocess(tmp_path, marker="run-A")
    markers = _read_in_subprocess(tmp_path, "all_runs=False")
    assert "run-A" not in markers, (
        f"all_runs=False must filter out previous runs, got {markers!r}"
    )


def test_all_runs_with_where_filters_backup_entries(tmp_path: Path):
    """all_runs=True + a where predicate: the where filter is applied to
    entries replayed from previous runs' rotated backups, not just the
    current log. Two prior runs (run-A, run-B) become backups; a where that
    keeps only run-A must yield exactly run-A from the backup replay."""
    _write_entry_in_subprocess(tmp_path, marker="run-A")
    _write_entry_in_subprocess(tmp_path, marker="run-B")
    markers = _read_in_subprocess(
        tmp_path, "where=lambda e: e.fields.get('marker') == 'run-A'"
    )
    assert markers == ["run-A"], (
        f"where must filter backup-replayed entries too, got {markers!r}"
    )
