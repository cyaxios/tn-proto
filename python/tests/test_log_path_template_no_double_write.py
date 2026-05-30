"""Regression: a templated ``logs.path`` must write each event exactly once.

Bug (fix/templated-logs-double-write): when ``logs.path`` contained TN path
tokens (e.g. ``{event_type}``) the ceremony wrote every event TWICE — once to
the template-resolved fan-out file (the Rust runtime's per-event write) and
again via the Python ``FileTemplatedRotatingHandler`` the registry builds for
the main-log template. That handler was never marked ``_tn_default`` (the
sentinel is set only when a handler's *literal* ``path`` equals
``cfg.logs.path``, and a templated sink exposes ``_template`` not ``path``), so
it ran in the post-Rust fan-out and produced a duplicate copy. On disk a
3-event run left 6 rows (3 in ``evt.ndjson`` + 3 in the empty-render
``tn.ndjson`` stem file); ``tn.read(log=template)`` returned 2N rows.

Invariant under test: exactly one file handler writes the main log. Under a
templated ``logs.path`` the Rust runtime owns the single canonical write and
the Python mirror is skipped; the default (non-templated) path is unchanged.

Each case runs ``tn init`` + the emit loop in a *subprocess* so the
module-level runtime cache in ``tn`` does not leak between cases.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path


_DRIVER = textwrap.dedent(
    """
    import glob, json, os, subprocess, sys
    import tn

    work = sys.argv[1]
    logs_path = sys.argv[2]
    read_arg = sys.argv[3]
    os.chdir(work)
    subprocess.run([sys.executable, "-m", "tn.cli", "init", "T", "--no-link"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    yp = os.path.join(work, ".tn", "T", "tn.yaml")
    t = open(yp, encoding="utf-8").read()
    # The scaffolder writes logs.path = ./logs/tn.ndjson. Set only the
    # logs: block path; the documented repro templates logs.path.
    t = t.replace("logs:\\n  path: ./logs/tn.ndjson",
                  "logs:\\n  path: " + logs_path, 1)
    open(yp, "w", encoding="utf-8").write(t)

    tn.use("T")
    for i in range(3):
        tn.info("evt", n=i)
    tn.flush_and_close()

    logs_dir = os.path.join(work, ".tn", "T", "logs")
    counts = {}
    for fp in glob.glob(os.path.join(logs_dir, "**", "*"), recursive=True):
        if os.path.isfile(fp):
            with open(fp, "rb") as fh:
                counts[os.path.basename(fp)] = sum(1 for ln in fh if ln.strip())
    read_rows = len(list(tn.read(log=read_arg)))
    print("RESULT::" + json.dumps({"counts": counts, "read": read_rows}))
    """
)


def _run_case(tmp_path: Path, logs_path: str, read_arg: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", _DRIVER, str(tmp_path), logs_path, read_arg],
        capture_output=True,
        text=True,
        check=True,
    )
    line = next(
        ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT::")
    )
    return json.loads(line[len("RESULT::"):])


def test_templated_logs_path_writes_each_event_once(tmp_path):
    res = _run_case(
        tmp_path,
        "./logs/{event_type}.ndjson",
        "./logs/{event_type}.ndjson",
    )
    counts = res["counts"]
    # The three `evt` events land in exactly one file, once each.
    assert counts.get("evt.ndjson") == 3, counts
    # No double-write: total data rows for the `evt` event_type == N, not 2N.
    evt_rows = sum(v for k, v in counts.items() if k.startswith("evt"))
    assert evt_rows == 3, counts
    # The empty-render stem file must not collect a duplicate copy.
    assert counts.get("tn.ndjson", 0) == 0, counts
    # tn.read against the template returns N rows, not 2N.
    assert res["read"] == 3, res


def test_default_logs_path_single_write_unchanged(tmp_path):
    res = _run_case(tmp_path, "./logs/tn.ndjson", "./logs/tn.ndjson")
    counts = res["counts"]
    # Non-templated path: one file, 3 events + the tn.ceremony.init row.
    assert list(counts) == ["tn.ndjson"], counts
    assert counts["tn.ndjson"] == 4, counts
    assert res["read"] == 4, res
