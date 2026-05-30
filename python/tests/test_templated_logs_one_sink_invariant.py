"""One-sink invariant for a templated ``logs.path``.

Companion to ``test_log_path_template_no_double_write.py``. That test
checks the on-disk row counts end-to-end; this one pins the *mechanism*:
when ``logs.path`` is templated but the ``tn init`` scaffolder left the
primary ``file.rotating`` handler at the literal stem
(``./logs/tn.ndjson``), the handler registry must still recognize that
handler as the Rust-owned canonical main log and mark it
``_tn_default=True``. ``DispatchRuntime`` then skips it at fan-out, so the
Rust runtime's per-event write is the *only* write to the main log.

Bug (fix/templated-logs-double-write-rust): the registry marked the sink
``_tn_default`` only when its literal ``path`` string equalled
``cfg.log_path``. A templated ``logs.path`` never string-matched the stem
handler, so the sink ran in the Python fan-out and every event landed in
two files. The drift case is the common one because ``tn init`` always
writes BOTH a ``logs.path`` and a stem-path handler.

Each case runs in a subprocess so the module-level ``tn`` runtime cache
does not leak between cases.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

_DRIVER = textwrap.dedent(
    """
    import json, os, subprocess, sys
    import tn

    work = sys.argv[1]
    logs_path = sys.argv[2]
    os.environ["TN_NO_STDOUT"] = "1"
    os.chdir(work)
    subprocess.run([sys.executable, "-m", "tn.cli", "init", "T", "--no-link"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    yp = os.path.join(work, ".tn", "T", "tn.yaml")
    t = open(yp, encoding="utf-8").read()
    t = t.replace("logs:\\n  path: ./logs/tn.ndjson",
                  "logs:\\n  path: " + logs_path, 1)
    open(yp, "w", encoding="utf-8").write(t)

    tn.use("T")
    # Force the singleton dispatch runtime to materialize.
    tn.info("evt", n=0)
    drt = tn._dispatch_rt

    py_handlers = [
        (type(h).__name__, getattr(h, "name", None), bool(getattr(h, "_tn_default", False)))
        for h in getattr(drt._py_rt, "handlers", [])
    ]
    effective = [type(h).__name__ for h in drt._cached_effective_handlers]
    print("RESULT::" + json.dumps({
        "using_rust": bool(drt.using_rust),
        "skip_fan_out": bool(drt._cached_skip_fan_out),
        "py_handlers": py_handlers,
        "effective": effective,
    }))
    """
)


def _run_case(tmp_path: Path, logs_path: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", _DRIVER, str(tmp_path), logs_path],
        capture_output=True,
        text=True,
        check=True,
    )
    line = next(ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT::"))
    return json.loads(line[len("RESULT::") :])


def test_templated_logs_marks_stem_main_handler_default(tmp_path):
    """Templated logs.path + literal-stem ``main`` handler: the stem
    handler is recognized as the Rust-owned main log and skipped."""
    res = _run_case(tmp_path, "./logs/{event_type}.ndjson")
    assert res["using_rust"] is True, res
    # The scaffolded main file.rotating must be marked default...
    main = [h for h in res["py_handlers"] if h[1] == "main"]
    assert main, res
    assert all(h[2] is True for h in main), res
    # ...so no file handler survives into the Python fan-out — Rust is
    # the only writer of the main log (stdout is also Rust-owned).
    assert "FileRotatingHandler" not in res["effective"], res
    assert res["skip_fan_out"] is True, res


def test_default_logs_path_main_handler_still_marked(tmp_path):
    """Non-templated default path: the literal-match marking still holds
    (no regression of the existing single-write behaviour)."""
    res = _run_case(tmp_path, "./logs/tn.ndjson")
    assert res["using_rust"] is True, res
    main = [h for h in res["py_handlers"] if h[1] == "main"]
    assert main, res
    assert all(h[2] is True for h in main), res
    assert "FileRotatingHandler" not in res["effective"], res
    assert res["skip_fan_out"] is True, res
