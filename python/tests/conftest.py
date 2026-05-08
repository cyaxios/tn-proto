"""pytest config — keep the test suite quiet by default.

The default-on stdout handler (added in this PR) would otherwise dump every
emitted envelope to pytest's captured stdout, ballooning failure traces and
making CI logs unreadable. Tests that *want* to exercise the stdout path
(e.g. ``tests/test_stdout_handler.py``) opt back in by clearing the env
var via ``monkeypatch.delenv("TN_NO_STDOUT", raising=False)``.

This is environmental, not a behavior change — production / dev / interactive
use still gets the default-on stdout that ``tn.init()`` provides.

We also prepend ``python/`` to ``sys.path`` so the in-repo ``tn`` package
resolves before any pip-installed ``tn-protocol`` in the active venv.
Without this, the first test to ``import tn`` (whichever pytest collects
first) might pull the published wheel from site-packages and shadow the
working tree we're actually testing.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure the in-repo ``tn`` package (python/tn/) wins over any installed
# tn-protocol wheel. Insert at index 0 so it precedes site-packages.
_PY_DIR = Path(__file__).resolve().parent.parent
_PY_DIR_STR = str(_PY_DIR)
if _PY_DIR_STR in sys.path:
    sys.path.remove(_PY_DIR_STR)
sys.path.insert(0, _PY_DIR_STR)

# If ``tn`` was already imported (e.g. by a plugin), drop it so the
# subsequent ``import tn`` picks up the in-repo source.
for _modname in [m for m in list(sys.modules) if m == "tn" or m.startswith("tn.")]:
    del sys.modules[_modname]


def pytest_configure(config):
    # Set BEFORE any test imports tn — tn.init() reads this at runtime
    # via os.environ, so setting it on the parent process suffices for all
    # in-process tests. Subprocess tests that explicitly need stdout-on
    # must clear it themselves.
    os.environ.setdefault("TN_NO_STDOUT", "1")
