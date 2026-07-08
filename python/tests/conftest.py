"""pytest config — keep the test suite quiet by default.

The default-on stdout handler (added in this PR) would otherwise dump every
emitted envelope to pytest's captured stdout, ballooning failure traces and
making CI logs unreadable. Tests that *want* to exercise the stdout path
(e.g. ``tests/test_stdout_handler.py``) opt back in by clearing the env
var via ``monkeypatch.delenv("TN_NO_STDOUT", raising=False)``.

This is environmental, not a behavior change — production / dev / interactive
use still gets the default-on stdout that ``tn.init()`` provides.

We also prepend ``python/`` to ``sys.path`` so the in-repo ``tn`` package
resolves before any pip-installed ``tn-proto`` in the active venv.
Without this, the first test to ``import tn`` (whichever pytest collects
first) might pull the published wheel from site-packages and shadow the
working tree we're actually testing.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure the in-repo ``tn`` package (python/tn/) wins over any installed
# tn-proto wheel. Insert at index 0 so it precedes site-packages.
_PY_DIR = Path(__file__).resolve().parent.parent
_PY_DIR_STR = str(_PY_DIR)
if _PY_DIR_STR in sys.path:
    sys.path.remove(_PY_DIR_STR)
sys.path.insert(0, _PY_DIR_STR)

# If ``tn`` was already imported from OUTSIDE the repo (e.g. a plugin
# pulled the pip-installed wheel), drop it so the subsequent ``import tn``
# picks up the in-repo source. An in-repo ``tn`` stays cached: evicting it
# would force a second init of the PyO3 native module in one process,
# which PyO3 refuses — that breaks the ``python tests/test_x.py`` shims
# (``pytest.main([__file__])``) the cipher sweep relies on.
_tn_mod = sys.modules.get("tn")
if _tn_mod is not None and not str(
    getattr(_tn_mod, "__file__", "") or ""
).startswith(_PY_DIR_STR):
    for _modname in [m for m in list(sys.modules) if m == "tn" or m.startswith("tn.")]:
        del sys.modules[_modname]


def pytest_configure(config):
    # Set BEFORE any test imports tn — tn.init() reads this at runtime
    # via os.environ, so setting it on the parent process suffices for all
    # in-process tests. Subprocess tests that explicitly need stdout-on
    # must clear it themselves.
    os.environ.setdefault("TN_NO_STDOUT", "1")

    # Keep the suite off the production vault. Ceremonies mint in linked
    # mode by default, so any test that runs an admin verb (or the session
    # ping) would otherwise phone https://vault.tn-proto.org — that leak
    # produced ~300 real autosync attempts against prod on 2026-07-02
    # alone. Port 9 (discard) refuses instantly, so a test that DOES reach
    # the network fails fast instead of hanging. Tests that exercise URL
    # resolution or a live local vault override this themselves.
    os.environ.setdefault("TN_VAULT_URL", "http://127.0.0.1:9")

    # Same containment for machine-local state (sync_queue failure records,
    # autosync throttle stamps): route it to a per-run temp dir instead of
    # the developer's real %APPDATA%/tn.
    import tempfile

    os.environ.setdefault(
        "TN_STATE_DIR", tempfile.mkdtemp(prefix="tn-pytest-state-")
    )

    # Latch the once-per-process session usage ping off for the whole run —
    # it would otherwise fire at whatever vault the FIRST tn.init() in the
    # run resolves (tests that delenv TN_VAULT_URL resolve prod).
    # tests/test_session_ping.py resets the latch to exercise the ping.
    import tn

    tn._session_ping_done = True
