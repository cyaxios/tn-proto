"""pytest config — keep the test suite quiet by default.

The default-on stdout handler (added in this PR) would otherwise dump every
emitted envelope to pytest's captured stdout, ballooning failure traces and
making CI logs unreadable. Tests that *want* to exercise the stdout path
(e.g. ``tests/test_stdout_handler.py``) opt back in by clearing the env
var via ``monkeypatch.delenv("TN_NO_STDOUT", raising=False)``.

This is environmental, not a behavior change — production / dev / interactive
use still gets the default-on stdout that ``tn.init()`` provides.
"""
from __future__ import annotations

import os


def pytest_configure(config):
    # Set BEFORE any test imports tn — tn.init() reads this at runtime
    # via os.environ, so setting it on the parent process suffices for all
    # in-process tests. Subprocess tests that explicitly need stdout-on
    # must clear it themselves.
    os.environ.setdefault("TN_NO_STDOUT", "1")
