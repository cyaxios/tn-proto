"""Pytest plugin: ``tn_session`` and ``tn_session_autouse`` fixtures.

To enable in a downstream project, add to ``conftest.py``:

    pytest_plugins = ["tn._pytest_fixtures"]

Then any test can request a ceremony scoped to ``tmp_path``:

    def test_foo(tn_session):
        tn_session.info("evt.test", k=1)

Or use ``tn_session_autouse`` (set up by autouse — every test gets one)
when the project decides every test should have a fresh ceremony.

The fixtures are thin wrappers over ``tn.session(tmp_path)``. They exist
so the plugin pattern is one import line away rather than copy-pasted
boilerplate per project.
"""

from __future__ import annotations

import pytest  # type: ignore[import-not-found]

import tn


@pytest.fixture
def tn_session(tmp_path):
    """Open a TN session bound to ``tmp_path``. Auto-cleanup on exit."""
    with tn.session(tmp_path) as t:
        yield t


@pytest.fixture(autouse=True)
def tn_session_autouse(request, tmp_path):
    """Same as ``tn_session`` but autouse — every test in the project
    that imports this plugin gets a fresh ceremony for free.

    Opt out per test with::

        @pytest.mark.no_tn_session
        def test_foo():
            ...

    The mark is honored because some tests want to manage init/close
    themselves (e.g. tests that exercise ``tn.set_strict``).
    """
    if "no_tn_session" in request.keywords:
        yield None
        return
    # Use a subdir so the autouse fixture and any tn_session fixture
    # both work in the same test without colliding on yaml paths.
    with tn.session(tmp_path / "tn-autouse") as t:
        yield t


def pytest_configure(config) -> None:
    config.addinivalue_line(
        "markers",
        "no_tn_session: opt out of the autouse tn_session fixture for this test",
    )
