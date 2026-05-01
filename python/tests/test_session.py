"""Tests for ``tn.session()`` — context manager + nested sessions + pytest fixture.

The session helper is the test-mode opt-in for tn: instead of
``tn.init(tmp_path / "tn.yaml") ... tn.flush_and_close()`` boilerplate,
a test does:

    with tn.session(tmp_path) as t:
        t.info(...)

On exit the inner ceremony is torn down. If the outer code had its own
``tn.init()`` active, it's restored.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import _autoinit

# ``pytester`` lives in pytest's contrib plugin; opt in here because the
# repo's pyproject doesn't enable it globally.
pytest_plugins = ["pytester"]


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.delenv("TN_STRICT", raising=False)
    monkeypatch.delenv("TN_AUTOINIT_QUIET", raising=False)
    # Always quiet the loud notice in this test file — we're not
    # testing the banner here, and it pollutes captured output.
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()


def _read_log_lines(yaml_dir: Path) -> list[dict]:
    log_path = yaml_dir / ".tn/tn/logs" / "tn.ndjson"
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]


def test_session_with_path_writes_to_that_dir(tmp_path):
    with tn.session(tmp_path) as t:
        t.info("evt.session", k=1)
        assert tn._dispatch_rt is not None
    # On exit, runtime is closed.
    assert tn._dispatch_rt is None

    entries = _read_log_lines(tmp_path)
    user = [e for e in entries if e["event_type"] == "evt.session"]
    assert len(user) == 1


def test_session_module_level_calls_route_through_context(tmp_path):
    """``tn.info(...)`` inside the with block must hit the session ceremony."""
    with tn.session(tmp_path):
        tn.info("evt.module", k=2)
    entries = _read_log_lines(tmp_path)
    assert any(e["event_type"] == "evt.module" for e in entries)


def test_session_no_arg_uses_tempdir_and_cleans_up():
    """No-arg form spins up a TemporaryDirectory; the dir is gone after exit."""
    captured_dir: list[Path] = []
    with tn.session() as t:
        t.info("evt.tmp", k=1)
        captured_dir.append(t.yaml_path.parent)
    # After exit the tempdir should have been removed.
    # Windows occasionally races on file handle release; allow
    # "either gone or empty".
    d = captured_dir[0]
    assert (not d.exists()) or list(d.iterdir()) == [], f"tempdir not cleaned: {d}"


def test_session_explicit_yaml_path(tmp_path):
    yaml = tmp_path / "explicit.yaml"
    with tn.session(yaml) as t:
        t.info("evt.explicit", k=1)
        assert t.yaml_path == yaml
    assert yaml.exists()


def test_session_nested_restores_outer(tmp_path):
    """Nested sessions: inner exit re-inits the outer ceremony."""
    outer_dir = tmp_path / "outer"
    inner_dir = tmp_path / "inner"
    outer_dir.mkdir()
    inner_dir.mkdir()

    with tn.session(outer_dir):
        tn.info("evt.outer.a", k=1)
        outer_yaml_before = tn.current_config().yaml_path

        with tn.session(inner_dir):
            tn.info("evt.inner", k=1)
            inner_yaml = tn.current_config().yaml_path
            assert inner_yaml != outer_yaml_before

        # Back to outer.
        assert tn._dispatch_rt is not None
        assert tn.current_config().yaml_path == outer_yaml_before
        tn.info("evt.outer.b", k=1)

    # Outer finished too.
    assert tn._dispatch_rt is None

    outer_entries = _read_log_lines(outer_dir)
    inner_entries = _read_log_lines(inner_dir)
    assert any(e["event_type"] == "evt.outer.a" for e in outer_entries)
    assert any(e["event_type"] == "evt.outer.b" for e in outer_entries)
    assert any(e["event_type"] == "evt.inner" for e in inner_entries)
    # No cross-contamination.
    assert not any(e["event_type"] == "evt.inner" for e in outer_entries)
    assert not any(e["event_type"].startswith("evt.outer") for e in inner_entries)


def test_session_nested_with_no_outer_restores_to_none(tmp_path):
    inner = tmp_path / "inner-only"
    inner.mkdir()

    with tn.session(inner):
        tn.info("evt.solo", k=1)
        assert tn._dispatch_rt is not None
    # No outer to restore — we should land back at None.
    assert tn._dispatch_rt is None


def test_session_handle_exposes_did(tmp_path):
    with tn.session(tmp_path) as t:
        assert isinstance(t.did, str)
        assert t.did.startswith("did:key:")


def test_pytest_fixture_round_trip(pytester):
    """Sanity-check the ``tn._pytest_fixtures`` plugin: a sample test
    using ``tn_session`` must pass."""
    pytester.makeconftest(
        """
        pytest_plugins = ["tn._pytest_fixtures"]
        """
    )
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.no_tn_session
        def test_uses_tn_session(tn_session):
            tn_session.info("fixture.evt", k=1)
            assert tn_session.did.startswith("did:key:")
        """
    )
    res = pytester.runpytest("-q")
    res.assert_outcomes(passed=1)
