"""Ergonomic tn.read() — args optional, fall back to init'd runtime."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn


@pytest.fixture(autouse=True)
def fresh_runtime():
    tn.flush_and_close()  # clean state before each test
    yield
    tn.flush_and_close()  # clean state after each test


def _user_events(iterable):
    """Filter out tn.* bootstrap attestations from a tn.read() iterator."""
    return [e for e in iterable if not e["event_type"].startswith("tn.")]


def test_read_no_args_uses_init_cfg(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path)
    tn.info("test.event", key="value")
    tn.flush_and_close()
    tn.init(yaml_path)
    entries = _user_events(tn.read())
    assert len(entries) == 1
    assert entries[0]["event_type"] == "test.event"


def test_read_path_only_uses_init_cfg(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    log_path = tmp_path / ".tn/tn/logs" / "custom.ndjson"
    tn.init(yaml_path, log_path=log_path)
    tn.info("test.event2", x=1)
    tn.flush_and_close()
    tn.init(yaml_path, log_path=log_path)
    entries = _user_events(tn.read(log_path))  # path only, cfg from runtime
    assert len(entries) == 1
    assert entries[0]["event_type"] == "test.event2"


def test_read_explicit_cfg_still_works(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    log_path = tmp_path / ".tn/tn/logs" / "tn.ndjson"
    tn.init(yaml_path, log_path=log_path)
    tn.info("test.event3", y=2)
    tn.flush_and_close()
    tn.init(yaml_path, log_path=log_path)
    cfg = tn.current_config()
    entries = _user_events(tn.read(log_path, cfg))  # legacy two-arg form — must work
    assert len(entries) == 1


def test_read_without_init_raises():
    """Strict mode keeps the pre-auto-init contract: read with no init
    raises. Without strict mode, auto-init (2026-04-25) would mint a
    ceremony silently — that's the no-arg ``tn.read()`` ergonomics fix
    we explicitly want, but the regression test for the old error path
    still has coverage via strict mode."""
    tn.set_strict(True)
    try:
        with pytest.raises(RuntimeError, match=r"tn\.init\(yaml_path\) must be called"):
            list(tn.read())
    finally:
        tn.set_strict(False)
