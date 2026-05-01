"""Tests for tn.handlers.filter.Filter (RFC §3.2).

Every predicate, composition, and the default-sync-true behaviour are
exercised here. No network, no disk IO.

Run:
    .venv/Scripts/python.exe -m pytest tn-protocol/python/tests/test_handler_filter.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tn.handlers.filter import Filter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env(event_type: str = "order.created", level: str = "info", **kw) -> dict:
    """Build a minimal envelope dict for testing."""
    return {"event_type": event_type, "level": level, **kw}


# ---------------------------------------------------------------------------
# event_type (exact match)
# ---------------------------------------------------------------------------


def test_event_type_exact_match():
    f = Filter.from_spec({"event_type": "order.created"})
    assert f.matches(_env("order.created")) is True
    assert f.matches(_env("order.paid")) is False
    assert f.matches(_env("")) is False


def test_event_type_exact_empty_string():
    f = Filter.from_spec({"event_type": ""})
    assert f.matches({"event_type": ""}) is True
    assert f.matches({"event_type": "x"}) is False


# ---------------------------------------------------------------------------
# event_type_prefix
# ---------------------------------------------------------------------------


def test_event_type_prefix_match():
    f = Filter.from_spec({"event_type_prefix": "tn."})
    assert f.matches(_env("tn.recipient.added")) is True
    assert f.matches(_env("tn.")) is True
    assert f.matches(_env("order.created")) is False


def test_event_type_prefix_empty_matches_all():
    f = Filter.from_spec({"event_type_prefix": ""})
    assert f.matches(_env("anything")) is True
    assert f.matches({"event_type": ""}) is True


# ---------------------------------------------------------------------------
# not_event_type_prefix
# ---------------------------------------------------------------------------


def test_not_event_type_prefix():
    f = Filter.from_spec({"not_event_type_prefix": "trace."})
    assert f.matches(_env("order.created")) is True
    assert f.matches(_env("trace.span")) is False
    assert f.matches(_env("trace.")) is False


def test_not_event_type_prefix_with_prefix():
    # Combined: only tn.* but not tn.debug.*
    f = Filter.from_spec(
        {
            "event_type_prefix": "tn.",
            "not_event_type_prefix": "tn.debug.",
        }
    )
    assert f.matches(_env("tn.recipient.added")) is True
    assert f.matches(_env("tn.debug.span")) is False
    assert f.matches(_env("order.paid")) is False


# ---------------------------------------------------------------------------
# event_type_in
# ---------------------------------------------------------------------------


def test_event_type_in():
    f = Filter.from_spec({"event_type_in": ["order.created", "order.paid"]})
    assert f.matches(_env("order.created")) is True
    assert f.matches(_env("order.paid")) is True
    assert f.matches(_env("order.shipped")) is False


def test_event_type_in_single_item():
    f = Filter.from_spec({"event_type_in": ["tn.batch.commit"]})
    assert f.matches(_env("tn.batch.commit")) is True
    assert f.matches(_env("tn.rotation.completed")) is False


# ---------------------------------------------------------------------------
# level
# ---------------------------------------------------------------------------


def test_level_exact():
    f = Filter.from_spec({"level": "error"})
    assert f.matches(_env(level="error")) is True
    assert f.matches(_env(level="warning")) is False
    assert f.matches(_env(level="info")) is False


# ---------------------------------------------------------------------------
# level_in
# ---------------------------------------------------------------------------


def test_level_in():
    f = Filter.from_spec({"level_in": ["warning", "error"]})
    assert f.matches(_env(level="warning")) is True
    assert f.matches(_env(level="error")) is True
    assert f.matches(_env(level="info")) is False
    assert f.matches(_env(level="debug")) is False


# ---------------------------------------------------------------------------
# sync predicate
# ---------------------------------------------------------------------------


def test_sync_true_explicit():
    f = Filter.from_spec({"sync": True})
    assert f.matches(_env(sync=True)) is True
    assert f.matches(_env(sync=False)) is False


def test_sync_false_explicit():
    f = Filter.from_spec({"sync": False})
    assert f.matches(_env(sync=False)) is True
    assert f.matches(_env(sync=True)) is False


def test_sync_missing_field_treated_as_true():
    """RFC §2.1: an envelope without a ``sync`` key is treated as sync=True."""
    env_no_sync = {"event_type": "order.created", "level": "info"}
    assert "sync" not in env_no_sync

    f_true = Filter.from_spec({"sync": True})
    assert f_true.matches(env_no_sync) is True, "missing sync should match sync=True"

    f_false = Filter.from_spec({"sync": False})
    assert f_false.matches(env_no_sync) is False, "missing sync should not match sync=False"


# ---------------------------------------------------------------------------
# Composition (AND semantics)
# ---------------------------------------------------------------------------


def test_composition_all_must_match():
    f = Filter.from_spec(
        {
            "event_type_prefix": "order.",
            "level_in": ["warning", "error"],
        }
    )
    assert f.matches(_env("order.shipped", level="error")) is True
    assert f.matches(_env("order.shipped", level="info")) is False
    assert f.matches(_env("auth.failed", level="error")) is False


def test_composition_event_type_in_plus_sync():
    f = Filter.from_spec(
        {
            "event_type_in": ["tn.recipient.added", "tn.recipient.revoked"],
            "sync": True,
        }
    )
    assert f.matches({"event_type": "tn.recipient.added", "level": "info", "sync": True}) is True
    assert (
        f.matches({"event_type": "tn.recipient.revoked", "level": "info"}) is True
    )  # missing sync -> True
    assert f.matches({"event_type": "tn.recipient.added", "level": "info", "sync": False}) is False
    assert f.matches({"event_type": "order.paid", "level": "info", "sync": True}) is False


# ---------------------------------------------------------------------------
# Empty filter (accept-all)
# ---------------------------------------------------------------------------


def test_empty_filter_accepts_all():
    f = Filter.from_spec(None)
    assert f.matches(_env("anything", level="debug", sync=False)) is True

    f2 = Filter.from_spec({})
    assert f2.matches(_env("anything", level="debug", sync=False)) is True


# ---------------------------------------------------------------------------
# from_spec: unknown keys ignored
# ---------------------------------------------------------------------------


def test_unknown_keys_ignored():
    f = Filter.from_spec({"event_type": "x", "future_field": "y"})
    assert f.matches({"event_type": "x", "level": "info"}) is True
    assert f.matches({"event_type": "z", "level": "info"}) is False
