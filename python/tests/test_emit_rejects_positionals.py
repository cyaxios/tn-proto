"""Emit verbs reject extra positional args (DX review #3).

Previously ``tn.info("evt", "a", 1, "b")`` silently folded the
positional tail into a single concatenated ``message`` string,
destroying the caller's structured intent. The five verbs now raise
``TypeError`` with a migration hint when called that way. The
``message=`` kwarg is the canonical way to attach a free-text
message.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def _ensure_tn_init(tmp_path: Path):
    """Run init in tmp_path so emits don't pollute the user's cwd."""
    cwd = os.getcwd()
    os.chdir(tmp_path)
    import tn
    try:
        tn.init()
    except Exception:  # pragma: no cover
        os.chdir(cwd)
        raise
    return cwd, tn


@pytest.mark.parametrize(
    "verb",
    ["info", "warning", "error", "debug", "log"],
)
def test_module_verbs_reject_extra_positionals(verb: str, tmp_path: Path):
    cwd, tn = _ensure_tn_init(tmp_path)
    try:
        fn = getattr(tn, verb)
        with pytest.raises(TypeError, match=r"extra positional argument"):
            fn("payment.completed", "user-123", 4999, "USD")
    finally:
        tn.flush_and_close()
        os.chdir(cwd)


def test_kwargs_path_still_works(tmp_path: Path):
    """Sanity: structured kwargs still produce a valid entry."""
    cwd, tn = _ensure_tn_init(tmp_path)
    try:
        tn.info(
            "payment.completed",
            user="user-123",
            amount=4999,
            currency="USD",
        )
        tn.flush_and_close()
        for e in tn.read():
            if e.event_type == "payment.completed":
                assert e.fields == {
                    "amount": 4999,
                    "currency": "USD",
                    "user": "user-123",
                }
                return
        pytest.fail("payment.completed event not found in log")
    finally:
        os.chdir(cwd)


def test_message_kwarg_is_the_migration_path(tmp_path: Path):
    """The TypeError points users at ``message=``. Confirm that works."""
    cwd, tn = _ensure_tn_init(tmp_path)
    try:
        tn.info("evt", message="hello world", level_hint="ok")
        tn.flush_and_close()
        for e in tn.read():
            if e.event_type == "evt":
                # message hoists to Entry.message (top-level slot)
                assert e.message == "hello world"
                return
        pytest.fail("evt not found in log")
    finally:
        os.chdir(cwd)


def test_handle_verbs_reject_extra_positionals(tmp_path: Path):
    """Per-instance TN.info etc. should mirror the module-level
    behaviour — same TypeError."""
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        import tn
        h = tn.init()
        try:
            for verb in ("info", "warning", "error", "debug", "log"):
                fn = getattr(h, verb)
                with pytest.raises(TypeError, match=r"extra positional argument"):
                    fn("evt", "extra")
        finally:
            tn.flush_and_close()
    finally:
        os.chdir(cwd)
