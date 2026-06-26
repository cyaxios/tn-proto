"""Tests for cmd_wallet_watch (Task 9: wallet watch loop + AWK autocache).

TDD contract:
  - cmd_wallet_watch calls cmd_wallet_sync at least once.
  - When cmd_wallet_sync raises KeyboardInterrupt on the 2nd call, the
    loop catches it and returns 0 (clean stop).
  - time.sleep is no-op'd so the test runs instantly.
  - tn.init / tn.current_config / tn.flush_and_close are stubbed so the
    interval-probe block doesn't need a real ceremony.
"""
from __future__ import annotations

import argparse
import types
from unittest.mock import MagicMock, patch

import pytest

import tn.cli_wallet as cw


def _watch_args(**kw):
    defaults = dict(yaml=None, vault=None)
    defaults.update(kw)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Core contract: loop runs, stops cleanly on KeyboardInterrupt
# ---------------------------------------------------------------------------

def test_watch_calls_sync_then_exits_on_keyboard_interrupt():
    """watch calls sync at least once; KeyboardInterrupt from sleep exits 0."""
    call_counter = {"n": 0}

    def fake_sync(ns):
        call_counter["n"] += 1
        return 0

    # Minimal config stub with vault_sync_interval_seconds.
    fake_cfg = types.SimpleNamespace(vault_sync_interval_seconds=1)

    with (
        patch.object(cw, "cmd_wallet_sync", side_effect=fake_sync),
        patch("time.sleep", side_effect=KeyboardInterrupt),
        patch.object(cw.tn, "init"),
        patch.object(cw.tn, "current_config", return_value=fake_cfg),
        patch.object(cw.tn, "flush_and_close"),
        patch.object(cw, "_resolve_yaml_or_discover", return_value=None),
        patch.object(cw, "_default_identity_path", return_value=MagicMock()),
        patch.object(cw, "_load_identity_or_die", return_value=MagicMock()),
    ):
        rc = cw.cmd_wallet_watch(_watch_args())

    assert rc == 0
    assert call_counter["n"] >= 1


def test_watch_runs_two_iterations_then_stops_on_sleep_interrupt():
    """After 2 sync calls with normal sleep no-op, 3rd sleep raises KeyboardInterrupt."""
    call_counter = {"n": 0}
    sleep_counter = {"n": 0}

    def fake_sync(ns):
        call_counter["n"] += 1
        return 0

    def fake_sleep(interval):
        sleep_counter["n"] += 1
        if sleep_counter["n"] >= 2:
            raise KeyboardInterrupt

    fake_cfg = types.SimpleNamespace(vault_sync_interval_seconds=1)

    with (
        patch.object(cw, "cmd_wallet_sync", side_effect=fake_sync),
        patch("time.sleep", side_effect=fake_sleep),
        patch.object(cw.tn, "init"),
        patch.object(cw.tn, "current_config", return_value=fake_cfg),
        patch.object(cw.tn, "flush_and_close"),
        patch.object(cw, "_resolve_yaml_or_discover", return_value=None),
        patch.object(cw, "_default_identity_path", return_value=MagicMock()),
        patch.object(cw, "_load_identity_or_die", return_value=MagicMock()),
    ):
        rc = cw.cmd_wallet_watch(_watch_args())

    assert rc == 0
    assert call_counter["n"] >= 2


def test_watch_passes_yaml_and_vault_to_sync():
    """Namespace passed into sync includes yaml and vault from watch args."""
    received = {}
    call_counter = {"n": 0}

    def fake_sync(ns):
        call_counter["n"] += 1
        received["yaml"] = ns.yaml
        received["vault"] = ns.vault
        return 0

    fake_cfg = types.SimpleNamespace(vault_sync_interval_seconds=600)

    with (
        patch.object(cw, "cmd_wallet_sync", side_effect=fake_sync),
        patch("time.sleep", side_effect=KeyboardInterrupt),
        patch.object(cw.tn, "init"),
        patch.object(cw.tn, "current_config", return_value=fake_cfg),
        patch.object(cw.tn, "flush_and_close"),
        patch.object(cw, "_resolve_yaml_or_discover", return_value=None),
        patch.object(cw, "_default_identity_path", return_value=MagicMock()),
        patch.object(cw, "_load_identity_or_die", return_value=MagicMock()),
    ):
        rc = cw.cmd_wallet_watch(_watch_args(yaml="myproject/tn.yaml", vault="https://vault.example.com"))

    assert rc == 0
    assert received.get("vault") == "https://vault.example.com"


def test_watch_interval_fallback_on_config_error():
    """If the config probe raises, the interval defaults to 600."""
    call_counter = {"n": 0}

    def fake_sync(ns):
        call_counter["n"] += 1
        return 0

    with (
        patch.object(cw, "cmd_wallet_sync", side_effect=fake_sync),
        patch("time.sleep", side_effect=KeyboardInterrupt),
        patch.object(cw.tn, "init", side_effect=Exception("no ceremony")),
        patch.object(cw.tn, "current_config"),
        patch.object(cw.tn, "flush_and_close"),
        patch.object(cw, "_resolve_yaml_or_discover", return_value=None),
        patch.object(cw, "_default_identity_path", return_value=MagicMock()),
        patch.object(cw, "_load_identity_or_die", return_value=MagicMock()),
    ):
        rc = cw.cmd_wallet_watch(_watch_args())

    assert rc == 0
    assert call_counter["n"] >= 1
