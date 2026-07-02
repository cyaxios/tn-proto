"""Session usage ping: one anonymous GET /api/v1/ping per process.

Fired from tn.init() when the ceremony's vault settings allow contact.
Must be latched (once per process), gated (no vault → no ping,
TN_NO_LINK=1 → no ping), and fully contained.
"""
from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

import tn


@pytest.fixture(autouse=True)
def _reset_latch(monkeypatch):
    monkeypatch.setattr(tn, "_session_ping_done", False)
    monkeypatch.delenv("TN_NO_LINK", raising=False)


def _patch_link(monkeypatch, *, enabled=True, url="https://vault.example.com"):
    fake_wallet = types.ModuleType("tn.wallet")
    fake_wallet.vault_link_info = lambda cfg: SimpleNamespace(
        enabled=enabled, url=url
    )
    monkeypatch.setattr("tn.wallet", fake_wallet, raising=False)
    monkeypatch.setitem(sys.modules, "tn.wallet", fake_wallet)


def _capture_threads(monkeypatch):
    """Run the ping thread body synchronously and record the GET url."""
    calls: list = []

    class FakeThread:
        def __init__(self, target=None, **kw):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr("threading.Thread", FakeThread)

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = lambda url, **kw: calls.append(url)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    return calls


def test_ping_fires_once_per_process(monkeypatch):
    _patch_link(monkeypatch)
    calls = _capture_threads(monkeypatch)
    tn._session_ping(SimpleNamespace())
    tn._session_ping(SimpleNamespace())
    assert calls == ["https://vault.example.com/api/v1/ping"], (
        f"expected exactly one ping, got {calls!r}"
    )


def test_no_ping_when_vault_disabled(monkeypatch):
    _patch_link(monkeypatch, enabled=False)
    calls = _capture_threads(monkeypatch)
    tn._session_ping(SimpleNamespace())
    assert calls == []
    assert tn._session_ping_done is False, (
        "a disabled vault must not latch — a later init with a linked "
        "ceremony should still ping"
    )


def test_no_ping_when_tn_no_link(monkeypatch):
    monkeypatch.setenv("TN_NO_LINK", "1")
    _patch_link(monkeypatch)
    calls = _capture_threads(monkeypatch)
    tn._session_ping(SimpleNamespace())
    assert calls == []


def test_ping_failure_is_contained(monkeypatch):
    _patch_link(monkeypatch)

    class FakeThread:
        def __init__(self, target=None, **kw):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr("threading.Thread", FakeThread)

    def boom(url, **kw):
        raise OSError("vault unreachable")

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = boom
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    tn._session_ping(SimpleNamespace())  # must not raise
    assert tn._session_ping_done is True
