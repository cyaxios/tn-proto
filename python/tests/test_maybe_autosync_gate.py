"""
Tests for _maybe_autosync gate logic (Task 9b).

Truth table being verified:
  vault_autosync=True,  env unset  → sync attempted
  vault_autosync=False, env unset  → NOT attempted
  TN_WALLET_AUTOSYNC=1, vault_autosync=False → attempted
  TN_WALLET_AUTOSYNC=0, vault_autosync=True  → NOT attempted
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from tn.admin import _maybe_autosync


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(*, autosync: bool = False, vault_enabled: bool = True) -> SimpleNamespace:
    """Minimal cfg that satisfies the downstream vault-link guard."""
    cfg = SimpleNamespace()
    cfg.vault_autosync = autosync
    cfg.vault_enabled = vault_enabled
    cfg.ceremony_id = "test-ceremony-id"
    # is_linked() returns True when mode=="linked" and linked_vault is truthy.
    # Use a real method rather than a SimpleNamespace lambda so getattr works.
    cfg.mode = "linked"
    cfg.linked_vault = "https://vault.example.com"
    # _maybe_autosync resolves the account binding via get_account_id(cfg.yaml_path)
    # before draining the AWK inbox. A non-existent path => get_account_id None.
    cfg.yaml_path = Path("/tmp/tn-autosync-test/tn.yaml")

    # Attach is_linked as a bound-ish callable
    cfg.is_linked = lambda: True
    return cfg


# Stub out everything the body of _maybe_autosync needs so we reach the sync call.

def _patch_sync_dependencies(monkeypatch, sync_flag: list,
                             sync_kwargs: dict | None = None,
                             awk_return=(None, None)):
    """
    Patch Identity.load, VaultClient.for_identity, vault_link_info,
    wallet.sync_ceremony, plus the AWK-resolution deps the running-logger
    autosync now hits (resolve_cached_awk / get_account_id / DeviceKey), so the
    test can record whether sync was attempted AND with what credential.

    ``sync_kwargs`` (if given) captures the kwargs sync_ceremony received —
    used to assert the cached AWK is forwarded. ``awk_return`` is what the
    patched resolve_cached_awk yields (``(awk, account_id)``).
    """
    # Build a fake wallet module
    fake_wallet = types.ModuleType("tn.wallet")

    link = SimpleNamespace(enabled=True, url="https://vault.example.com")
    fake_wallet.vault_link_info = lambda cfg: link

    def fake_sync(cfg, client, **kwargs):
        sync_flag.append(True)
        if sync_kwargs is not None:
            sync_kwargs.update(kwargs)
        return SimpleNamespace(errors=[])

    fake_wallet.sync_ceremony = fake_sync

    # Patch the import inside _maybe_autosync. Use monkeypatch.setitem so the
    # real tn.wallet is RESTORED after each test — a raw sys.modules assignment
    # leaks the stub and breaks later tests that import read_sync_queue/
    # link_ceremony from tn.wallet (collection-order-dependent failures on CI).
    monkeypatch.setattr("tn.wallet", fake_wallet, raising=False)
    monkeypatch.setitem(sys.modules, "tn.wallet", fake_wallet)

    # AWK inbox drain + cached-AWK resolution (no real network in unit tests).
    monkeypatch.setattr("tn.awk_pickup.resolve_cached_awk",
                        lambda **kw: awk_return)
    monkeypatch.setattr("tn.sync_state.get_account_id", lambda p: None)
    monkeypatch.setattr("tn.signing.DeviceKey.from_private_bytes",
                        staticmethod(lambda b: MagicMock()))

    # Patch Identity.load — linked_account_id is a real value so the
    # write-back branch is a no-op (avoids touching a real identity file).
    fake_identity = MagicMock()
    fake_identity.linked_account_id = "01ACCT_AUTOSYNC"
    fake_identity.device_private_key_bytes = MagicMock(return_value=b"\x00" * 32)
    monkeypatch.setattr("tn.identity.Identity.load", staticmethod(lambda path: fake_identity))

    # Patch VaultClient.for_identity so it returns a context-manager-compatible mock
    fake_client = MagicMock()
    fake_client.close = MagicMock()
    monkeypatch.setattr("tn.vault_client.VaultClient.for_identity",
                        staticmethod(lambda identity, url: fake_client))


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestMaybeAutosyncGate:

    def test_yaml_autosync_true_env_unset_syncs(self, monkeypatch):
        """vault_autosync=True with no env var → sync is attempted."""
        monkeypatch.delenv("TN_WALLET_AUTOSYNC", raising=False)
        sync_flag: list = []
        cfg = _make_cfg(autosync=True)
        _patch_sync_dependencies(monkeypatch, sync_flag)
        _maybe_autosync(cfg)
        assert sync_flag, "Expected sync to be attempted when vault_autosync=True"

    def test_yaml_autosync_false_env_unset_no_sync(self, monkeypatch):
        """vault_autosync=False with no env var → sync is NOT attempted."""
        monkeypatch.delenv("TN_WALLET_AUTOSYNC", raising=False)
        sync_flag: list = []
        cfg = _make_cfg(autosync=False)
        _patch_sync_dependencies(monkeypatch, sync_flag)
        _maybe_autosync(cfg)
        assert not sync_flag, "Expected sync NOT to be attempted when vault_autosync=False"

    def test_env_force_on_overrides_yaml_false(self, monkeypatch):
        """TN_WALLET_AUTOSYNC=1 with vault_autosync=False → sync IS attempted."""
        monkeypatch.setenv("TN_WALLET_AUTOSYNC", "1")
        sync_flag: list = []
        cfg = _make_cfg(autosync=False)
        _patch_sync_dependencies(monkeypatch, sync_flag)
        _maybe_autosync(cfg)
        assert sync_flag, "Expected sync when TN_WALLET_AUTOSYNC=1 even if vault_autosync=False"

    def test_env_force_off_overrides_yaml_true(self, monkeypatch):
        """TN_WALLET_AUTOSYNC=0 with vault_autosync=True → sync is NOT attempted."""
        monkeypatch.setenv("TN_WALLET_AUTOSYNC", "0")
        sync_flag: list = []
        cfg = _make_cfg(autosync=True)
        _patch_sync_dependencies(monkeypatch, sync_flag)
        _maybe_autosync(cfg)
        assert not sync_flag, "Expected sync NOT attempted when TN_WALLET_AUTOSYNC=0"

    def test_autosync_drains_inbox_and_forwards_awk(self, monkeypatch):
        """The running-logger autosync MUST drain the AWK inbox and forward the
        cached AWK to sync_ceremony — otherwise the keystore body backup is
        skipped on every flush (and a browser-minted pickup is never picked up
        while the logger runs). Regression guard for that gap."""
        monkeypatch.delenv("TN_WALLET_AUTOSYNC", raising=False)
        sync_flag: list = []
        sync_kwargs: dict = {}
        cached_awk = b"\xab" * 32
        cfg = _make_cfg(autosync=True)
        _patch_sync_dependencies(
            monkeypatch, sync_flag, sync_kwargs=sync_kwargs,
            awk_return=(cached_awk, "01ACCT_AUTOSYNC"),
        )
        _maybe_autosync(cfg)
        assert sync_flag, "autosync should have fired"
        assert sync_kwargs.get("awk") == cached_awk, (
            "autosync must forward the drained/cached AWK to sync_ceremony; "
            f"got {sync_kwargs!r}"
        )
        assert sync_kwargs.get("author_did") is not None, (
            "autosync must author the group-keys snapshot as the device DID"
        )
