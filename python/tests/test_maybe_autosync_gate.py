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

def _make_cfg(*, autosync: bool = False, vault_enabled: bool = True,
              linked_project_id: str = "proj_TEST") -> SimpleNamespace:
    """Minimal cfg that satisfies the downstream vault-link guard."""
    cfg = SimpleNamespace()
    cfg.vault_autosync = autosync
    cfg.vault_enabled = vault_enabled
    cfg.ceremony_id = "test-ceremony-id"
    # is_linked() returns True when mode=="linked" and linked_vault is truthy.
    # Use a real method rather than a SimpleNamespace lambda so getattr works.
    cfg.mode = "linked"
    cfg.linked_vault = "https://vault.example.com"
    # A claimed ceremony carries the vault-side project id; the empty string
    # is the unclaimed (pending-claim) state that must never reach the network.
    cfg.linked_project_id = linked_project_id
    cfg.vault_sync_interval_seconds = 600
    # _maybe_autosync resolves the account binding via get_account_id(cfg.yaml_path)
    # before draining the AWK inbox. A non-existent path => get_account_id None.
    cfg.yaml_path = Path("/tmp/tn-autosync-test/tn.yaml")

    # Attach is_linked as a bound-ish callable
    cfg.is_linked = lambda: True
    return cfg


# Stub out everything the body of _maybe_autosync needs so we reach the sync call.

def _patch_sync_dependencies(monkeypatch, sync_flag: list,
                             sync_kwargs: dict | None = None,
                             awk_return=(None, None),
                             awk_calls: list | None = None):
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
    def fake_resolve(**kw):
        if awk_calls is not None:
            awk_calls.append(kw)
        return awk_return

    monkeypatch.setattr("tn.awk_pickup.resolve_cached_awk", fake_resolve)
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
    fake_client.token = "jwt-test-token"
    monkeypatch.setattr("tn.vault_client.VaultClient.for_identity",
                        staticmethod(lambda identity, url: fake_client))
    return fake_client


@pytest.fixture(autouse=True)
def _isolated_state_dir(monkeypatch, tmp_path):
    """Route throttle stamps + sync-queue writes to a per-test dir so tests
    never read another test's throttle stamp (or the developer's real state)."""
    monkeypatch.setenv("TN_STATE_DIR", str(tmp_path / "state"))


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


class TestMaybeAutosyncNetworkDiscipline:
    """An unclaimed ceremony must never reach the network, repeated ops must
    be throttled, and one cycle must reuse a single auth handshake.

    These guard the call-home flood of 2026-07-02: ~300 test/demo ceremonies
    with autosync=true but no linked_project_id each fired 2 challenge/verify
    pairs + 1 pickups-pending GET at production per admin op."""

    def test_unclaimed_ceremony_never_touches_network(self, monkeypatch):
        """No linked_project_id → no drain, no client, no sync attempt."""
        monkeypatch.delenv("TN_WALLET_AUTOSYNC", raising=False)
        sync_flag: list = []
        awk_calls: list = []
        cfg = _make_cfg(autosync=True, linked_project_id="")
        client = _patch_sync_dependencies(monkeypatch, sync_flag,
                                          awk_calls=awk_calls)
        _maybe_autosync(cfg)
        assert not sync_flag, "unclaimed ceremony must not attempt sync"
        assert not awk_calls, "unclaimed ceremony must not drain the AWK inbox"
        assert not client.method_calls, "unclaimed ceremony must not build a client"

    def test_second_call_within_interval_is_throttled(self, monkeypatch):
        """Two admin ops back-to-back → one sync, not two."""
        monkeypatch.delenv("TN_WALLET_AUTOSYNC", raising=False)
        sync_flag: list = []
        cfg = _make_cfg(autosync=True)
        _patch_sync_dependencies(monkeypatch, sync_flag)
        _maybe_autosync(cfg)
        _maybe_autosync(cfg)
        assert len(sync_flag) == 1, (
            f"expected exactly one sync within the interval, got {len(sync_flag)}"
        )

    def test_stale_stamp_syncs_again(self, monkeypatch):
        """A stamp older than vault_sync_interval_seconds does not block."""
        import os
        import time

        monkeypatch.delenv("TN_WALLET_AUTOSYNC", raising=False)
        sync_flag: list = []
        cfg = _make_cfg(autosync=True)
        _patch_sync_dependencies(monkeypatch, sync_flag)
        _maybe_autosync(cfg)

        from tn.admin import _autosync_stamp_path
        stamp = _autosync_stamp_path(cfg.ceremony_id)
        old = time.time() - (cfg.vault_sync_interval_seconds + 1)
        os.utime(stamp, (old, old))

        _maybe_autosync(cfg)
        assert len(sync_flag) == 2, "stale stamp must not suppress the next sync"

    def test_drain_reuses_client_token(self, monkeypatch):
        """One challenge/verify per cycle: the drain gets the client's JWT."""
        monkeypatch.delenv("TN_WALLET_AUTOSYNC", raising=False)
        sync_flag: list = []
        awk_calls: list = []
        cfg = _make_cfg(autosync=True)
        _patch_sync_dependencies(monkeypatch, sync_flag, awk_calls=awk_calls)
        _maybe_autosync(cfg)
        assert sync_flag, "sync should have fired"
        assert awk_calls and awk_calls[0].get("token") == "jwt-test-token", (
            "the AWK drain must reuse the already-authed client's JWT instead "
            f"of running its own challenge/verify; got {awk_calls!r}"
        )
