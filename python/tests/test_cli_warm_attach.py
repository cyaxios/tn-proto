"""`tn init` warm-attach path — when the device already belongs to a
vault account, a new init attaches the project over the device DID's
challenge-issued JWT (link_ceremony + sync_ceremony) instead of minting
a browser claim URL.

These tests exercise the `_try_warm_attach` helper in isolation, mocking
the authenticated vault path so no network is required. The gating in
cmd_init (``warm_signal and _try_warm_attach(...)``) is a thin wrapper
over this helper.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import tn
from tn import cli


def _fake_cfg() -> SimpleNamespace:
    return SimpleNamespace(
        project_name="MyProject",
        ceremony_id="local_abc123",
        linked_project_id="proj_xyz",
    )


def _patch_wallet(uploaded=("default.btn.mykit",), errors=()):
    fake_wallet = mock.Mock()
    fake_wallet.link_ceremony.return_value = None
    fake_wallet.sync_ceremony.return_value = SimpleNamespace(
        uploaded=list(uploaded), errors=list(errors)
    )
    return fake_wallet


def test_warm_attach_success(tmp_path: Path, capsys, monkeypatch):
    """Auth + link + sync all succeed -> returns True, prints the attach
    banner, and never mentions a claim URL."""
    yaml_path = tmp_path / ".tn" / "MyProject" / "tn.yaml"
    identity = mock.Mock()

    fake_client = mock.Mock()
    fake_wallet = _patch_wallet()

    monkeypatch.setattr(cli.VaultClient, "for_identity", lambda *a, **k: fake_client)
    monkeypatch.setattr(cli, "_wallet", fake_wallet)
    monkeypatch.setattr(tn, "init", lambda *a, **k: None)
    monkeypatch.setattr(tn, "current_config", _fake_cfg)
    monkeypatch.setattr(tn, "flush_and_close", lambda: None)

    ok = cli._try_warm_attach(yaml_path, identity, "https://vault.local", "btn")

    assert ok is True
    fake_wallet.link_ceremony.assert_called_once()
    fake_wallet.sync_ceremony.assert_called_once()
    fake_client.close.assert_called_once()
    out = capsys.readouterr().out
    assert "Attached to your vault account" in out
    assert "claim" not in out.lower()


def test_warm_attach_auth_failure_falls_back(tmp_path: Path, capsys, monkeypatch):
    """If DID-challenge auth fails, the helper returns False so the
    caller can mint a claim URL instead. link/sync are never reached."""
    yaml_path = tmp_path / ".tn" / "MyProject" / "tn.yaml"
    identity = mock.Mock()
    fake_wallet = _patch_wallet()

    def _boom(*a, **k):
        raise RuntimeError("challenge rejected")

    monkeypatch.setattr(cli.VaultClient, "for_identity", _boom)
    monkeypatch.setattr(cli, "_wallet", fake_wallet)

    ok = cli._try_warm_attach(yaml_path, identity, "https://vault.local", "btn")

    assert ok is False
    fake_wallet.link_ceremony.assert_not_called()
    fake_wallet.sync_ceremony.assert_not_called()
    assert "claim URL instead" in capsys.readouterr().out


def test_warm_attach_link_failure_falls_back(tmp_path: Path, capsys, monkeypatch):
    """If link_ceremony fails (pre-binding), return False -> cold fallback.
    sync_ceremony must not run (no project row was created)."""
    yaml_path = tmp_path / ".tn" / "MyProject" / "tn.yaml"
    identity = mock.Mock()

    fake_client = mock.Mock()
    fake_wallet = _patch_wallet()
    fake_wallet.link_ceremony.side_effect = RuntimeError("project create 500")

    monkeypatch.setattr(cli.VaultClient, "for_identity", lambda *a, **k: fake_client)
    monkeypatch.setattr(cli, "_wallet", fake_wallet)
    monkeypatch.setattr(tn, "init", lambda *a, **k: None)
    monkeypatch.setattr(tn, "current_config", _fake_cfg)
    monkeypatch.setattr(tn, "flush_and_close", lambda: None)

    ok = cli._try_warm_attach(yaml_path, identity, "https://vault.local", "btn")

    assert ok is False
    fake_wallet.sync_ceremony.assert_not_called()
    fake_client.close.assert_called_once()
    assert "claim URL instead" in capsys.readouterr().out


def test_warm_attach_sync_errors_still_attached(tmp_path: Path, capsys, monkeypatch):
    """Once link_ceremony succeeds we're committed to the warm path:
    upload errors are reported but the helper still returns True (we
    must not double-register via the claim-URL fallback)."""
    yaml_path = tmp_path / ".tn" / "MyProject" / "tn.yaml"
    identity = mock.Mock()

    fake_client = mock.Mock()
    fake_wallet = _patch_wallet(uploaded=(), errors=("default.btn.mykit: 503",))

    monkeypatch.setattr(cli.VaultClient, "for_identity", lambda *a, **k: fake_client)
    monkeypatch.setattr(cli, "_wallet", fake_wallet)
    monkeypatch.setattr(tn, "init", lambda *a, **k: None)
    monkeypatch.setattr(tn, "current_config", _fake_cfg)
    monkeypatch.setattr(tn, "flush_and_close", lambda: None)

    ok = cli._try_warm_attach(yaml_path, identity, "https://vault.local", "btn")

    assert ok is True
    out = capsys.readouterr().out
    assert "Attached to your vault account" in out
    assert "upload error" in out
