"""`tn init` warm-attach path.

``_try_warm_attach`` drives the shared ``attach_or_sync`` engine and renders
its ``AttachOutcome`` into the CLI banner + a True/False fall-back signal.
The engine itself (WARM_CREATE / WARM_SYNC against a real vault) is proven in
``test_init_attach_live.py``; here we pin the thin CLI wrapper's
outcome → banner/bool mapping with ``attach_or_sync`` mocked.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import tn
import tn._init_attach as _ia
from tn import cli_init
from tn._init_attach import AttachMode, AttachOutcome


def _patch(monkeypatch: pytest.MonkeyPatch, outcome: AttachOutcome) -> None:
    """Stub the cycle-broken inline imports + the engine to return ``outcome``."""
    monkeypatch.setattr(tn, "init", lambda *a, **k: None)
    monkeypatch.setattr(tn, "current_config", lambda: mock.Mock())
    monkeypatch.setattr(tn, "flush_and_close", lambda: None)
    monkeypatch.setattr(cli_init, "attach_or_sync", lambda *a, **k: outcome)


def test_warm_create_attaches(tmp_path: Path, capsys, monkeypatch) -> None:
    _patch(
        monkeypatch,
        AttachOutcome(
            mode=AttachMode.WARM_CREATE,
            project_id="pr_1",
            uploaded=["a.mykit"],
            attached=True,
        ),
    )
    ok = cli_init._try_warm_attach(
        tmp_path / "tn.yaml", mock.Mock(), "https://vault.local", "btn"
    )
    assert ok is True
    out = capsys.readouterr().out
    assert "Attached to your vault account" in out
    assert "claim" not in out.lower()
    assert "pr_1" in out


def test_warm_sync_attaches(tmp_path: Path, capsys, monkeypatch) -> None:
    _patch(
        monkeypatch,
        AttachOutcome(
            mode=AttachMode.WARM_SYNC,
            project_id="pr_1",
            uploaded=["a.mykit"],
            attached=True,
        ),
    )
    ok = cli_init._try_warm_attach(
        tmp_path / "tn.yaml", mock.Mock(), "https://vault.local", "btn"
    )
    assert ok is True
    assert "synced" in capsys.readouterr().out.lower()


def test_no_account_falls_back_to_claim_url(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    # CLAIM_URL outcome (no logged-in account) → caller mints a claim URL.
    _patch(monkeypatch, AttachOutcome(mode=AttachMode.CLAIM_URL))
    ok = cli_init._try_warm_attach(
        tmp_path / "tn.yaml", mock.Mock(), "https://vault.local", "btn"
    )
    assert ok is False


def test_contained_warnings_still_attached(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    # A contained failure (e.g. no cached credential) does NOT revert to the
    # claim URL — the project is attached; the warning is surfaced.
    _patch(
        monkeypatch,
        AttachOutcome(
            mode=AttachMode.WARM_CREATE,
            attached=True,
            project_id="pr_1",
            uploaded=[],
            warnings=["<passphrase>: account credential required"],
        ),
    )
    ok = cli_init._try_warm_attach(
        tmp_path / "tn.yaml", mock.Mock(), "https://vault.local", "btn"
    )
    assert ok is True
    # The no-credential case is surfaced in plain language (the internal
    # "<passphrase>:" tag is suppressed in favour of the NOTE), and the project
    # stays attached rather than reverting to the claim-URL flow.
    out = capsys.readouterr().out
    assert "NOT backed up" in out
    assert "<passphrase>" not in out


# --- warm-attach signal: which credential to use, or fall through -----
#
# The guard now lives INSIDE the shared engine (tn._init_attach) so it
# gates BOTH attach_or_sync callers: cli.cmd_init AND the library
# tn.__init__._auto_link_after_init path. TN_API_KEY (explicit operator
# key) always wins; the remembered account in identity.json only applies
# when the target vault is the one that account actually lives on.


def _signal_identity(*, account_id, linked_vault):
    return SimpleNamespace(linked_account_id=account_id, linked_vault=linked_vault)


def test_warm_signal_uses_account_when_vault_matches(monkeypatch):
    monkeypatch.delenv("TN_API_KEY", raising=False)
    identity = _signal_identity(account_id="acct_1", linked_vault="https://vault.local")
    assert _ia._warm_attach_signal(identity, "https://vault.local") == "acct_1"


def test_warm_signal_skips_account_when_vault_differs(monkeypatch):
    # Regression #6: a device whose account lives on vault A must NOT warm-
    # attach to vault B (e.g. `tn init --link B`); fall through to claim URL.
    monkeypatch.delenv("TN_API_KEY", raising=False)
    identity = _signal_identity(account_id="acct_1", linked_vault="https://vault.A")
    assert _ia._warm_attach_signal(identity, "https://vault.B") is None


def test_warm_signal_api_key_wins_regardless_of_vault(monkeypatch):
    # Explicit TN_API_KEY is the operator's deliberate choice for this run;
    # it is honored even when the remembered vault differs from the target.
    monkeypatch.setenv("TN_API_KEY", "key_xyz")
    identity = _signal_identity(account_id="acct_1", linked_vault="https://vault.A")
    assert _ia._warm_attach_signal(identity, "https://vault.B") == "key_xyz"


def test_warm_signal_none_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TN_API_KEY", raising=False)
    identity = _signal_identity(account_id=None, linked_vault=None)
    assert _ia._warm_attach_signal(identity, "https://vault.local") is None


def test_cli_reexports_warm_signal():
    # cli_init._warm_attach_signal must stay importable (it is the same function
    # object as the engine's — a re-export, not a divergent copy).
    assert cli_init._warm_attach_signal is _ia._warm_attach_signal


def test_engine_gates_warm_attach_on_vault_mismatch(monkeypatch):
    # Regression #6, engine level: attach_or_sync itself must fall back to
    # CLAIM_URL when the remembered account lives on a DIFFERENT vault, so
    # the library tn.init() path (which calls the engine directly, without
    # the CLI's pre-gate) cannot warm-attach vault A's account against B.
    monkeypatch.delenv("TN_API_KEY", raising=False)
    identity = _signal_identity(account_id="acct_1", linked_vault="https://vault.A")
    cfg = SimpleNamespace(linked_project_id="pr_1", yaml_path=Path("tn.yaml"))
    claim_calls: list[str] = []

    monkeypatch.setattr(_ia, "_default_client_factory", lambda url, ident: mock.Mock())
    monkeypatch.setattr(
        _ia,
        "init_upload",
        lambda cfg, client, vault_base: claim_calls.append(vault_base)
        or {"claim_url": f"{vault_base}/claim/xyz"},
    )

    out = _ia.attach_or_sync(cfg, identity, "https://vault.B")

    assert out.mode is AttachMode.CLAIM_URL
    assert claim_calls == ["https://vault.B"]
    assert out.claim_url == "https://vault.B/claim/xyz"
