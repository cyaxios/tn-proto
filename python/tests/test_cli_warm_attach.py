"""`tn init` warm-attach path.

``_try_warm_attach`` drives the shared ``attach_or_sync`` engine and renders
its ``AttachOutcome`` into the CLI banner + a True/False fall-back signal.
The engine itself (WARM_CREATE / WARM_SYNC against a real vault) is proven in
``test_init_attach_live.py``; here we pin the thin CLI wrapper's
outcome → banner/bool mapping with ``attach_or_sync`` mocked.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

import tn
import tn._init_attach as _ia
from tn import cli
from tn._init_attach import AttachMode, AttachOutcome


def _patch(monkeypatch: pytest.MonkeyPatch, outcome: AttachOutcome) -> None:
    """Stub the cycle-broken inline imports + the engine to return ``outcome``."""
    monkeypatch.setattr(tn, "init", lambda *a, **k: None)
    monkeypatch.setattr(tn, "current_config", lambda: mock.Mock())
    monkeypatch.setattr(tn, "flush_and_close", lambda: None)
    monkeypatch.setattr(_ia, "attach_or_sync", lambda *a, **k: outcome)


def test_warm_create_attaches(tmp_path: Path, capsys, monkeypatch) -> None:
    _patch(
        monkeypatch,
        AttachOutcome(
            mode=AttachMode.WARM_CREATE, project_id="pr_1", uploaded=["a.mykit"]
        ),
    )
    ok = cli._try_warm_attach(
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
            mode=AttachMode.WARM_SYNC, project_id="pr_1", uploaded=["a.mykit"]
        ),
    )
    ok = cli._try_warm_attach(
        tmp_path / "tn.yaml", mock.Mock(), "https://vault.local", "btn"
    )
    assert ok is True
    assert "synced" in capsys.readouterr().out.lower()


def test_no_account_falls_back_to_claim_url(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    # CLAIM_URL outcome (no logged-in account) → caller mints a claim URL.
    _patch(monkeypatch, AttachOutcome(mode=AttachMode.CLAIM_URL))
    ok = cli._try_warm_attach(
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
            project_id="pr_1",
            warnings=["<passphrase>: account credential required"],
        ),
    )
    ok = cli._try_warm_attach(
        tmp_path / "tn.yaml", mock.Mock(), "https://vault.local", "btn"
    )
    assert ok is True
    assert "WARN" in capsys.readouterr().out
