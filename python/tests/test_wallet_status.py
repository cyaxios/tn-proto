"""Tests for `tn wallet status` (cmd_wallet_status).

Covers:
  - no identity on disk → informational message, exit 0
  - identity present, no --yaml → prints DID, linked vault, prefs
  - identity + --yaml → prints ceremony fields
  - identity + --yaml + pending sync queue → shows failure count + latest error
  - missing yaml path → graceful "no yaml at <path>" message

All tests run without a vault or network; ceremony config is mocked.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import tn
from tn.cli import build_parser, cmd_wallet_status
from tn.identity import Identity, _default_identity_path
from tn.admin import _sync_queue_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mint_identity(path: Path) -> Identity:
    """Create a fresh identity and persist it to *path*."""
    ident = Identity.create_new()
    ident.ensure_written(path)
    return ident


def _fake_config(ceremony_id: str = "test_ceremony_01") -> SimpleNamespace:
    return SimpleNamespace(
        ceremony_id=ceremony_id,
        mode="local",
        cipher_name="btn",
        linked_vault=None,
        linked_project_id=None,
        groups={"default": object()},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point TN_IDENTITY_DIR at an empty tmp dir so no real identity leaks in."""
    monkeypatch.setenv("TN_IDENTITY_DIR", str(tmp_path / "tn-id"))


# ---------------------------------------------------------------------------
# Tests: no identity on disk
# ---------------------------------------------------------------------------


def test_no_identity_prints_message(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    args = parser.parse_args(["wallet", "status"])
    rc = cmd_wallet_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "No identity" in out
    assert "tn init" in out


def test_no_identity_wired_into_parser() -> None:
    parser = build_parser()
    args = parser.parse_args(["wallet", "status"])
    assert args.func is cmd_wallet_status


# ---------------------------------------------------------------------------
# Tests: identity present, no yaml
# ---------------------------------------------------------------------------


def test_identity_only_prints_did(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    id_path = tmp_path / "tn-id" / "identity.json"
    ident = _mint_identity(id_path)

    parser = build_parser()
    args = parser.parse_args(["wallet", "status"])
    rc = cmd_wallet_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Identity:" in out
    assert ident.did in out
    assert "file:" in out
    assert "linked:" in out
    assert "prefs:" in out
    assert "default_new_ceremony_mode=local" in out
    assert "prefs_version=0" in out


def test_identity_linked_vault_shown(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    id_path = tmp_path / "tn-id" / "identity.json"
    ident = _mint_identity(id_path)
    # Inject a linked_vault into the file.
    doc = json.loads(id_path.read_text())
    doc["linked_vault"] = "https://vault.example"
    id_path.write_text(json.dumps(doc, indent=2))

    parser = build_parser()
    args = parser.parse_args(["wallet", "status"])
    rc = cmd_wallet_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "https://vault.example" in out


# ---------------------------------------------------------------------------
# Tests: identity + ceremony yaml
# ---------------------------------------------------------------------------


def test_with_yaml_prints_ceremony_fields(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    id_path = tmp_path / "tn-id" / "identity.json"
    _mint_identity(id_path)
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.touch()  # exists so the existence check passes

    cfg = _fake_config("ceremony_abc")
    monkeypatch.setattr(tn, "init", lambda *a, **k: None)
    monkeypatch.setattr(tn, "current_config", lambda: cfg)
    monkeypatch.setattr(tn, "flush_and_close", lambda: None)
    monkeypatch.setattr("tn.wallet.read_sync_queue", lambda cid: [])

    parser = build_parser()
    args = parser.parse_args(["wallet", "status", str(yaml_path)])
    rc = cmd_wallet_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Ceremony:" in out
    assert "ceremony_abc" in out
    assert "mode:" in out
    assert "cipher:" in out
    assert "linked_vault:" in out
    assert "linked_project:" in out
    assert "groups:" in out
    assert "pending_sync:    (queue empty)" in out


def test_with_yaml_missing_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    id_path = tmp_path / "tn-id" / "identity.json"
    _mint_identity(id_path)
    missing = tmp_path / "does-not-exist.yaml"

    parser = build_parser()
    args = parser.parse_args(["wallet", "status", str(missing)])
    rc = cmd_wallet_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "no yaml at" in out


# ---------------------------------------------------------------------------
# Tests: pending sync queue
# ---------------------------------------------------------------------------


def test_pending_sync_queue_shown(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    id_path = tmp_path / "tn-id" / "identity.json"
    _mint_identity(id_path)
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.touch()

    cfg = _fake_config("ceremony_pending")
    monkeypatch.setattr(tn, "init", lambda *a, **k: None)
    monkeypatch.setattr(tn, "current_config", lambda: cfg)
    monkeypatch.setattr(tn, "flush_and_close", lambda: None)
    pending = [{"ceremony_id": "ceremony_pending", "ts": 1.0, "error": "upload timed out"}]
    monkeypatch.setattr("tn.wallet.read_sync_queue", lambda cid: pending)

    parser = build_parser()
    args = parser.parse_args(["wallet", "status", str(yaml_path)])
    rc = cmd_wallet_status(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 queued failure" in out
    assert "upload timed out" in out
    assert "--drain-queue" in out


# ---------------------------------------------------------------------------
# Tests: read_sync_queue (unit)
# ---------------------------------------------------------------------------


def test_read_sync_queue_empty_when_file_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    from tn.wallet import read_sync_queue
    result = read_sync_queue("nonexistent_ceremony_xyz")
    assert result == []


def test_read_sync_queue_reads_jsonl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tn.wallet import read_sync_queue
    monkeypatch.setenv("TN_STATE_DIR", str(tmp_path))
    ceremony_id = "test_queue_ceremony"
    q_path = _sync_queue_path(ceremony_id)
    q_path.parent.mkdir(parents=True, exist_ok=True)
    q_path.write_text(
        json.dumps({"ceremony_id": ceremony_id, "ts": 1.0, "error": "err1"}) + "\n"
        + json.dumps({"ceremony_id": ceremony_id, "ts": 2.0, "error": "err2"}) + "\n",
        encoding="utf-8",
    )
    result = read_sync_queue(ceremony_id)
    assert len(result) == 2
    assert result[0]["error"] == "err1"
    assert result[1]["error"] == "err2"
