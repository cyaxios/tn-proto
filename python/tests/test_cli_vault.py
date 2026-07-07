"""Tests for ``tn.cli_vault`` — the ``vault link`` / ``vault unlink`` verbs.

Exercises every line of both ``cmd_vault_link`` and ``cmd_vault_unlink``:
happy paths (link, unlink with/without reason), the JSON receipt shape,
and every error branch (missing positionals, yaml-not-found,
discovery failure). Asserts the attested ``tn.vault.linked`` /
``tn.vault.unlinked`` entry actually lands in the admin log via
``tn.read``.
"""
from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import argparse
import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

import tn
from tn import cli_vault


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _ns(**kw) -> argparse.Namespace:
    base = {"vault_did": None, "project_id": None, "reason": None, "yaml": None}
    base.update(kw)
    return argparse.Namespace(**base)


def _make_ceremony(tmp_path: Path) -> Path:
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    tn.flush_and_close()
    return yaml


def _admin_events(yaml: Path, event_type: str):
    """Read back attested events of ``event_type`` from the admin log."""
    from tn.admin.log import resolve_admin_log_path

    tn.init(yaml)
    try:
        log = resolve_admin_log_path(tn.current_config())
        return [e for e in tn.read(log=log) if e.event_type == event_type]
    finally:
        tn.flush_and_close()


# ---------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------


def test_vault_link_emits_and_prints_receipt(tmp_path, capsys):
    yaml = _make_ceremony(tmp_path)
    args = _ns(vault_did="did:web:tn-proto.org", project_id="proj_x", yaml=str(yaml))

    rc = cli_vault.cmd_vault_link(args)
    assert rc == 0

    out = capsys.readouterr().out.strip()
    receipt = json.loads(out)
    assert receipt["ok"] is True
    assert receipt["verb"] == "vault.linked"
    assert receipt["vault_did"] == "did:web:tn-proto.org"
    assert receipt["project_id"] == "proj_x"
    assert receipt["event_id"]  # recovered from the read-back
    assert receipt["row_hash"]

    # The attested event landed in the admin log.
    events = _admin_events(yaml, "tn.vault.linked")
    assert len(events) == 1
    e = events[0]
    assert e.fields["vault_identity"] == "did:web:tn-proto.org"
    assert e.fields["project_id"] == "proj_x"
    assert e.event_id == receipt["event_id"]
    assert e.row_hash == receipt["row_hash"]


def test_vault_unlink_with_reason(tmp_path, capsys):
    yaml = _make_ceremony(tmp_path)
    cli_vault.cmd_vault_link(
        _ns(vault_did="did:web:tn-proto.org", project_id="proj_x", yaml=str(yaml))
    )
    capsys.readouterr()  # drain the link receipt

    rc = cli_vault.cmd_vault_unlink(
        _ns(
            vault_did="did:web:tn-proto.org",
            project_id="proj_x",
            reason="user_request",
            yaml=str(yaml),
        )
    )
    assert rc == 0
    receipt = json.loads(capsys.readouterr().out.strip())
    assert receipt["verb"] == "vault.unlinked"
    assert receipt["event_id"]

    events = _admin_events(yaml, "tn.vault.unlinked")
    assert len(events) == 1
    assert events[0].fields["reason"] == "user_request"


def test_vault_unlink_without_reason(tmp_path, capsys):
    yaml = _make_ceremony(tmp_path)
    cli_vault.cmd_vault_link(
        _ns(vault_did="did:web:tn-proto.org", project_id="proj_x", yaml=str(yaml))
    )
    capsys.readouterr()

    rc = cli_vault.cmd_vault_unlink(
        _ns(vault_did="did:web:tn-proto.org", project_id="proj_x", yaml=str(yaml))
    )
    assert rc == 0
    capsys.readouterr()

    events = _admin_events(yaml, "tn.vault.unlinked")
    assert len(events) == 1
    assert events[0].fields.get("reason") is None


def test_vault_link_discovery_via_env(tmp_path, capsys, monkeypatch):
    """No --yaml: tn.init() discovers the ceremony via $TN_YAML."""
    yaml = _make_ceremony(tmp_path)
    monkeypatch.setenv("TN_YAML", str(yaml))

    rc = cli_vault.cmd_vault_link(
        _ns(vault_did="did:web:tn-proto.org", project_id="proj_disc")
    )
    assert rc == 0
    receipt = json.loads(capsys.readouterr().out.strip())
    assert receipt["project_id"] == "proj_disc"
    assert receipt["event_id"]


# ---------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------


def test_link_missing_positionals_exits_2(capsys):
    rc = cli_vault.cmd_vault_link(_ns(vault_did=None, project_id=None))
    assert rc == 2
    err = capsys.readouterr().err
    assert "required positionals" in err
    assert "vault linked" in err


def test_unlink_missing_project_exits_2(capsys):
    rc = cli_vault.cmd_vault_unlink(_ns(vault_did="did:web:x", project_id=None))
    assert rc == 2
    assert "required positionals" in capsys.readouterr().err


def test_yaml_not_found_exits_1(tmp_path, capsys):
    missing = tmp_path / "nope.yaml"
    rc = cli_vault.cmd_vault_link(
        _ns(vault_did="did:web:x", project_id="p", yaml=str(missing))
    )
    assert rc == 1
    assert "yaml not found" in capsys.readouterr().err


def test_discovery_failure_exits_1(tmp_path, capsys, monkeypatch):
    """No --yaml and nothing discoverable -> clean exit 1."""
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.delenv("TN_HOME", raising=False)
    # cwd with no tn.yaml; make tn.init() raise by pointing discovery at
    # an empty dir.
    monkeypatch.chdir(tmp_path)

    def _boom(*a, **k):
        raise RuntimeError("no ceremony found")

    monkeypatch.setattr(tn, "init", _boom)
    rc = cli_vault.cmd_vault_link(_ns(vault_did="did:web:x", project_id="p"))
    assert rc == 1
    assert "could not load a ceremony" in capsys.readouterr().err
