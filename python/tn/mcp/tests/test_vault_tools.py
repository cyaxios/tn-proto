"""Vault connector tool tests (tn.mcp.vault_tools).

The deterministic tests prove the containment contract: an unreachable vault,
an invalid ceremony name, or a missing identity each come back as a clear,
professional status dict - never an exception into the host, never a raw
traceback where a sentence does.

The live test mints a real cold pending-claim against the dev vault and is
gated on reachability (TN_DAY1_VAULT, default http://127.0.0.1:38790,
mirroring tests/test_day1_backup_restore_live.py); it skips cleanly when the
vault is down. The probe runs lazily inside the live test so the offline
tests never pay for it.

Every test runs under an isolated identity dir + temp cwd, so nothing touches
the user's real identity, vault account, or any repo path.
"""
from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import tn
from tn.mcp import vault_tools

VAULT_URL = os.environ.get("TN_DAY1_VAULT", "http://127.0.0.1:38790").rstrip("/")

# A loopback port with nothing listening: connection refused, immediately.
DEAD_VAULT = "http://127.0.0.1:9"


def _vault_reachable() -> bool:
    """POST the dev-login probe (same gate as the day-1 live suite)."""
    try:
        req = urllib.request.Request(
            f"{VAULT_URL}/api/v1/dev/login",
            data=json.dumps({"handle": "reach" + secrets.token_hex(3)}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.getcode() == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _fresh_name(prefix: str) -> str:
    """Unique ceremony name per test: the in-process ceremony registry is
    process-global, so a reused name would hand back a stale handle."""
    return f"{prefix}{secrets.token_hex(4)}"


@pytest.fixture
def isolated_tn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolated TN environment: temp identity dir, no auto-link, temp cwd."""
    monkeypatch.setenv("TN_IDENTITY_DIR", str(tmp_path / "id"))
    monkeypatch.setenv("TN_NO_LINK", "1")
    monkeypatch.setenv("TN_FORCE_PYTHON", "1")
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.chdir(tmp_path)
    yield tmp_path
    try:
        tn.flush_and_close()
    except Exception:  # noqa: BLE001 - teardown only; nothing to flush is fine
        pass


# --- recognizer -----------------------------------------------------------------

def test_is_tn_envelope_recognizer() -> None:
    envelope = {
        "device_identity": "did:key:z6MkExample",
        "event_type": "order.created",
        "sequence": 1,
        "row_hash": "ab12",
        "signature": "sig",
        "finance": {"ciphertext": "deadbeef", "field_hashes": {}},
    }
    assert vault_tools.is_tn_envelope(envelope) is True
    # a json line is accepted too (the ambient-skill path)
    assert vault_tools.is_tn_envelope(json.dumps(envelope)) is True
    # header fields without a ciphertext group block are not an envelope
    assert vault_tools.is_tn_envelope(
        {"device_identity": "d", "event_type": "x", "sequence": 1}) is False
    # plain records, junk strings, and non-dicts are rejected quietly
    assert vault_tools.is_tn_envelope({"event_type": "x", "email": "a@b.co"}) is False
    assert vault_tools.is_tn_envelope("not json at all") is False
    assert vault_tools.is_tn_envelope(42) is False


# --- vault_status ---------------------------------------------------------------

def test_vault_status_contained_without_identity(isolated_tn: Path) -> None:
    """With no local identity, vault_status reports state instead of raising."""
    status = vault_tools.vault_status()
    assert isinstance(status, dict)
    assert "identity_error" not in status
    assert status["identity"].startswith("none")
    assert isinstance(status["ceremonies"], list)


# --- new_workstream / claim / vault_sync containment ------------------------------

def test_new_workstream_unbound_creates_local_ceremony(isolated_tn: Path) -> None:
    name = _fresh_name("wsa")
    out = vault_tools.new_workstream(
        name, project_dir=str(isolated_tn / "proj"), bind=False)
    assert "error" not in out
    assert out["workstream"] == name
    yaml_path = Path(out["yaml"])
    assert yaml_path.exists()
    assert yaml_path.name == "tn.yaml"
    assert name in out["ceremonies"]
    # bind=False never touches the vault; the note says how to bind later
    assert "claim_url" not in out
    assert "unlinked" in out["note"]
    assert f"claim(name='{name}')" in out["note"]


def test_new_workstream_contains_unreachable_vault(isolated_tn: Path) -> None:
    """bind=True against a dead vault: the ceremony still lands locally and the
    claim failure surfaces as one clear sentence, not an exception."""
    name = _fresh_name("wsb")
    out = vault_tools.new_workstream(
        name, project_dir=str(isolated_tn / "proj"),
        vault_url=DEAD_VAULT, open_browser=False, bind=True)
    assert "error" not in out
    assert Path(out["yaml"]).exists()
    assert out["claim_error"].startswith("could not mint claim")
    assert "Traceback" not in out["claim_error"]
    assert "claim_url" not in out
    assert f"claim(name='{name}')" in out["note"]


def test_claim_contains_invalid_ceremony_name(isolated_tn: Path) -> None:
    out = vault_tools.claim(name="tn")  # reserved name; cannot be a ceremony
    assert out["workstream"] == "tn"
    assert out["error"].startswith("could not open ceremony:")
    assert "Traceback" not in out["error"]
    assert "claim_url" not in out


def test_vault_sync_contains_unreachable_vault(isolated_tn: Path) -> None:
    name = _fresh_name("wsc")
    created = vault_tools.new_workstream(
        name, project_dir=str(isolated_tn / "proj"), bind=False)
    assert "error" not in created
    out = vault_tools.vault_sync(name=name, vault_url=DEAD_VAULT)
    assert out["workstream"] == name
    assert out["error"].startswith("vault auth failed")
    assert "Traceback" not in out["error"]
    assert "pulled_inbox" not in out


# --- live (opt-in): cold-claim mint against the dev vault --------------------------

def test_live_cold_claim_mints_claim_url(isolated_tn: Path) -> None:
    """Tier 2: mint a real cold pending-claim against the dev vault.

    Proves the connector end of the bind flow up to (not through) the human
    passkey step: a claim URL under the vault, with the backup key riding the
    local-only ``#k=`` fragment. Skips cleanly when the vault is down.
    """
    if not _vault_reachable():
        pytest.skip(f"dev vault unreachable at {VAULT_URL} (set TN_DAY1_VAULT)")

    name = _fresh_name("live")
    out = vault_tools.new_workstream(
        name, project_dir=str(isolated_tn / "ws"),
        vault_url=VAULT_URL, open_browser=False, bind=True)
    assert "error" not in out and "claim_error" not in out, out
    assert out["vault"] == VAULT_URL
    assert out["vault_id"]
    assert out["browser_opened"] is False

    claim_url = out["claim_url"]
    assert claim_url.startswith(f"{VAULT_URL}/claim/")
    assert "#k=" in claim_url  # the key fragment never reaches the server
    assert any("passkey" in step.lower() for step in out["next_steps"])

    status = vault_tools.vault_status(vault_url=VAULT_URL)
    assert status["identity"] == "present"
    assert name in status["ceremonies"]
