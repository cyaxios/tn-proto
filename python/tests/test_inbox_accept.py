"""
Tests for tn.inbox.accept -- local kit acceptance.

Covers:
  1. accept() raises InboxError for a non-existent zip.
  2. accept() raises InboxError for a missing manifest.json in zip.
  3. accept() raises InboxError when kit hash doesn't match manifest.
  4. accept() happy path: installs kit file, backs up existing, returns correct dict.
  5. accept() backs up existing kit with .previous.<timestamp> suffix.
  6. list_local() returns matching zip files.

Run with:
  cd C:\\codex\\content_platform
  PYTHONPATH=tn-protocol/python .venv/Scripts/python.exe -m pytest tn-protocol/python/tests/test_inbox_accept.py -v
"""

from __future__ import annotations

import hashlib
import json

# Add tn-protocol/python to sys.path so 'tn' is importable.
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

import pytest
import yaml

_TN_PY = Path(__file__).parent.parent
if str(_TN_PY) not in sys.path:
    sys.path.insert(0, str(_TN_PY))

from tn.inbox import InboxError, accept, list_local

# ── Helpers ──────────────────────────────────────────────────────────


def _make_zip(tmp: Path, kit_bytes: bytes, manifest: dict) -> Path:
    """Write a valid invitation zip into tmp dir and return its path."""
    zip_path = tmp / "tn-invite-TEST.zip"
    with zipfile.ZipFile(str(zip_path), "w") as zf:
        zf.writestr("kit.tnpkg", kit_bytes)
        zf.writestr("manifest.json", json.dumps(manifest))
    return zip_path


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _minimal_tn_yaml(keystore_dir: Path) -> dict:
    """Minimal tn.yaml structure enough for accept() to parse."""
    return {
        "me": {"did": "did:key:z6Mkfrank"},
        "ceremony": {"id": "test-ceremony", "mode": "local"},
        "groups": {},
    }


def _write_yaml(yaml_path: Path, keystore_dir: Path) -> None:
    with open(yaml_path, "w") as f:
        yaml.safe_dump(_minimal_tn_yaml(keystore_dir), f)


# ── Tests ─────────────────────────────────────────────────────────────


def test_accept_missing_zip():
    """InboxError raised when zip file doesn't exist."""
    with tempfile.TemporaryDirectory() as tmp:
        yaml_path = Path(tmp) / "tn.yaml"
        _write_yaml(yaml_path, Path(tmp) / ".tn/tn/keys")
        with pytest.raises(InboxError, match="not found"):
            accept(Path(tmp) / "nonexistent.zip", yaml_path=yaml_path)


def test_accept_missing_manifest(tmp_path):
    """InboxError raised when zip has no manifest.json."""
    kit_bytes = b"\x00" * 32
    zip_path = tmp_path / "tn-invite-TEST.zip"
    with zipfile.ZipFile(str(zip_path), "w") as zf:
        zf.writestr("kit.tnpkg", kit_bytes)
        # No manifest.json

    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, tmp_path / ".tn/tn/keys")

    with pytest.raises(InboxError, match="manifest.json"):
        accept(zip_path, yaml_path=yaml_path)


def test_accept_hash_mismatch(tmp_path):
    """InboxError raised when kit bytes don't match manifest sha256."""
    kit_bytes = b"\x01" * 32
    manifest = {
        "group_name": "default",
        "leaf_index": 1,
        "from_email": "alice@demo.local",
        "from_account_did": "did:vault:alice",
        "kit_sha256": "sha256:" + "a" * 64,  # deliberate wrong hash
    }
    zip_path = _make_zip(tmp_path, kit_bytes, manifest)
    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, tmp_path / ".tn/tn/keys")

    with pytest.raises(InboxError, match="hash mismatch"):
        accept(zip_path, yaml_path=yaml_path)


def test_accept_happy_path(tmp_path):
    """Happy path: kit installed, attestation emitted (mocked), result returned."""
    kit_bytes = b"\xab\xcd\xef" * 16
    sha = _sha256(kit_bytes)
    manifest = {
        "group_name": "default",
        "leaf_index": 5,
        "from_email": "alice@demo.local",
        "from_account_did": "did:vault:alice",
        "kit_sha256": sha,
    }
    zip_path = _make_zip(tmp_path, kit_bytes, manifest)
    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, tmp_path / ".tn/tn/keys")

    # inbox.py does "import tn" inside the accept() function body, so patching
    # at the tn module level intercepts the call cleanly.
    import tn.inbox as inbox_module

    captured_events = []

    def fake_init(yaml_path, **kw):
        pass

    def fake_info(event_type, **fields):
        captured_events.append((event_type, fields))

    def fake_flush():
        pass

    with (
        mock.patch("tn.init", fake_init),
        mock.patch("tn.info", fake_info),
        mock.patch("tn.flush_and_close", fake_flush),
    ):
        result = inbox_module.accept(zip_path, yaml_path=yaml_path)

    # Kit file installed.
    kit_path = tmp_path / ".tn/tn/keys" / "default.btn.mykit"
    assert kit_path.exists()
    assert kit_path.read_bytes() == kit_bytes

    # Result has correct shape.
    assert result["group_name"] == "default"
    assert result["leaf_index"] == 5
    assert result["from_email"] == "alice@demo.local"
    assert result["kit_path"] == str(kit_path)
    assert "absorbed_at" in result

    # Attestation emitted.
    assert any(ev == "tn.enrolment.absorbed" for ev, _ in captured_events)


def test_accept_backs_up_existing_kit(tmp_path):
    """Existing kit is renamed to .previous.<ts> before installing new one."""
    # Pre-install an old kit.
    keystore_dir = tmp_path / ".tn/tn/keys"
    keystore_dir.mkdir()
    old_kit = keystore_dir / "default.btn.mykit"
    old_kit.write_bytes(b"\xde\xad" * 8)

    kit_bytes = b"\xbe\xef" * 16
    sha = _sha256(kit_bytes)
    manifest = {
        "group_name": "default",
        "leaf_index": 2,
        "from_email": "alice@demo.local",
        "from_account_did": "did:vault:alice",
        "kit_sha256": sha,
    }
    zip_path = _make_zip(tmp_path, kit_bytes, manifest)
    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, keystore_dir)

    with (
        mock.patch("tn.init"),
        mock.patch("tn.info"),
        mock.patch("tn.flush_and_close"),
    ):
        import tn.inbox as inbox_module

        inbox_module.accept(zip_path, yaml_path=yaml_path)

    # New kit installed.
    assert (keystore_dir / "default.btn.mykit").read_bytes() == kit_bytes

    # Old kit backed up.
    backups = list(keystore_dir.glob("default.btn.mykit.previous.*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == b"\xde\xad" * 8


def test_list_local(tmp_path):
    """list_local() returns matching zip files sorted by name."""
    (tmp_path / "tn-invite-AAA.zip").write_bytes(b"")
    (tmp_path / "tn-invite-BBB.zip").write_bytes(b"")
    (tmp_path / "other.zip").write_bytes(b"")

    result = list_local(tmp_path)
    names = [p.name for p in result]
    assert "tn-invite-AAA.zip" in names
    assert "tn-invite-BBB.zip" in names
    assert "other.zip" not in names


def test_list_local_nonexistent_dir():
    """list_local() returns empty list for a non-existent directory."""
    result = list_local(Path("/nonexistent/dir/that/does/not/exist"))
    assert result == []
