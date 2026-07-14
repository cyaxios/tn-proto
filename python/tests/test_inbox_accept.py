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
  PYTHONPATH=tn_proto/python .venv/Scripts/python.exe -m pytest tn_proto/python/tests/test_inbox_accept.py -v
"""

from __future__ import annotations

import hashlib
import json

# Add tn_proto/python to sys.path so 'tn' is importable.
import sys
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

import pytest
import yaml

_TN_PY = Path(__file__).parent.parent
if str(_TN_PY) not in sys.path:
    sys.path.insert(0, str(_TN_PY))

from tn.inbox import InboxError, _read_inner_manifest, accept, list_local

# ── Helpers ──────────────────────────────────────────────────────────


def _make_zip(
    tmp: Path,
    kit_bytes: bytes,
    manifest: dict,
    kit_entry: str = "kit.tnpkg",
) -> Path:
    """Write a valid invitation zip into tmp dir and return its path.

    ``kit_entry`` is the inner kit filename. Defaults to the legacy
    ``kit.tnpkg``; pass ``<group>.btn.mykit`` to mirror what the real
    server (``tn_proto_web`` ``_make_invitation_zip``) actually produces.
    """
    zip_path = tmp / "tn-invite-TEST.zip"
    with zipfile.ZipFile(str(zip_path), "w") as zf:
        zf.writestr(kit_entry, kit_bytes)
        zf.writestr("manifest.json", json.dumps(manifest))
    return zip_path


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_secure_inner_package_uses_bounded_tnpkg_reader() -> None:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("manifest.json", "{}")

    with pytest.raises(InboxError, match="ZIP compression"):
        _read_inner_manifest(buffer.getvalue())


def _minimal_tn_yaml(keystore_dir: Path) -> dict:
    """Minimal tn.yaml structure enough for accept() to parse.

    Pin ``keystore.path`` explicitly so the test doesn't depend on the
    inbox.py default (which is ``./.tn/keys`` and predates the per-stem
    namespacing default that other parts of the SDK now use).
    """
    return {
        "device": {"device_identity": "did:key:z6Mkfrank"},
        "ceremony": {"id": "test-ceremony", "mode": "local"},
        "groups": {},
        "keystore": {"path": str(keystore_dir).replace("\\", "/")},
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


def test_accept_rejects_outer_archive_bomb_before_member_read(tmp_path):
    zip_path = tmp_path / "tn-invite-bomb.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("kit.tnpkg", b"0" * (1024 * 1024))
        zf.writestr("manifest.json", "{}")
    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, tmp_path / ".tn/tn/keys")

    with pytest.raises(InboxError, match="compression ratio"):
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


def test_accept_real_server_kit_entry_name(tmp_path):
    """Bug-fix: accept the inner kit named with the REAL server entry name.

    The production invitation producer (``tn_proto_web``
    ``_make_invitation_zip`` / ``_kit_entry_name``) names the inner kit
    ``<group>.btn.mykit``, NOT the legacy ``kit.tnpkg``. Before the fix,
    ``accept`` only looked up ``kit.tnpkg`` and so raised "missing
    kit.tnpkg" on a genuine server-minted zip. This test packs the kit
    under the real name and proves ``accept`` finds, hash-verifies, and
    installs it.

    Note: this is a fixture-level bug-fix test, not a full round-trip.
    A faithful end-to-end round-trip (mint a real recipient-bound invite
    zip, then accept it) lives in ``test_inbox_accept_roundtrip.py``,
    which drives the ``tn invite`` -> ``tn inbox accept`` chain.
    """
    kit_bytes = b"\x12\x34\x56" * 16
    sha = _sha256(kit_bytes)
    manifest = {
        "group_name": "payments",
        "leaf_index": 9,
        "from_email": "alice@demo.local",
        "from_account_did": "did:vault:alice",
        "kit_sha256": sha,
    }
    # REAL server entry name: <group>.btn.mykit, not kit.tnpkg.
    zip_path = _make_zip(tmp_path, kit_bytes, manifest, kit_entry="payments.btn.mykit")
    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, tmp_path / ".tn/tn/keys")

    with (
        mock.patch("tn.init"),
        mock.patch("tn.info"),
        mock.patch("tn.flush_and_close"),
    ):
        import tn.inbox as inbox_module

        result = inbox_module.accept(zip_path, yaml_path=yaml_path)

    kit_path = tmp_path / ".tn/tn/keys" / "payments.btn.mykit"
    assert kit_path.exists()
    assert kit_path.read_bytes() == kit_bytes
    assert result["group_name"] == "payments"
    assert result["leaf_index"] == 9
    assert result["kit_path"] == str(kit_path)


def test_accept_missing_kit_entry(tmp_path):
    """InboxError raised when the zip has a manifest but no kit entry."""
    zip_path = tmp_path / "tn-invite-TEST.zip"
    with zipfile.ZipFile(str(zip_path), "w") as zf:
        # Only a manifest; no kit.tnpkg / <group>.btn.mykit entry.
        zf.writestr(
            "manifest.json",
            json.dumps({"group_name": "default", "leaf_index": 1}),
        )
    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, tmp_path / ".tn/tn/keys")

    with pytest.raises(InboxError, match="missing kit"):
        accept(zip_path, yaml_path=yaml_path)


def test_accept_garbage_zip(tmp_path):
    """InboxError raised for non-zip / garbage bytes."""
    bad = tmp_path / "tn-invite-garbage.zip"
    bad.write_bytes(b"this is not a zip at all")
    yaml_path = tmp_path / "tn.yaml"
    _write_yaml(yaml_path, tmp_path / ".tn/tn/keys")

    with pytest.raises(InboxError, match="Invalid zip file"):
        accept(bad, yaml_path=yaml_path)


def test_accept_missing_yaml(tmp_path):
    """InboxError raised when the tn.yaml does not exist."""
    kit_bytes = b"\x00" * 32
    manifest = {"group_name": "default", "leaf_index": 1, "kit_sha256": _sha256(kit_bytes)}
    zip_path = _make_zip(tmp_path, kit_bytes, manifest)
    missing_yaml = tmp_path / "does-not-exist.yaml"

    with pytest.raises(InboxError, match="tn.yaml not found"):
        accept(zip_path, yaml_path=missing_yaml)


def test_accept_backs_up_existing_kit(tmp_path):
    """Existing kit is renamed to .previous.<ts> before installing new one."""
    # Pre-install an old kit.
    keystore_dir = tmp_path / ".tn/tn/keys"
    keystore_dir.mkdir(parents=True)
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
