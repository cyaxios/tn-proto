"""Tests for tn.handlers.vault_pull.VaultPullHandler (plan §5.2).

Mocks the vault GET endpoints with an in-memory shim; verifies absorb
runs for each available `.tnpkg`, the local admin log advances, the
cursor persists across handler instances, and bad-signature snapshots
are rejected without losing the cursor.

Run:
    .venv/Scripts/python.exe -m pytest tn-protocol/python/tests/test_vault_pull_handler.py -v
"""

from __future__ import annotations

import json
import sys
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
import yaml as _yaml

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn.admin.log import resolve_admin_log_path
from tn.export import export
from tn.handlers.vault_pull import VaultPullHandler

# ---------------------------------------------------------------------------
# Mock vault client
# ---------------------------------------------------------------------------


class _MockInbox:
    """Captures items the test wants the handler to see, plus call log."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.blobs: dict[str, bytes] = {}
        self.list_calls: list[str | None] = []  # records `since`
        self.download_calls: list[str] = []
        self.closed = False

    def add_snapshot(
        self,
        path: str,
        blob: bytes,
        *,
        head_row_hash: str,
        received_at: str,
        since_marker: str | None = None,
    ):
        item = {
            "path": path,
            "head_row_hash": head_row_hash,
            "received_at": received_at,
        }
        if since_marker is not None:
            item["since_marker"] = since_marker
        self.items.append(item)
        self.blobs[path] = blob

    def list_incoming(self, did: str, *, since: str | None = None):
        self.list_calls.append(since)
        out = []
        for it in self.items:
            # Mirror server semantics: when items carry an opaque since_marker
            # the server filters by since_marker > since; otherwise it falls
            # back to received_at. Per spec §4.1 the SDK should advance
            # cursor by since_marker when present.
            if since is None:
                out.append(dict(it))
                continue
            key_field = "since_marker" if "since_marker" in it else "received_at"
            if it[key_field] > since:
                out.append(dict(it))
        return out

    def download(self, path: str) -> bytes:
        self.download_calls.append(path)
        if path not in self.blobs:
            raise KeyError(path)
        return self.blobs[path]

    def close(self) -> None:
        self.closed = True


def _factory(mock: _MockInbox):
    def factory(endpoint: str, identity: Any) -> _MockInbox:
        return mock

    return factory


# ---------------------------------------------------------------------------
# Fixtures: producer + consumer ceremonies
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _force_admin_log_yaml(yaml_path: Path) -> None:
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["admin_log_location"] = "./.tn/admin/admin.ndjson"
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _build_producer_snapshot(
    tmp_path: Path, *, sub_dir: str = "producer"
) -> tuple[Path, bytes, str]:
    """Build a btn ceremony with one admin event and export a snapshot.
    Returns (yaml_path, snapshot_bytes, head_row_hash)."""
    src = tmp_path / sub_dir
    src.mkdir()
    yaml_path = src / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("vault_pull tests require the Rust runtime (btn)")
    out_dir = src / "_kits"
    out_dir.mkdir()
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out_dir / "alice.btn.mykit")
    cfg = tn.current_config()
    snapshot_path = src / "snap.tnpkg"
    export(snapshot_path, kind="admin_log_snapshot", cfg=cfg)
    blob = snapshot_path.read_bytes()
    # Read manifest for head_row_hash
    from tn.tnpkg import _read_manifest

    manifest, _ = _read_manifest(blob)
    head = manifest.head_row_hash
    tn.flush_and_close()
    return yaml_path, blob, head or ""


def _build_consumer_cfg(tmp_path: Path) -> Any:
    """Build an empty btn ceremony to act as the consumer side. We do
    NOT call admin_add_recipient because the absorb path expects to
    receive its admin envelopes via .tnpkg, not local emits.
    """
    cons = tmp_path / "consumer"
    cons.mkdir()
    yaml_path = cons / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("vault_pull tests require the Rust runtime (btn)")
    cfg = tn.current_config()
    return cfg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVaultPullHappyPath:
    def test_pull_absorbs_snapshots(self, tmp_path: Path):
        # Build producer snapshot first (closes runtime when done).
        _, snap_blob, head = _build_producer_snapshot(tmp_path)
        cfg = _build_consumer_cfg(tmp_path)

        mock = _MockInbox()
        mock.add_snapshot(
            "/api/v1/inbox/foo/snapshots/c1/2026-04-24T10-00-00Z.tnpkg",
            snap_blob,
            head_row_hash=head,
            received_at="2026-04-24T10:00:00Z",
        )

        h = VaultPullHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(mock),
            poll_interval=999.0,
            autostart=False,
        )

        absorbed = h.tick_once()
        assert absorbed == 1, mock.download_calls

        admin_log = resolve_admin_log_path(cfg)
        assert admin_log.exists()
        body = admin_log.read_text(encoding="utf-8")
        assert "tn.recipient.added" in body

        # Cursor file persisted
        cursor_path = cfg.yaml_path.parent / ".tn/tn/admin" / "vault_pull.cursor.json"
        assert cursor_path.exists()
        cursor = json.loads(cursor_path.read_text(encoding="utf-8"))
        assert cursor["last_seen"] == "2026-04-24T10:00:00Z"

    def test_cursor_persists_across_restart(self, tmp_path: Path):
        _, snap_blob, head = _build_producer_snapshot(tmp_path)
        cfg = _build_consumer_cfg(tmp_path)

        mock = _MockInbox()
        mock.add_snapshot(
            "/api/v1/inbox/foo/snapshots/c1/p1.tnpkg",
            snap_blob,
            head_row_hash=head,
            received_at="2026-04-24T10:00:00Z",
        )

        h1 = VaultPullHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(mock),
            autostart=False,
        )
        assert h1.tick_once() == 1
        h1.close()

        # Second handler instance (simulating a restart). The mock would
        # return the same item, but the cursor should mean list_incoming
        # is called with `since=...` and yields nothing.
        h2 = VaultPullHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(mock),
            autostart=False,
        )
        absorbed_again = h2.tick_once()
        assert absorbed_again == 0
        # The mock's filter applied since='...' so the item was excluded.
        assert mock.list_calls[-1] == "2026-04-24T10:00:00Z"
        h2.close()


class TestVaultPullErrorPath:
    def test_bad_signature_does_not_advance_cursor(self, tmp_path: Path):
        # Build a corrupt snapshot by tampering the manifest signature.
        _, snap_blob, head = _build_producer_snapshot(tmp_path)
        # Rebuild the zip with a tampered manifest_signature_b64.
        bad_buf = BytesIO()
        with zipfile.ZipFile(BytesIO(snap_blob), "r") as src_zf, zipfile.ZipFile(
            bad_buf, "w", zipfile.ZIP_DEFLATED
        ) as dst_zf:
            for name in src_zf.namelist():
                data = src_zf.read(name)
                if name == "manifest.json":
                    doc = json.loads(data.decode("utf-8"))
                    doc["manifest_signature_b64"] = "AA" * 32  # bogus
                    data = json.dumps(doc).encode("utf-8")
                dst_zf.writestr(name, data)
        bad_blob = bad_buf.getvalue()

        cfg = _build_consumer_cfg(tmp_path)
        mock = _MockInbox()
        mock.add_snapshot(
            "/api/v1/inbox/foo/snapshots/c1/bad.tnpkg",
            bad_blob,
            head_row_hash=head,
            received_at="2026-04-24T11:00:00Z",
        )

        h = VaultPullHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(mock),
            on_absorb_error="log",
            autostart=False,
        )
        absorbed = h.tick_once()
        # absorb dispatch returns AbsorbReceipt with legacy_status=rejected;
        # tick_once treats that as not-absorbed and skips advancing the
        # cursor. (cursor is only advanced on `accepted` status.)
        assert absorbed == 0
        cursor_path = cfg.yaml_path.parent / ".tn/tn/admin" / "vault_pull.cursor.json"
        # Either the cursor wasn't written at all (no successful items) or
        # it was written but doesn't contain the bad item's timestamp.
        if cursor_path.exists():
            cursor = json.loads(cursor_path.read_text(encoding="utf-8"))
            assert cursor.get("last_seen") != "2026-04-24T11:00:00Z"
        h.close()


class TestVaultPullCursorContract:
    """§4.1 verification: cursor advances by server-supplied since_marker.

    Per spec, the wire returns `since_marker` per item (opaque, server-chosen).
    The SDK should pass that value back via `?since=...` on the next poll.
    Today the SDK uses received_at string-compare, which silently skips
    items when wall-clock order disagrees with arrival order.
    """

    def test_cursor_uses_since_marker_when_present(self, tmp_path: Path):
        _, snap_blob, head = _build_producer_snapshot(tmp_path)
        cfg = _build_consumer_cfg(tmp_path)

        mock = _MockInbox()
        # since_marker intentionally distinct from received_at so the
        # next-poll cursor reveals which field the SDK trusts.
        mock.add_snapshot(
            "/api/v1/inbox/foo/snapshots/c1/marker-test.tnpkg",
            snap_blob,
            head_row_hash=head,
            received_at="2026-04-24T10:00:00Z",
            since_marker="opaque-cursor-002",
        )

        h = VaultPullHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(mock),
            poll_interval=999.0,
            autostart=False,
        )
        assert h.tick_once() == 1
        h.close()

        # Restart -- the cursor passed to list_incoming should be the
        # server-supplied since_marker, not received_at.
        h2 = VaultPullHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(mock),
            poll_interval=999.0,
            autostart=False,
        )
        h2.tick_once()
        h2.close()

        assert mock.list_calls[-1] == "opaque-cursor-002", (
            f"§4.1 contract violation: cursor should advance by since_marker, "
            f"got {mock.list_calls[-1]!r}. SDK is using received_at."
        )
