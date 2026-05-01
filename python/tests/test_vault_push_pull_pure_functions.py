"""Tests for the pure one-shot entry points behind the vault push/pull
handlers. Per 2026-04-27 vault-passive-backup-and-sync-design §4.11
and §10 item 6: a future ``tn sync`` CLI verb should be able to call
``push_snapshot`` / ``pull_inbox`` directly without instantiating any
handler/scheduler thread.

These tests import the pure functions directly and exercise them with
mock clients. If they pass, the one-shot path works for the CLI.

Run:
    .venv/Scripts/python.exe -m pytest tn-protocol/python/tests/test_vault_push_pull_pure_functions.py -v
"""

from __future__ import annotations

import sys
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
from tn.handlers.vault_pull import pull_inbox
from tn.handlers.vault_push import push_snapshot
from tn.tnpkg import _read_manifest, _verify_manifest_signature


# ---------------------------------------------------------------------------
# Mocks (no handler / scheduler involved)
# ---------------------------------------------------------------------------


class _CapturedPushClient:
    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []

    def post_inbox_snapshot(
        self, path: str, body: bytes, *, params: dict[str, str] | None = None
    ) -> None:
        self.posts.append({"path": path, "body": body, "params": dict(params or {})})


class _MockInboxClient:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.blobs: dict[str, bytes] = {}
        self.list_calls: list[str | None] = []

    def add_snapshot(
        self,
        path: str,
        blob: bytes,
        *,
        head_row_hash: str,
        received_at: str,
    ) -> None:
        self.items.append(
            {"path": path, "head_row_hash": head_row_hash, "received_at": received_at}
        )
        self.blobs[path] = blob

    def list_incoming(self, did: str, *, since: str | None = None):
        self.list_calls.append(since)
        if since is None:
            return [dict(it) for it in self.items]
        return [dict(it) for it in self.items if it["received_at"] > since]

    def download(self, path: str) -> bytes:
        return self.blobs[path]


# ---------------------------------------------------------------------------
# Fixtures (mirror the existing handler-test fixtures)
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


def _build_ceremony_with_recipient(tmp_path: Path) -> Any:
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("requires the Rust runtime (btn)")
    out = tmp_path / "_kits"
    out.mkdir()
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out / "alice.btn.mykit")
    return tn.current_config()


def _build_consumer_cfg(tmp_path: Path) -> Any:
    cons = tmp_path / "consumer"
    cons.mkdir()
    yaml_path = cons / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("requires the Rust runtime (btn)")
    return tn.current_config()


def _build_producer_snapshot(tmp_path: Path) -> tuple[bytes, str]:
    src = tmp_path / "producer"
    src.mkdir()
    yaml_path = src / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("requires the Rust runtime (btn)")
    out_dir = src / "_kits"
    out_dir.mkdir()
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out_dir / "alice.btn.mykit")
    cfg = tn.current_config()
    snap = src / "snap.tnpkg"
    export(snap, kind="admin_log_snapshot", cfg=cfg)
    blob = snap.read_bytes()
    manifest, _ = _read_manifest(blob)
    head = manifest.head_row_hash or ""
    tn.flush_and_close()
    return blob, head


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPushSnapshotPureFunction:
    def test_push_snapshot_runs_without_handler(self, tmp_path: Path):
        cfg = _build_ceremony_with_recipient(tmp_path)
        client = _CapturedPushClient()

        result = push_snapshot(cfg, client, scope="admin")

        assert result["pushed"] is True
        assert result["head_row_hash"]
        assert result["stored_path"] is not None
        assert len(client.posts) == 1
        post = client.posts[0]
        assert post["path"].startswith(f"/api/v1/inbox/{cfg.device.did}/snapshots/")
        manifest, _body = _read_manifest(post["body"])
        assert manifest.kind == "admin_log_snapshot"
        assert _verify_manifest_signature(manifest)

    def test_push_snapshot_dedupe_skip(self, tmp_path: Path):
        cfg = _build_ceremony_with_recipient(tmp_path)
        client = _CapturedPushClient()

        first = push_snapshot(cfg, client, scope="admin")
        head = first["head_row_hash"]
        assert first["pushed"] is True

        second = push_snapshot(
            cfg, client, scope="admin", skip_if_head_matches=head
        )
        assert second["pushed"] is False
        assert second["stored_path"] is None
        assert second["head_row_hash"] == head
        # Only the first call POSTed.
        assert len(client.posts) == 1


class TestPullInboxPureFunction:
    def test_pull_inbox_runs_without_handler(self, tmp_path: Path):
        snap_blob, head = _build_producer_snapshot(tmp_path)
        cfg = _build_consumer_cfg(tmp_path)
        client = _MockInboxClient()
        client.add_snapshot(
            "/api/v1/inbox/foo/snapshots/c1/p1.tnpkg",
            snap_blob,
            head_row_hash=head,
            received_at="2026-04-27T10:00:00Z",
        )

        result = pull_inbox(cfg, client, since_cursor=None)

        assert result["absorbed"] == 1
        assert result["new_cursor"] == "2026-04-27T10:00:00Z"
        admin_log = resolve_admin_log_path(cfg)
        assert admin_log.exists()
        assert "tn.recipient.added" in admin_log.read_text(encoding="utf-8")

    def test_pull_inbox_empty_returns_prior_cursor(self, tmp_path: Path):
        cfg = _build_consumer_cfg(tmp_path)
        client = _MockInboxClient()  # no items
        result = pull_inbox(cfg, client, since_cursor="prev-cursor")
        assert result == {"absorbed": 0, "new_cursor": "prev-cursor"}
        assert client.list_calls == ["prev-cursor"]
