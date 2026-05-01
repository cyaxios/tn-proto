"""Tests for tn.handlers.vault_push.VaultPushHandler (plan §5.2).

Mocks the vault HTTP endpoint with a captured-request shim and verifies
that admin events trigger a `.tnpkg` POST with a valid manifest.

Run:
    .venv/Scripts/python.exe -m pytest tn-protocol/python/tests/test_vault_push_handler.py -v
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
from tn.handlers.vault_push import VaultPushHandler
from tn.tnpkg import _read_manifest, _verify_manifest_signature

# ---------------------------------------------------------------------------
# Mock client capturing POST requests
# ---------------------------------------------------------------------------


class _CapturedClient:
    """Stand-in for VaultClient: records every snapshot POST in memory."""

    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []
        self.closed = False

    def post_inbox_snapshot(
        self, path: str, body: bytes, *, params: dict[str, str] | None = None
    ) -> None:
        self.posts.append({"path": path, "body": body, "params": dict(params or {})})

    def close(self) -> None:
        self.closed = True


def _factory(captured: _CapturedClient):
    """Build the client_factory the handler expects."""

    def factory(endpoint: str, identity: Any) -> _CapturedClient:
        return captured

    return factory


# ---------------------------------------------------------------------------
# Fixture: a btn ceremony with admin events, configured for the dedicated
# admin log so snapshots include real envelopes.
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
        pytest.skip("vault_push tests require the Rust runtime (btn)")
    out = tmp_path / "_kits"
    out.mkdir()
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out / "alice.btn.mykit")
    cfg = tn.current_config()
    # These steady-state tests predate D-19 / init-upload mode. Stamp the
    # sync_state to bound so the new dispatcher in `_push_snapshot` takes
    # the steady-state branch (the original /inbox/ POST path).
    from tn.sync_state import mark_account_bound
    mark_account_bound(cfg.yaml_path, "test-account-id")
    return cfg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVaultPushOnSchedule:
    def test_push_snapshot_posts_signed_manifest(self, tmp_path: Path):
        cfg = _build_ceremony_with_recipient(tmp_path)
        captured = _CapturedClient()

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,  # disable scheduler firing during test
            scope="admin",
        )
        try:
            ok = h._push_snapshot()
            assert ok is True
        finally:
            h._stop_ev.set()

        assert len(captured.posts) == 1
        post = captured.posts[0]
        assert "/api/v1/inbox/" in post["path"]
        assert post["path"].startswith(f"/api/v1/inbox/{cfg.device.did}/snapshots/")
        # head_row_hash rides as a query param for vault-side dedupe.
        assert "head_row_hash" in post["params"]
        # Body is a real signed `.tnpkg`.
        manifest, body = _read_manifest(post["body"])
        assert manifest.kind == "admin_log_snapshot"
        assert manifest.from_did == cfg.device.did
        assert _verify_manifest_signature(manifest)
        # Body has at least one envelope (the admin_add_recipient call).
        assert b"tn.recipient.added" in body["body/admin.ndjson"]

    def test_push_dedupes_when_head_unchanged(self, tmp_path: Path):
        cfg = _build_ceremony_with_recipient(tmp_path)
        captured = _CapturedClient()

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_schedule",
            poll_interval=999.0,
        )
        try:
            assert h._push_snapshot() is True
            # Second call: nothing has changed locally, so the handler
            # should skip the POST.
            assert h._push_snapshot() is False
        finally:
            h._stop_ev.set()

        assert len(captured.posts) == 1


class TestVaultPushOnEmit:
    def test_only_admin_events_trigger(self, tmp_path: Path):
        cfg = _build_ceremony_with_recipient(tmp_path)
        captured = _CapturedClient()

        h = VaultPushHandler(
            "vp",
            endpoint="https://mock.vault.local",
            project_id="proj_xxx",
            cfg_provider=lambda: cfg,
            client_factory=_factory(captured),
            trigger="on_emit",
        )
        try:
            non_admin = {"event_type": "user.login", "did": cfg.device.did}
            admin = {"event_type": "tn.recipient.added", "did": cfg.device.did}
            assert h.accepts(non_admin) is False
            assert h.accepts(admin) is True
            # emit() with non-admin would never be called by the runtime
            # (filter checks accepts first), but we still verify directly:
            h.emit(admin, b"")
        finally:
            h._stop_ev.set()
        assert len(captured.posts) == 1


class TestVaultPushTriggerValidation:
    def test_invalid_trigger_raises(self, tmp_path):
        with pytest.raises(ValueError, match="trigger"):
            VaultPushHandler(
                "vp",
                endpoint="https://x",
                project_id="p",
                trigger="lol",
                cfg_provider=lambda: None,
                client_factory=lambda *_a, **_k: _CapturedClient(),
            )
