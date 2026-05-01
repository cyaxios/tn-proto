"""Tests for tn.handlers.fs_drop.FsDropHandler (plan §5.2).

Verifies that admin-event emits drop a `.tnpkg` into the configured
out_dir, that the filename template substitutes correctly, and that the
``on:`` allowlist filters event types.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml as _yaml

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn.handlers.fs_drop import FsDropHandler
from tn.tnpkg import _read_manifest, _verify_manifest_signature


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _force_admin_log_yaml(yaml_path: Path) -> None:
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["admin_log_location"] = "./.tn/admin/admin.ndjson"
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _build_ceremony(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("fs_drop tests require the Rust runtime (btn)")
    out_dir = tmp_path / "_kits"
    out_dir.mkdir()
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out_dir / "alice.btn.mykit")
    return tn.current_config()


class TestFsDropEmits:
    def test_drops_signed_snapshot_on_admin_event(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        outbox = tmp_path / "outbox"
        h = FsDropHandler(
            "fd",
            out_dir=outbox,
            cfg_provider=lambda: cfg,
        )
        env = {"event_type": "tn.recipient.added", "did": cfg.device.did}
        h.emit(env, b"")

        files = list(outbox.glob("*.tnpkg"))
        assert len(files) == 1, files
        manifest, body = _read_manifest(files[0])
        assert manifest.kind == "admin_log_snapshot"
        assert _verify_manifest_signature(manifest)
        # head_row_hash should appear in the templated name.
        assert manifest.head_row_hash is not None
        assert _short_in_name(files[0].name, manifest.head_row_hash)

    def test_filename_template_custom(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        outbox = tmp_path / "outbox"
        h = FsDropHandler(
            "fd",
            out_dir=outbox,
            cfg_provider=lambda: cfg,
            filename_template="snap_{head_row_hash:short}.tnpkg",
        )
        h.emit({"event_type": "tn.recipient.added", "did": cfg.device.did}, b"")
        files = list(outbox.glob("snap_*.tnpkg"))
        assert len(files) == 1


class TestFsDropFilter:
    def test_on_allowlist(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        outbox = tmp_path / "outbox"
        h = FsDropHandler(
            "fd",
            out_dir=outbox,
            on=["tn.recipient.added"],
            cfg_provider=lambda: cfg,
        )
        # An unrelated admin event should NOT pass `accepts()`. The
        # dispatcher relies on this check before calling emit; here we
        # mirror that contract explicitly.
        unrelated = {"event_type": "tn.vault.linked", "did": cfg.device.did}
        assert h.accepts(unrelated) is False

        # The allowlisted event passes accepts() and (when emit fires)
        # produces a snapshot file.
        wanted = {"event_type": "tn.recipient.added", "did": cfg.device.did}
        assert h.accepts(wanted) is True
        h.emit(wanted, b"")
        assert len(list(outbox.glob("*.tnpkg"))) == 1

    def test_non_admin_event_rejected(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        outbox = tmp_path / "outbox"
        h = FsDropHandler(
            "fd",
            out_dir=outbox,
            cfg_provider=lambda: cfg,
        )
        non_admin = {"event_type": "user.login", "did": cfg.device.did}
        assert h.accepts(non_admin) is False


class TestFsDropDedupe:
    def test_dedupes_unchanged_head(self, tmp_path: Path):
        cfg = _build_ceremony(tmp_path)
        outbox = tmp_path / "outbox"
        h = FsDropHandler(
            "fd",
            out_dir=outbox,
            cfg_provider=lambda: cfg,
        )
        env = {"event_type": "tn.recipient.added", "did": cfg.device.did}
        h.emit(env, b"")
        h.emit(env, b"")  # Should NOT produce a second file.
        assert len(list(outbox.glob("*.tnpkg"))) == 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _short_in_name(name: str, head_row_hash: str) -> bool:
    if head_row_hash.startswith("sha256:"):
        return head_row_hash[len("sha256:") : len("sha256:") + 12] in name
    return head_row_hash[:12] in name
