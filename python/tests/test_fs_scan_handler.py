"""Tests for tn.handlers.fs_scan.FsScanHandler (plan §5.2).

Verifies that `.tnpkg` files in a watched directory get absorbed and
moved to the archive (or rejected) directory based on outcome.
"""

from __future__ import annotations

import json
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
import yaml as _yaml

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn.admin.log import resolve_admin_log_path
from tn.export import export
from tn.handlers.fs_scan import FsScanHandler


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _force_admin_log_yaml(yaml_path: Path) -> None:
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["admin_log_location"] = "./.tn/admin/admin.ndjson"
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _build_producer_snapshot(tmp_path: Path, sub: str) -> bytes:
    src = tmp_path / sub
    src.mkdir()
    yaml_path = src / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("fs_scan tests require the Rust runtime (btn)")
    out_dir = src / "_kits"
    out_dir.mkdir()
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out_dir / "alice.btn.mykit")
    cfg = tn.current_config()
    snap = src / "snap.tnpkg"
    export(snap, kind="admin_log_snapshot", cfg=cfg)
    blob = snap.read_bytes()
    tn.flush_and_close()
    return blob


def _build_consumer(tmp_path: Path, sub: str = "consumer"):
    cons = tmp_path / sub
    cons.mkdir()
    yaml_path = cons / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("fs_scan tests require the Rust runtime (btn)")
    return tn.current_config()


class TestFsScanHappy:
    def test_absorbs_and_archives(self, tmp_path: Path):
        snap_blob = _build_producer_snapshot(tmp_path, "producer")
        cfg = _build_consumer(tmp_path)
        in_dir = tmp_path / "inbox"
        in_dir.mkdir()
        (in_dir / "a.tnpkg").write_bytes(snap_blob)

        h = FsScanHandler(
            "fs",
            in_dir=in_dir,
            cfg_provider=lambda: cfg,
            autostart=False,
        )
        absorbed = h.tick_once()
        assert absorbed == 1

        # Original file moved to archive.
        assert not (in_dir / "a.tnpkg").exists()
        archive = in_dir / ".processed"
        assert archive.exists()
        assert (archive / "a.tnpkg").exists()

        # Admin log advanced.
        admin_log = resolve_admin_log_path(cfg)
        assert "tn.recipient.added" in admin_log.read_text(encoding="utf-8")

    def test_delete_mode(self, tmp_path: Path):
        snap_blob = _build_producer_snapshot(tmp_path, "producer")
        cfg = _build_consumer(tmp_path)
        in_dir = tmp_path / "inbox"
        in_dir.mkdir()
        (in_dir / "a.tnpkg").write_bytes(snap_blob)
        h = FsScanHandler(
            "fs",
            in_dir=in_dir,
            cfg_provider=lambda: cfg,
            on_processed="delete",
            autostart=False,
        )
        h.tick_once()
        assert not (in_dir / "a.tnpkg").exists()
        assert not (in_dir / ".processed").exists()


class TestFsScanRejects:
    def test_bad_signature_moves_to_rejected(self, tmp_path: Path):
        good_blob = _build_producer_snapshot(tmp_path, "producer")
        # Tamper signature
        bad_buf = BytesIO()
        with zipfile.ZipFile(BytesIO(good_blob), "r") as src_zf, zipfile.ZipFile(
            bad_buf, "w", zipfile.ZIP_DEFLATED
        ) as dst_zf:
            for name in src_zf.namelist():
                data = src_zf.read(name)
                if name == "manifest.json":
                    doc = json.loads(data.decode("utf-8"))
                    doc["manifest_signature_b64"] = "AA" * 32
                    data = json.dumps(doc).encode("utf-8")
                dst_zf.writestr(name, data)

        cfg = _build_consumer(tmp_path)
        in_dir = tmp_path / "inbox"
        in_dir.mkdir()
        (in_dir / "bad.tnpkg").write_bytes(bad_buf.getvalue())

        h = FsScanHandler(
            "fs",
            in_dir=in_dir,
            cfg_provider=lambda: cfg,
            autostart=False,
        )
        absorbed = h.tick_once()
        assert absorbed == 0
        rejected = in_dir / ".rejected"
        assert (rejected / "bad.tnpkg").exists()
        assert not (in_dir / "bad.tnpkg").exists()
        assert not (in_dir / ".processed" / "bad.tnpkg").exists()
