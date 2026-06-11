"""Tests for the unified `tn.pkg.export()` / `tn.pkg.absorb()` surface.

Round-trip every kind shipped in v1 and verify the manifest signature /
secret-protection invariants.
"""

from __future__ import annotations

import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn import admin
from tn.compile import compile_enrolment
from tn.config import load_or_create
from tn.export import _build_kit_bundle_body, export
from tn.offer import offer
from tn.tnpkg import _read_manifest, _verify_manifest_signature


@pytest.fixture(autouse=True)
def fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def test_export_offer_round_trip(tmp_path: Path):
    bob = tmp_path / "bob"
    bob.mkdir()
    bob_cfg = load_or_create(bob / "tn.yaml", cipher="jwe")
    pkg = offer(bob_cfg, publisher_did="did:key:z6MkAlice")
    out = tmp_path / "offer.tnpkg"
    export(out, kind="offer", cfg=bob_cfg, package=pkg, to_did="did:key:z6MkAlice")
    assert out.exists()

    manifest, body = _read_manifest(out)
    assert manifest.kind == "offer"
    assert manifest.publisher_identity == bob_cfg.device.device_identity
    assert manifest.recipient_identity == "did:key:z6MkAlice"
    assert "body/package.json" in body
    assert _verify_manifest_signature(manifest)


def test_export_enrolment_round_trip(tmp_path: Path):
    alice = tmp_path / "alice"
    alice.mkdir()
    alice_cfg = load_or_create(alice / "tn.yaml", cipher="jwe")
    admin._add_recipient_jwe_impl(alice_cfg, "default", "did:key:z6MkBob", os.urandom(32))
    pkg = compile_enrolment(alice_cfg, "default", "did:key:z6MkBob")

    out = tmp_path / "enrolment.tnpkg"
    export(out, kind="enrolment", cfg=alice_cfg, package=pkg, to_did="did:key:z6MkBob")

    manifest, body = _read_manifest(out)
    assert manifest.kind == "enrolment"
    assert manifest.recipient_identity == "did:key:z6MkBob"
    assert _verify_manifest_signature(manifest)
    body_pkg = json.loads(body["body/package.json"].decode("utf-8"))
    assert body_pkg["package_kind"] == "enrolment"


def test_export_kit_bundle_round_trip(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()
    out = tmp_path / "bundle.tnpkg"
    export(out, kind="kit_bundle", cfg=cfg)
    tn.flush_and_close()

    manifest, body = _read_manifest(out)
    assert manifest.kind == "kit_bundle"
    assert _verify_manifest_signature(manifest)
    # At least one btn kit body file must be present.
    assert any(name.endswith(".btn.mykit") for name in body)
    # Marker should NOT be present for readers-only.
    assert "body/WARNING_CONTAINS_PRIVATE_KEYS" not in body


def _mk_keystore(tmp_path: Path, *names: str) -> Path:
    ks = tmp_path / "keys"
    ks.mkdir()
    for n in names:
        (ks / n).write_bytes(b"kitdata-" + n.encode())
    return ks


def test_build_kit_bundle_body_groups_filter(tmp_path: Path):
    """groups_filter restricts which group kits land in the body."""
    ks = _mk_keystore(tmp_path, "default.btn.mykit", "payments.btn.mykit")
    body, extras = _build_kit_bundle_body(
        None, ks, full=False, groups_filter=["payments"], confirm_includes_secrets=False
    )
    assert "body/payments.btn.mykit" in body
    assert "body/default.btn.mykit" not in body
    assert len(extras["state"]["kits"]) == 1
    assert extras["scope"] == "kit_bundle"


def test_build_kit_bundle_body_all_kits_when_no_filter(tmp_path: Path):
    ks = _mk_keystore(tmp_path, "default.btn.mykit", "payments.btn.mykit")
    body, extras = _build_kit_bundle_body(
        None, ks, full=False, groups_filter=None, confirm_includes_secrets=False
    )
    assert "body/default.btn.mykit" in body
    assert "body/payments.btn.mykit" in body
    assert len(extras["state"]["kits"]) == 2


def test_build_kit_bundle_body_no_kits_raises(tmp_path: Path):
    ks = tmp_path / "empty_keys"
    ks.mkdir()
    with pytest.raises(RuntimeError, match=r"no \*\.btn\.mykit"):
        _build_kit_bundle_body(
            None, ks, full=False, groups_filter=None, confirm_includes_secrets=False
        )


def test_export_full_keystore_requires_confirmation(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    out = tmp_path / "full.tnpkg"
    with pytest.raises(ValueError, match="confirm_includes_secrets"):
        export(out, kind="full_keystore", cfg=cfg)
    assert not out.exists()

    # With confirmation, the export proceeds and the loud marker lives in body/.
    export(out, kind="full_keystore", cfg=cfg, confirm_includes_secrets=True)
    tn.flush_and_close()
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    assert "body/WARNING_CONTAINS_PRIVATE_KEYS" in names
    assert "body/local.private" in names
