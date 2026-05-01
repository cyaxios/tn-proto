import base64
import os
import zipfile
from pathlib import Path

import pytest

from tn import admin
from tn.compile import compile_enrolment, compile_kit_bundle, emit_to_outbox
from tn.config import load_or_create
from tn.conventions import outbox_dir
from tn.packaging import verify


def test_compile_enrolment_produces_signed_package(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher="jwe")
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob", os.urandom(32))
    pkg = compile_enrolment(cfg, "default", "did:key:z6MkBob")
    assert pkg.package_kind == "enrolment"
    assert pkg.peer_did == "did:key:z6MkBob"
    assert pkg.ceremony_id == cfg.ceremony_id
    assert "sender_pub_b64" in pkg.payload
    assert len(base64.b64decode(pkg.payload["sender_pub_b64"])) == 32
    assert verify(pkg) is True


def test_emit_to_outbox_writes_file(tmp_path: Path):
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob", os.urandom(32))
    pkg = compile_enrolment(cfg, "default", "did:key:z6MkBob")
    path = emit_to_outbox(cfg, pkg)
    assert path.exists()
    assert path.parent == outbox_dir(tmp_path)
    assert path.suffix == ".tnpkg"


def test_compile_enrolment_rejects_btn_group(tmp_path: Path):
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    admin.ensure_group(cfg, "press", cipher="btn")
    import pytest

    with pytest.raises(RuntimeError) as e:
        compile_enrolment(cfg, "press", "did:key:z6MkBob")
    msg = str(e.value)
    assert "press" in msg
    assert "jwe" in msg.lower()


def _bootstrap_btn_keystore(tmp_path: Path) -> Path:
    """Init a btn ceremony so the keystore has a `*.btn.mykit` for
    compile_kit_bundle to bundle. Returns the keystore directory.
    """
    import tn

    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()
    cfg = load_or_create(yaml)
    return cfg.keystore


def test_compile_kit_bundle_full_requires_secret_acknowledgment(tmp_path: Path):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"
    with pytest.raises(ValueError) as exc:
        compile_kit_bundle(keystore, out_path=out, full=True)
    msg = str(exc.value)
    assert "private keys" in msg.lower()
    # Without confirm the archive must NOT have been written.
    assert not out.exists()


def test_compile_kit_bundle_full_with_ack_writes_warning_marker(tmp_path: Path):
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"
    # The keystore now lives under .tn/<stem>/keys/, so pass yaml_path so
    # compile_kit_bundle can sign the manifest using the ceremony's device key.
    path = compile_kit_bundle(
        keystore,
        out_path=out,
        full=True,
        confirm_includes_secrets=True,
        yaml_path=tmp_path / "tn.yaml",
    )
    assert path.exists()
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        # The new universal `.tnpkg` wrapper places body files under body/.
        assert "body/WARNING_CONTAINS_PRIVATE_KEYS" in names
        # Marker is zero-byte by contract.
        assert zf.read("body/WARNING_CONTAINS_PRIVATE_KEYS") == b""


def test_compile_kit_bundle_readers_only_skips_secret_marker(tmp_path: Path):
    """full=False is the safe path; no marker, no acknowledgment needed."""
    keystore = _bootstrap_btn_keystore(tmp_path)
    out = tmp_path / "bundle.tnpkg"
    # See sibling test for why yaml_path is now required.
    path = compile_kit_bundle(
        keystore, out_path=out, full=False, yaml_path=tmp_path / "tn.yaml",
    )
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        assert "WARNING_CONTAINS_PRIVATE_KEYS" not in names
        assert "body/WARNING_CONTAINS_PRIVATE_KEYS" not in names
