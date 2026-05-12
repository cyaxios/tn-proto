"""full_keystore manifests carry every stream's tn.yaml verbatim.

See docs/superpowers/specs/2026-05-12-cold-start-completeness-design.md
(Cluster B2.1).
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
import tn


@pytest.fixture(autouse=True)
def _isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Per-test isolation: fresh cwd, no env leakage, cleared registry."""
    from tn import _autoinit, _registry
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    _registry.clear_registry_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.chdir(tmp_path)
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _registry.clear_registry_for_tests()


def test_full_keystore_packs_stream_yamls(tmp_path: Path) -> None:
    """A project with named streams packs each stream's yaml verbatim
    into body/streams/<name>/tn.yaml of the manifest body."""
    tn.init()
    payments = tn.use("payments")
    audits = tn.use("audits")

    payments_yaml_bytes = payments.yaml_path.read_bytes()
    audits_yaml_bytes = audits.yaml_path.read_bytes()

    out = tmp_path / "snapshot.tnpkg"
    cfg = tn.current_config()
    tn.export(
        out,
        kind="full_keystore",
        cfg=cfg,
        confirm_includes_secrets=True,
    )

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert "body/streams/payments/tn.yaml" in names, (
            f"stream payments yaml missing from manifest; saw {sorted(names)}"
        )
        assert "body/streams/audits/tn.yaml" in names, (
            f"stream audits yaml missing from manifest; saw {sorted(names)}"
        )
        with zf.open("body/streams/payments/tn.yaml") as fh:
            packed_payments = fh.read()
        with zf.open("body/streams/audits/tn.yaml") as fh:
            packed_audits = fh.read()

    assert packed_payments == payments_yaml_bytes, (
        "packed payments yaml differs from on-disk version"
    )
    assert packed_audits == audits_yaml_bytes, (
        "packed audits yaml differs from on-disk version"
    )
