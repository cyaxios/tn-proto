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

    # Export from the Project root config so the packer walks
    # .tn/<project>/streams/ and finds all stream overlays.
    tn.init()

    out = tmp_path / "snapshot.tnpkg"
    tn.export(
        out,
        kind="full_keystore",
        cfg=tn.current_config(),
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


def test_full_keystore_absorbs_stream_yamls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pack a project's full_keystore on node A, absorb its body into
    a fresh node B keystore; stream yamls land at node B with original
    ceremony.ids preserved verbatim."""
    import yaml as _yaml

    # --- Node A: mint, pack ---
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn"))

    tn.init()
    payments = tn.use("payments")
    audits = tn.use("audits")

    payments_id_a = _yaml.safe_load(payments.yaml_path.read_text())["ceremony"]["id"]
    audits_id_a = _yaml.safe_load(audits.yaml_path.read_text())["ceremony"]["id"]

    # Export from the Project root config so stream overlay discovery
    # starts from .tn/<project>/.
    tn.init()
    out = tmp_path / "snapshot.tnpkg"
    cfg_a = tn.current_config()
    tn.export(
        out,
        kind="full_keystore",
        cfg=cfg_a,
        confirm_includes_secrets=True,
    )
    sealed = out.read_bytes()

    # --- Call the absorber directly against a fresh project root ---
    # We pin the target keystore so absorb writes there, not back into
    # the source project. Streams should appear under the target
    # Project's streams/ directory.
    from tn.absorb import _absorb_dispatch
    from tn.config import LoadedConfig

    node_b_root = tmp_path / "node_b" / ".tn"
    node_b_default = node_b_root / "default"
    node_b_keystore = node_b_default / "keys"
    node_b_default.mkdir(parents=True, exist_ok=True)
    node_b_keystore.mkdir(parents=True, exist_ok=True)

    cfg_b = LoadedConfig(
        yaml_path=node_b_default / "tn.yaml",
        keystore=node_b_keystore,
        device=cfg_a.device,
        ceremony_id="default",
        master_index_key=b"",
        cipher_name="btn",
        public_fields=[],
        default_policy="private",
        groups={},
        field_to_groups={},
        handler_specs=None,
        admin_log_location="./admin/admin.ndjson",
        log_path="./logs/tn.ndjson",
    )

    receipt = _absorb_dispatch(cfg_b, sealed)
    assert receipt.legacy_status != "rejected", (
        f"absorb rejected: {receipt.legacy_reason}"
    )

    # --- Verify streams exist at node B with original ceremony.ids ---
    payments_yaml_b = node_b_root / "payments" / "tn.yaml"
    audits_yaml_b = node_b_root / "audits" / "tn.yaml"
    assert payments_yaml_b.is_file(), (
        f"payments yaml missing on node B at {payments_yaml_b}"
    )
    assert audits_yaml_b.is_file(), (
        f"audits yaml missing on node B at {audits_yaml_b}"
    )

    payments_id_b = _yaml.safe_load(payments_yaml_b.read_text())["ceremony"]["id"]
    audits_id_b = _yaml.safe_load(audits_yaml_b.read_text())["ceremony"]["id"]

    assert payments_id_b == payments_id_a, (
        f"payments ceremony.id drifted: {payments_id_a!r} -> {payments_id_b!r}"
    )
    assert audits_id_b == audits_id_a, (
        f"audits ceremony.id drifted: {audits_id_a!r} -> {audits_id_b!r}"
    )
