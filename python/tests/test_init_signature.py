"""tn.init signature semantics: new aliases, conflict detection, stream sugar."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import tn


@pytest.fixture(autouse=True)
def _isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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


# ── alias resolution ────────────────────────────────────────────────


def test_ceremony_kwarg_is_alias_for_name() -> None:
    """tn.init(ceremony="foo") == tn.init(name="foo")."""
    h_via_ceremony = tn.init(ceremony="foo")
    assert h_via_ceremony.name == "foo"


def test_load_kwarg_is_alias_for_yaml_path(tmp_path: Path) -> None:
    """tn.init(load=path) == tn.init(yaml_path=path)."""
    yaml = tmp_path / "explicit.yaml"
    h = tn.init(load=yaml)
    assert h.yaml_path.resolve() == yaml.resolve()


def test_device_seed_kwarg_is_alias_for_device_private_bytes(tmp_path: Path) -> None:
    """tn.init(device_seed=bytes) installs the seed as the device key.

    The DID written into the yaml derives from this seed; same bytes →
    same DID across runs.
    """
    seed = bytes(range(32))  # deterministic 32-byte test seed
    h = tn.init(device_seed=seed)
    cfg = tn.current_config()
    assert cfg.device.private_bytes == seed


# ── conflict detection ──────────────────────────────────────────────


def test_name_and_ceremony_both_set_raises_type_error() -> None:
    with pytest.raises(TypeError, match="name.*ceremony.*aliases"):
        tn.init(name="foo", ceremony="bar")


def test_yaml_path_and_load_both_set_raises_type_error(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="yaml_path.*load.*aliases"):
        tn.init(yaml_path=tmp_path / "a.yaml", load=tmp_path / "b.yaml")


def test_device_private_bytes_and_device_seed_both_set_raises_type_error() -> None:
    with pytest.raises(TypeError, match="device_private_bytes.*device_seed.*aliases"):
        tn.init(device_private_bytes=bytes(32), device_seed=bytes(32))


def test_identity_and_device_private_bytes_both_set_raises_type_error() -> None:
    """Both seed the device key — pass exactly one (or neither)."""
    # A minimal duck-typed object is sufficient — the conflict check
    # only inspects the kwargs, not the values themselves.
    class FakeIdentity:
        def device_private_key_bytes(self) -> bytes:
            return bytes(32)

    with pytest.raises(TypeError, match="identity.*device_private_bytes"):
        tn.init(identity=FakeIdentity(), device_private_bytes=bytes(32))


# ── stream= post-init sugar ─────────────────────────────────────────


def test_stream_kwarg_returns_stream_handle() -> None:
    """tn.init(stream='payments') returns the stream's handle, not default's."""
    h = tn.init(stream="payments")
    assert h.name == "payments"


def test_stream_kwarg_composes_with_name() -> None:
    """tn.init(name='base', stream='payments') runs both; returns stream."""
    h = tn.init(name="base", stream="payments")
    assert h.name == "payments"


# ── project= placeholder ────────────────────────────────────────────


def test_project_kwarg_is_accepted_and_stored() -> None:
    """tn.init(project='foo') succeeds; tag stored on the package
    as informational metadata. Future PR wires this to vault behavior."""
    tn.init(project="my-app")
    assert getattr(tn, "_current_project", None) == "my-app"
