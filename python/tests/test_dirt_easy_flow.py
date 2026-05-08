"""Dirt-easy lifecycle tests — the headline UX.

After ``tn.absorb`` of a self-contained bootstrap bundle (project_seed
or identity_seed) the runtime is auto-bound to the freshly-absorbed
``./tn.yaml``. The user can immediately call ``tn.info`` / ``tn.read``
without an explicit ``tn.init`` step.

Also exercises the discovery chain: ``tn.init()`` no-args picks up
``./tn.yaml`` (legacy), ``./.tn/default/tn.yaml`` (multi-ceremony), and
the top-level ``tn.absorb`` / ``tn.export`` aliases.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import tn
from tn import _autoinit


_HERE = Path(__file__).resolve().parent
FIXTURE_PROJECT_SEED = _HERE / "fixtures" / "Agentic20.project.tnpkg"


@pytest.fixture(autouse=True)
def _reset_runtime_state(monkeypatch):
    """Tear down any inherited runtime + autoinit state per test."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.delenv("TN_STRICT", raising=False)
    monkeypatch.delenv("TN_AUTOINIT_QUIET", raising=False)
    monkeypatch.delenv("TN_HOME", raising=False)
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()


@pytest.mark.skipif(
    not FIXTURE_PROJECT_SEED.exists(),
    reason=f"real dashboard fixture not present at {FIXTURE_PROJECT_SEED}",
)
def test_dirt_easy_project_bootstrap(tmp_path, monkeypatch):
    """The headline flow: download a project_seed tnpkg, absorb it,
    and immediately use the SDK without calling tn.init explicitly."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tnhome"))

    # 1. Absorb the project_seed bundle. Implicit init binds the runtime
    #    to the freshly-absorbed ./tn.yaml.
    receipt = tn.pkg.absorb(str(FIXTURE_PROJECT_SEED))
    assert receipt.kind == "project_seed"
    assert receipt.legacy_status == "enrolment_applied"
    assert tn._dispatch_rt is not None, (
        "implicit init on bootstrap absorb did not bind a runtime"
    )

    # 2. Emit — no init call required.
    tn.info("hello.world", who="alice")

    # 3. Read — same Tn, same process, no rebinding.
    entries = list(tn.read())
    types = [e.event_type for e in entries]
    assert "hello.world" in types, f"expected hello.world; saw {types}"


@pytest.mark.skipif(
    not FIXTURE_PROJECT_SEED.exists(),
    reason=f"real dashboard fixture not present at {FIXTURE_PROJECT_SEED}",
)
def test_dirt_easy_top_level_absorb_alias(tmp_path, monkeypatch):
    """``tn.absorb`` is the convenience alias for ``tn.pkg.absorb``."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tnhome"))

    receipt = tn.absorb(str(FIXTURE_PROJECT_SEED))
    assert receipt.kind == "project_seed"
    tn.info("first.event")
    assert sum(1 for _ in tn.read()) >= 1


def test_dirt_easy_identity_bootstrap(tmp_path, monkeypatch):
    """Identity_seed bootstrap path: hand-build a bundle, absorb it,
    use the SDK immediately."""
    from tn.export import export_identity_seed
    from tn.signing import DeviceKey

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tnhome"))

    # Build an identity_seed in a side directory (simulates the
    # dashboard / minter shipping a tnpkg).
    builder_dir = tmp_path / "_minter"
    builder_dir.mkdir()
    device = DeviceKey.generate()
    seed_path = export_identity_seed(
        builder_dir / "id.tnpkg",
        device=device,
    )
    assert seed_path.exists()

    # Now in the user's cwd: absorb-then-use, no init.
    receipt = tn.absorb(str(seed_path))
    assert receipt.kind == "identity_seed"
    assert receipt.legacy_status == "enrolment_applied"
    assert tn._dispatch_rt is not None

    tn.info("first.event")
    assert sum(1 for _ in tn.read()) >= 1


def test_init_discovery_finds_legacy_yaml(tmp_path, monkeypatch):
    """``tn.init()`` no-args picks up ``./tn.yaml`` when present, before
    falling through to ``.tn/default/``."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tnhome"))

    # Mint a legacy-layout ceremony at ./tn.yaml.
    tn.init(tmp_path / "tn.yaml")
    tn.flush_and_close()
    _autoinit.reset_state_for_tests()

    # No-args init should rediscover the legacy file (NOT mint a fresh
    # .tn/default/ ceremony).
    tn.init()
    cfg = tn.current_config()
    assert cfg.yaml_path.parent == tmp_path, (
        f"expected legacy ./tn.yaml; got {cfg.yaml_path}"
    )
    # And no .tn/default/ should have appeared as a side effect.
    assert not (tmp_path / ".tn" / "default" / "tn.yaml").exists()


def test_init_discovery_finds_multi_ceremony_yaml(tmp_path, monkeypatch):
    """``tn.init()`` no-args also discovers ``.tn/default/tn.yaml`` for
    projects on the multi-ceremony layout."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tnhome"))
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    # Mint via the multi-ceremony tn.init('default'). This writes
    # ./.tn/default/tn.yaml + keystore.
    tn.init("default")
    tn.flush_and_close()
    _autoinit.reset_state_for_tests()

    # No-args init should pick up ./.tn/default/tn.yaml (NOT fall through
    # to TN_HOME or mint another ceremony).
    tn.init()
    cfg = tn.current_config()
    assert cfg.yaml_path.parent == (tmp_path / ".tn" / "default").resolve(), (
        f"expected .tn/default/; got {cfg.yaml_path}"
    )


def test_export_alias(tmp_path, monkeypatch):
    """``tn.export`` is the convenience alias for ``tn.pkg.export``."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tnhome"))
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    tn.init(tmp_path / "tn.yaml")
    tn.info("x.y")
    out = tmp_path / "snap.tnpkg"
    # The export verb's signature is positional-friendly: out_path first.
    tn.export(out, kind="admin_log_snapshot")
    assert out.exists()
