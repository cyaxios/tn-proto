"""Tests for ceremony.mode / linked_vault / linked_project_id and
tn.admin.set_link_state."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml as yaml_mod

import tn


def _fresh_local_ceremony():
    td = tempfile.TemporaryDirectory(prefix="link_")
    ws = Path(td.name)
    tn.init(ws / "tn.yaml", log_path=ws / ".tn/tn/logs/tn.ndjson", cipher="jwe")
    cfg = tn.current_config()
    return td, cfg


# --- Defaults --------------------------------------------------------


def test_fresh_ceremony_is_local():
    td, cfg = _fresh_local_ceremony()
    try:
        assert cfg.mode == "local"
        assert cfg.linked_vault is None
        assert cfg.linked_project_id is None
        assert cfg.is_linked() is False
    finally:
        tn.flush_and_close()
        td.cleanup()


# --- set_link_state — link / unlink round trip ----------------------


def test_set_link_state_flips_to_linked_and_persists():
    td, cfg = _fresh_local_ceremony()
    try:
        tn.set_link_state(
            cfg,
            mode="linked",
            linked_vault="https://vault.tn-proto.org",
            linked_project_id="proj_abc",
        )
        # In-memory cfg is mutated
        assert cfg.mode == "linked"
        assert cfg.linked_vault == "https://vault.tn-proto.org"
        assert cfg.linked_project_id == "proj_abc"
        assert cfg.is_linked() is True

        # Persisted to yaml
        doc = yaml_mod.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
        assert doc["ceremony"]["mode"] == "linked"
        assert doc["ceremony"]["linked_vault"] == "https://vault.tn-proto.org"
        assert doc["ceremony"]["linked_project_id"] == "proj_abc"
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_set_link_state_back_to_local_drops_fields():
    td, cfg = _fresh_local_ceremony()
    try:
        tn.set_link_state(
            cfg,
            mode="linked",
            linked_vault="https://vault.tn-proto.org",
            linked_project_id="proj_abc",
        )
        tn.set_link_state(cfg, mode="local")
        assert cfg.mode == "local"
        assert cfg.linked_vault is None
        assert cfg.linked_project_id is None
        doc = yaml_mod.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
        assert doc["ceremony"]["mode"] == "local"
        assert "linked_vault" not in doc["ceremony"]
        assert "linked_project_id" not in doc["ceremony"]
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_linked_persists_across_reload():
    td, cfg = _fresh_local_ceremony()
    try:
        yaml_path = cfg.yaml_path
        log_path = cfg.keystore.parent / ".tn/tn/logs" / "tn.ndjson"
        tn.set_link_state(
            cfg,
            mode="linked",
            linked_vault="https://vault.tn-proto.org",
            linked_project_id="proj_xyz",
        )
        tn.flush_and_close()

        tn.init(yaml_path, log_path=log_path, cipher="jwe")
        reloaded = tn.current_config()
        assert reloaded.mode == "linked"
        assert reloaded.linked_vault == "https://vault.tn-proto.org"
        assert reloaded.linked_project_id == "proj_xyz"
    finally:
        tn.flush_and_close()
        td.cleanup()


# --- Validation ------------------------------------------------------


def test_set_link_state_rejects_unknown_mode():
    td, cfg = _fresh_local_ceremony()
    try:
        with pytest.raises(ValueError):
            tn.set_link_state(cfg, mode="bogus")
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_set_link_state_linked_requires_vault_url():
    td, cfg = _fresh_local_ceremony()
    try:
        with pytest.raises(ValueError, match="linked_vault"):
            tn.set_link_state(cfg, mode="linked")
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_set_link_state_idempotent_same_vault():
    td, cfg = _fresh_local_ceremony()
    try:
        tn.set_link_state(
            cfg,
            mode="linked",
            linked_vault="https://vault.tn-proto.org",
            linked_project_id="p1",
        )
        tn.set_link_state(
            cfg,
            mode="linked",
            linked_vault="https://vault.tn-proto.org",
            linked_project_id="p1",
        )
        assert cfg.linked_project_id == "p1"
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_set_link_state_rejects_relink_to_different_vault():
    td, cfg = _fresh_local_ceremony()
    try:
        tn.set_link_state(
            cfg,
            mode="linked",
            linked_vault="https://vault.tn-proto.org",
            linked_project_id="p1",
        )
        with pytest.raises(RuntimeError, match="already linked"):
            tn.set_link_state(
                cfg,
                mode="linked",
                linked_vault="https://vault.other.com",
                linked_project_id="p2",
            )
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_load_rejects_linked_mode_without_vault(tmp_path):
    # Hand-craft a broken yaml.
    yaml_path = tmp_path / "tn.yaml"
    # First create a good ceremony so key files exist, then corrupt the yaml.
    tn.init(yaml_path, log_path=tmp_path / ".tn/tn/logs/tn.ndjson", cipher="jwe")
    tn.flush_and_close()
    doc = yaml_mod.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["ceremony"]["mode"] = "linked"  # but no linked_vault
    yaml_path.write_text(yaml_mod.safe_dump(doc, sort_keys=False))

    with pytest.raises(ValueError, match="requires ceremony.linked_vault"):
        tn.init(yaml_path, log_path=tmp_path / ".tn/tn/logs/tn.ndjson", cipher="jwe")
    tn.flush_and_close()


def test_load_rejects_unknown_mode(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, log_path=tmp_path / ".tn/tn/logs/tn.ndjson", cipher="jwe")
    tn.flush_and_close()
    doc = yaml_mod.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["ceremony"]["mode"] = "bogus"
    yaml_path.write_text(yaml_mod.safe_dump(doc, sort_keys=False))

    with pytest.raises(ValueError, match="unknown ceremony.mode"):
        tn.init(yaml_path, log_path=tmp_path / ".tn/tn/logs/tn.ndjson", cipher="jwe")
    tn.flush_and_close()
