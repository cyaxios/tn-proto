"""Tests for ceremony.mode / linked_vault / linked_project_id and
tn.admin.set_link_state."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml as yaml_mod

import tn
from tn import wallet as _wallet


def _fresh_local_ceremony():
    td = tempfile.TemporaryDirectory(prefix="link_")
    ws = Path(td.name)
    tn.init(ws / "tn.yaml", log_path=ws / ".tn/tn/logs/tn.ndjson", cipher="jwe")
    cfg = tn.current_config()
    return td, cfg


@pytest.fixture(autouse=True)
def _hermetic_vault_env(monkeypatch):
    """This module asserts against DEFAULT_VAULT_URL-minted ceremonies and
    same-vault link flips. An ambient TN_VAULT_URL (including the suite-wide
    localhost isolation default from conftest) would shadow the minted URL
    and turn the same-vault paths into re-link errors. Safe: set_link_state
    is yaml-only — nothing here touches the network. Tests that exercise the
    env override (test_fresh_ceremony_honors_tn_vault_url) set it back
    inside their own bodies, which run after this fixture."""
    monkeypatch.delenv("TN_VAULT_URL", raising=False)
    monkeypatch.delenv("TN_NO_LINK", raising=False)


# --- Defaults --------------------------------------------------------


def test_fresh_ceremony_is_linked_to_default_vault(monkeypatch):
    """Fresh ceremonies mint vault-linked by default. The yaml points at
    the canonical hosted vault; ``linked_project_id`` is empty until the
    operator calls ``tn.vault.link`` to claim one. Nothing reaches the
    network until an explicit vault verb runs.
    """
    from tn.vault_client import DEFAULT_VAULT_URL

    # Hermetic: create_fresh resolves the link URL via resolve_vault_url(),
    # so an ambient TN_VAULT_URL / TN_NO_LINK would otherwise shadow the
    # hardcoded default this test asserts.
    monkeypatch.delenv("TN_VAULT_URL", raising=False)
    monkeypatch.delenv("TN_NO_LINK", raising=False)

    td, cfg = _fresh_local_ceremony()
    try:
        assert cfg.mode == "linked"
        assert cfg.linked_vault == DEFAULT_VAULT_URL
        assert cfg.vault_enabled is True
        assert cfg.vault_url == DEFAULT_VAULT_URL
        assert cfg.vault_linked_project_id is None
        assert cfg.vault_autosync is True
        assert cfg.vault_sync_interval_seconds == 600
        # linked_project_id is unset until claim — yaml writes "" and
        # the loader coerces empty string to None.
        assert cfg.linked_project_id is None
        # is_linked() returns True as soon as mode=linked AND vault is
        # set — project_id is not part of the gate. The gate matters for
        # which operations the vault verbs permit, not for routing.
        assert cfg.is_linked() is True
        doc = yaml_mod.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
        assert doc["vault"]["enabled"] is True
        assert doc["vault"]["url"] == DEFAULT_VAULT_URL
        assert doc["vault"]["autosync"] is True
        assert doc["vault"]["sync_interval_seconds"] == 600
    finally:
        tn.flush_and_close()
        td.cleanup()


# --- Env-driven link defaults (regression: create_fresh ignored env) -


def test_fresh_ceremony_honors_tn_vault_url(monkeypatch):
    """A fresh (default-linked) ceremony stamps the vault URL resolved
    from ``TN_VAULT_URL`` — not the hardcoded prod default.

    Regression: ``config.create_fresh`` wrote ``DEFAULT_VAULT_URL``
    directly instead of going through ``resolve_vault_url()``, so a
    developer pointing ``TN_VAULT_URL`` at a local vault still got a
    ceremony born linked to prod.
    """
    monkeypatch.setenv("TN_VAULT_URL", "http://127.0.0.1:8790")
    monkeypatch.delenv("TN_NO_LINK", raising=False)

    td = tempfile.TemporaryDirectory(prefix="link_env_")
    ws = Path(td.name)
    try:
        tn.init(ws / "tn.yaml", log_path=ws / ".tn/tn/logs/tn.ndjson", cipher="jwe")
        cfg = tn.current_config()
        assert cfg.mode == "linked"
        assert cfg.linked_vault == "http://127.0.0.1:8790"
        assert cfg.vault_url == "http://127.0.0.1:8790"
        doc = yaml_mod.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
        assert doc["ceremony"]["linked_vault"] == "http://127.0.0.1:8790"
        assert doc["vault"]["url"] == "http://127.0.0.1:8790"
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_fresh_ceremony_honors_tn_no_link_env(monkeypatch):
    """``TN_NO_LINK=1`` mints an unlinked (offline) ceremony even when the
    caller does not pass ``link=False``.

    Regression: ``config.create_fresh`` keyed ``_is_unlinked`` off the
    ``link`` kwarg alone, so the documented env opt-out never reached the
    yaml stamping and the ceremony was born ``mode: linked``.
    """
    monkeypatch.setenv("TN_NO_LINK", "1")
    monkeypatch.delenv("TN_VAULT_URL", raising=False)

    td = tempfile.TemporaryDirectory(prefix="link_env_")
    ws = Path(td.name)
    try:
        tn.init(ws / "tn.yaml", log_path=ws / ".tn/tn/logs/tn.ndjson", cipher="jwe")
        cfg = tn.current_config()
        assert cfg.mode == "local"
        assert cfg.linked_vault is None
        assert cfg.vault_enabled is False
        doc = yaml_mod.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
        assert doc["ceremony"]["mode"] == "local"
        assert doc["vault"]["enabled"] is False
        assert doc["vault"]["url"] == ""
    finally:
        tn.flush_and_close()
        td.cleanup()


def test_link_ceremony_claims_project_when_born_linked(monkeypatch):
    """A ceremony born vault-linked (mode=linked, no project yet) still
    claims a project the first time ``wallet.link_ceremony`` runs.

    Regression #5: link_ceremony short-circuited on ``is_linked()`` alone,
    so a ceremony already pointing at the vault but with an empty
    ``linked_project_id`` returned early and never claimed a project —
    leaving the id empty forever (now reliably triggered because fresh
    ceremonies are born linked). A born-linked ceremony is not *fully*
    linked until it has a project id.
    """
    monkeypatch.setenv("TN_VAULT_URL", "http://127.0.0.1:8790")
    monkeypatch.delenv("TN_NO_LINK", raising=False)

    td = tempfile.TemporaryDirectory(prefix="link_claim_")
    ws = Path(td.name)
    try:
        tn.init(ws / "tn.yaml", log_path=ws / ".tn/tn/logs/tn.ndjson", cipher="jwe")
        cfg = tn.current_config()
        assert cfg.is_linked() is True
        assert cfg.linked_project_id is None  # born linked, unclaimed

        class _FakeVaultClient:
            base_url = "http://127.0.0.1:8790"

            def __init__(self):
                self.created = []

            def create_project(self, *, name, ceremony_id=None):
                self.created.append((name, ceremony_id))
                return {"id": "proj_born_linked", "name": name}

        client = _FakeVaultClient()
        _wallet.link_ceremony(cfg, client)
        assert client.created, "link_ceremony must claim a project, not no-op"
        assert cfg.linked_project_id == "proj_born_linked"

        # Persists across a fresh load.
        yaml_path = cfg.yaml_path
        tn.flush_and_close()
        tn.init(yaml_path, log_path=ws / ".tn/tn/logs/tn.ndjson", cipher="jwe")
        assert tn.current_config().linked_project_id == "proj_born_linked"
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
        assert cfg.vault_enabled is True
        assert cfg.vault_url == "https://vault.tn-proto.org"
        assert cfg.vault_linked_project_id == "proj_abc"
        assert cfg.vault_autosync is True
        assert cfg.vault_sync_interval_seconds == 600
        assert cfg.is_linked() is True

        # Persisted to yaml
        doc = yaml_mod.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
        assert doc["ceremony"]["mode"] == "linked"
        assert doc["ceremony"]["linked_vault"] == "https://vault.tn-proto.org"
        assert doc["ceremony"]["linked_project_id"] == "proj_abc"
        assert doc["vault"]["enabled"] is True
        assert doc["vault"]["url"] == "https://vault.tn-proto.org"
        assert doc["vault"]["linked_project_id"] == "proj_abc"
        assert doc["vault"]["autosync"] is True
        assert doc["vault"]["sync_interval_seconds"] == 600
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
        assert cfg.vault_enabled is False
        assert cfg.vault_url is None
        assert cfg.vault_linked_project_id is None
        assert cfg.vault_autosync is False
        doc = yaml_mod.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
        assert doc["ceremony"]["mode"] == "local"
        assert "linked_vault" not in doc["ceremony"]
        assert "linked_project_id" not in doc["ceremony"]
        assert doc["vault"]["enabled"] is False
        assert doc["vault"]["url"] == ""
        assert doc["vault"]["linked_project_id"] == ""
        assert doc["vault"]["autosync"] is False
        assert doc["vault"]["sync_interval_seconds"] == 600
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


def test_load_rejects_enabled_vault_without_url(tmp_path):
    # Hand-craft a broken yaml.
    yaml_path = tmp_path / "tn.yaml"
    # First create a good ceremony so key files exist, then corrupt the yaml.
    tn.init(yaml_path, log_path=tmp_path / ".tn/tn/logs/tn.ndjson", cipher="jwe")
    tn.flush_and_close()
    doc = yaml_mod.safe_load(yaml_path.read_text(encoding="utf-8"))
    # Fresh ceremonies now carry the vault URL in the project-level
    # ``vault:`` block, so a linked config without a usable URL is rejected
    # at the normalized vault layer.
    doc["ceremony"]["mode"] = "linked"
    doc["ceremony"].pop("linked_vault", None)
    doc["vault"].pop("url", None)
    yaml_path.write_text(yaml_mod.safe_dump(doc, sort_keys=False))

    with pytest.raises(ValueError, match="requires vault.url"):
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
