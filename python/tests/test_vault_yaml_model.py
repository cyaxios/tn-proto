from __future__ import annotations

from pathlib import Path

import yaml

from tn.config import load, load_or_create


def _doc(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _write_doc(path: Path, doc: dict) -> None:
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def test_no_vault_block_means_vault_off(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    load_or_create(yaml_path, link=False)
    doc = _doc(yaml_path)
    doc.pop("vault", None)
    doc["ceremony"].pop("linked_vault", None)
    doc["ceremony"].pop("linked_project_id", None)
    _write_doc(yaml_path, doc)

    cfg = load(yaml_path)

    assert cfg.vault_enabled is False
    assert cfg.vault_declared is False
    assert cfg.vault_url is None
    assert cfg.vault_autosync is False
    assert cfg.vault_sync_interval_seconds == 600
    assert cfg.linked_vault is None
    assert cfg.linked_project_id is None


def test_vault_block_normalizes_with_600_second_default(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    load_or_create(yaml_path, link=False)
    doc = _doc(yaml_path)
    doc["vault"] = {
        "enabled": True,
        "url": "https://vault.example",
        "linked_project_id": "",
        "autosync": True,
    }
    _write_doc(yaml_path, doc)

    cfg = load(yaml_path)

    assert cfg.vault_enabled is True
    assert cfg.vault_declared is True
    assert cfg.vault_url == "https://vault.example"
    assert cfg.vault_linked_project_id is None
    assert cfg.vault_autosync is True
    assert cfg.vault_sync_interval_seconds == 600
    assert cfg.linked_vault == "https://vault.example"
    assert cfg.linked_project_id is None


def test_legacy_ceremony_link_fields_still_populate_vault_view(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    load_or_create(yaml_path, link=True)
    doc = _doc(yaml_path)
    doc.pop("vault", None)
    doc["ceremony"]["linked_vault"] = "https://legacy-vault.example"
    doc["ceremony"]["linked_project_id"] = "proj_legacy"
    _write_doc(yaml_path, doc)

    cfg = load(yaml_path)

    assert cfg.linked_vault == "https://legacy-vault.example"
    assert cfg.linked_project_id == "proj_legacy"
    assert cfg.vault_enabled is True
    assert cfg.vault_declared is False
    assert cfg.vault_url == "https://legacy-vault.example"
    assert cfg.vault_linked_project_id == "proj_legacy"
    assert cfg.vault_autosync is True
    assert cfg.vault_sync_interval_seconds == 600


def test_disabled_vault_block_suppresses_legacy_link_fields(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    load_or_create(yaml_path, link=True)
    doc = _doc(yaml_path)
    doc["ceremony"]["mode"] = "local"
    doc["ceremony"]["linked_vault"] = "https://legacy-vault.example"
    doc["ceremony"]["linked_project_id"] = "proj_legacy"
    doc["vault"] = {
        "enabled": False,
        "url": "",
        "linked_project_id": "",
        "autosync": False,
        "sync_interval_seconds": 600,
    }
    _write_doc(yaml_path, doc)

    cfg = load(yaml_path)

    assert cfg.linked_vault is None
    assert cfg.linked_project_id is None
    assert cfg.vault_enabled is False
    assert cfg.vault_declared is True
    assert cfg.vault_url is None
    assert cfg.vault_linked_project_id is None
    assert cfg.vault_autosync is False
    assert cfg.vault_sync_interval_seconds == 600
