from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tn.wallet import _ceremony_files, sync_ceremony, vault_link_info


def test_wallet_sync_never_includes_application_logs(tmp_path: Path):
    keys = tmp_path / "keys"
    logs = tmp_path / "logs"
    keys.mkdir()
    logs.mkdir()
    (keys / "local.private").write_bytes(b"k")
    (keys / "local.public").write_text("did:key:zExample", encoding="utf-8")
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("ceremony:\n  sync_logs: true\n", encoding="utf-8")
    (logs / "tn.ndjson").write_text('{"event_type":"user.login"}\n', encoding="utf-8")
    (logs / "tn.ndjson.1").write_text('{"event_type":"user.logout"}\n', encoding="utf-8")

    cfg = SimpleNamespace(
        keystore=keys,
        yaml_path=yaml_path,
        sync_logs=True,
        resolve_log_path=lambda: logs / "tn.ndjson",
    )

    names = [name for name, _path in _ceremony_files(cfg)]

    assert names == ["local.private", "local.public", "tn.yaml"]
    assert not any(name.startswith("logs__") for name in names)


def test_wallet_sync_uses_project_level_vault_block(tmp_path: Path):
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "local.private").write_bytes(b"k")
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("vault:\n  enabled: true\n", encoding="utf-8")
    calls: list[tuple[str, str, bytes]] = []

    cfg = SimpleNamespace(
        ceremony_id="cer_test",
        keystore=keys,
        yaml_path=yaml_path,
        linked_vault=None,
        linked_project_id=None,
        vault_enabled=True,
        vault_url="https://vault.example",
        vault_linked_project_id="proj_vault",
    )
    client = SimpleNamespace(
        upload_file=lambda project_id, file_name, data, ceremony_id: calls.append(
            (project_id, file_name, data)
        )
    )

    result = sync_ceremony(cfg, client)

    assert result.project_id == "proj_vault"
    assert result.errors == []
    assert [name for _project_id, name, _data in calls] == ["local.private", "tn.yaml"]
    assert {project_id for project_id, _name, _data in calls} == {"proj_vault"}


def test_wallet_sync_rejects_disabled_vault_even_with_legacy_fields(tmp_path: Path):
    cfg = SimpleNamespace(
        ceremony_id="cer_test",
        linked_vault="https://legacy.example",
        linked_project_id="proj_legacy",
        vault_enabled=False,
        vault_declared=True,
    )

    assert vault_link_info(cfg).enabled is False
    with pytest.raises(RuntimeError, match="vault sync disabled"):
        sync_ceremony(cfg, SimpleNamespace())
