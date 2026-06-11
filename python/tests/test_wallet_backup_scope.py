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


def test_wallet_sync_uses_project_level_vault_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The project-level ``vault:`` block is authoritative for sync routing.

    Pins that ``sync_ceremony`` pushes to the vault URL + project id from the
    normalized ``vault_link_info`` view (NOT the legacy ``ceremony.linked_*``
    fields) through the AWK/BEK body-push engine.
    """
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "local.private").write_bytes(b"k")
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("vault:\n  enabled: true\n", encoding="utf-8")
    calls: list[dict[str, object]] = []

    def fake_push_ceremony_body(
        *, vault_url, bearer, project_id, passphrase=None, awk=None,
        body, credential_id=None, if_match=None,
    ):
        calls.append(
            {
                "vault_url": vault_url,
                "project_id": project_id,
                "body_keys": sorted(body),
            }
        )
        return {"project_id": project_id, "generation": 1}

    import tn.wallet_push

    monkeypatch.setattr(
        tn.wallet_push, "push_ceremony_body", fake_push_ceremony_body
    )

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
    client = SimpleNamespace(token="jwt", base_url="https://client.example")

    result = sync_ceremony(cfg, client, awk=b"\x00" * 32, publish_groups=False)

    assert result.project_id == "proj_vault"
    assert result.errors == []
    assert len(calls) == 1
    assert calls[0]["project_id"] == "proj_vault"
    assert calls[0]["vault_url"] == "https://vault.example"
    assert calls[0]["body_keys"] == ["body/keys/local.private", "body/tn.yaml"]
    assert result.uploaded == ["keys/local.private", "tn.yaml"]


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
