from __future__ import annotations

from pathlib import Path

import yaml

import tn
from tn import config as tn_config
from tn._multi import ensure_project_layout_on_disk, ensure_project_stream_on_disk


def test_ensure_project_layout_creates_root_yaml_and_default_overlay(tmp_path: Path) -> None:
    yaml_path = ensure_project_layout_on_disk("payroll", project_dir=tmp_path, link=False)

    assert yaml_path == tmp_path / ".tn" / "payroll" / "tn.yaml"
    assert yaml_path.is_file()
    assert (tmp_path / ".tn" / "payroll" / "keys" / "local.private").is_file()
    assert (tmp_path / ".tn" / "payroll" / "streams" / "default.yaml").is_file()
    assert (tmp_path / ".tn" / "payroll" / "logs").is_dir()
    assert (tmp_path / ".tn" / "payroll" / "admin").is_dir()
    assert (tmp_path / ".tn" / "payroll" / "vault").is_dir()

    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert doc["ceremony"]["project_name"] == "payroll"
    assert doc["logs"]["path"] == "./logs/default.ndjson"
    assert doc["ceremony"]["admin_log_location"] == "./admin/default.ndjson"
    assert doc["keystore"]["path"] == "./keys"

    cfg = tn_config.load(yaml_path)
    assert cfg.resolve_log_path() == tmp_path / ".tn" / "payroll" / "logs" / "default.ndjson"


def test_ensure_project_stream_creates_overlay_with_project_paths(tmp_path: Path) -> None:
    stream_yaml = ensure_project_stream_on_disk("api", project="payroll", project_dir=tmp_path)

    assert stream_yaml == tmp_path / ".tn" / "payroll" / "streams" / "api.yaml"
    assert stream_yaml.is_file()
    assert not (tmp_path / ".tn" / "payroll" / "streams" / "keys").exists()

    doc = yaml.safe_load(stream_yaml.read_text(encoding="utf-8"))
    assert doc["extends"] == "../tn.yaml"
    assert doc["logs"]["path"] == "../logs/api.ndjson"
    assert doc["ceremony"]["admin_log_location"] == "../admin/api.ndjson"
    assert doc["ceremony"]["id"].startswith("stream_api_")
    assert "groups" not in doc
    assert "keystore" not in doc

    cfg = tn_config.load(stream_yaml)
    assert cfg.resolve_log_path() == tmp_path / ".tn" / "payroll" / "logs" / "api.ndjson"
    assert cfg.keystore == tmp_path / ".tn" / "payroll" / "keys"


def test_public_init_project_keyword_uses_project_root_layout(tmp_path: Path) -> None:
    handle = tn.init(project="payroll", project_dir=tmp_path, link=False)
    again = tn.init(project="payroll", project_dir=tmp_path, link=False)

    assert handle.name == "payroll"
    assert again is handle
    assert handle.yaml_path == tmp_path / ".tn" / "payroll" / "tn.yaml"
    assert handle.directory == tmp_path / ".tn" / "payroll"
    assert tn.current_config().project_name == "payroll"
    assert tn.current_config().resolve_log_path() == (
        tmp_path / ".tn" / "payroll" / "logs" / "default.ndjson"
    )


def test_public_init_without_name_uses_workspace_project(tmp_path: Path) -> None:
    workspace = tmp_path / "acme-payroll"
    workspace.mkdir()

    handle = tn.init(project_dir=workspace, link=False)

    assert handle.name == "acme-payroll"
    assert handle.yaml_path == workspace / ".tn" / "acme-payroll" / "tn.yaml"
    assert handle.directory == workspace / ".tn" / "acme-payroll"
    assert tn.current_config().project_name == "acme-payroll"
    assert tn.current_config().resolve_log_path() == (
        workspace / ".tn" / "acme-payroll" / "logs" / "default.ndjson"
    )
    assert not (workspace / ".tn" / "default" / "tn.yaml").exists()


def test_public_use_project_keyword_caches_by_project_and_stream(tmp_path: Path) -> None:
    api_1 = tn.use("api", project="payroll", project_dir=tmp_path)
    api_2 = tn.use("api", project="payroll", project_dir=tmp_path)
    audit = tn.use("api", project="audit", project_dir=tmp_path)

    assert api_1 is api_2
    assert api_1 is not audit
    assert api_1.yaml_path == tmp_path / ".tn" / "payroll" / "streams" / "api.yaml"
    assert audit.yaml_path == tmp_path / ".tn" / "audit" / "streams" / "api.yaml"


def test_public_init_project_with_stream_returns_project_stream(tmp_path: Path) -> None:
    handle = tn.init(project="payroll", stream="api", project_dir=tmp_path, link=False)

    assert handle.name == "api"
    assert handle.yaml_path == tmp_path / ".tn" / "payroll" / "streams" / "api.yaml"
    assert (tmp_path / ".tn" / "payroll" / "tn.yaml").is_file()
    assert not (tmp_path / ".tn" / "api" / "tn.yaml").exists()


def test_public_use_after_init_project_uses_current_project(tmp_path: Path) -> None:
    tn.init(project="payroll", project_dir=tmp_path, link=False)

    handle = tn.use("api", project_dir=tmp_path)

    assert handle.name == "api"
    assert handle.yaml_path == tmp_path / ".tn" / "payroll" / "streams" / "api.yaml"
    assert not (tmp_path / ".tn" / "api" / "tn.yaml").exists()


def test_public_use_without_current_project_infers_workspace_project(tmp_path: Path) -> None:
    workspace = tmp_path / "acme-payroll"
    workspace.mkdir()

    handle = tn.use("api", project_dir=workspace)

    assert handle.name == "api"
    assert handle.yaml_path == workspace / ".tn" / "acme-payroll" / "streams" / "api.yaml"
    assert (workspace / ".tn" / "acme-payroll" / "tn.yaml").is_file()
    assert not (workspace / ".tn" / "api" / "tn.yaml").exists()
