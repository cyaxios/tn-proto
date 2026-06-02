from __future__ import annotations

import json
from pathlib import Path

import pytest

from tn._layout import (
    TNInvalidName,
    default_project_name,
    is_valid_ceremony_name,
    project_layout,
    stream_layout,
)


REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "layout" / "project_stream_paths.json"


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


@pytest.fixture(scope="module")
def layout_contract() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_project_stream_name_validation_matches_contract(layout_contract: dict) -> None:
    for name in layout_contract["valid_names"]:
        assert is_valid_ceremony_name(name), name
    for name in layout_contract["invalid_names"]:
        assert not is_valid_ceremony_name(name), name


@pytest.mark.parametrize("case_id", [
    "init_named_payroll_default_stream",
    "use_api_in_payroll",
    "cwd_name_as_project",
    "default_project_is_valid",
])
def test_project_stream_paths_match_contract(
    tmp_path: Path,
    layout_contract: dict,
    case_id: str,
) -> None:
    case = next(c for c in layout_contract["cases"] if c["id"] == case_id)
    workspace = tmp_path / case["workspace"]
    workspace.mkdir()

    project = case["project"]
    pl = project_layout(project, project_dir=workspace)
    sl = stream_layout(case["stream"], project=project, project_dir=workspace)

    expected_project = case.get("expected_project", project)
    assert pl.project == expected_project
    assert default_project_name(workspace) == workspace.name
    assert _rel(pl.project_dir, workspace) == case["project_dir"]
    assert _rel(pl.project_yaml, workspace) == case["project_yaml"]
    assert _rel(pl.keys_dir, workspace) == case["keys_dir"]
    assert _rel(pl.streams_dir, workspace) == case["streams_dir"]
    assert _rel(pl.logs_dir, workspace) == case["logs_dir"]
    assert _rel(pl.admin_dir, workspace) == case["admin_dir"]
    assert _rel(pl.vault_dir, workspace) == case["vault_dir"]

    assert sl.project == pl
    assert sl.stream == case["stream"]
    assert _rel(sl.stream_yaml, workspace) == case["stream_yaml"]
    assert _rel(sl.log_path, workspace) == case["log_path"]
    assert _rel(sl.admin_log_path, workspace) == case["admin_log_path"]
    assert sl.extends_relpath == case["stream_extends"]


@pytest.mark.parametrize("name", ["", "tn", ".hidden", "bad/name", "bad\\name", "bad name", "-bad"])
def test_project_stream_layout_rejects_invalid_names(
    tmp_path: Path,
    name: str,
) -> None:
    with pytest.raises(TNInvalidName):
        project_layout(name, project_dir=tmp_path)
    with pytest.raises(TNInvalidName):
        stream_layout(name, project="payroll", project_dir=tmp_path)
