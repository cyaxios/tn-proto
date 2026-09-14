"""Release tooling preserves the independent Python and TypeScript versions."""

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.fixture
def release_tree(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    (tmp_path / "tools").mkdir()
    shutil.copy2(repo / "tools/bump.py", tmp_path / "tools/bump.py")
    (tmp_path / "ts-sdk/src").mkdir(parents=True)
    (tmp_path / "python").mkdir()
    (tmp_path / "VERSION").write_text("0.6.11\n", encoding="utf-8")
    (tmp_path / "ts-sdk/package.json").write_text(json.dumps({"version": "0.6.11"}, indent=2), encoding="utf-8")
    (tmp_path / "ts-sdk/src/version.ts").write_text(
        'export const SDK_VERSION = "0.6.11";\n', encoding="utf-8"
    )
    (tmp_path / "python/pyproject.toml").write_text(
        '[project]\nversion = "2026.9.13b5"\n', encoding="utf-8"
    )
    return tmp_path


def run_tool(root, argument):
    return subprocess.run(
        [sys.executable, str(root / "tools/bump.py"), argument],
        capture_output=True, text=True, check=False,
    )


def test_version_check_accepts_independent_python_version(release_tree):
    result = run_tool(release_tree, "--check")
    assert result.returncode == 0, result.stderr
    (release_tree / "ts-sdk/package.json").write_text(json.dumps({"version": "0.6.10"}, indent=2), encoding="utf-8")
    result = run_tool(release_tree, "--check")
    assert result.returncode == 1
    assert "package.json" in result.stderr


def test_typescript_bump_preserves_python_version(release_tree):
    python_project = release_tree / "python/pyproject.toml"
    before = python_project.read_bytes()
    result = run_tool(release_tree, "0.6.12")
    assert result.returncode == 0, result.stderr
    assert python_project.read_bytes() == before
    assert (release_tree / "VERSION").read_text().strip() == "0.6.12"
    assert json.loads((release_tree / "ts-sdk/package.json").read_text())["version"] == "0.6.12"
    assert run_tool(release_tree, "--check").returncode == 0
