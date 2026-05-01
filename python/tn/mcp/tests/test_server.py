"""Smoke tests for the MCP server entry point and basic dispatch."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def _find_console_script(name: str) -> str | None:
    """Resolve a console script path, even when the venv isn't on PATH.

    Pytest is typically invoked as ``.venv/Scripts/python.exe -m pytest`` —
    the launched subprocess inherits the parent's PATH, which often doesn't
    include the venv's Scripts/bin dir. So a bare ``shutil.which`` won't
    find ``tn-mcp-server.exe``. Fall back to looking next to the running
    interpreter (sys.executable's directory).
    """
    found = shutil.which(name)
    if found:
        return found
    interp_dir = Path(sys.executable).parent
    for candidate in (interp_dir / name, interp_dir / f"{name}.exe"):
        if candidate.exists():
            return str(candidate)
    return None


def test_module_invokable():
    """`python -m tn.mcp --help` exits 0 and prints something useful."""
    result = subprocess.run(
        [sys.executable, "-m", "tn.mcp", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "tn-mcp-server" in result.stdout.lower() or "mcp" in result.stdout.lower()


def test_console_script_version():
    """tn-mcp-server --version prints the package version."""
    from tn.mcp import __version__
    script = _find_console_script("tn-mcp-server")
    assert script is not None, (
        "tn-mcp-server console script not found. Did `pip install -e tn-protocol/python` "
        "run after pyproject.toml's [project.scripts] entry was added?"
    )
    result = subprocess.run(
        [script, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert __version__ in result.stdout


def test_jwe_fixture_available(jwe_ceremony):
    """The committed jwe fixture loads cleanly into a temp dir."""
    assert jwe_ceremony.name == "tn.yaml"
    assert jwe_ceremony.exists()
    # The cookbook nests the log dir as .tn/tn/logs/ (vs the .tn/logs/ the
    # plan originally guessed). The .ndjson file holds the seeded events.
    logs = jwe_ceremony.parent / ".tn" / "tn" / "logs"
    assert logs.exists(), f"expected log dir at {logs}"
    log_files = list(logs.glob("*.ndjson"))
    assert len(log_files) >= 1, f"expected at least one log file in {logs}"
