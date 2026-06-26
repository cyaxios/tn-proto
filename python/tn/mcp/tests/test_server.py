"""Smoke tests for the MCP server entry point and the committed fixture."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


def _find_console_script(name: str) -> str | None:
    """Resolve a console script path, even when the venv isn't on PATH.

    Pytest is typically invoked as ``.venv/Scripts/python.exe -m pytest``;
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
    """`python -m tn.mcp --help` exits 0 and names the transports."""
    result = subprocess.run(
        [sys.executable, "-m", "tn.mcp", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "tn-mcp-server" in result.stdout
    assert "stdio" in result.stdout
    assert "streamable-http" in result.stdout


def test_console_script_version():
    """tn-mcp-server --version prints the package version."""
    from tn.mcp import __version__
    script = _find_console_script("tn-mcp-server")
    assert script is not None, (
        "tn-mcp-server console script not found. Did `pip install -e tn_proto/python` "
        "run after pyproject.toml's [project.scripts] entry was added?"
    )
    result = subprocess.run(
        [script, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert __version__ in result.stdout


def test_import_is_inert():
    """Importing tn.mcp (and the server module) must not start a transport,
    bind a TN runtime, or block. A child interpreter that imports both and
    exits proves it: a started stdio server would sit on stdin forever and
    trip the timeout."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import tn.mcp, tn.mcp.server; print('imported-ok')",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "imported-ok" in result.stdout


def test_jwe_fixture_available(jwe_ceremony):
    """The committed jwe fixture carries a live, readable seeded log.

    The fixture's handler is ``rotate_on_init: false`` by design: an older
    build carried ``true``, and every re-init against it rotated the seeded
    entries into tn.ndjson.1 where the cookbook (which reads ``logs.path``)
    never looks. The glob is deliberately strict so a regression back to a
    self-destructing fixture fails here, loudly.
    """
    assert jwe_ceremony.name == "tn.yaml"
    assert jwe_ceremony.exists()
    # The cookbook nests the log dir as .tn/tn/logs/ for a bare-yaml init.
    logs = jwe_ceremony.parent / ".tn" / "tn" / "logs"
    assert logs.exists(), f"expected log dir at {logs}"
    log_files = list(logs.glob("*.ndjson"))
    assert len(log_files) >= 1, f"expected at least one log file in {logs}"

    # The ACTIVE log (the exact path the cookbook reads) holds the seeded
    # envelopes, not a rotated sibling.
    active = logs / "tn.ndjson"
    assert active.exists(), (
        f"seeded log missing at {active}. If only tn.ndjson.1 exists, the "
        "fixture was built with rotate_on_init: true and self-destructed; "
        "rebuild it: python scripts/build_test_ceremony.py"
    )
    lines = [
        line
        for line in active.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) >= 5, f"expected the 5 seeded entries, found {len(lines)}"
    envelope = json.loads(lines[0])
    for key in ("event_type", "row_hash", "signature"):
        assert key in envelope, f"first envelope missing {key}"
