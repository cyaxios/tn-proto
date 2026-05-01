"""Shared pytest fixtures for the tn.mcp test suite."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def jwe_ceremony(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Copy the jwe_two_recipients fixture into a temp dir and chdir there.

    Yields the absolute path of the temp ceremony's tn.yaml. The cookbook
    reads ./tn.yaml from cwd, so chdir lets every test exercise the
    cookbook's discovery chain naturally.
    """
    src = FIXTURES_DIR / "jwe_two_recipients"
    if not src.exists():
        pytest.skip(
            f"Fixture not built. Run: python scripts/build_test_ceremony.py "
            f"(missing: {src})"
        )

    dst = tmp_path / "jwe_two_recipients"
    shutil.copytree(src, dst)
    monkeypatch.chdir(dst)
    monkeypatch.setenv("TN_FORCE_PYTHON", "1")
    monkeypatch.setenv("TN_NO_STDOUT", "1")

    # Force a fresh tn module state so a previous test's tn.init() doesn't
    # bleed into this one. The cookbook holds a process-global runtime.
    import tn
    try:
        tn.flush_and_close()
    except Exception:  # noqa: BLE001
        # First call may have nothing to flush; that's fine.
        pass

    return dst / "tn.yaml"


@pytest.fixture
def fresh_tn_module(monkeypatch: pytest.MonkeyPatch):
    """Yield the `tn` module with strict mode off and stdout silenced.

    Use when a test needs to exercise auto-init or first-emit behavior.
    """
    monkeypatch.setenv("TN_STRICT", "0")
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_FORCE_PYTHON", "1")
    import tn
    return tn
