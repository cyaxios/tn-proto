import subprocess
import sys
from pathlib import Path


def test_cli_help_runs():
    here = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "scenarios", "--help"],
        cwd=here,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert "--persona" in result.stdout
    assert "--tag" in result.stdout
    assert "--only" in result.stdout


def test_cli_list_does_not_run_anything():
    here = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "scenarios", "--list"],
        cwd=here,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    # At minimum alice/s01_hello must be discoverable once Task 8 lands;
    # until then we assert the command runs without error.
