"""Rust and Python applications exchange the very same signed TN wire."""

import json
from pathlib import Path
import subprocess
import sys

import tn

SDK = Path(__file__).resolve().parents[2]


def rust_example(*args):
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "-p", "tn-core", "--example", "governed_workflow", "--", *args],
        cwd=SDK, capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_python_verifies_rust_publications_without_reserializing():
    assert tn.GovernedObject is tn._native.governed.GovernedObject
    result = rust_example()
    assert result["total_minor_units"] == 3900
    for name in ("source", "output"):
        object = tn.GovernedObject.parse(result[f"{name}_wire"])
        assert object.id == result[f"{name}_id"]
        assert object.wire == result[f"{name}_wire"]


def test_rust_verifies_python_publications_without_reserializing(tmp_path):
    process = subprocess.run(
        [sys.executable, str(SDK / "python/examples/governed_workflow.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["total_minor_units"] == 3900
    source = tmp_path / "python-release.tn.json"
    source.write_text(result["output_wire"], encoding="utf-8", newline="")
    verified = rust_example("--verify", str(source))
    assert verified["id"] == result["output_id"]
    assert verified["wire"] == result["output_wire"]
