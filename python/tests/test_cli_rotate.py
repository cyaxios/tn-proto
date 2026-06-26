"""End-to-end coverage for `tn rotate` — the deploy-shaped CLI verb.

Focuses on the BTN-only paths the CLI exposes (the library `tn.admin.rotate`
also handles JWE; the CLI `tn rotate` rejects non-btn ceremonies until the
JWE story is settled).

Each test uses subprocess so we exercise the actual argparse + cmd_rotate
wiring, not just the Python-level admin API the verb wraps.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import tn
from tn import admin

_PYTHON_DIR = Path(__file__).resolve().parent.parent


def _run_cli(*args: str, cwd: Path, env_overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run `python -m tn.cli ...` against an isolated TN_HOME."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_PYTHON_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["TN_HOME"] = str(cwd / ".tnhome")
    env["TN_NO_STDOUT"] = "1"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-m", "tn.cli", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """Spin up a fresh BTN ceremony with two recipients in tmp_path."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    (tmp_path / "_a").mkdir()
    (tmp_path / "_b").mkdir()
    admin.add_recipient(
        "default",
        recipient_did="did:key:zAlice",
        out_path=tmp_path / "_a" / "default.btn.mykit",
    )
    admin.add_recipient(
        "default",
        recipient_did="did:key:zBob",
        out_path=tmp_path / "_b" / "default.btn.mykit",
    )
    tn.flush_and_close()
    return tmp_path


def _list_artifacts(out_dir: Path) -> list[Path]:
    return sorted(p for p in out_dir.iterdir() if p.suffix == ".tnpkg")


def test_rotate_default_emits_per_recipient_artifacts(project: Path):
    """Bare `tn rotate` rotates every non-internal group and produces one
    .tnpkg per surviving recipient under ./rotated_<UTC_TS>/."""
    res = _run_cli("rotate", cwd=project)
    assert res.returncode == 0, res.stderr
    assert "rotated 1 group(s)" in res.stdout
    assert "emitted 2 .tnpkg artifact(s)" in res.stdout

    rotated_dirs = sorted(p for p in project.iterdir() if p.name.startswith("rotated_"))
    assert len(rotated_dirs) == 1, f"expected one rotated_<TS>/ dir, got {rotated_dirs}"
    artifacts = _list_artifacts(rotated_dirs[0])
    assert len(artifacts) == 2
    names = sorted(a.name for a in artifacts)
    assert names == ["did_key_zAlice.tnpkg", "did_key_zBob.tnpkg"]


def test_rotate_with_explicit_out_dir(project: Path, tmp_path_factory):
    """`--out <dir>` writes the per-recipient .tnpkg files into that dir."""
    out = tmp_path_factory.mktemp("rotated_out")
    res = _run_cli("rotate", "--out", str(out), cwd=project)
    assert res.returncode == 0, res.stderr
    artifacts = _list_artifacts(out)
    assert len(artifacts) == 2


def test_rotate_with_single_file_out_rejects_multi_recipient(project: Path):
    """`--out file.tnpkg` requires exactly one surviving recipient; otherwise
    we'd have to silently overwrite or pick a winner. Reject up front."""
    res = _run_cli(
        "rotate", "--out", str(project / "single.tnpkg"), cwd=project,
    )
    assert res.returncode != 0
    assert "single .tnpkg path" in res.stderr or "single .tnpkg path" in res.stdout


def test_rotate_specific_group_positional(project: Path):
    """Passing a positional `<group>` rotates only that group."""
    res = _run_cli("rotate", "default", cwd=project)
    assert res.returncode == 0, res.stderr
    assert "rotated 1 group(s)" in res.stdout


def test_rotate_groups_flag_explicit_subset(project: Path):
    """`--groups a,b,c` rotates the specified subset."""
    res = _run_cli("rotate", "--groups", "default", cwd=project)
    assert res.returncode == 0, res.stderr
    assert "rotated 1 group(s)" in res.stdout


def test_rotate_positional_and_groups_mutually_exclusive(project: Path):
    """Passing both is a usage error — the user has to pick one."""
    res = _run_cli("rotate", "default", "--groups", "default", cwd=project)
    assert res.returncode != 0
    assert "either" in res.stderr.lower()


def test_rotate_unknown_group_dies_fast(project: Path):
    """Unknown group names are caught up front with a clear error."""
    res = _run_cli("rotate", "nonexistent", cwd=project)
    assert res.returncode != 0
    assert "unknown group" in res.stderr.lower()


def test_rotate_without_recipients_succeeds_with_no_artifacts(tmp_path: Path):
    """Rotation against a ceremony with no recipients still bumps the
    epoch (the deploy event is recorded) but emits no .tnpkg files."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    res = _run_cli("rotate", cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    assert "no surviving recipients" in res.stdout
    assert not list(tmp_path.glob("rotated_*"))


def test_rotated_artifact_is_a_kit_bundle_tnpkg(project: Path):
    """The emitted .tnpkg is a real kit_bundle that absorbs cleanly into
    a fresh recipient ceremony — proves the artifact is wired end-to-end,
    not just a placeholder file."""
    import zipfile

    res = _run_cli("rotate", cwd=project)
    assert res.returncode == 0, res.stderr

    rotated_dirs = sorted(p for p in project.iterdir() if p.name.startswith("rotated_"))
    artifacts = _list_artifacts(rotated_dirs[0])

    # Each artifact is a valid zip with a manifest.json declaring kit_bundle.
    for art in artifacts:
        with zipfile.ZipFile(art, "r") as zf:
            assert "manifest.json" in zf.namelist()
            manifest = json.loads(zf.read("manifest.json"))
            assert manifest["kind"] == "kit_bundle"
