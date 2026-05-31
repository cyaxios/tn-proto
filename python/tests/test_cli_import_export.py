"""Prove the `tn export --kind project_seed` + `tn import` CLI verbs.

Drives the real console entry (`python -m tn ...`) across two temp
directories: mint a project_seed backup from one ceremony, restore it
into a fresh directory, and assert the restored device identity matches
the original (strict equality, not just "a DID was printed").
"""
from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from pathlib import Path

# The full subcommand CLI is the ``tn`` console script (tn.cli:main).
# ``python -m tn`` is only the read-shortcut (__main__.py), so drive the
# installed console script that sits next to the venv interpreter.
_SCRIPTS = Path(sys.executable).parent
_TN = str(_SCRIPTS / ("tn.exe" if sys.platform == "win32" else "tn"))


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_TN, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=180,
    )


def _did(text: str) -> str:
    m = re.search(r"did:key:z[1-9A-HJ-NP-Za-km-z]+", text)
    return m.group(0) if m else ""


def test_cli_export_project_seed_then_import(tmp_path: Path) -> None:
    a = tmp_path / "A"
    b = tmp_path / "B"
    a.mkdir()
    b.mkdir()
    seed = a / "backup.tnpkg"

    assert _run(a, "init", "CliProj", "--no-link").returncode == 0

    exp = _run(a, "export", "--kind", "project_seed", "--out", str(seed), "--include-secrets")
    assert exp.returncode == 0, exp.stderr
    assert seed.exists() and seed.stat().st_size > 0
    orig_did = _did(exp.stdout)
    assert orig_did, f"export did not print a device DID:\n{exp.stdout}"

    # The minted seed must be a self-addressed project_seed with canonical yaml.
    with zipfile.ZipFile(seed) as z:
        import json
        manifest = json.loads(z.read("manifest.json"))
        yaml_text = z.read("body/tn.yaml").decode("utf-8")
        priv = z.read("body/keys/local.private")
    assert manifest["kind"] == "project_seed"
    assert manifest["publisher_identity"] == manifest["recipient_identity"] == orig_did
    assert len(priv) == 32
    assert "device:" in yaml_text and "recipient_identity" in yaml_text
    assert "\nme:" not in yaml_text and "\nproject_id:" not in yaml_text and "\nlabel:" not in yaml_text

    imp = _run(b, "import", str(seed))
    assert imp.returncode == 0, imp.stderr
    assert "project_seed" in imp.stdout
    restored_did = _did(imp.stdout)
    assert restored_did == orig_did, f"restored {restored_did!r} != original {orig_did!r}"

    # The restored ceremony is live: `tn read` succeeds in the fresh dir
    # (the event log is device-local and NOT part of the keys+config
    # backup, so it starts empty — key usability is proven at the API
    # level in test_project_seed_roundtrip.py).
    rd = _run(b, "read")
    assert rd.returncode == 0, rd.stderr
