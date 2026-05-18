"""tn validate must detect yaml.me.did vs keystore.local.public mismatch.

Covers DX review #2: previously, ``tn validate`` only checked yaml
parse + profile catalog + presence of ``default``. It missed the most
basic ceremony invariant — that the DID written into the yaml matches
the did:key recorded in the keystore. The very next ``tn.init`` would
raise ``ValueError: keystore DID ... does not match yaml me.did``,
but the validator (whose job is to surface exactly these problems)
returned ``OK`` and exit 0.

Fix is in ``tn.cli.cmd_validate``: for each ceremony, compare
``yaml['me']['did']`` to the contents of the matching ``local.public``
(resolved via the yaml's ``keystore.path`` for streams, falling back
to ``<yaml_dir>/keys/local.public`` for default).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml as pyyaml


def _init_default(cwd: Path) -> None:
    """Run a fresh `tn.init()` in the given dir via subprocess so the
    test stays in process-isolation territory (the cli we then invoke
    expects the .tn/ tree to already exist)."""
    script = cwd / "_init.py"
    script.write_text(
        'import os; os.environ["TN_NO_STDOUT"]="1"\n'
        "import tn; tn.init(); tn.flush_and_close()\n"
    )
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(cwd),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, (
        f"init failed: stdout={rc.stdout!r} stderr={rc.stderr!r}"
    )


def _run_validate(cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "tn.cli", "validate"],
        cwd=str(cwd),
        capture_output=True,
        timeout=30,
    )


def test_validate_passes_on_clean_ceremony(tmp_path: Path):
    """Sanity: an untouched freshly-inited ceremony validates clean."""
    _init_default(tmp_path)
    rc = _run_validate(tmp_path)
    assert rc.returncode == 0
    assert b"OK:" in rc.stdout


def test_validate_catches_yaml_did_keystore_mismatch(tmp_path: Path):
    """Mutate yaml.me.did to a fake did:key and confirm validate fails."""
    _init_default(tmp_path)
    yaml_path = tmp_path / ".tn" / "default" / "tn.yaml"
    doc = pyyaml.safe_load(yaml_path.read_text())
    real_did = doc["me"]["did"]
    fake_did = "did:key:z6MkfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKE"
    assert real_did != fake_did
    doc["me"]["did"] = fake_did
    yaml_path.write_text(pyyaml.safe_dump(doc, sort_keys=False))

    rc = _run_validate(tmp_path)
    assert rc.returncode != 0, (
        "tn validate exited 0 on yaml.me.did != keystore.local.public; "
        "expected non-zero exit + diagnostic"
    )
    combined = (rc.stdout + rc.stderr).decode(errors="replace")
    assert "yaml me.did does not match keystore" in combined
    assert fake_did in combined
    # The real keystore did:key must also appear so operators can see
    # both sides of the divergence at a glance.
    pub_path = tmp_path / ".tn" / "default" / "keys" / "local.public"
    keystore_did = pub_path.read_text(encoding="ascii").strip()
    assert keystore_did in combined


def test_validate_catches_keystore_drift_after_swap(tmp_path: Path):
    """Replace keys/local.public with a different did:key; validator
    should still flag (symmetric to the yaml-side mutation test)."""
    _init_default(tmp_path)
    pub_path = tmp_path / ".tn" / "default" / "keys" / "local.public"
    pub_path.write_text(
        "did:key:z6MkfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKE",
        encoding="ascii",
    )
    rc = _run_validate(tmp_path)
    assert rc.returncode != 0
    assert b"yaml me.did does not match keystore" in rc.stdout + rc.stderr


def test_validate_clean_when_no_tn_directory(tmp_path: Path):
    """Without a .tn/ tree, validate prints the friendly message and
    exits 0 — unchanged from previous behaviour, but worth pinning."""
    rc = _run_validate(tmp_path)
    assert rc.returncode == 0
    assert b"nothing to validate" in rc.stdout
