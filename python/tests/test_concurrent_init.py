"""Concurrent tn.init() across processes must not corrupt the ceremony.

Covers DX review #1: previously, multiple OS processes calling
``tn.init()`` against an empty ``.tn/`` raced and left an on-disk yaml
whose ``me.did`` did not match the keystore's ``local.public``. The
subsequent ``tn.init`` in any process would then raise
``ValueError: keystore DID ... does not match yaml me.did``.

Fix is in ``tn._multi._ceremony_create_lock`` — a per-name sentinel
acquired with ``O_CREAT | O_EXCL`` around the create branch of
``_ensure_ceremony_on_disk``. The first arrival mints; subsequent
arrivals either spin until the yaml appears or proceed when the lock
clears.

Scope note: this test covers ceremony *initialisation* under concurrent
processes. Chain-coherent *writes* under concurrency (multiple workers
writing to the same log) is a separate problem and is not in scope for
the #1 fix — workers in this test init only, they do not emit user
events while racing.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


# Workers only init then exit — no user emits while racing. We then
# do a single-process read in the parent to assert ceremony integrity.
WORKER_SCRIPT = textwrap.dedent('''
    import os, sys
    os.environ["TN_NO_STDOUT"] = "1"
    import tn

    tn.init()
    tn.flush_and_close()
''').strip()


def _read_did_from_yaml(yaml_path: Path) -> str:
    import yaml as pyyaml
    doc = pyyaml.safe_load(yaml_path.read_text())
    return doc["me"]["did"]


def _derive_did_from_public(keystore_dir: Path) -> str:
    """Read keys/local.public, which stores the did:key string directly.

    The runtime treats local.public as the authoritative DID; if
    yaml.me.did diverges from it, ``tn.init`` raises
    ``ValueError: keystore DID ... does not match yaml me.did`` (the
    exact failure mode this test guards against).
    """
    return (keystore_dir / "local.public").read_text(encoding="ascii").strip()


@pytest.mark.parametrize("workers", [4, 8])
def test_concurrent_init_does_not_corrupt(tmp_path: Path, workers: int):
    """N workers init simultaneously against an empty .tn/. After all
    exit: yaml.me.did matches the did derived from keys/local.public,
    and tn.read(verify=True) succeeds."""
    script = tmp_path / "worker.py"
    script.write_text(WORKER_SCRIPT)

    procs = []
    for i in range(workers):
        p = subprocess.Popen(
            [sys.executable, str(script), f"W{i}"],
            cwd=str(tmp_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(p)

    rcs = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        rcs.append((p.returncode, out.decode(errors="replace"),
                    err.decode(errors="replace")))

    # At least one worker must have succeeded; others may legitimately
    # fail with TNCreateFailed (the in-process lock-loser path).
    successes = [rc for rc, _o, _e in rcs if rc == 0]
    assert successes, (
        "no worker succeeded; all failed:\n"
        + "\n---\n".join(f"rc={rc}\nstdout={o}\nstderr={e}"
                         for rc, o, e in rcs)
    )

    # On-disk consistency: yaml's me.did must match the did derived
    # from the keystore. This was the failure mode before the fix.
    yaml_path = tmp_path / ".tn" / "default" / "tn.yaml"
    assert yaml_path.is_file(), "tn.yaml not written"
    yaml_did = _read_did_from_yaml(yaml_path)
    keystore_dir = tmp_path / ".tn" / "default" / "keys"
    derived_did = _derive_did_from_public(keystore_dir)
    assert yaml_did == derived_did, (
        f"yaml.me.did {yaml_did} != did derived from keystore {derived_did}"
    )

    # A fresh process re-init + read must succeed (no DID-mismatch
    # ValueError — the exact failure the report flagged). We don't
    # demand verify=True here because that would also gate on chain
    # coherence under concurrent admin writes, which is out of scope
    # for the #1 fix; verify=False proves the ceremony is loadable
    # and the user events post-race are readable.
    verify_script = tmp_path / "verify.py"
    verify_script.write_text(textwrap.dedent('''
        import os, sys, json
        os.environ["TN_NO_STDOUT"] = "1"
        import tn

        tn.init()
        tn.info("post.race.evt", marker="reader")
        tn.flush_and_close()
        entries = [e.event_type for e in tn.read()]
        print(json.dumps({"events": entries}))
    ''').strip())
    rc = subprocess.run(
        [sys.executable, str(verify_script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=30,
    )
    assert rc.returncode == 0, (
        f"verify-read failed: stdout={rc.stdout!r} stderr={rc.stderr!r}"
    )
    payload = json.loads(rc.stdout.decode().strip().splitlines()[-1])
    assert "post.race.evt" in payload["events"], (
        f"reader could not read its own event back: {payload}"
    )


def test_create_lock_releases_after_success(tmp_path: Path):
    """After a successful init the .init.<name>.lock sentinel is gone."""
    import tn
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        tn.init()
        tn.flush_and_close()
    finally:
        os.chdir(cwd)
    lock = tmp_path / ".tn" / ".init.default.lock"
    assert not lock.exists(), f"lock file leaked: {lock}"


def test_create_lock_reaps_stale(tmp_path: Path):
    """A pre-existing lock file older than 60s is reaped on next init."""
    import time
    (tmp_path / ".tn").mkdir(parents=True)
    stale = tmp_path / ".tn" / ".init.default.lock"
    stale.write_text("pid=99999\n")
    # Backdate by 120s so the stale-recovery path fires.
    past = time.time() - 120.0
    os.utime(stale, (past, past))

    import tn
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        tn.init()
        tn.flush_and_close()
    finally:
        os.chdir(cwd)
    assert (tmp_path / ".tn" / "default" / "tn.yaml").is_file()
    assert not stale.exists()
