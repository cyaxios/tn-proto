"""`tn init` non-TTY behavior — must run unattended in CI / containers
without prompting and without leaking the mnemonic to logs.

Pre-fix this verb refused to run when stdin/stdout weren't TTYs unless
``--mnemonic-file`` was supplied. That made the dirt-easy CI path
("here's a runner, give me a fresh ceremony") impossible. Now the
non-TTY path:

- Skips the "Press Enter after recording mnemonic" prompt
- Skips printing the mnemonic banner (which would land in CI logs)
- Persists the mnemonic into identity.json so the operator can
  recover it later via ``tn wallet export-mnemonic`` — identity.json
  becomes the secret-handling boundary
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_PYTHON_DIR = Path(__file__).resolve().parent.parent


def _run_init_non_tty(project_dir: Path, *extra_args: str) -> subprocess.CompletedProcess:
    """Run `python -m tn.cli init <project> --no-link` with stdin closed
    and isolated TN_HOME / XDG_DATA_HOME so the test doesn't touch the
    user's real identity store."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_PYTHON_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    home = project_dir.parent / ".tnhome"
    env["TN_HOME"] = str(home)
    env["XDG_DATA_HOME"] = str(home)
    env["TN_NO_STDOUT"] = "1"
    return subprocess.run(
        [
            sys.executable, "-m", "tn.cli", "init",
            str(project_dir), "--no-link", *extra_args,
        ],
        env=env,
        stdin=subprocess.DEVNULL,  # closes stdin → not a TTY
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_init_non_tty_succeeds(tmp_path: Path):
    """Without a TTY and without --mnemonic-file, init should still
    provision a fresh identity + ceremony."""
    project = tmp_path / "proj"
    res = _run_init_non_tty(project)
    assert res.returncode == 0, f"stdout={res.stdout!r} stderr={res.stderr!r}"
    assert (project / "tn.yaml").exists()


def test_init_non_tty_announces_mode(tmp_path: Path):
    """The non-interactive provisioning prints a clear status line so
    operators see what happened (mnemonic in identity.json, treat as
    secret)."""
    project = tmp_path / "proj"
    res = _run_init_non_tty(project)
    assert res.returncode == 0
    assert "non-interactive mode" in res.stdout
    assert "identity.json" in res.stdout


def test_init_non_tty_does_not_print_mnemonic(tmp_path: Path):
    """The 12-word mnemonic must NOT land in stdout — that's the whole
    point of the non-TTY path. We can't easily detect "is this a
    mnemonic?" generically, so we assert on the absent banner heading
    + that the persisted mnemonic words don't appear in stdout."""
    project = tmp_path / "proj"
    res = _run_init_non_tty(project)
    assert res.returncode == 0

    # Banner heading from _print_mnemonic_banner is suppressed.
    assert "WRITE THIS DOWN NOW" not in res.stdout

    # Stronger check: read the persisted mnemonic and confirm none of
    # its words show up in stdout. (12 BIP-39 words + one or two
    # English stop-words like "the" / "you" might collide; we filter
    # those before comparing.)
    identity_path = tmp_path / ".tnhome" / "tn" / "identity.json"
    identity = json.loads(identity_path.read_text())
    words = identity["mnemonic_stored"].split()
    # BIP-39 wordlists contain some short common English words; ignore
    # the truly common ones to avoid false positives from CLI prose.
    common = {"a", "an", "the", "you", "i", "is", "are", "as", "at", "be", "by",
              "do", "in", "of", "on", "or", "so", "to", "up", "us", "we", "if",
              "it", "no", "any", "all", "for", "into", "next"}
    leaked = [w for w in words if w.lower() not in common and w in res.stdout]
    assert not leaked, (
        f"non-TTY init leaked mnemonic word(s) {leaked!r} into stdout — "
        f"these would land in CI logs."
    )


def test_init_non_tty_persists_mnemonic_for_recovery(tmp_path: Path):
    """The mnemonic has to land in identity.json — otherwise it's
    unrecoverable and the operator just lost their identity."""
    project = tmp_path / "proj"
    res = _run_init_non_tty(project)
    assert res.returncode == 0

    identity_path = tmp_path / ".tnhome" / "tn" / "identity.json"
    assert identity_path.exists()
    identity = json.loads(identity_path.read_text())
    stored = identity.get("mnemonic_stored")
    assert isinstance(stored, str) and stored, "mnemonic_stored is empty"
    # 12 or 24 BIP-39 words (default is 12).
    assert len(stored.split()) in (12, 15, 18, 21, 24)


def test_init_non_tty_with_existing_identity_skips_provisioning(tmp_path: Path):
    """If an identity is already on disk, non-TTY init reuses it — no
    new mnemonic, no warnings, no banner."""
    # First init mints the identity.
    res1 = _run_init_non_tty(tmp_path / "proj1")
    assert res1.returncode == 0

    # Second init in a different project dir must reuse, not re-provision.
    res2 = _run_init_non_tty(tmp_path / "proj2")
    assert res2.returncode == 0
    assert "Reusing identity" in res2.stdout
    assert "non-interactive mode" not in res2.stdout
