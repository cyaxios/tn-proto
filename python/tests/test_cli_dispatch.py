"""Smoke tests proving the 6 newly-wired verbs DISPATCH via the real CLI.

These exercise the argparse dispatch tree through ``python -m tn.cli``
(the installed-console-script entry path) rather than calling the
``cmd_*`` handlers directly. The goal is narrow: confirm each verb is
registered (no argparse "invalid choice") and reaches its handler.

* ``seal`` / ``verify`` / ``canonical`` take pure stdin -> stdout, so we
  pipe a real (tiny) payload and assert the handler ran.
* ``info`` / ``compile`` / ``vault`` need on-disk ceremony / keystore
  state to do real work, so ``--help`` (exit 0, usage printed) is enough
  to prove the subparser exists and dispatches.

The subprocess form is deliberate: it catches packaging/import-time
breakage that an in-process ``build_parser()`` call would mask.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

# Run the CLI from the repo's ``python/`` dir so ``tn`` imports resolve
# without depending on an editable install.
_PY_ROOT = Path(__file__).resolve().parent.parent


def _run(argv: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Drive ``python -m tn.cli <argv...>`` as a real subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "tn.cli", *argv],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=str(_PY_ROOT),
    )


def _assert_dispatched(proc: subprocess.CompletedProcess[str], verb: str) -> None:
    """A dispatched verb never trips argparse's unknown-choice error."""
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert "invalid choice" not in combined, (
        f"verb {verb!r} did not dispatch (argparse invalid choice):\n{combined}"
    )


# ── --help reaches every subparser (proves registration) ─────────────


@pytest.mark.parametrize(
    "argv",
    [
        ["seal", "--help"],
        ["verify", "--help"],
        ["canonical", "--help"],
        ["info", "--help"],
        ["compile", "--help"],
        ["vault", "--help"],
        ["vault", "link", "--help"],
        ["vault", "unlink", "--help"],
    ],
)
def test_verb_help_dispatches(argv: list[str]) -> None:
    proc = _run(argv)
    _assert_dispatched(proc, argv[0])
    # argparse prints usage to stdout and exits 0 for an existing --help.
    assert proc.returncode == 0, proc.stderr
    assert "usage:" in proc.stdout.lower()


# ── seal: real stdin -> envelope ndjson ──────────────────────────────


def test_seal_real_invocation() -> None:
    seed_b64 = base64.b64encode(bytes(range(32))).decode("ascii")
    inp = {
        "seed_b64": seed_b64,
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": "sha256:" + "0" * 64,
        "timestamp": "2026-04-23T12:00:00.000000Z",
        "event_id": "00000000-0000-4000-8000-000000000000",
    }
    proc = _run(["seal"], stdin=json.dumps(inp) + "\n")
    _assert_dispatched(proc, "seal")
    assert proc.returncode == 0, proc.stderr
    env = json.loads(proc.stdout.strip())
    assert env["event_type"] == "order.created"
    assert env["row_hash"] and env["signature"]


# ── canonical: real stdin -> canonical bytes ─────────────────────────


def test_canonical_real_invocation() -> None:
    proc = _run(["canonical"], stdin=json.dumps({"b": 2, "a": 1}) + "\n")
    _assert_dispatched(proc, "canonical")
    assert proc.returncode == 0, proc.stderr
    # Canonical form sorts keys; the exact bytes are tested elsewhere —
    # here we just prove the handler produced output.
    assert proc.stdout.strip() != ""


# ── verify: feed seal's own output back in -> ok:true ────────────────


def test_verify_real_invocation_roundtrip() -> None:
    seed_b64 = base64.b64encode(bytes(range(32))).decode("ascii")
    inp = {
        "seed_b64": seed_b64,
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": "sha256:" + "0" * 64,
        "timestamp": "2026-04-23T12:00:00.000000Z",
        "event_id": "00000000-0000-4000-8000-000000000000",
    }
    sealed = _run(["seal"], stdin=json.dumps(inp) + "\n")
    assert sealed.returncode == 0, sealed.stderr

    proc = _run(["verify"], stdin=sealed.stdout)
    _assert_dispatched(proc, "verify")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["ok"] is True, result
    assert result["event_type"] == "order.created"
