"""DX review #21, #22, #23 — CLI + stdout polish (0.4.2a4).

- #21: ``tn show`` with no subverb defaults to ``tn show env``.
- #22: ``tn show profiles`` prints the 5-profile catalog (human + json).
- #23: stdout handler filters ``tn.*`` admin events by default;
       ``TN_STDOUT_INCLUDE_ADMIN=1`` (or ``include_admin=True`` on
       the handler) restores the previous noisy behaviour.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path


# --------------------------------------------------------------------
# #21 — tn show no-args
# --------------------------------------------------------------------


def test_tn_show_no_args_defaults_to_env():
    """``tn show`` with no subverb prints the env-var surface and
    exits 0. Previously argparse rejected the call with
    ``arguments required: show_verb`` and exit code 2."""
    rc = subprocess.run(
        [sys.executable, "-m", "tn.cli", "show"],
        capture_output=True,
        timeout=30,
    )
    assert rc.returncode == 0, (
        f"`tn show` exited non-zero: stdout={rc.stdout!r} stderr={rc.stderr!r}"
    )
    out = rc.stdout.decode(errors="replace")
    # The env-format output starts with a comment header mentioning
    # the canonical env-var surface.
    assert "TN_" in out, (
        f"expected env-var table in output; got first 200 chars: {out[:200]!r}"
    )


# --------------------------------------------------------------------
# #22 — tn show profiles
# --------------------------------------------------------------------


def test_tn_show_profiles_lists_all_five():
    """``tn show profiles`` prints a table with every catalog entry."""
    rc = subprocess.run(
        [sys.executable, "-m", "tn.cli", "show", "profiles"],
        capture_output=True,
        timeout=30,
    )
    assert rc.returncode == 0, rc.stderr
    out = rc.stdout.decode(errors="replace")
    for name in ("transaction", "audit", "secure_log", "telemetry", "stdout"):
        assert name in out, f"missing profile {name!r} in output: {out!r}"
    # Default-profile marker.
    assert "transaction*" in out or "* = catalog default" in out


def test_tn_show_profiles_json_format():
    """``--format json`` emits a parseable JSON payload with the
    catalog fields wired for tooling."""
    rc = subprocess.run(
        [sys.executable, "-m", "tn.cli", "show", "profiles", "--format", "json"],
        capture_output=True,
        timeout=30,
    )
    assert rc.returncode == 0, rc.stderr
    payload = json.loads(rc.stdout.decode())
    assert "profiles" in payload
    names = [p["name"] for p in payload["profiles"]]
    assert set(names) == {
        "transaction", "audit", "secure_log", "telemetry", "stdout",
    }
    for p in payload["profiles"]:
        for key in ("encrypts", "signs", "chains", "flush", "default_sink", "intended_use"):
            assert key in p, f"profile {p['name']!r} missing key {key!r}"


# --------------------------------------------------------------------
# #23 — stdout handler filters tn.* admin events by default
# --------------------------------------------------------------------


def _emit_one(tmp_path: Path, env_extra: dict | None = None) -> str:
    """Run a tn.init + tn.info subprocess and return captured stdout."""
    script = tmp_path / "emit.py"
    script.write_text(textwrap.dedent("""
        import tn
        tn.init()
        tn.info("order.created", x=1)
    """).strip())
    env = os.environ.copy()
    env.pop("TN_NO_STDOUT", None)
    env.pop("TN_STDOUT_INCLUDE_ADMIN", None)
    if env_extra:
        env.update(env_extra)
    rc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=30,
        env=env,
    )
    assert rc.returncode == 0, rc.stderr
    return rc.stdout.decode()


def test_stdout_filters_admin_events_by_default(tmp_path: Path):
    """A fresh init + one user emit prints exactly one stdout line —
    the user's event. Three admin events (ceremony.init + 2x group.added)
    are suppressed."""
    out = _emit_one(tmp_path)
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"expected exactly 1 stdout line; got {len(lines)}:\n{out}"
    )
    assert "order.created" in lines[0]
    assert "tn.ceremony.init" not in out
    assert "tn.group.added" not in out


def test_stdout_include_admin_env_restores_noise(tmp_path: Path):
    """``TN_STDOUT_INCLUDE_ADMIN=1`` brings the admin events back —
    operators who want the protocol bookkeeping on stdout opt in."""
    out = _emit_one(
        tmp_path, env_extra={"TN_STDOUT_INCLUDE_ADMIN": "1"}
    )
    assert "tn.ceremony.init" in out
    assert "tn.group.added" in out
    assert "order.created" in out


def test_stdout_handler_include_admin_kwarg_directly():
    """Per-handler ``include_admin=True`` flips ``accepts()`` /
    routing for admin events without needing the env var. Tests the
    handler directly to avoid the Python/Rust stdout dedup logic
    that would otherwise hide a custom handler when a default one
    is in play."""
    import io
    from tn.handlers.stdout import StdoutHandler

    # Default (include_admin=None): admin events suppressed unless
    # TN_STDOUT_INCLUDE_ADMIN=1.
    saved = os.environ.pop("TN_STDOUT_INCLUDE_ADMIN", None)
    try:
        buf_default = io.BytesIO()
        h_default = StdoutHandler(stream=buf_default)
        admin_env = {
            "event_type": "tn.ceremony.init",
            "level": "info",
            "sequence": 1,
            "timestamp": "2026-05-19T00:00:00.000Z",
        }
        h_default.emit(admin_env, b'{"event_type":"tn.ceremony.init"}\n')
        assert buf_default.getvalue() == b"", (
            f"default handler should suppress tn.* admin events; got "
            f"{buf_default.getvalue()!r}"
        )

        # include_admin=True forces the admin event through.
        buf_loud = io.BytesIO()
        h_loud = StdoutHandler(stream=buf_loud, include_admin=True)
        h_loud.emit(admin_env, b'{"event_type":"tn.ceremony.init"}\n')
        assert buf_loud.getvalue() != b"", (
            "include_admin=True should let tn.* admin events through"
        )
        assert b"tn.ceremony.init" in buf_loud.getvalue()
    finally:
        if saved is not None:
            os.environ["TN_STDOUT_INCLUDE_ADMIN"] = saved
