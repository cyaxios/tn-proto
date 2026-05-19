"""Auto-init via tn.info() (no explicit tn.init() first) must produce
the same on-disk layout as explicit tn.init().

Regression test for the bug filed against 0.4.2a5:
    Auto-init was producing ``.tn/default/.tn/tn/{admin,keys,logs}/``
    (nested + missing the ``vault/`` subdir) while explicit init
    produced ``.tn/default/{admin,keys,logs,vault}/`` (flat).

Root cause: the auto-init helper dispatched through
``tn.init(<yaml_path>)`` (legacy single-yaml path), which routes
``config.create_fresh`` without a keystore_dir override and falls
back to the legacy ``<yaml_dir>/.tn/<stem>/...`` layout. Explicit
``tn.init()`` (no args) routes via the multi-ceremony path
(``_create_default_ceremony``) which passes the flat layout.

Fix: when auto-init creates a fresh ceremony at the canonical
``<cwd>/.tn/default/tn.yaml`` location, dispatch through the
no-arg ``tn.init()`` so both paths converge on the same layout.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path


def _layout_dirs(tn_root: Path) -> list[str]:
    """Return sorted list of relative directory paths under .tn/."""
    if not tn_root.is_dir():
        return []
    return sorted(
        str(p.relative_to(tn_root)).replace("\\", "/")
        for p in tn_root.rglob("*")
        if p.is_dir()
    )


def test_autoinit_layout_matches_explicit(tmp_path: Path):
    """tn.info() before tn.init() and tn.init() alone must produce
    identical .tn/ directory layouts."""
    autoinit_dir = tmp_path / "auto"
    explicit_dir = tmp_path / "explicit"
    autoinit_dir.mkdir()
    explicit_dir.mkdir()

    body_auto = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        os.environ["TN_AUTOINIT_QUIET"] = "1"
        import tn
        tn.info("hello", x=1)
        tn.flush_and_close()
    ''').strip()
    body_explicit = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        import tn
        tn.init()
        tn.flush_and_close()
    ''').strip()

    rc_auto = subprocess.run(
        [sys.executable, "-c", body_auto],
        cwd=str(autoinit_dir),
        capture_output=True,
        timeout=60,
    )
    assert rc_auto.returncode == 0, rc_auto.stderr
    rc_explicit = subprocess.run(
        [sys.executable, "-c", body_explicit],
        cwd=str(explicit_dir),
        capture_output=True,
        timeout=60,
    )
    assert rc_explicit.returncode == 0, rc_explicit.stderr

    auto_layout = _layout_dirs(autoinit_dir / ".tn")
    explicit_layout = _layout_dirs(explicit_dir / ".tn")
    assert auto_layout == explicit_layout, (
        f"autoinit layout diverged from explicit:\n"
        f"  auto:     {auto_layout!r}\n"
        f"  explicit: {explicit_layout!r}"
    )

    # Pin the specific shape the canonical layout produces so a
    # future refactor can't silently flip both paths together.
    assert auto_layout == [
        "default",
        "default/admin",
        "default/keys",
        "default/logs",
        "default/vault",
    ], f"expected canonical .tn/default/{{admin,keys,logs,vault}} layout; got {auto_layout!r}"


def test_autoinit_does_not_nest_under_yaml_stem(tmp_path: Path):
    """Explicit anti-regression: confirm the bad nested layout
    `.tn/default/.tn/tn/...` does NOT appear after autoinit."""
    body = textwrap.dedent('''
        import os
        os.environ["TN_NO_STDOUT"] = "1"
        os.environ["TN_AUTOINIT_QUIET"] = "1"
        import tn
        tn.info("hello", x=1)
        tn.flush_and_close()
    ''').strip()
    rc = subprocess.run(
        [sys.executable, "-c", body],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
    )
    assert rc.returncode == 0, rc.stderr

    nested = tmp_path / ".tn" / "default" / ".tn"
    assert not nested.exists(), (
        f"nested layout {nested} regressed; layout should be flat at "
        f".tn/default/{{admin,keys,logs,vault}}/"
    )
