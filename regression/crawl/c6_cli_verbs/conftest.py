"""C6 silo conftest — hermetic fixture + a CLI runner helper.

`cli_run(*args, **kwargs)` is a thin wrapper around `subprocess.run`
that:

* invokes `python -m tn.cli ...` in the test's cwd
* propagates the hermetic env (TN_IDENTITY_DIR, TN_NO_LINK, TN_NO_STDOUT)
* captures stdout + stderr as text
* returns a `CliResult` dataclass — same shape across every CLI test
  so failures read uniformly.

Use it like:

    def test_init(hermetic_machine, cli_run):
        result = cli_run("init", "myproject")
        assert_named(name="init-exit-0", expected=0, observed=result.code, ...)
        assert_named(name="init-writes-yaml", expected=True,
                     observed=(hermetic_machine / "myproject" / "tn.yaml").exists(),
                     ...)
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from regression._shared.fixtures import (  # noqa: F401 — re-exported for pytest discovery
    assert_user_home_untouched,
    hermetic_machine,
    hermetic_machine_with_vault,
)


@dataclass
class CliResult:
    """One subprocess invocation of `python -m tn.cli ...`.

    Attributes:
      code: exit code (0 on success).
      stdout: captured stdout (text, decoded UTF-8 with errors='replace').
      stderr: captured stderr (text, same decoding).
      cmd: the argv that was invoked, for failure messages.
    """
    code: int
    stdout: str
    stderr: str
    cmd: tuple[str, ...]


@pytest.fixture
def cli_run(
    hermetic_machine: Path,
) -> Callable[..., CliResult]:
    """Yield a callable that runs `python -m tn.cli <args>` against the
    hermetic test environment.

    The runner inherits the test's TN_IDENTITY_DIR / TN_NO_LINK env
    set by `hermetic_machine`, so the CLI subprocess writes to the
    tmpdir, not to the real user home. Default cwd is the
    hermetic_machine cwd; pass cwd= to override.
    """
    def _run(*args: str, cwd: Path | None = None, extra_env: dict[str, str] | None = None) -> CliResult:
        cmd = (sys.executable, "-m", "tn.cli", *map(str, args))
        env = {**os.environ}
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            cmd,
            cwd=str(cwd or hermetic_machine),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return CliResult(
            code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            cmd=cmd,
        )

    return _run
