"""
SILO: C1 — Python module-level logging
TEST: tn.init(stdout=False) suppresses stdout but keeps the file handler
SEE: regression/crawl/c1_python_module_log/README.md

Flow:
  1. Hermetic machine — TN user-home redirected to a tmpdir.
  2. tn.init(stdout=False) — opt-in to the no-console path.
  3. tn.info() one envelope.
  4. Assert stdout captured nothing.
  5. Assert the file handler still produced the envelope on disk.

Why we care:
  - Servers and cron jobs don't want console noise. stdout=False is
    the documented opt-out (or TN_NO_STDOUT=1 env). If this regresses,
    every consumer who's silenced stdout will start seeing console
    output again on upgrade.

Asserts (named):
  - "stdout-empty": stdout captured during the emit is empty
  - "file-still-has-event": the log file contains the emitted envelope
"""
from __future__ import annotations

from pathlib import Path

import pytest
import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def test_stdout_false_suppresses_console(
    hermetic_machine: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tn.init(stdout=False)
    # Drain any banner output that might have come during init so the
    # post-emit capture is only what tn.info produced.
    capsys.readouterr()

    tn.info("c1.stdout.disabled", note="should-not-print")

    captured = capsys.readouterr()
    assert_named(
        name="stdout-empty",
        expected="",
        observed=captured.out,
        on_miss=(
            "tn.init(stdout=False) was passed but stdout still produced "
            "output. Check python/tn/logger.py:_resolve_stdout_handler and "
            "the handler-stack assembly in build_runtime."
        ),
    )

    # File side: the envelope should still be on disk.
    cfg = tn.current_config()
    log = LogQuery(ceremony_path=cfg.yaml_path)
    log.assert_contains(
        name="file-still-has-event",
        where={"event_type": "c1.stdout.disabled"},
        on_miss=(
            "stdout was correctly silenced, but the file handler ALSO "
            "stopped writing. stdout=False should only affect stdout. "
            "Check python/tn/logger.py:build_runtime handler list."
        ),
    )

    assert_user_home_untouched()
