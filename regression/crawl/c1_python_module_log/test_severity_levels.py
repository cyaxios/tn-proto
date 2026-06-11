"""
SILO: C1 — Python module-level logging
TEST: every public severity verb (info/warning/error/debug/log) writes an
      envelope with the right level field
SEE: regression/crawl/c1_python_module_log/README.md

Flow:
  1. Hermetic machine — TN user-home redirected to a tmpdir.
  2. tn.init() with no args (rung 1 — simplest path).
  3. Call tn.info / tn.warning / tn.error / tn.debug / tn.log with
     distinct event_types so each is independently locatable.
  4. Assert each shows up in the log with the matching level (info/
     warning/error/debug/"" for the severity-less log verb).

Asserts (named):
  - "level-<verb>-stamped": envelope present on disk for each verb
  - "level-<verb>-is-<level>": envelope's level field matches the verb

Failure modes the test catches:
  - One of the verbs is missing from the module surface.
  - A verb writes but stamps the wrong level.
  - The "log" verb (severity-less) puts something into the level
    field instead of empty string.
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def test_each_severity_verb_stamps_correct_level(hermetic_machine: Path) -> None:
    tn.init()

    # Set log level to debug so the debug call isn't filtered out.
    tn.set_level("debug")

    tn.info("c1.sev.info", marker="info-marker")
    tn.warning("c1.sev.warning", marker="warning-marker")
    tn.error("c1.sev.error", marker="error-marker")
    tn.debug("c1.sev.debug", marker="debug-marker")
    tn.log("c1.sev.log", marker="log-marker")

    cfg = tn.current_config()
    log = LogQuery(ceremony_path=cfg.yaml_path)

    # info
    env = log.assert_contains(
        name="level-info-stamped",
        where={"event_type": "c1.sev.info"},
        on_miss="tn.info(...) didn't produce its envelope. Check python/tn/emit.py:info.",
    )
    assert_named(
        name="level-info-is-info",
        expected="info",
        observed=env.get("level"),
        on_miss="tn.info wrote the envelope but the level field is wrong. Check python/tn/emit.py:info severity arg.",
    )

    # warning
    env = log.assert_contains(
        name="level-warning-stamped",
        where={"event_type": "c1.sev.warning"},
        on_miss="tn.warning(...) didn't produce its envelope. Check python/tn/emit.py:warning.",
    )
    assert_named(
        name="level-warning-is-warning",
        expected="warning",
        observed=env.get("level"),
        on_miss="tn.warning wrote the envelope but the level field is wrong.",
    )

    # error
    env = log.assert_contains(
        name="level-error-stamped",
        where={"event_type": "c1.sev.error"},
        on_miss="tn.error(...) didn't produce its envelope. Check python/tn/emit.py:error.",
    )
    assert_named(
        name="level-error-is-error",
        expected="error",
        observed=env.get("level"),
        on_miss="tn.error wrote the envelope but the level field is wrong.",
    )

    # debug
    env = log.assert_contains(
        name="level-debug-stamped",
        where={"event_type": "c1.sev.debug"},
        on_miss="tn.debug(...) didn't produce its envelope. Check python/tn/emit.py:debug and the level threshold.",
    )
    assert_named(
        name="level-debug-is-debug",
        expected="debug",
        observed=env.get("level"),
        on_miss="tn.debug wrote the envelope but the level field is wrong.",
    )

    # severity-less log — level should be empty string per the public verb's docstring
    env = log.assert_contains(
        name="level-log-stamped",
        where={"event_type": "c1.sev.log"},
        on_miss="tn.log(...) didn't produce its envelope. Check python/tn/emit.py:log.",
    )
    assert_named(
        name="level-log-is-empty",
        expected="",
        observed=env.get("level"),
        on_miss="tn.log is severity-less — its envelope's level field must be the empty string. Check python/tn/emit.py:log.",
    )

    assert_user_home_untouched()
