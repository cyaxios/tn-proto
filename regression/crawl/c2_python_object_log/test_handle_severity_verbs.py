"""
SILO: C2 — Python object-level logging
TEST: every severity verb on a TN handle stamps the correct level.
SEE: regression/crawl/c2_python_object_log/README.md

Parity with C1's severity-levels test, but exercised against the
object-level dispatch path (per-instance runtime). The two paths must
agree on level naming — a level field that drifts between module-level
and handle-level would silently corrupt anyone who mixes the two
surfaces.
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def test_handle_severity_verbs_stamp_correct_level(
    hermetic_machine: Path,
) -> None:
    t = tn.use("ops")
    tn.set_level("debug")  # process-global; debug verb wouldn't fire otherwise

    t.info("ops.sev.info", marker="info")
    t.warning("ops.sev.warning", marker="warning")
    t.error("ops.sev.error", marker="error")
    t.debug("ops.sev.debug", marker="debug")
    t.log("ops.sev.log", marker="log")

    log = LogQuery(ceremony_path=t.yaml_path)

    cases = [
        ("ops.sev.info", "info"),
        ("ops.sev.warning", "warning"),
        ("ops.sev.error", "error"),
        ("ops.sev.debug", "debug"),
        ("ops.sev.log", ""),  # severity-less log → empty string
    ]
    for event_type, expected_level in cases:
        env = log.assert_contains(
            name=f"handle-{event_type.split('.')[-1]}-stamped",
            where={"event_type": event_type},
            on_miss=(
                f"Handle's {event_type.split('.')[-1]}() didn't produce "
                f"its envelope. Check _handle.py:_emit and the level "
                f"mapping in _emit_via."
            ),
        )
        assert_named(
            name=f"handle-{event_type.split('.')[-1]}-is-{expected_level or 'empty'}",
            expected=expected_level,
            observed=env.get("level"),
            on_miss=(
                f"Handle's {event_type} envelope has level="
                f"{env.get('level')!r}, expected {expected_level!r}. "
                f"_handle.py:{event_type.split('.')[-1]} method passes "
                f"the wrong level string to _emit."
            ),
        )

    assert_user_home_untouched()
