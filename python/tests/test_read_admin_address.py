"""``tn.read`` is symmetric with ``tn.watch`` re: admin log addressing.

Default ``tn.read()`` returns main-log entries only. Admin events
(``tn.*``) live in their own log since the runtime-correctness split
and must be addressed explicitly:

    tn.read(log="admin")                       # alias sugar
    tn.read(log=cfg.admin_log_location)        # explicit path
    tn.read(log="./.tn/admin/admin.ndjson")    # literal

The previous behaviour (read = main only, watch = main + admin
unconditionally) was an asymmetry that surprised operators reaching
for ``tn.read`` to forensically reconstruct what happened. The fix
is "admin is named, never merged."
"""
from __future__ import annotations

from pathlib import Path

import tn


def _emit_mixed_then_close(yaml_path: Path) -> None:
    """Emit one user event + one admin event into a fresh ceremony.

    Closed explicitly so the main + admin ndjson files are fully
    flushed by the time the caller reads them back.
    """
    tn.init(yaml_path)
    tn.info("user.thing", marker="alpha")
    tn.log("tn.test.admin_address", level="info", marker="beta")
    tn.flush_and_close()


def test_read_default_main_log_only(tmp_path):
    """Default ``tn.read(all_runs=True)`` returns user events only,
    no admin envelopes."""
    yaml_path = tmp_path / "tn.yaml"
    _emit_mixed_then_close(yaml_path)
    tn.init(yaml_path)

    event_types = {e.event_type for e in tn.read(all_runs=True)}
    assert "user.thing" in event_types, f"user event missing; saw {event_types}"
    assert "tn.test.admin_address" not in event_types, (
        f"admin event leaked into default tn.read(); saw {event_types}"
    )


def test_read_admin_alias_returns_admin_log(tmp_path):
    """``tn.read(log='admin', all_runs=True)`` yields the admin log
    and does NOT merge in user events from the main log."""
    yaml_path = tmp_path / "tn.yaml"
    _emit_mixed_then_close(yaml_path)
    tn.init(yaml_path)

    event_types = {e.event_type for e in tn.read(log="admin", all_runs=True)}
    assert "tn.test.admin_address" in event_types, (
        f"admin event missing via log='admin'; saw {event_types}"
    )
    assert "user.thing" not in event_types, (
        f"main-log event leaked into log='admin' read; saw {event_types}"
    )


def test_read_explicit_admin_path_returns_admin_log(tmp_path):
    """``tn.read(log=cfg.admin_log_location, all_runs=True)`` is the
    explicit form of the ``"admin"`` alias and must give the same
    answer.
    """
    yaml_path = tmp_path / "tn.yaml"
    _emit_mixed_then_close(yaml_path)
    tn.init(yaml_path)

    admin_path = tn.current_config().admin_log_location
    event_types = {
        e.event_type for e in tn.read(log=admin_path, all_runs=True)
    }
    assert "tn.test.admin_address" in event_types, (
        f"admin event missing via explicit path {admin_path!r}; saw {event_types}"
    )
    assert "user.thing" not in event_types, (
        f"main-log event leaked into explicit admin read; saw {event_types}"
    )
