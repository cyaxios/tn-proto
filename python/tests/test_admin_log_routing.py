"""Rust runtime routes admin (tn.*) events to admin_log_location,
user events to log_path. Defaults match Python's LoadedConfig.

See docs/superpowers/specs/2026-05-12-runtime-correctness-design.md
(Cluster A2).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import tn


@pytest.fixture(autouse=True)
def _isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from tn import _autoinit, _registry
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _autoinit.reset_state_for_tests()
    _registry.clear_registry_for_tests()
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.setenv("TN_HOME", str(tmp_path / ".tn"))
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.chdir(tmp_path)
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    _registry.clear_registry_for_tests()


def test_admin_emit_goes_to_admin_log_not_main(tmp_path: Path) -> None:
    """A `tn.*` event written via the rust runtime appears in the admin
    log file and NOT in the main user log."""
    tn.init()
    tn.log("user.hello", msg="hello-user")
    tn.log("tn.test.routing", msg="hello-admin")

    cfg = tn.current_config()
    main_log = cfg.resolve_log_path()
    from tn.admin.log import resolve_admin_log_path

    admin_log = resolve_admin_log_path(cfg)

    main_lines = (
        main_log.read_text().splitlines() if main_log.exists() else []
    )
    admin_lines = (
        admin_log.read_text().splitlines() if admin_log.exists() else []
    )

    main_types = {
        json.loads(line)["event_type"]
        for line in main_lines
        if line.strip()
    }
    admin_types = {
        json.loads(line)["event_type"]
        for line in admin_lines
        if line.strip()
    }

    assert "user.hello" in main_types, (
        f"user event missing from main log; saw {main_types}"
    )
    assert "user.hello" not in admin_types, (
        f"user event leaked into admin log; saw {admin_types}"
    )
    assert "tn.test.routing" in admin_types, (
        f"admin event missing from admin log; "
        f"main={main_types}, admin={admin_types}"
    )
    assert "tn.test.routing" not in main_types, (
        f"admin event leaked into main log; saw {main_types}"
    )
