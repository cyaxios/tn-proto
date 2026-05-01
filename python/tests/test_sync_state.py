"""Tests for tn.sync_state (§4.9 + §10 deferred workstream item 5).

Covers the persisted-state primitives and the run-kill-rerun
scenario: restart of a push handler picks up the persisted
last_pushed_admin_head and skips re-pushing the same snapshot.

Run:
    .venv/Scripts/python.exe -m pytest tn-protocol/python/tests/test_sync_state.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from tn.sync_state import (
    get_last_pushed_admin_head,
    load_sync_state,
    save_sync_state,
    set_last_pushed_admin_head,
    state_path,
    update_sync_state,
)


def _yaml_path(tmp_path: Path) -> Path:
    """Synthetic yaml path (file doesn't have to exist; only its parent
    matters for state_path resolution)."""
    return tmp_path / "tn.yaml"


def test_load_returns_empty_when_missing(tmp_path: Path):
    assert load_sync_state(_yaml_path(tmp_path)) == {}


def test_save_then_load_roundtrips(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    save_sync_state(yaml_path, {"a": 1, "b": "two", "c": ["x", "y"]})
    assert load_sync_state(yaml_path) == {"a": 1, "b": "two", "c": ["x", "y"]}


def test_save_creates_parent_directory(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    sp = state_path(yaml_path)
    assert not sp.parent.exists()
    save_sync_state(yaml_path, {"k": "v"})
    assert sp.parent.exists()
    assert sp.exists()


def test_update_merges_fields(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    save_sync_state(yaml_path, {"a": 1, "b": 2})
    new_state = update_sync_state(yaml_path, b=20, c=3)
    assert new_state == {"a": 1, "b": 20, "c": 3}
    assert load_sync_state(yaml_path) == {"a": 1, "b": 20, "c": 3}


def test_update_with_none_clears_field(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    save_sync_state(yaml_path, {"a": 1, "b": 2})
    update_sync_state(yaml_path, b=None)
    assert load_sync_state(yaml_path) == {"a": 1}


def test_corrupt_file_treated_as_empty(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    sp = state_path(yaml_path)
    sp.parent.mkdir(parents=True)
    sp.write_text("{ this is not valid json", encoding="utf-8")
    # Should not raise; returns empty dict.
    assert load_sync_state(yaml_path) == {}


def test_non_object_root_treated_as_empty(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    sp = state_path(yaml_path)
    sp.parent.mkdir(parents=True)
    sp.write_text('["not", "an", "object"]', encoding="utf-8")
    assert load_sync_state(yaml_path) == {}


def test_typed_helper_get_returns_none_when_unset(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    assert get_last_pushed_admin_head(yaml_path) is None


def test_typed_helper_set_then_get(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    set_last_pushed_admin_head(yaml_path, "sha256:abc123")
    assert get_last_pushed_admin_head(yaml_path) == "sha256:abc123"
    # File reflects it too
    state = load_sync_state(yaml_path)
    assert state["last_pushed_admin_head"] == "sha256:abc123"


def test_typed_helper_overwrites(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    set_last_pushed_admin_head(yaml_path, "sha256:first")
    set_last_pushed_admin_head(yaml_path, "sha256:second")
    assert get_last_pushed_admin_head(yaml_path) == "sha256:second"


def test_set_preserves_other_fields(tmp_path: Path):
    yaml_path = _yaml_path(tmp_path)
    save_sync_state(yaml_path, {"vault_endpoint": "https://example.com",
                                "inbox_cursor": "abc"})
    set_last_pushed_admin_head(yaml_path, "sha256:xyz")
    state = load_sync_state(yaml_path)
    assert state == {
        "vault_endpoint": "https://example.com",
        "inbox_cursor": "abc",
        "last_pushed_admin_head": "sha256:xyz",
    }


def test_get_with_non_string_value_returns_none(tmp_path: Path):
    """Defensive: if someone manually writes a non-string head, the
    typed getter returns None rather than handing back garbage."""
    yaml_path = _yaml_path(tmp_path)
    save_sync_state(yaml_path, {"last_pushed_admin_head": 42})
    assert get_last_pushed_admin_head(yaml_path) is None


def test_state_file_is_pretty_json(tmp_path: Path):
    """File is human-readable for debugging; not just a blob."""
    yaml_path = _yaml_path(tmp_path)
    save_sync_state(yaml_path, {"b": 2, "a": 1})
    text = state_path(yaml_path).read_text(encoding="utf-8")
    # Sorted keys + indent
    assert '"a": 1' in text
    assert '"b": 2' in text
    assert text.index('"a": 1') < text.index('"b": 2')  # sorted


# ---- run-kill-rerun integration scenario ----


def test_run_kill_rerun_via_typed_helpers(tmp_path: Path):
    """Mirrors the scenario in spec §4.9 verification:
    1. First run sets last_pushed_admin_head
    2. Process exits (instance state lost)
    3. Second run reads back the persisted value

    Uses the typed helpers directly (the handler-integration version
    of this test would require a live runtime, which is heavier)."""
    yaml_path = _yaml_path(tmp_path)

    # First "process": records a successful push
    set_last_pushed_admin_head(yaml_path, "sha256:run1-head")

    # Second "process": fresh start, must see the persisted value
    persisted = get_last_pushed_admin_head(yaml_path)
    assert persisted == "sha256:run1-head"

    # And further updates accumulate (third run)
    set_last_pushed_admin_head(yaml_path, "sha256:run2-head")
    assert get_last_pushed_admin_head(yaml_path) == "sha256:run2-head"


# ---- pull-side cursor migration into unified state.json (item 5 part 2) ----


def test_pull_cursor_lands_in_unified_state(tmp_path: Path):
    """Verify pull-side _save_cursor writes inbox_cursor to state.json."""
    # Synthetic ceremony directory + minimal cfg shim
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.touch()  # _save_cursor calls cfg.yaml_path.parent

    class _CfgShim:
        pass
    cfg = _CfgShim()
    cfg.yaml_path = yaml_path  # type: ignore[attr-defined]

    # Import here to avoid pulling in the runtime at module load
    from tn.handlers.vault_pull import VaultPullHandler

    h = VaultPullHandler(
        "pull",
        endpoint="https://example.com",
        project_id="proj",
        cfg_provider=lambda: cfg,
        client_factory=lambda *_: None,
        autostart=False,
    )

    # Direct save (bypasses tick logic)
    h._save_cursor(cfg, {"last_seen": "marker-abc"})

    # Verify the unified state.json picked it up
    from tn.sync_state import load_sync_state
    state = load_sync_state(yaml_path)
    assert state.get("inbox_cursor") == "marker-abc"

    # And legacy file still exists too (transitional)
    legacy = yaml_path.parent / ".tn" / "admin" / "vault_pull.cursor.json"
    assert legacy.exists()


def test_pull_cursor_load_prefers_unified_state(tmp_path: Path):
    """When state.json has inbox_cursor, _load_cursor returns it."""
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.touch()

    class _CfgShim:
        pass
    cfg = _CfgShim()
    cfg.yaml_path = yaml_path  # type: ignore[attr-defined]

    # Pre-populate unified state
    from tn.sync_state import update_sync_state
    update_sync_state(yaml_path, inbox_cursor="from-state-json")

    from tn.handlers.vault_pull import VaultPullHandler
    h = VaultPullHandler(
        "pull",
        endpoint="https://example.com",
        project_id="proj",
        cfg_provider=lambda: cfg,
        client_factory=lambda *_: None,
        autostart=False,
    )

    loaded = h._load_cursor(cfg)
    assert loaded == {"last_seen": "from-state-json"}


def test_pull_cursor_load_falls_back_to_legacy_when_unified_missing(tmp_path: Path):
    """When state.json has no inbox_cursor but legacy file exists,
    return the legacy value."""
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.touch()

    class _CfgShim:
        pass
    cfg = _CfgShim()
    cfg.yaml_path = yaml_path  # type: ignore[attr-defined]

    # Write only the legacy cursor file
    legacy = yaml_path.parent / ".tn" / "admin" / "vault_pull.cursor.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"last_seen": "legacy-value"}', encoding="utf-8")

    from tn.handlers.vault_pull import VaultPullHandler
    h = VaultPullHandler(
        "pull",
        endpoint="https://example.com",
        project_id="proj",
        cfg_provider=lambda: cfg,
        client_factory=lambda *_: None,
        autostart=False,
    )

    loaded = h._load_cursor(cfg)
    assert loaded == {"last_seen": "legacy-value"}
