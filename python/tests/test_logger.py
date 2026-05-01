"""Unit tests for tn.logger — level wrappers, event_type validation, context, lifecycle.

Scope (Workstream B1):
  * Level wrappers propagate the intended severity into the envelope.
  * Bare `tn.log()` emits with empty level.
  * event_type validation rejects bad strings.
  * contextvars-backed context merges into every emitted envelope.
  * `flush_and_close` is idempotent and invalidates the runtime.
  * `tn.log` before `tn.init` raises a clear error.

Uses cipher=btn so tests stay hermetic (no JWE keypair wiring required).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Make sure every test starts with a fresh runtime state."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _read_user_envelopes(log_path: Path) -> list[dict]:
    """Parse the ndjson log and drop bootstrap `tn.*` protocol events."""
    out = []
    for raw in log_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        env = json.loads(raw)
        if not env.get("event_type", "").startswith("tn."):
            out.append(env)
    return out


# ---------------------------------------------------------------------------
# Level wrappers
# ---------------------------------------------------------------------------


def test_log_bare_emits_with_empty_level(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.log("evt.bare", n=1)
    tn.flush_and_close()

    entries = _read_user_envelopes(tmp_path / ".tn/tn/logs" / "tn.ndjson")
    assert len(entries) == 1
    assert entries[0]["level"] == ""
    assert entries[0]["event_type"] == "evt.bare"


@pytest.mark.parametrize(
    "wrapper_name,expected_level",
    [
        ("debug", "debug"),
        ("info", "info"),
        ("warning", "warning"),
        ("error", "error"),
    ],
)
def test_level_wrappers_propagate_to_envelope(tmp_path, wrapper_name, expected_level):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    getattr(tn, wrapper_name)(f"evt.{wrapper_name}", k=1)
    tn.flush_and_close()

    entries = _read_user_envelopes(tmp_path / ".tn/tn/logs" / "tn.ndjson")
    assert len(entries) == 1
    assert entries[0]["level"] == expected_level


# ---------------------------------------------------------------------------
# event_type validation
# ---------------------------------------------------------------------------


# NOTE: Python's tn.logger regex enforces `^[a-z0-9._-]{1,64}$`, but the
# production dispatch path routes through the Rust runtime which is more
# permissive about length. The cases below are rejected by both.
@pytest.mark.parametrize(
    "bad_event_type",
    [
        "",                       # empty
        "has space",             # whitespace
        "bad/slash",             # path separator
        "contains\nnewline",     # newline injection attempt
    ],
)
def test_rejects_invalid_event_type(tmp_path, bad_event_type):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    with pytest.raises((ValueError, RuntimeError), match=r"event_?type|invalid"):
        tn.info(bad_event_type, k=1)


def test_accepts_ordinary_event_type(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    event_type = "module.submodule.event-name_v2"
    tn.info(event_type, k=1)
    tn.flush_and_close()
    entries = _read_user_envelopes(tmp_path / ".tn/tn/logs" / "tn.ndjson")
    assert entries and entries[0]["event_type"] == event_type


# ---------------------------------------------------------------------------
# Context propagation
# ---------------------------------------------------------------------------


def test_context_merges_into_every_envelope(tmp_path):
    from tn.context import clear_context, set_context

    yaml = tmp_path / "tn.yaml"
    # Auto-create a ceremony yaml (fills in `me`, keystore paths, etc.),
    # then append request_id to public_fields so we can inspect it without
    # decryption.
    tn.init(yaml, cipher="btn")
    tn.flush_and_close()

    text = yaml.read_text(encoding="utf-8")
    text = text.replace(
        "public_fields:\n- timestamp",
        "public_fields:\n- request_id\n- timestamp",
    )
    yaml.write_text(text, encoding="utf-8")

    tn.init(yaml)
    try:
        set_context(request_id="req-123")
        tn.info("with.ctx", k=1)
        tn.info("with.ctx.again", k=2)
        clear_context()
        tn.info("no.ctx", k=3)
    finally:
        tn.flush_and_close()

    entries = _read_user_envelopes(tmp_path / ".tn/tn/logs" / "tn.ndjson")
    by_type = {e["event_type"]: e for e in entries}
    assert by_type["with.ctx"].get("request_id") == "req-123"
    assert by_type["with.ctx.again"].get("request_id") == "req-123"
    assert "request_id" not in by_type["no.ctx"]


# ---------------------------------------------------------------------------
# Lifecycle / init ordering
# ---------------------------------------------------------------------------


def test_log_before_init_raises_runtime_error():
    """Pre-auto-init behavior — keep coverage by opting into strict mode.

    Auto-init (added 2026-04-25) silently mints a ceremony when no
    ``tn.init`` has happened. Strict mode (``TN_STRICT=1`` or
    ``tn.set_strict(True)``) restores the original "must call init"
    contract so this regression test still has something to assert.
    """
    tn.set_strict(True)
    try:
        with pytest.raises(RuntimeError, match="tn.init"):
            tn.info("never.emitted", k=1)
    finally:
        tn.set_strict(False)


def test_flush_and_close_is_idempotent(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("evt.one", k=1)
    tn.flush_and_close()
    # Calling a second time must not raise even though the runtime is already gone.
    tn.flush_and_close()
    # And logging after close must surface the "init first" error rather than
    # silently writing to a stale runtime — under strict mode, since
    # auto-init would otherwise paper over this case.
    tn.set_strict(True)
    try:
        with pytest.raises(RuntimeError, match="tn.init"):
            tn.info("after.close", k=2)
    finally:
        tn.set_strict(False)


def test_reinit_flushes_old_runtime(tmp_path):
    """init() on an already-initialized process must close the prior runtime first."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("evt.first", k=1)
    # Re-init with the same yaml should succeed and pick up the prior chain.
    tn.init(yaml)
    tn.info("evt.second", k=2)
    tn.flush_and_close()

    entries = _read_user_envelopes(tmp_path / ".tn/tn/logs" / "tn.ndjson")
    event_types = [e["event_type"] for e in entries]
    assert "evt.first" in event_types
    assert "evt.second" in event_types


# ---------------------------------------------------------------------------
# Chain continuity across re-init (restart simulates crash/restart)
# ---------------------------------------------------------------------------


def test_chain_state_seeds_from_existing_log_across_reinit(tmp_path):
    """After re-init, new entries for the same event_type must keep the chain linked."""
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    tn.info("chained", k=1)
    tn.flush_and_close()

    tn.init(yaml)
    tn.info("chained", k=2)
    tn.flush_and_close()

    entries = [
        e
        for e in _read_user_envelopes(tmp_path / ".tn/tn/logs" / "tn.ndjson")
        if e["event_type"] == "chained"
    ]
    assert len(entries) == 2
    entries.sort(key=lambda e: e["sequence"])
    assert entries[0]["sequence"] == 1
    assert entries[1]["sequence"] == 2
    # The second entry's prev_hash must be the first entry's row_hash.
    assert entries[1]["prev_hash"] == entries[0]["row_hash"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
