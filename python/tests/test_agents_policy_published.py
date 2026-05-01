"""tn.agents.policy_published admin event lifecycle.

Spec: docs/superpowers/plans/2026-04-25-tn-read-ergonomics-and-agents-group.md
section 2.7.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn

_POLICY_V1 = """\
## payment.completed

### instruction
v1 instruction

### use_for
v1 use_for

### do_not_use_for
v1 do_not_use_for

### consequences
v1 consequences

### on_violation_or_error
POST https://example.com/v1
"""

_POLICY_V2 = """\
## payment.completed

### instruction
v2 INSTRUCTION CHANGED

### use_for
v1 use_for

### do_not_use_for
v1 do_not_use_for

### consequences
v1 consequences

### on_violation_or_error
POST https://example.com/v1
"""


@pytest.fixture(autouse=True)
def _clean_tn():
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _write_policy(yaml_dir: Path, text: str) -> None:
    p = yaml_dir / ".tn/config" / "agents.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _published_events() -> list[dict]:
    return [
        e for e in tn.read() if e.get("event_type") == "tn.agents.policy_published"
    ]


def test_init_with_no_policy_emits_no_event(tmp_path):
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    events = _published_events()
    assert events == []


def test_first_init_with_policy_emits_event(tmp_path):
    yaml = tmp_path / "tn.yaml"
    _write_policy(tmp_path, _POLICY_V1)
    tn.init(yaml, cipher="btn")
    events = _published_events()
    assert len(events) == 1
    assert events[0]["policy_uri"] == ".tn/config/agents.md"
    assert events[0]["content_hash"].startswith("sha256:")
    # Event types covered list is sorted.
    assert events[0]["event_types_covered"] == ["payment.completed"]


def test_second_init_unchanged_does_not_re_emit(tmp_path):
    yaml = tmp_path / "tn.yaml"
    _write_policy(tmp_path, _POLICY_V1)
    tn.init(yaml, cipher="btn")
    first = _published_events()
    assert len(first) == 1
    tn.flush_and_close()

    tn.init(yaml, cipher="btn")
    second = _published_events()
    assert len(second) == 1, (
        "policy unchanged → no second tn.agents.policy_published event"
    )


def test_init_with_changed_policy_emits_new_event(tmp_path):
    yaml = tmp_path / "tn.yaml"
    _write_policy(tmp_path, _POLICY_V1)
    tn.init(yaml, cipher="btn")
    first = _published_events()
    h1 = first[0]["content_hash"]
    tn.flush_and_close()

    # Edit the policy.
    _write_policy(tmp_path, _POLICY_V2)
    tn.init(yaml, cipher="btn")
    events = _published_events()
    assert len(events) == 2
    assert events[1]["content_hash"] != h1
