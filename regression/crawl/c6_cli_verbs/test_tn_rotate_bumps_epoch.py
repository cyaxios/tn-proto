"""
SILO: C6 — `tn` CLI verbs
TEST: `tn rotate <group>` produces a fresh epoch + emits
      `tn.rotation.completed` in the admin log.

Flow:
  1. Hermetic machine. `tn init`. `tn add_recipient` (so the group has
     a recipient to rotate against).
  2. Before-state: count `tn.rotation.completed` events for group=default
     (expected 0).
  3. `tn rotate default --yaml <proj>/tn.yaml`.
  4. After-state: count again.
  5. Assert exit 0; assert before==0 and after>=1; assert latest event
     has group="default" and a numeric `new_epoch`.

Asserts (named):
  - "tn-rotate-exit-0"
  - "tn-rotate-no-events-before"
  - "tn-rotate-emits-event-after"
  - "tn-rotate-event-group-default"
  - "tn-rotate-event-bumped-epoch"
  - "user-home-untouched"
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def _count_events(yaml_path: Path, where: dict) -> int:
    """Iterate the ceremony's logs and count matching envelopes."""
    log = LogQuery(ceremony_path=yaml_path)
    return sum(1 for _ in log.find_all(where=where))


def test_tn_rotate_bumps_epoch(
    hermetic_machine: Path,
    cli_run: Callable[..., object],
) -> None:
    project = hermetic_machine / "myproject"
    yaml_path = project / "tn.yaml"

    init_r = cli_run("init", str(project), "--skip-confirm", "--keep-mnemonic", "--no-link")  # type: ignore[arg-type]
    assert_named(
        name="tn-rotate-precondition-init",
        expected=0,
        observed=getattr(init_r, "code", -1),
        on_miss=f"`tn init` failed: stderr={getattr(init_r, 'stderr', '')[:400]!r}",
    )

    add_r = cli_run("add_recipient", "default", "alice_test_label", "--yaml", str(yaml_path))  # type: ignore[arg-type]
    assert_named(
        name="tn-rotate-precondition-add",
        expected=0,
        observed=getattr(add_r, "code", -1),
        on_miss=f"`tn add_recipient` failed: stderr={getattr(add_r, 'stderr', '')[:400]!r}",
    )

    # Before rotation: no rotation events exist yet.
    before = _count_events(yaml_path, where={"event_type": "tn.rotation.completed", "group": "default"})
    assert_named(
        name="tn-rotate-no-events-before",
        expected=0,
        observed=before,
        on_miss=(
            f"Expected zero tn.rotation.completed events for group=default "
            f"before any rotate. Got {before}. Either the ceremony was "
            f"pre-populated (fixture leak?) or admin events are being "
            f"counted across run-ids unintentionally."
        ),
    )

    rotate_r = cli_run("rotate", "default", "--yaml", str(yaml_path))  # type: ignore[arg-type]
    assert_named(
        name="tn-rotate-exit-0",
        expected=0,
        observed=getattr(rotate_r, "code", -1),
        on_miss=(
            f"`tn rotate default` exited {getattr(rotate_r, 'code', -1)}. "
            f"stderr={getattr(rotate_r, 'stderr', '')[:600]!r}"
        ),
    )

    after = _count_events(yaml_path, where={"event_type": "tn.rotation.completed", "group": "default"})
    assert_named(
        name="tn-rotate-emits-event-after",
        expected=True,
        observed=after >= 1,
        on_miss=(
            f"After `tn rotate default`, expected >=1 tn.rotation.completed "
            f"event for group=default; got {after}. Check "
            f"python/tn/admin/__init__.py:rotate emit path."
        ),
    )

    # Pull the actual event so we can introspect.
    log = LogQuery(ceremony_path=yaml_path)
    rot_event = log.assert_contains(
        name="tn-rotate-event-group-default",
        where={"event_type": "tn.rotation.completed", "group": "default"},
        on_miss="rotate event missing or has wrong group field.",
    )

    # The event should carry a new_epoch (or generation; the field name
    # is admin-internal). Either is acceptable as long as it's a number
    # greater than zero — that's the post-condition that distinguishes
    # "rotate happened" from "rotate was a no-op".
    new_epoch = rot_event.get("new_epoch") or rot_event.get("generation")
    assert_named(
        name="tn-rotate-event-bumped-epoch",
        expected=True,
        observed=isinstance(new_epoch, int) and new_epoch > 0,
        on_miss=(
            f"tn.rotation.completed envelope has new_epoch="
            f"{rot_event.get('new_epoch')!r}, generation="
            f"{rot_event.get('generation')!r}; expected one of them to be a "
            f"positive int. Check admin/__init__.py:rotate's emit shape."
        ),
    )

    assert_user_home_untouched()
