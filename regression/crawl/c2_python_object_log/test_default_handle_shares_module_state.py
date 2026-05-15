"""
SILO: C2 — Python object-level logging
TEST: tn.info(...) and tn.use("default").info(...) write to the SAME stream.
SEE: regression/crawl/c2_python_object_log/README.md

The default ceremony's runtime is intentionally wired to the module-level
singleton — so callers can mix the two APIs without surprise. If this
contract drifts (default handle gets its own per-instance runtime), then
`tn.read()` would see only the module-level writes and a developer
testing with `tn.use("default")` would think nothing got written.

Flow:
  1. tn.init()  — binds the default singleton.
  2. tn.info("module.event") via the bare API.
  3. d = tn.use("default") — same ceremony, returned as a handle.
  4. d.info("handle.event")
  5. Both events must appear in BOTH:
     - tn.read() (module-level reader)
     - d.read()  (handle-level reader)

Asserts (named):
  - "default-handle-name-is-default"
  - "default-handle-is-default-flag"
  - "default-handle-yaml-matches-singleton-yaml"
  - "module-read-sees-module-event"
  - "module-read-sees-handle-event"
  - "handle-read-sees-module-event"
  - "handle-read-sees-handle-event"
  - "user-home-untouched"

Failure modes the test catches:
  - default handle drifted to per-instance runtime (handle.read won't
    see module writes or vice versa).
  - the singleton bridge in _multi.py:_bind_default_singleton broke.
  - tn.use("default") returns a fresh ceremony in a different yaml dir.
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


def test_default_handle_and_module_singleton_share_state(
    hermetic_machine: Path,
) -> None:
    # Step 1: bind the default singleton via the bare API.
    tn.init()
    cfg = tn.current_config()
    module_yaml = cfg.yaml_path

    # Step 2: bare-API write.
    tn.info("module.event", marker="from-module-level")

    # Step 3: get the handle for the same ceremony.
    d = tn.use("default")

    assert_named(
        name="default-handle-name-is-default",
        expected="default",
        observed=d.name,
        on_miss=f"tn.use('default') returned handle.name={d.name!r}.",
    )
    assert_named(
        name="default-handle-is-default-flag",
        expected=True,
        observed=d.is_default,
        on_miss=(
            "tn.use('default').is_default is False — the handle isn't "
            "recognizing itself as the default ceremony. Check "
            "_handle.py:is_default and DEFAULT_CEREMONY_NAME constant."
        ),
    )
    assert_named(
        name="default-handle-yaml-matches-singleton-yaml",
        expected=str(module_yaml),
        observed=str(d.yaml_path),
        on_miss=(
            f"Default handle's yaml_path ({d.yaml_path!r}) differs from "
            f"the singleton's ({module_yaml!r}). tn.use('default') is "
            f"minting a fresh ceremony in a different dir instead of "
            f"binding to the already-init'd one. Check "
            f"python/tn/_multi.py:use's registry-hit path for the "
            f"'default' name."
        ),
    )

    # Step 4: handle-API write.
    d.info("handle.event", marker="from-handle")

    # Step 5: both readers must see both events.
    module_events = sorted(e.event_type for e in tn.read())
    handle_events = sorted(e.event_type for e in d.read())

    assert_named(
        name="module-read-sees-module-event",
        expected=True,
        observed="module.event" in module_events,
        on_miss=f"tn.read() missing 'module.event'. Got {module_events!r}.",
    )
    assert_named(
        name="module-read-sees-handle-event",
        expected=True,
        observed="handle.event" in module_events,
        on_miss=(
            f"tn.read() missing 'handle.event'. Got {module_events!r}. "
            f"tn.use('default').info() wrote somewhere tn.read() can't see. "
            f"The default-singleton bridge is broken."
        ),
    )
    assert_named(
        name="handle-read-sees-module-event",
        expected=True,
        observed="module.event" in handle_events,
        on_miss=(
            f"tn.use('default').read() missing 'module.event'. Got "
            f"{handle_events!r}. The default handle is reading from a "
            f"different log file than tn.info wrote to."
        ),
    )
    assert_named(
        name="handle-read-sees-handle-event",
        expected=True,
        observed="handle.event" in handle_events,
        on_miss=(
            f"tn.use('default').read() missing its own 'handle.event'. "
            f"Got {handle_events!r}."
        ),
    )

    assert_user_home_untouched()
