"""
SILO: C1 — Python module-level logging
TEST: tn.init() with no args round-trips through tn.info/tn.read
SEE: regression/crawl/c1_python_module_log/README.md

Flow:
  1. Hermetic machine — user-home TN dir redirected to a tmpdir,
     TN_NO_LINK=1, cwd is a tmpdir.
  2. `tn.init()` with no args. Discovery mints at `./.tn/default/`.
  3. tn.info("app.hello", a=1, b="two").
  4. tn.read() yields the entry.
  5. Assert: real user-home is still untouched (proves the hermetic
     fixture worked).

Asserts (named):
  - "log-event-on-disk": attested log has the app.hello envelope
  - "read-returns-entry": tn.read() surfaces it
  - "fields-preserved-int" / "fields-preserved-str": types round-trip
  - "user-home-untouched": real ~/AppData/Roaming/tn/ is still gone
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery


def test_init_emit_read_round_trip(hermetic_machine: Path) -> None:
    # No yaml_path, no kwargs — the simplest possible path.
    tn.init()
    tn.info("app.hello", a=1, b="two")

    cfg = tn.current_config()
    yaml_path = cfg.yaml_path

    log = LogQuery(ceremony_path=yaml_path)
    log.assert_contains(
        name="log-event-on-disk",
        where={"event_type": "app.hello"},
        on_miss=(
            "tn.info('app.hello', ...) didn't produce an attested envelope. "
            "Check python/tn/emit.py:info and the cipher pipeline."
        ),
    )

    entries = list(tn.read())
    ours = next((e for e in entries if e.event_type == "app.hello"), None)
    assert_named(
        name="read-returns-entry",
        expected="found",
        observed="found" if ours is not None else "not-found",
        on_miss=(
            "tn.read() did not surface the just-written app.hello envelope. "
            "Check python/tn/_read_impl.py filter chain (run_id scope)."
        ),
    )
    assert ours is not None  # narrowed by the assert_named above

    flat = ours.to_dict() if hasattr(ours, "to_dict") else dict(ours.fields)
    assert_named(
        name="fields-preserved-int",
        expected=1,
        observed=flat.get("a"),
        on_miss="Field 'a' came back wrong; canonical-encode round-trip in tn.canonical.",
    )
    assert_named(
        name="fields-preserved-str",
        expected="two",
        observed=flat.get("b"),
        on_miss="Field 'b' came back wrong.",
    )

    # Proves the hermetic redirect held — the real user-home tn dir
    # was NOT touched by this test, even though tn.init() might
    # otherwise write to it in some code paths.
    assert_user_home_untouched()
