"""
SILO: C1 — Python module-level logging
TEST: tn.init() + tn.info() round-trip with the default handler stack
SEE: regression/crawl/c1_python_module_log/README.md

Flow:
  1. Fresh tmpdir, no prior keystore.
  2. tn.init(yaml_path) with default args (file rotating + stdout both
     active).
  3. tn.info("app.hello", a=1, b="two") to write one envelope.
  4. tn.read() to yield the envelope back.
  5. Inspect the on-disk log file directly to confirm bytes hit disk.

Asserts (named):
  - "yaml-file-on-disk": the ceremony yaml exists after init
  - "log-file-on-disk": the default log file exists after the first call
  - "log-event-on-disk": the attested log contains the app.hello envelope
  - "read-returns-entry": tn.read() surfaces the just-written entry
  - "fields-preserved": the entry's flat dict has a=1 and b="two"

Failure modes the test catches:
  - tn.init silently mints to the wrong path
  - file handler doesn't flush; envelope not on disk after info()
  - read() doesn't see entries written in the same process
  - Field types get mangled (int → string, etc.)
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.log_query import LogQuery


def test_init_emit_read_round_trip(fresh_ceremony: Path) -> None:
    yaml_path = fresh_ceremony

    tn.init(yaml_path)

    assert_named(
        name="yaml-file-on-disk",
        expected=True,
        observed=yaml_path.exists(),
        on_miss=(
            f"tn.init({yaml_path}) returned but the yaml file wasn't "
            f"created on disk. Check python/tn/_multi.py:_init_named_ceremony "
            f"write step + python/tn/config.py:create_fresh."
        ),
    )

    tn.info("app.hello", a=1, b="two")

    # Confirm bytes hit disk (handler-side flush) before asking tn.read.
    cfg = tn.current_config()
    log_path = Path(cfg.resolve_log_path())
    assert_named(
        name="log-file-on-disk",
        expected=True,
        observed=log_path.exists() and log_path.stat().st_size > 0,
        on_miss=(
            f"Expected default log file at {log_path} to have content "
            f"after tn.info(). Check python/tn/handlers/file.py flush "
            f"behavior and python/tn/_dispatch.py emit fan-out."
        ),
    )

    # Style-1: TN-native log query.
    log = LogQuery(ceremony_path=yaml_path)
    log.assert_contains(
        name="log-event-on-disk",
        where={"event_type": "app.hello"},
        on_miss=(
            "tn.info('app.hello', ...) didn't produce an envelope with "
            "event_type=app.hello. Check python/tn/emit.py:info and "
            "the cipher pipeline in python/tn/cipher.py."
        ),
    )

    # Round-trip via the public read verb.
    entries = list(tn.read())
    assert_named(
        name="read-returns-entry",
        expected="at least one entry with event_type=app.hello",
        observed=[e.event_type for e in entries],
        on_miss=(
            "tn.read() did not surface the just-written app.hello "
            "envelope. Check python/tn/_read_impl.py filter chain "
            "(run_id scope) and the read pipeline."
        ),
        predicate=lambda expected, observed: "app.hello" in observed,
    )

    ours = next((e for e in entries if e.event_type == "app.hello"), None)
    assert_named(
        name="entry-not-none",
        expected="Entry instance",
        observed=type(ours).__name__,
        on_miss="Entry lookup returned None despite event_type being in the list above.",
        predicate=lambda _e, o: o != "NoneType",
    )
    # Narrow for the type-checker — protected by the assert_named above:
    # if ours WERE None we'd have raised already.
    assert ours is not None

    # Field types preserved across the encrypt/decrypt round-trip.
    flat = ours.to_dict() if hasattr(ours, "to_dict") else dict(ours.fields)
    assert_named(
        name="fields-preserved-int",
        expected=1,
        observed=flat.get("a"),
        on_miss=(
            "Field 'a' came back wrong. Check canonical encoding round-trip "
            "in python/tn/canonical.py and the wire format."
        ),
    )
    assert_named(
        name="fields-preserved-str",
        expected="two",
        observed=flat.get("b"),
        on_miss="Field 'b' came back wrong. Same code paths as fields-preserved-int.",
    )
