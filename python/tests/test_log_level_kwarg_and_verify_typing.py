"""DX review #13 (tn.log level= kwarg) and #17 (verify typing) tests.

- #13: ``tn.log`` accepts an optional ``level=`` kwarg. The verb is
  not an alias of the named-level verbs; it always emits regardless
  of the active threshold and lets the caller stamp any level
  string on ``Entry.level``.
- #17: ``tn.read(verify=...)`` type annotation narrowed from
  ``bool | str`` to ``bool | Literal["skip", "raise"]`` so IDEs
  autocomplete the legal string values. Runtime accepts the same
  four values as before (``False``, ``True``, ``"skip"``, ``"raise"``).
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest


# --------------------------------------------------------------------
# #13 — tn.log level= kwarg
# --------------------------------------------------------------------


@pytest.fixture()
def fresh_ceremony(tmp_path: Path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    os.environ["TN_NO_STDOUT"] = "1"
    import tn

    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.init()
    try:
        yield tn
    finally:
        tn.flush_and_close()
        os.chdir(cwd)


def test_tn_log_default_level_is_empty_string(fresh_ceremony):
    """Backwards compat: bare ``tn.log("evt")`` keeps level=""."""
    tn = fresh_ceremony
    tn.log("scan.start", phase="discovery")
    tn.flush_and_close()
    tn.init()
    for e in tn.read():
        if e.event_type == "scan.start":
            assert e.level == ""
            assert e.fields == {"phase": "discovery"}
            return
    pytest.fail("scan.start event not found")


def test_tn_log_with_level_kwarg(fresh_ceremony):
    """``tn.log('e', level='trace', ...)`` stamps the level on the entry."""
    tn = fresh_ceremony
    tn.log("scan.tick", level="trace", n=1)
    tn.log("audit.lookup", level="audit", who="alice")
    tn.flush_and_close()
    tn.init()
    by_event = {e.event_type: e for e in tn.read()}
    assert by_event["scan.tick"].level == "trace"
    assert by_event["audit.lookup"].level == "audit"


def test_tn_log_with_level_emits_regardless_of_threshold(fresh_ceremony):
    """``tn.log`` always emits; threshold is irrelevant. Pin this so
    a future change to ``tn.log`` doesn't quietly start filtering.

    Restores the threshold on exit so subsequent tests (which read
    ``tn._session._log_level_threshold`` directly) aren't filtered.
    """
    tn = fresh_ceremony
    try:
        tn.set_level("error")  # would normally drop info/warning/debug
        tn.log("ignored.by.threshold", level="info", x=1)
        tn.flush_and_close()
        tn.init()
        event_types = [e.event_type for e in tn.read()]
        assert "ignored.by.threshold" in event_types
    finally:
        # Restore the threshold so subsequent tests aren't filtered.
        tn.set_level("debug")


def test_tn_handle_log_level_kwarg(fresh_ceremony):
    """Per-instance ``TN.log`` mirrors the module-level signature."""
    tn = fresh_ceremony
    handle = tn.init("aux", profile="audit")
    handle.log("stream.evt", level="trace", marker="ok")
    tn.flush_and_close()


def test_tn_log_still_rejects_extra_positionals(fresh_ceremony):
    """DX review #3 protection holds: extras after event_type raise."""
    tn = fresh_ceremony
    with pytest.raises(TypeError, match=r"extra positional"):
        tn.log("evt", "extra-positional", level="info")


# --------------------------------------------------------------------
# #17 — verify typing
# --------------------------------------------------------------------


def test_verify_type_annotation_uses_literal():
    """Pin the annotation so IDE autocomplete keeps working."""
    import tn
    sig = inspect.signature(tn.read)
    verify_anno = sig.parameters["verify"].annotation
    # The annotation should resolve to a Union containing Literal.
    # We accept either the typing.Union form or PEP 604 (X | Y).
    rendered = str(verify_anno)
    assert "Literal" in rendered, (
        f"verify annotation should include Literal['skip', 'raise']; "
        f"got {rendered!r}"
    )
    assert "skip" in rendered and "raise" in rendered


@pytest.mark.parametrize("v", [False, True, "skip", "raise"])
def test_verify_validator_accepts_legal_values(v):
    """All four legal verify values pass the validator. Iteration is
    covered separately in test_read_skip_observability.py; this test
    just pins the validator's accept set."""
    from tn.read import _check_verify_kwarg

    # Should not raise.
    _check_verify_kwarg(v)


def test_verify_validator_rejects_unknown_strings():
    """An invalid verify string (e.g. 'strict' before we expand the
    catalog) is rejected at the gate with a clear message."""
    from tn.read import _check_verify_kwarg

    with pytest.raises(ValueError, match=r"verify must be"):
        _check_verify_kwarg("strict")   # type: ignore[arg-type]
