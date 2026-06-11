"""Unit tests for tn.canonical — RFC 8785-style JSON canonical serialization.

Covers:
  * Happy path: primitives, nested containers round-trip deterministically.
  * Key ordering is stable regardless of insertion order.
  * Bytes round-trip via the `$b64` tag.
  * datetime/date: tz-aware datetimes are normalized to UTC.
  * Floats: NaN/+inf/-inf are rejected loudly.
  * Unsupported types (set, object) raise TypeError.

Failure-mode coverage (per Workstream B1 rule "each file must include at
least one failure-mode test") is enforced below via `test_reject_*`.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from tn.canonical import _canonical_bytes

# ---------------------------------------------------------------------------
# Happy path — deterministic encoding
# ---------------------------------------------------------------------------


def test_primitives_round_trip_stable_bytes():
    # Two calls with the same value must produce byte-identical output.
    a = _canonical_bytes({"n": 1, "s": "hello", "b": True, "nil": None})
    b = _canonical_bytes({"n": 1, "s": "hello", "b": True, "nil": None})
    assert a == b
    assert a == b'{"b":true,"n":1,"nil":null,"s":"hello"}'


def test_key_order_is_insertion_independent():
    """Whatever order dicts are built in, canonical output is the same."""
    forward = _canonical_bytes({"a": 1, "b": 2, "c": 3})
    reverse = _canonical_bytes({"c": 3, "b": 2, "a": 1})
    assert forward == reverse


def test_nested_dict_sorts_at_every_level():
    value = {"z": {"b": 2, "a": 1}, "a": {"y": 1, "x": 2}}
    out = _canonical_bytes(value)
    assert out == b'{"a":{"x":2,"y":1},"z":{"a":1,"b":2}}'


def test_list_order_is_preserved():
    """Unlike dicts, list order is semantic — must not be sorted."""
    out = _canonical_bytes([3, 1, 2])
    assert out == b"[3,1,2]"


def test_tuple_encodes_as_list():
    # tuples are serialized identically to lists at the byte level.
    assert _canonical_bytes((1, 2, 3)) == _canonical_bytes([1, 2, 3])


def test_non_string_dict_keys_are_coerced():
    # canonical._encode coerces keys via str(); int 1 and "1" collapse.
    out = _canonical_bytes({1: "one", 2: "two"})
    assert out == b'{"1":"one","2":"two"}'


# ---------------------------------------------------------------------------
# Bytes round-trip via $b64 tag
# ---------------------------------------------------------------------------


def test_bytes_round_trip_via_b64_tag():
    out = _canonical_bytes({"blob": b"\x00\x01\xff"})
    assert out == b'{"blob":{"$b64":"AAH/"}}'


def test_empty_bytes_round_trip():
    out = _canonical_bytes(b"")
    assert out == b'{"$b64":""}'


# ---------------------------------------------------------------------------
# Datetime handling
# ---------------------------------------------------------------------------


def test_naive_datetime_serializes_as_isoformat_with_z():
    dt = datetime(2026, 4, 24, 12, 30, 45)
    out = _canonical_bytes(dt)
    assert out == b'"2026-04-24T12:30:45Z"'


def test_tzaware_datetime_normalizes_to_utc():
    # Start in a non-UTC tz and confirm it's reprojected to UTC.
    from datetime import timedelta

    pacific = timezone(timedelta(hours=-8))
    dt = datetime(2026, 4, 24, 4, 0, 0, tzinfo=pacific)
    # 04:00 in UTC-8 is 12:00 UTC.
    out = _canonical_bytes(dt)
    assert out == b'"2026-04-24T12:00:00Z"'


def test_date_serializes_as_plain_isoformat():
    out = _canonical_bytes(date(2026, 4, 24))
    assert out == b'"2026-04-24"'


def test_utc_tzaware_datetime_round_trip_matches_naive_equivalent():
    # A UTC-labeled datetime must produce the same bytes as the equivalent naive one.
    aware = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    naive = datetime(2026, 1, 1, 0, 0, 0)
    assert _canonical_bytes(aware) == _canonical_bytes(naive)


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_reject_nan_float():
    with pytest.raises(ValueError, match="NaN"):
        _canonical_bytes(float("nan"))


def test_reject_positive_infinity():
    with pytest.raises(ValueError, match="NaN/inf"):
        _canonical_bytes(float("inf"))


def test_reject_negative_infinity():
    with pytest.raises(ValueError, match="NaN/inf"):
        _canonical_bytes(float("-inf"))


def test_reject_unsupported_type_set():
    with pytest.raises(TypeError, match="unsupported type"):
        _canonical_bytes({1, 2, 3})


def test_reject_unsupported_type_object():
    class Custom:
        pass

    with pytest.raises(TypeError, match="unsupported type"):
        _canonical_bytes(Custom())


def test_reject_unsupported_type_nested_inside_dict():
    # Even a deep nested unsupported value must bubble up.
    with pytest.raises(TypeError):
        _canonical_bytes({"outer": {"inner": object()}})


# ---------------------------------------------------------------------------
# Cross-language contract: _canonical_bytes must be UTF-8 (not ASCII) so
# non-ASCII values round-trip without escape mangling.
# ---------------------------------------------------------------------------


def test_utf8_literal_not_escaped():
    # ensure_ascii=False in canonical.py — multibyte chars appear verbatim.
    out = _canonical_bytes({"name": "café"})
    assert out == '{"name":"café"}'.encode()


if __name__ == "__main__":
    import sys as _sys

    _sys.exit(pytest.main([__file__, "-v"]))
