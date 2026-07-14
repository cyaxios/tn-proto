from __future__ import annotations

import json

import pytest

from tn._bounded_json import JsonNestingError, MAX_JSON_NESTING, loads_bounded


def test_loads_bounded_accepts_the_documented_limit() -> None:
    wire = "[" * MAX_JSON_NESTING + "0" + "]" * MAX_JSON_NESTING

    assert loads_bounded(wire) is not None


def test_loads_bounded_rejects_one_level_over_the_limit() -> None:
    wire = "[" * (MAX_JSON_NESTING + 1) + "0" + "]" * (MAX_JSON_NESTING + 1)

    with pytest.raises(JsonNestingError, match=str(MAX_JSON_NESTING)):
        loads_bounded(wire)


def test_loads_bounded_ignores_delimiters_inside_strings() -> None:
    assert loads_bounded(r'{"value":"[[{\"still a string\"}]]"}') == {
        "value": '[[{"still a string"}]]'
    }


def test_loads_bounded_preserves_json_decode_errors() -> None:
    with pytest.raises(json.JSONDecodeError):
        loads_bounded("{")
