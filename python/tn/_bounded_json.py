"""Deterministic JSON parsing limits for untrusted protocol documents."""

from __future__ import annotations

import json
from typing import Any

MAX_JSON_NESTING = 128


class JsonNestingError(ValueError):
    """The JSON container depth exceeds TN's version-independent limit."""


def _assert_nesting(text: str, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise JsonNestingError(f"JSON nesting exceeds deterministic limit of {max_depth}")
        elif char in "]}":
            depth = max(0, depth - 1)


def loads_bounded(
    value: str | bytes | bytearray,
    *,
    max_depth: int = MAX_JSON_NESTING,
) -> Any:
    """Parse UTF-8 JSON after enforcing a stable container-depth ceiling."""
    if max_depth < 1:
        raise ValueError("max_depth must be positive")
    text = value if isinstance(value, str) else bytes(value).decode("utf-8")
    _assert_nesting(text, max_depth)
    try:
        return json.loads(text)
    except RecursionError as exc:  # Defensive fallback for parser implementation changes.
        raise JsonNestingError(f"JSON nesting exceeds deterministic limit of {max_depth}") from exc


__all__ = ["MAX_JSON_NESTING", "JsonNestingError", "loads_bounded"]
