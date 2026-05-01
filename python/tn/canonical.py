"""Canonical serialization for deterministic field hashing.

PRD §3.4: `sha256(canonical_serialize(value))` — the same value must
always produce the same hash, across publishers and readers, across
Python versions. We use RFC 8785-style JSON Canonical Serialization
lite (sorted keys, no whitespace, no optional separators), good enough
for a pairwise-agreeable deterministic encoding.

Supported types:
    None, bool, int, float, str, bytes, list/tuple, dict[str, ...],
    datetime/date, decimal.Decimal

Non-standard encodings:
    bytes      -> {"$b64": "..."}      # bytes get b64 tag so they round-trip
    datetime   -> ISO-8601 string in UTC
    Decimal    -> string ("4.99")      # preserves precision; reader gets a
                                        # str back and parses to Decimal as needed
"""

from __future__ import annotations

import base64
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any


def _encode(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        # NaN/inf aren't JSON-valid. Reject loudly rather than silently mangle.
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("float NaN/inf not supported in canonical form")
        return value
    if isinstance(value, Decimal):
        # Money-shaped values land here. Serialize as a plain string so the
        # exact decimal representation survives the round-trip — no float
        # precision loss, no surprises in cryptographically-attested rows.
        # Readers get the string back and can parse to Decimal as needed.
        # (FINDINGS.md #9, #10, #13.) NaN/sNaN/Infinity are rejected for
        # the same reason as float.
        if not value.is_finite():
            raise ValueError("Decimal NaN/Infinity not supported in canonical form")
        return str(value)
    if isinstance(value, bytes):
        return {"$b64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (datetime, date)):
        if isinstance(value, datetime) and value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat() + ("Z" if isinstance(value, datetime) else "")
    if isinstance(value, (list, tuple)):
        return [_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _encode(v) for k, v in value.items()}
    raise TypeError(f"canonical: unsupported type {type(value).__name__}")


def _canonical_bytes(value: Any) -> bytes:
    """Serialize `value` to deterministic bytes suitable for hashing."""
    return json.dumps(
        _encode(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
