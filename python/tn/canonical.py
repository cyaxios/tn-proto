"""Canonical serialization for deterministic field hashing.

The reference Python implementation of the TN canonical-bytes wire
spec. ``sha256(canonical_bytes(value))`` is the chain of trust under
every signature and row_hash in the protocol; the same value MUST
always produce identical bytes across publishers, readers, languages,
and time. We use RFC 8785-style JSON Canonical Serialization lite
(sorted keys, no whitespace, no optional separators) plus three
TN-specific extensions for bytes / Decimal / datetime.

Supported types:
    None, bool, int, float, str, bytes, list/tuple, dict[str, ...],
    datetime/date, decimal.Decimal

Non-standard encodings:
    bytes      -> {"$b64": "..."}      # bytes get b64 tag so they round-trip
    datetime   -> ISO-8601 string in UTC
    Decimal    -> string ("4.99")      # preserves precision; reader gets a
                                        # str back and parses to Decimal as needed

See Also:
    `docs/spec/canonical-bytes.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/canonical-bytes.md>`_:
        The full wire spec including golden vectors. Treat the spec as
        authoritative; this module is a conformant implementation.
    ``crypto/tn-core/tests/fixtures/canonical_vectors.json``:
        Golden vectors every TN canonicalizer must reproduce.
    ``crypto/tn-core/src/canonical.rs``:
        The Rust mirror implementation.
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
        # NaN/sNaN/Infinity are rejected for the same reason as float.
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
    """Serialize ``value`` to deterministic UTF-8 bytes for hashing or signing.

    Sort-key recursive JSON encoding with no whitespace plus TN's
    sentinel-wrappers for bytes (``$b64``), :class:`decimal.Decimal`
    (str), and :class:`datetime.datetime` (ISO-8601 UTC). The output
    is byte-identical to the Rust and TS implementations for any
    valid input.

    Args:
        value: A JSON-shaped value (None, bool, int, float, str,
            list, tuple, dict[str, ...]) optionally containing bytes,
            Decimal, or datetime — those are wrapped per the spec.

    Returns:
        UTF-8 encoded bytes. Newlines, leading whitespace, or
        non-canonical key ordering are NEVER present in the output.

    Raises:
        ValueError: If a float is NaN / Inf, or a Decimal is NaN /
            Inf — these have no canonical encoding.
        TypeError: If ``value`` contains a type outside the supported
            set (e.g. a custom class, set, complex number).

    Example:
        >>> from tn.canonical import _canonical_bytes
        >>> _canonical_bytes({"b": 2, "a": 1})
        b'{"a":1,"b":2}'
        >>> _canonical_bytes({"ts": __import__("datetime").datetime(2026, 5, 22)})
        b'{"ts":"2026-05-22T00:00:00Z"}'
        >>> _canonical_bytes({"data": b"hi"})
        b'{"data":{"$b64":"aGk="}}'

    Note:
        Underscore-prefixed (legacy). The wasm + Rust exports use the
        public name ``canonicalBytes`` / ``canonical_bytes``.

    See Also:
        `docs/spec/canonical-bytes.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/canonical-bytes.md>`_:
            Wire spec + golden vectors.
    """
    return json.dumps(
        _encode(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
