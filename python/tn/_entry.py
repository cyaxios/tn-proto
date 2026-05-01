"""Ergonomic log-entry wrapper returned by `tn.read`.

The underlying SDK produces `{envelope, plaintext, valid}` dicts that
leak group names and crypto scaffolding into the reader. `Entry` presents
a flat, log-like view: one timestamp, one level, one event_type, one
dict of merged fields. Groups are an internal implementation detail of
the write path; they do not appear in the read API.

For audit or forensic use, `entry.audit` exposes the raw envelope,
per-group breakdown, signatures, row_hash, and field_hashes.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any


class VerifyError(Exception):
    """Raised when a log entry fails verification.

    Produced by `tn.read()` when an entry's signature, row_hash, or chain
    linkage does not verify. Call `tn.read(verify=False)` to suppress and
    inspect `entry.valid` / `entry.audit.validity` yourself.
    """

    def __init__(self, sequence: int, event_type: str, failed_checks: list[str]):
        self.sequence = sequence
        self.event_type = event_type
        self.failed_checks = failed_checks
        super().__init__(
            f"entry seq={sequence} event={event_type!r} failed: {', '.join(failed_checks)}"
        )


_RESERVED_ENVELOPE_KEYS = frozenset(
    {
        "did",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "sequence",
        "prev_hash",
        "row_hash",
        "signature",
    }
)


def _parse_timestamp(ts_str: str) -> datetime:
    # Accept "2026-04-22T14:44:26.267738Z"
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    return datetime.fromisoformat(ts_str)


def _is_group_payload(v: Any) -> bool:
    """Group payloads are dicts with both ciphertext and field_hashes keys."""
    return isinstance(v, dict) and "ciphertext" in v and "field_hashes" in v


class Audit:
    """Crypto and protocol details of an entry.

    Lazy accessor — exists so the common-case `tn.read()` loop never has
    to look at ciphertext or group internals, but audit tooling has a
    stable place to find them.
    """

    __slots__ = ("_raw",)

    def __init__(self, raw_entry: dict):
        self._raw = raw_entry

    @property
    def signature(self) -> str:
        """URL-safe base64 Ed25519 signature over row_hash."""
        return self._raw["envelope"]["signature"]

    @property
    def row_hash(self) -> str:
        """`sha256:<hex>` row hash covering did, ts, event, prev_hash, groups."""
        return self._raw["envelope"]["row_hash"]

    @property
    def prev_hash(self) -> str:
        """`sha256:<hex>` previous row hash for this event_type chain."""
        return self._raw["envelope"]["prev_hash"]

    @property
    def per_group(self) -> dict[str, dict[str, Any]]:
        """Plaintext fields split per group: `{group_name: {field: value}}`."""
        return dict(self._raw["plaintext"])

    @property
    def field_hashes(self) -> dict[str, dict[str, str]]:
        """HMAC-SHA256 index tokens per group: `{group: {field: token}}`.

        Useful for searching a log by field value without decryption.
        """
        env = self._raw["envelope"]
        out: dict[str, dict[str, str]] = {}
        for k, v in env.items():
            if k in _RESERVED_ENVELOPE_KEYS:
                continue
            if _is_group_payload(v):
                out[k] = dict(v["field_hashes"])
        return out

    @property
    def ciphertext(self) -> dict[str, bytes]:
        """Per-group raw ciphertext bytes, base64-decoded."""
        env = self._raw["envelope"]
        out: dict[str, bytes] = {}
        for k, v in env.items():
            if k in _RESERVED_ENVELOPE_KEYS:
                continue
            if _is_group_payload(v):
                out[k] = base64.standard_b64decode(v["ciphertext"])
        return out

    @property
    def validity(self) -> dict[str, bool]:
        """Per-check validity: `{signature: bool, row_hash: bool, chain: bool}`."""
        return dict(self._raw["valid"])

    @property
    def envelope(self) -> dict[str, Any]:
        """The raw envelope dict (includes group payloads)."""
        return self._raw["envelope"]

    @property
    def raw(self) -> dict[str, Any]:
        """The original `{envelope, plaintext, valid}` dict."""
        return self._raw


class Entry:
    """One decoded log entry, presented as a flat logging record.

    Attributes:
        timestamp: UTC datetime with microsecond precision.
        level: Uppercased level string (`INFO`, `WARNING`, ...). Empty for
            level-less entries (`tn.log(event_type, ...)` with no level).
        event_type: Dotted event type (e.g. `order.created`).
        sequence: Monotonic per-event_type counter, starting at 1.
        did: Signer's `did:key:z...`.
        event_id: UUID v4 unique to this entry.
        fields: Merged dict of plaintext fields across every group the
            reader can decrypt. Also includes any public envelope fields.
        valid: `True` iff signature, row_hash, and chain all verified.

    Use `entry[key]` for field access (delegates to `fields`).
    Use `entry.audit` for crypto details (signature, row_hash, per-group).
    Use `str(entry)`, `entry.to_logfmt()`, `entry.to_json()` for formatting.
    """

    __slots__ = (
        "_raw",
        "did",
        "event_id",
        "event_type",
        "fields",
        "level",
        "sequence",
        "timestamp",
        "valid",
    )

    def __init__(self, raw_entry: dict):
        env = raw_entry["envelope"]
        pt = raw_entry["plaintext"]
        valid = raw_entry["valid"]

        self.timestamp = _parse_timestamp(env["timestamp"])
        self.level = env["level"].upper() if env.get("level") else ""
        self.event_type = env["event_type"]
        self.sequence = env["sequence"]
        self.did = env["did"]
        self.event_id = env["event_id"]

        # Merge plaintext across every group we can decrypt into one flat dict.
        # Also include public envelope fields (anything not reserved or a group payload).
        merged: dict[str, Any] = {}
        for group_fields in pt.values():
            if isinstance(group_fields, dict):
                merged.update(group_fields)
        for k, v in env.items():
            if k in _RESERVED_ENVELOPE_KEYS:
                continue
            if _is_group_payload(v):
                continue  # skip group sub-dicts; already merged from plaintext
            merged[k] = v
        self.fields = merged

        self.valid = all(valid.values())
        self._raw = raw_entry

    @property
    def audit(self) -> Audit:
        return Audit(self._raw)

    # Dict-like field access ---------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def __contains__(self, key: str) -> bool:
        return key in self.fields

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    # Formatting ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Flat dict suitable for JSON dumps: envelope metadata + fields."""
        return {
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "level": self.level,
            "event_type": self.event_type,
            "sequence": self.sequence,
            "did": self.did,
            "event_id": self.event_id,
            "valid": self.valid,
            **self.fields,
        }

    def to_json(self) -> str:
        """One-line JSON, suitable for piping to jq / lnav / fluent-bit."""
        return json.dumps(self.to_dict(), default=_json_default, separators=(",", ":"))

    def to_logfmt(self) -> str:
        """Logfmt line: `ts=... level=INFO event=order.created amount=100 ...`."""
        parts = [
            f"ts={self.timestamp.isoformat().replace('+00:00', 'Z')}",
        ]
        if self.level:
            parts.append(f"level={self.level}")
        parts.append(f"event={self.event_type}")
        parts.append(f"seq={self.sequence}")
        if not self.valid:
            parts.append("valid=false")
        for k, v in self.fields.items():
            parts.append(f"{k}={_logfmt_value(v)}")
        return " ".join(parts)

    def __str__(self) -> str:
        """Human-readable log line, same shape as stdlib logging output.

        `2026-04-22 14:44:26.267 INFO order.created  amount=100  note=first`
        """
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        ts += f".{self.timestamp.microsecond // 1000:03d}"
        lvl = self.level or "-"
        fields_str = "  ".join(f"{k}={_display_value(v)}" for k, v in self.fields.items())
        flag = "" if self.valid else "  [!INVALID!]"
        if fields_str:
            return f"{ts} {lvl:<7} {self.event_type}  {fields_str}{flag}"
        return f"{ts} {lvl:<7} {self.event_type}{flag}"

    def __repr__(self) -> str:
        return (
            f"<Entry seq={self.sequence} event={self.event_type!r} "
            f"fields={list(self.fields)} valid={self.valid}>"
        )


def _display_value(v: Any) -> str:
    if isinstance(v, str):
        # Quote strings containing spaces so the display stays parseable.
        if " " in v or "=" in v:
            return f'"{v}"'
        return v
    if isinstance(v, (list, dict)):
        return json.dumps(v, default=_json_default, separators=(",", ":"))
    return str(v)


def _logfmt_value(v: Any) -> str:
    if isinstance(v, str):
        if " " in v or '"' in v or "=" in v:
            escaped = v.replace('"', '\\"')
            return f'"{escaped}"'
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, dict)):
        return json.dumps(v, default=_json_default, separators=(",", ":"))
    return str(v)


def _json_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat().replace("+00:00", "Z")
    if isinstance(o, bytes):
        return base64.standard_b64encode(o).decode("ascii")
    # Decimal as plain string preserves precision through JSON round-trip
    # — same convention as _canonical_bytes() so envelope JSON, hash input,
    # and reader-side flat dicts all agree on the encoding (FINDINGS.md
    # #9, #10, #13). Reader gets a `str` back; parse to Decimal as needed.
    from decimal import Decimal
    if isinstance(o, Decimal):
        if not o.is_finite():
            raise TypeError("Decimal NaN/Infinity is not JSON serializable")
        return str(o)
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def wrap_raw_entries(
    raw_iter: Iterator[dict],
    *,
    verify: bool = True,
) -> Iterator[Entry]:
    """Wrap a raw-entry iterator as an Entry iterator.

    If `verify` is True, raises VerifyError on the first entry whose
    signature, row_hash, or chain linkage does not verify. If False,
    yields entries with `valid=False` and lets the caller inspect.
    """
    for raw in raw_iter:
        entry = Entry(raw)
        if verify and not entry.valid:
            failed = [k for k, ok in raw["valid"].items() if not ok]
            raise VerifyError(entry.sequence, entry.event_type, failed)
        yield entry
