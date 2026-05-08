"""TN log entry — the typed return value of ``tn.read`` and ``tn.watch``.

Replaces the legacy ``dict[str, Any]`` shape. User-emitted kwargs land in
``Entry.fields``; envelope and chain plumbing surface as typed attributes
the IDE autocompletes.

A first user emit produces something like::

    Entry(
        event_type='order.created',
        timestamp=2026-05-08T03:30:20.184000+00:00,
        level='info',
        message=None,
        fields={'order_id': 'A100', 'amount': 4999},
        did='did:key:z6Mkp8DNkY...8FAZ',
        sequence=4,
        ...
    )

Wire format on disk is unchanged — this module is purely about how
entries surface to caller code.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VerifyError(Exception):
    """Raised when ``tn.read(verify=True)`` hits an entry that fails one or
    more of (signature, row_hash, chain).

    Use ``verify="skip"`` to drop invalid rows silently, or ``verify=False``
    (the default) to read without integrity checks.
    """

    def __init__(self, sequence: int, event_type: str, failed_checks: list[str]):
        self.sequence = sequence
        self.event_type = event_type
        self.failed_checks = failed_checks
        super().__init__(
            f"entry seq={sequence} event={event_type!r} failed: "
            f"{', '.join(failed_checks)}"
        )


class Entry(BaseModel):
    """One TN log entry."""

    model_config = ConfigDict(frozen=False)

    # Essentials — user-visible, typed
    event_type: str
    timestamp: datetime
    level: str
    message: str | None = None

    # User payload — emitted kwargs live here
    fields: dict[str, Any] = Field(default_factory=dict)

    # Chain / authorship — typed, always present
    did: str
    event_id: str
    sequence: int
    run_id: str
    prev_hash: str
    row_hash: str
    signature: str

    # Read-time signal — populated when reading as recipient and some
    # group ciphertext blocks were present in the envelope but the
    # caller's keystore couldn't decrypt them.
    hidden_groups: list[str] = Field(default_factory=list)

    # ---------------------------------------------------------------
    # Constructors
    # ---------------------------------------------------------------

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "Entry":
        """Build an Entry from a raw ``{envelope, plaintext, valid}`` triple
        as produced by the reader's parse path.

        - Envelope fields go to typed attributes.
        - Decrypted plaintext from every group (alphabetical, last-write-wins
          on collision) merges into ``fields``.
        - Group blocks the caller couldn't decrypt land in ``hidden_groups``.
        """
        env = raw["envelope"]
        plaintext = raw.get("plaintext") or {}

        # Build user fields by merging decrypted group plaintexts +
        # public envelope fields that aren't reserved or group blocks.
        fields: dict[str, Any] = {}
        hidden: list[str] = []
        for gname in sorted(plaintext.keys()):
            body = plaintext[gname]
            if not isinstance(body, dict):
                continue
            if body.get("$decrypt_error") is True:
                # Decrypt error — surface as hidden, don't merge.
                hidden.append(gname)
                continue
            if body.get("$no_read_key") is True:
                # No kit for this group — surface as hidden.
                continue
            fields.update(body)

        envelope_basics = {
            "event_type", "timestamp", "level", "did", "sequence",
            "event_id", "run_id", "prev_hash", "row_hash", "signature",
            "message",
        }
        for k, v in env.items():
            if k in envelope_basics:
                continue
            if isinstance(v, dict) and "ciphertext" in v:
                # Group block. Surface as hidden if we couldn't decrypt it.
                if k not in plaintext or (
                    isinstance(plaintext.get(k), dict)
                    and plaintext[k].get("$no_read_key") is True
                ):
                    hidden.append(k)
                continue
            # Non-group public envelope extra (e.g. handler-injected).
            fields[k] = v

        # ``run_id`` and the positional ``message`` are both emitted as
        # part of the plaintext payload (so they encrypt with the rest
        # of a user's kwargs). Pull them out of ``fields`` and into
        # their typed envelope slots so callers can use ``e.message``
        # / ``e.run_id`` instead of having to reach into ``e.fields``.
        # Empty string for run_id when absent (admin events emitted
        # before run-id minting); ``None`` for message when the user
        # called info / log / etc. without a positional argument.
        run_id = fields.pop("run_id", env.get("run_id", "")) or ""
        message = fields.pop("message", env.get("message"))

        return cls(
            event_type=env["event_type"],
            timestamp=env["timestamp"],
            level=env.get("level", ""),
            message=message,
            fields=fields,
            did=env["did"],
            event_id=env["event_id"],
            sequence=env["sequence"],
            run_id=run_id,
            prev_hash=env.get("prev_hash", ""),
            row_hash=env.get("row_hash", ""),
            signature=env.get("signature", ""),
            hidden_groups=sorted(set(hidden)),
        )

    @classmethod
    def from_flat(cls, d: dict[str, Any]) -> "Entry":
        """Build an Entry from the legacy flat-dict shape produced by
        ``flatten_raw_entry``. Keys not in the envelope schema land in
        ``fields``; legacy underscore-prefixed metadata (``_decrypt_errors``,
        ``_valid``) is dropped.
        """
        envelope_keys = {
            "event_type", "timestamp", "level", "message",
            "did", "event_id", "sequence", "run_id",
            "prev_hash", "row_hash", "signature",
        }
        kwargs: dict[str, Any] = {}
        user_fields: dict[str, Any] = {}
        hidden_groups: list[str] = []

        for k, v in d.items():
            if k == "_hidden_groups":
                hidden_groups = list(v)
            elif k.startswith("_"):
                continue
            elif k in envelope_keys:
                kwargs[k] = v
            else:
                user_fields[k] = v

        for required in ("event_type", "did", "event_id", "sequence",
                         "run_id", "prev_hash", "row_hash", "signature"):
            if required not in kwargs:
                raise ValueError(
                    f"Entry.from_flat: required envelope field {required!r} "
                    f"missing from input dict (keys={sorted(d.keys())!r})"
                )

        # ``run_id`` and ``message`` are plaintext-payload, not
        # envelope, so they show up under whichever bucket the upstream
        # populated. Hoist them into their typed slots so callers use
        # ``e.run_id`` / ``e.message`` rather than reaching into
        # ``e.fields``.
        kwargs["run_id"] = (
            kwargs.pop("run_id", None) or user_fields.pop("run_id", None) or ""
        )
        kwargs["message"] = (
            kwargs.pop("message", None) or user_fields.pop("message", None)
        )
        kwargs.setdefault("level", "")
        kwargs["fields"] = user_fields
        kwargs["hidden_groups"] = hidden_groups
        return cls(**kwargs)

    # ---------------------------------------------------------------
    # Human-readable
    # ---------------------------------------------------------------

    def __str__(self) -> str:
        """One-line scannable view; mirrors StdoutHandler's pretty format."""
        ts = self.timestamp.astimezone(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        head = f"{ts} {self.level.upper():<7} seq={self.sequence}  {self.event_type}"
        if self.fields:
            kvs = "  ".join(f"{k}={v!r}" for k, v in self.fields.items())
            return f"{head}  {kvs}"
        return head

    def __repr__(self) -> str:
        """Developer-facing; truncates long opaque values."""
        did_short = (
            f"{self.did[:16]}...{self.did[-8:]}"
            if len(self.did) > 30
            else self.did
        )
        fields_repr = (
            repr(self.fields)
            if len(repr(self.fields)) <= 60
            else f"{{...{len(self.fields)} kwargs}}"
        )
        return (
            f"Entry(event_type={self.event_type!r}, "
            f"timestamp={self.timestamp.isoformat()!r}, "
            f"level={self.level!r}, "
            f"sequence={self.sequence}, "
            f"did={did_short!r}, "
            f"fields={fields_repr})"
        )

    def _repr_html_(self) -> str:
        """Rendered table for Jupyter / Databricks display() calls."""
        head = (
            f"<tr><th colspan='2' style='text-align:left;background:#f5f5f5;"
            f"padding:4px 8px'>{self.event_type}</th></tr>"
        )
        sys_rows: list[tuple[str, Any]] = [
            ("timestamp", self.timestamp.isoformat()),
            ("level", self.level),
        ]
        if self.message:
            sys_rows.append(("message", self.message))
        user_rows = list(self.fields.items())

        def _row(k: str, v: Any) -> str:
            return (
                f"<tr><td style='font-family:monospace;color:#666;"
                f"padding:2px 8px'>{k}</td>"
                f"<td style='font-family:monospace;padding:2px 8px'>"
                f"{v!r}</td></tr>"
            )

        body = head + "".join(_row(k, v) for k, v in sys_rows + user_rows)
        return (
            "<table style='border-collapse:collapse;border:1px solid #ddd'>"
            f"{body}</table>"
        )

    def _repr_markdown_(self) -> str:
        """Markdown rendering for Jupyter / Databricks markdown cells.

        Mirrors ``_repr_html_`` but in plain markdown so a tester can
        copy-paste the rendered cell text into a chat / notes / PR
        description without HTML escaping.
        """
        ts = self.timestamp.isoformat()
        lines = [
            f"**{self.event_type}** — `{self.level}`",
            "",
            f"`timestamp`: {ts}",
        ]
        if self.message:
            lines.append(f"`message`: {self.message}")
        if self.fields:
            lines.append("")
            for k, v in self.fields.items():
                lines.append(f"- `{k}`: `{v!r}`")
        return "\n".join(lines)


# ---------------------------------------------------------------------
# Internal — JSON encoder helper used by the writer side (logger.py).
# Preserved across the read-side refactor since the writer hasn't moved
# off it.
# ---------------------------------------------------------------------


def _json_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat().replace("+00:00", "Z")
    if isinstance(o, bytes):
        return base64.standard_b64encode(o).decode("ascii")
    if isinstance(o, Decimal):
        if not o.is_finite():
            raise TypeError("Decimal NaN/Infinity is not JSON serializable")
        return str(o)
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")
