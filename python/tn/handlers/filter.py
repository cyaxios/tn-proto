"""Handler filter grammar (RFC §3.2).

A ``Filter`` dataclass holds the parsed predicates from a handler's
``filter:`` yaml block. All predicates in one ``Filter`` are AND-ed. To
express OR, declare multiple handlers each with their own filter.

Supported predicates (all optional; omitting one means "accept anything"):

    event_type           -- exact string match
    event_type_prefix    -- envelope event_type starts with this prefix
    not_event_type_prefix -- envelope event_type does NOT start with prefix
    event_type_in        -- envelope event_type is in this list
    level                -- exact string match on the level field
    level_in             -- level is in this list
    sync                 -- bool match; missing ``sync`` field treated as True

Usage::

    f = Filter.from_spec({"event_type_prefix": "tn.", "sync": True})
    if f.matches(envelope):
        handler.emit(envelope, raw_line)

The ``_compile_filter`` function in ``tn.filters`` continues to handle the
richer field/op dict syntax used by the other handler kinds. This module
provides the *shorthand* grammar described in the RFC.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Filter:
    """Compiled filter for a single handler.

    All populated predicates must match for :meth:`matches` to return True.
    An empty ``Filter`` (all fields None) matches every envelope.
    """

    # Exact match on event_type
    event_type: str | None = None

    # Prefix match on event_type  (startswith)
    event_type_prefix: str | None = None

    # Negated prefix match on event_type (not startswith)
    not_event_type_prefix: str | None = None

    # Membership test on event_type
    event_type_in: frozenset[str] | None = None

    # Exact match on level
    level: str | None = None

    # Membership test on level
    level_in: frozenset[str] | None = None

    # Bool match on the envelope's ``sync`` field.
    # ``None`` means "do not filter on sync".
    # When the envelope has no ``sync`` field the runtime treats it as True.
    sync: bool | None = None

    # ------------------------------------------------------------------ #
    # Factory                                                              #
    # ------------------------------------------------------------------ #

    @classmethod
    def from_spec(cls, spec: dict[str, Any] | None) -> Filter:
        """Build a Filter from a handler's ``filter:`` yaml block.

        Unknown keys are silently ignored so the grammar can be extended
        without breaking older handler definitions.
        """
        if not spec:
            return cls()

        event_type_in_raw = spec.get("event_type_in")
        level_in_raw = spec.get("level_in")
        sync_raw = spec.get("sync")

        return cls(
            event_type=spec.get("event_type"),
            event_type_prefix=spec.get("event_type_prefix"),
            not_event_type_prefix=spec.get("not_event_type_prefix"),
            event_type_in=(frozenset(event_type_in_raw) if event_type_in_raw is not None else None),
            level=spec.get("level"),
            level_in=(frozenset(level_in_raw) if level_in_raw is not None else None),
            sync=(bool(sync_raw) if sync_raw is not None else None),
        )

    # ------------------------------------------------------------------ #
    # Predicate                                                            #
    # ------------------------------------------------------------------ #

    def matches(self, envelope: dict[str, Any]) -> bool:
        """Return True if *all* populated predicates match the envelope."""
        et = envelope.get("event_type", "")

        if self.event_type is not None and et != self.event_type:
            return False

        if self.event_type_prefix is not None and not et.startswith(self.event_type_prefix):
            return False

        if self.not_event_type_prefix is not None and et.startswith(self.not_event_type_prefix):
            return False

        if self.event_type_in is not None and et not in self.event_type_in:
            return False

        lv = envelope.get("level", "")

        if self.level is not None and lv != self.level:
            return False

        if self.level_in is not None and lv not in self.level_in:
            return False

        if self.sync is not None:
            # Missing ``sync`` field in the envelope is treated as True per RFC §2.1.
            envelope_sync: bool = envelope.get("sync", True)
            if bool(envelope_sync) != self.sync:
                return False

        return True
