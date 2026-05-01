"""Predicate compiler for per-handler filters.

Two YAML shapes are supported (all optional; absent filter = accept all):

Classic field/op shape:

    filter:
      event_type:
        starts_with: "order."
        # or: equals, in, regex, not_equals, not_in, not_starts_with
      level:
        in: [warning, error]
      did:
        equals: did:key:z6Mk...

RFC §3.2 shorthand shape (all keys AND-ed):

    filter:
      event_type: "order.created"          # exact match
      event_type_prefix: "tn."             # prefix match
      not_event_type_prefix: "trace."      # negated prefix
      event_type_in: [order.created, ...]  # membership
      level: "error"                       # exact level
      level_in: [warning, error]           # level membership
      sync: true                           # bool; missing field treated as True

Semantics:
    - AND across top-level filter keys.
    - AND across predicates within one field (classic shape).
    - Unknown fields on the envelope are treated as missing (no match).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

Predicate = Callable[[dict[str, Any]], bool]

# ── RFC §3.2 shorthand keys ──────────────────────────────────────────
# These are processed before the classic field/op loop so they don't
# collide with envelope field names.
_RFC_SHORTHAND_KEYS = frozenset(
    {
        "event_type_prefix",
        "not_event_type_prefix",
        "event_type_in",
        "level_in",
        "sync",
    }
)


def _as_str(v: Any) -> str:
    return v if isinstance(v, str) else "" if v is None else str(v)


def _predicate_for(field: str, op: str, rhs: Any) -> Predicate:
    """Build a single predicate callable for (field, op, rhs)."""
    if op == "equals":
        return lambda env: env.get(field) == rhs
    if op == "not_equals":
        return lambda env: env.get(field) != rhs
    if op == "in":
        allowed = set(rhs)
        return lambda env: env.get(field) in allowed
    if op == "not_in":
        denied = set(rhs)
        return lambda env: env.get(field) not in denied
    if op == "starts_with":
        needle = str(rhs)
        return lambda env: _as_str(env.get(field)).startswith(needle)
    if op == "not_starts_with":
        needle = str(rhs)
        return lambda env: not _as_str(env.get(field)).startswith(needle)
    if op == "ends_with":
        needle = str(rhs)
        return lambda env: _as_str(env.get(field)).endswith(needle)
    if op == "contains":
        needle = str(rhs)
        return lambda env: needle in _as_str(env.get(field))
    if op == "regex":
        pattern = re.compile(str(rhs))
        return lambda env: bool(pattern.search(_as_str(env.get(field))))
    raise ValueError(f"filter: unknown predicate {op!r} on field {field!r}")


def _build_rfc_shorthand(key: str, rhs: Any) -> Predicate:
    """Compile one RFC §3.2 shorthand predicate."""
    if key == "event_type_prefix":
        needle = str(rhs)
        return lambda env: _as_str(env.get("event_type")).startswith(needle)

    if key == "not_event_type_prefix":
        needle = str(rhs)
        return lambda env: not _as_str(env.get("event_type")).startswith(needle)

    if key == "event_type_in":
        allowed = frozenset(rhs)
        return lambda env: env.get("event_type") in allowed

    if key == "level_in":
        allowed = frozenset(rhs)
        return lambda env: env.get("level") in allowed

    if key == "sync":
        want = bool(rhs)
        # Missing ``sync`` field is treated as True per RFC §2.1.
        return lambda env: bool(env.get("sync", True)) == want

    raise ValueError(f"filter: unrecognised RFC shorthand key {key!r}")


def _compile_filter(spec: dict[str, Any] | None) -> Predicate:
    """Compile a filter spec into a callable. None / {} -> accept-all.

    Handles both the classic field/op dict shape and the RFC §3.2
    shorthand keys in the same spec block.
    """
    if not spec:
        return lambda env: True

    predicates: list[Predicate] = []
    for key, ops in spec.items():
        if key in _RFC_SHORTHAND_KEYS:
            predicates.append(_build_rfc_shorthand(key, ops))
            continue

        if not isinstance(ops, dict):
            # Shorthand: `event_type: "order.created"` -> equals
            predicates.append(_predicate_for(key, "equals", ops))
            continue

        for op, rhs in ops.items():
            predicates.append(_predicate_for(key, op, rhs))

    def run(env: dict[str, Any]) -> bool:
        return all(p(env) for p in predicates)

    return run
