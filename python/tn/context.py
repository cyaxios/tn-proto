"""Per-request context via contextvars (PRD §13).

FastAPI + asyncio run concurrent requests in one process. A plain
module-level dict would cross-contaminate between requests. contextvars
isolates per async task automatically.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

_context: ContextVar[dict[str, Any] | None] = ContextVar("tn_context", default=None)


def _current() -> dict[str, Any]:
    """Read the current context, materializing an empty dict when unset.

    Using `None` as the ContextVar's default (vs a shared `{}` literal)
    avoids the mutable-default pitfall: a shared dict would leak writes
    across async tasks unless every setter took care to copy first.
    """
    v = _context.get()
    return {} if v is None else v


def set_context(**kwargs: Any) -> None:
    """Replace the current context with these kwargs."""
    _context.set(dict(kwargs))


def update_context(**kwargs: Any) -> None:
    """Merge kwargs into the current context."""
    current = dict(_current())
    current.update(kwargs)
    _context.set(current)


def clear_context() -> None:
    _context.set({})


def get_context() -> dict[str, Any]:
    """Return a copy of the current context."""
    return dict(_current())


class _ScopeContextManager:
    """Context manager returned by ``tn.scope(**fields)``. Layers fields
    on top of the existing context for the duration of the ``with`` block,
    then restores the prior context on exit (handles nesting cleanly).

    Usage:
        with tn.scope(sale_id=sid, _register=2):
            tn.info("sale.start")
            for line in cart:
                tn.info("sale.line", **line)
            tn.info("sale.end", total=total)
        # outside the block, sale_id/_register are gone
    """

    __slots__ = ("_fields", "_prior")

    def __init__(self, fields: dict[str, Any]):
        self._fields = fields
        self._prior: dict[str, Any] | None = None

    def __enter__(self) -> _ScopeContextManager:
        self._prior = dict(_current())
        merged = dict(self._prior)
        merged.update(self._fields)
        _context.set(merged)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Restore the snapshot taken on enter — preserves correct
        # behavior when scopes nest.
        prior = self._prior if self._prior is not None else {}
        _context.set(prior)


def scope(**fields: Any) -> _ScopeContextManager:
    """Context manager that layers ``fields`` on top of the current
    request-scoped context for the duration of a ``with`` block.

    On exit, the prior context is restored — even if the block raises.
    Cleaner than manual ``update_context()`` + ``clear_context()`` pairs,
    and safe with nested scopes (FINDINGS.md #8).
    """
    return _ScopeContextManager(dict(fields))
