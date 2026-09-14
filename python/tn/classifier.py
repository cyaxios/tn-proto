"""Application-supplied field routing for the Python pipeline.

Register a callable with ``_register(fn)``. It receives the field name,
value type name, and available groups, and returns a group name.
Unknown results and callback failures route to ``default``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

ClassifierFn = Callable[[str, str, list[str]], str]
_active: ClassifierFn | None = None


def _register(fn: ClassifierFn) -> None:
    """Register the callable used to route undeclared fields."""
    global _active
    _active = fn


def _classify(field_name: str, value: Any, group_names: list[str]) -> str:
    """Return a registered callback's group, or ``default``."""
    if _active is None:
        return "default"
    try:
        result = _active(field_name, type(value).__name__, list(group_names))
        return result if isinstance(result, str) and result in group_names else "default"
    except Exception:  # Callback failures retain the default field route.
        return "default"
