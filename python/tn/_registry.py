"""Process-local registry of named TN ceremony handles.

The registry maps a ceremony's *registry name* (the directory name
under ``.tn/``) to its in-process ``TN`` handle. Lookups are O(1),
and insertion is the source of truth for ``tn.list()``.

The registry is process-local. Multi-process write coordination is a
separate concern (file locking on ``.tn/<name>/``), not solved here.

See ``docs/directory-layout.md`` for the registry semantics this
module enforces.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from ._layout import is_valid_ceremony_name

if TYPE_CHECKING:
    from ._handle import TN

__all__ = [
    "TNNotFound",
    "clear_registry_for_tests",
    "get",
    "list_names",
    "register",
    "unregister",
]


class TNNotFound(KeyError):
    """Raised by strict registry lookups when a name is not registered.

    Carries the requested name and the list of currently-registered
    names so the message can be made friendly at the call site (the
    ``tn.use`` wrapper formats this with did-you-mean suggestions).
    """

    def __init__(self, name: str, registered: list[str]):
        self.name = name
        self.registered = registered
        super().__init__(name)


_registry: dict[str, TN] = {}
_lock = threading.Lock()


def register(name: str, handle: TN) -> None:
    """Bind ``name -> handle`` in the registry.

    Idempotent if the handle is the same object; otherwise raises
    ``RuntimeError`` to prevent silent replacement (which would be a
    nasty source of "I emitted to the wrong ceremony" bugs).
    """
    if not is_valid_ceremony_name(name):
        # The layout module already validates; this is a defense in
        # depth so nothing odd makes it into the registry even if a
        # caller bypasses ``tn.init`` / ``tn.use``.
        raise ValueError(f"invalid ceremony name {name!r}")
    with _lock:
        existing = _registry.get(name)
        if existing is None:
            _registry[name] = handle
            return
        if existing is handle:
            return
        raise RuntimeError(
            f"ceremony {name!r} is already registered to a different "
            "TN handle in this process. This is almost always a bug "
            "in init/use ordering. Investigate before forcing a swap."
        )


def get(name: str) -> TN:
    """Strict registry lookup. Raises ``TNNotFound`` if missing.

    The friendly-error wrapping (did-you-mean, disk-attach hint) lives
    in ``tn.use`` — this function stays terse so internal callers can
    use it without paying for that work.
    """
    with _lock:
        handle = _registry.get(name)
        if handle is None:
            raise TNNotFound(name, sorted(_registry.keys()))
        return handle


def list_names() -> list[str]:
    """Return the registered ceremony names, sorted."""
    with _lock:
        return sorted(_registry.keys())


def unregister(name: str) -> None:
    """Remove ``name`` from the registry. No-op if absent.

    Intended for test cleanup and for ``flush_and_close`` semantics.
    Production code should not normally need to call this.
    """
    with _lock:
        _registry.pop(name, None)


def clear_registry_for_tests() -> None:
    """Empty the registry. Test-only; do not call from production."""
    with _lock:
        _registry.clear()
