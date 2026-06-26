"""Process-local registry of named TN ceremony handles.

The registry maps ``(project_root, registry_name)`` to its in-process
``TN`` handle. The project component matters: two Projects can both
have a stream named ``api`` and must not alias each other in one
process.

The registry is process-local. Multi-process write coordination is a
separate concern (file locking on ``.tn/<name>/``), not solved here.
"""

from __future__ import annotations

import threading
from pathlib import Path
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


_registry: dict[tuple[str, str], TN] = {}
_lock = threading.Lock()


def _project_key(project_dir: str | Path | None, handle: TN | None = None) -> str:
    if project_dir is not None:
        return str(Path(project_dir).resolve())
    if handle is not None:
        directory = Path(handle.directory).resolve()
        if directory.parent.name == ".tn":
            return str(directory.parent.parent.resolve())
    return str(Path.cwd().resolve())


def _matching_by_name(name: str) -> list[tuple[tuple[str, str], TN]]:
    return [(k, h) for k, h in _registry.items() if k[1] == name]


def register(name: str, handle: TN, *, project_dir: str | Path | None = None) -> None:
    """Bind ``(project_dir, name) -> handle`` in the registry.

    Idempotent if the handle is the same object; otherwise raises
    ``RuntimeError`` to prevent silent replacement (which would be a
    nasty source of "I emitted to the wrong ceremony" bugs).
    """
    if not is_valid_ceremony_name(name):
        # The layout module already validates; this is a defense in
        # depth so nothing odd makes it into the registry even if a
        # caller bypasses ``tn.init`` / ``tn.use``.
        raise ValueError(f"invalid ceremony name {name!r}")
    key = (_project_key(project_dir, handle), name)
    with _lock:
        existing = _registry.get(key)
        if existing is None:
            _registry[key] = handle
            return
        if existing is handle:
            return
        raise RuntimeError(
            f"ceremony {name!r} in project {key[0]!r} is already registered "
            "to a different TN handle in this process. This is almost "
            "always a bug in init/use ordering. Investigate before forcing "
            "a swap."
        )


def get(name: str, *, project_dir: str | Path | None = None) -> TN:
    """Strict registry lookup. Raises ``TNNotFound`` if missing.

    The friendly-error wrapping (did-you-mean, disk-attach hint) lives
    in ``tn.use`` — this function stays terse so internal callers can
    use it without paying for that work.
    """
    with _lock:
        if project_dir is not None:
            handle = _registry.get((_project_key(project_dir), name))
        else:
            matches = _matching_by_name(name)
            handle = matches[0][1] if len(matches) == 1 else None
        if handle is None:
            if project_dir is not None:
                pkey = _project_key(project_dir)
                registered = sorted(n for (project, n) in _registry if project == pkey)
            else:
                registered = sorted({n for (_project, n) in _registry})
            raise TNNotFound(name, registered)
        return handle


def list_names(*, project_dir: str | Path | None = None) -> list[str]:
    """Return registered ceremony names, sorted.

    When ``project_dir`` is provided, only names in that Project are
    returned. Without it, names are de-duplicated across Projects for
    backwards-compatible test/debug usage.
    """
    with _lock:
        if project_dir is not None:
            pkey = _project_key(project_dir)
            return sorted(name for (project, name) in _registry if project == pkey)
        return sorted({name for (_project, name) in _registry})


def unregister(name: str, *, project_dir: str | Path | None = None) -> None:
    """Remove ``name`` from the registry. No-op if absent.

    Intended for test cleanup and for ``flush_and_close`` semantics.
    Production code should not normally need to call this.
    """
    with _lock:
        if project_dir is not None:
            _registry.pop((_project_key(project_dir), name), None)
            return
        for key in [k for k in _registry if k[1] == name]:
            _registry.pop(key, None)


def clear_registry_for_tests() -> None:
    """Empty the registry. Test-only; do not call from production."""
    with _lock:
        _registry.clear()
