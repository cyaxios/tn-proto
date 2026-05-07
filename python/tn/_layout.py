"""On-disk layout helpers for the multi-ceremony ``.tn/`` directory.

Every function in this module is purely filesystem-shaped. No SDK
runtime state, no logger imports, no module globals. This keeps the
layout rules independent of the rest of the SDK so the ``.tn/`` shape
can be reasoned about (and migrated) without spinning up a runtime.

See ``docs/directory-layout.md`` for the contract this implements.
"""

from __future__ import annotations

import re
from pathlib import Path

from ._defaults import DEFAULT_CEREMONY_NAME, LEGACY_DEFAULT_DIRNAME

__all__ = [
    "TN_ROOT_DIRNAME",
    "TNInvalidName",
    "ceremony_dir",
    "ceremony_yaml_path",
    "is_valid_ceremony_name",
    "list_ceremonies_on_disk",
    "migrate_legacy_layout",
    "tn_root",
]


# The name of the hidden root directory. Everything ceremony-shaped
# lives under this; nothing else is allowed to.
TN_ROOT_DIRNAME = ".tn"


# Disallowed: separators (would walk out of .tn/), leading dots
# (collisions with hidden files / parent refs), and anything outside
# a conservative ascii-safe alphabet. The rule is intentionally
# stricter than the filesystem requires; cross-platform headaches
# from spaces, unicode, etc. aren't worth it for a registry name.
_VALID_NAME = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_\-]*$")


class TNInvalidName(ValueError):
    """Raised when a registry name fails ``is_valid_ceremony_name``."""


def is_valid_ceremony_name(name: str) -> bool:
    """True iff ``name`` is safe to use as a ``.tn/`` subdirectory.

    Conservative: ascii letters/digits/underscore/dash, must not start
    with a dash, must not be empty. Rejects path separators, leading
    dots, and the reserved legacy name ``tn`` (which would collide
    with the legacy single-ceremony layout)."""
    if not isinstance(name, str) or not name:
        return False
    if name == LEGACY_DEFAULT_DIRNAME:
        # The legacy directory name. Reserving it prevents a user from
        # accidentally registering a ceremony there and stepping on the
        # migration logic.
        return False
    return bool(_VALID_NAME.match(name))


def _require_valid_name(name: str) -> None:
    if not is_valid_ceremony_name(name):
        raise TNInvalidName(
            f"invalid ceremony name {name!r}: must match "
            f"[a-zA-Z0-9_][a-zA-Z0-9_-]* and is not 'tn' (reserved)."
        )


def tn_root(project_dir: Path | str | None = None) -> Path:
    """Return the ``.tn/`` directory for ``project_dir`` (default: cwd).

    Does not create it. Callers that want creation should call
    ``.mkdir(parents=True, exist_ok=True)`` themselves so the
    intent-to-create is visible at the call site.
    """
    base = Path(project_dir) if project_dir is not None else Path.cwd()
    return base.resolve() / TN_ROOT_DIRNAME


def ceremony_dir(name: str, *, project_dir: Path | str | None = None) -> Path:
    """Return the directory for ceremony ``name``."""
    _require_valid_name(name)
    return tn_root(project_dir) / name


def ceremony_yaml_path(name: str, *, project_dir: Path | str | None = None) -> Path:
    """Return the canonical ``tn.yaml`` path for ceremony ``name``."""
    return ceremony_dir(name, project_dir=project_dir) / "tn.yaml"


def list_ceremonies_on_disk(project_dir: Path | str | None = None) -> list[str]:
    """List ceremony names found on disk under ``.tn/`` for ``project_dir``.

    Returns names of immediate subdirectories of ``.tn/`` that contain a
    ``tn.yaml`` file. Subdirectories without a ``tn.yaml`` are ignored
    (they may be in the middle of being created, or be unrelated).

    Sorted for deterministic output. Empty list if ``.tn/`` does not
    exist.
    """
    root = tn_root(project_dir)
    if not root.is_dir():
        return []
    out: list[str] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if not is_valid_ceremony_name(child.name) and child.name != LEGACY_DEFAULT_DIRNAME:
            # Reject directories whose names aren't in the registry-safe
            # alphabet. Defensive: such a directory wasn't put there by
            # this SDK, so we don't claim it's a ceremony.
            continue
        if (child / "tn.yaml").is_file():
            out.append(child.name)
    return out


def migrate_legacy_layout(
    project_dir: Path | str | None = None,
    *,
    dry_run: bool = False,
) -> Path | None:
    """Migrate the legacy single-ceremony layout to the multi-ceremony
    layout, in place.

    Specifically: if ``.tn/tn/tn.yaml`` exists and ``.tn/default/`` does
    not, rename ``.tn/tn/`` to ``.tn/default/``. Returns the new path
    if a migration was performed, ``None`` otherwise.

    If both ``.tn/tn/`` and ``.tn/default/`` exist, raises
    ``RuntimeError`` rather than guessing which one to keep — that is
    state the user must resolve by hand.

    ``dry_run=True`` returns the would-migrate-to path without touching
    the filesystem. Useful for tests and for surfacing the migration
    in a dry-run CLI.
    """
    root = tn_root(project_dir)
    legacy = root / LEGACY_DEFAULT_DIRNAME
    target = root / DEFAULT_CEREMONY_NAME

    if not (legacy.is_dir() and (legacy / "tn.yaml").is_file()):
        return None

    if target.exists():
        # Both exist: ambiguous. Don't touch either. Surface a friendly
        # error so the user knows exactly what to do.
        raise RuntimeError(
            f"TN layout migration ambiguous: both {legacy} and "
            f"{target} exist. Resolve by hand: pick one, delete the "
            "other, then re-run."
        )

    if dry_run:
        return target

    legacy.rename(target)
    return target
