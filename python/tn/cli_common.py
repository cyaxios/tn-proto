"""Shared leaf helpers for the ``tn`` CLI command modules.

These are the small, dependency-light pieces used across ``cli.py`` and the
``cli_<domain>.py`` handler modules: TTY detection, the fatal-error printer,
identity loading, and yaml discovery. Keeping them here lets every command
module import one canonical copy instead of redefining its own.

``_die`` is ``NoReturn`` (it calls :func:`sys.exit`); callers do not need a
trailing ``return``/``raise`` after it.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NoReturn

from ._autoinit import _resolve_existing_yaml
from .identity import Identity, IdentityError


def _is_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _die(msg: str, code: int = 1) -> NoReturn:
    print(f"tn: error: {msg}", file=sys.stderr)
    sys.exit(code)


def _print_mnemonic_banner(mnemonic: str) -> None:
    bar = "=" * 76
    print()
    print(bar)
    print("  WRITE THIS DOWN NOW. You will NOT see it again without")
    print("  explicit re-display, and without it you CANNOT recover")
    print("  your TN identity if this machine is lost.")
    print(bar)
    print()
    print(f"  {mnemonic}")
    print()
    print(bar)
    print()


def _load_identity_or_die(path: Path) -> Identity:
    try:
        return Identity.load(path)
    except IdentityError as e:
        _die(
            f"{e}. Run `tn init <project>` to create one, or "
            f"`tn wallet restore --mnemonic ...` on a fresh machine.",
        )


def _resolve_yaml_or_discover(arg: str | None) -> Path:
    """Resolve a yaml path: explicit arg if given; otherwise walk the same
    discovery chain ``tn.init()`` uses (``$TN_YAML``, ``./tn.yaml``,
    ``$TN_HOME/tn.yaml``), then fall back to any single ``*.yaml`` in
    the cwd that looks like a TN ceremony (top-level ``ceremony:`` AND
    ``me:`` blocks). Lets the recipient-flow verbs (S6.4) work as one
    bare command in a project dir whose yaml isn't called ``tn.yaml``
    — e.g. the cash-_register assignment's ``_register.yaml``.

    Errors loudly if nothing's found or multiple ceremonies tie. CLI
    verbs are operator actions, not onboarding flows; auto-creating a
    fresh ceremony from the CLI would surprise the caller."""
    if arg:
        p = Path(arg).resolve()
        if not p.exists():
            _die(f"yaml not found: {p}")
        return p

    discovered = _resolve_existing_yaml()
    if discovered is not None:
        return discovered

    # Final fallback: any *.yaml in cwd that smells like a ceremony.
    cwd_candidates: list[Path] = []
    for entry in sorted(Path.cwd().iterdir()):
        if not entry.is_file() or entry.suffix not in (".yaml", ".yml"):
            continue
        try:
            head = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "ceremony:" in head and "me:" in head and "did:" in head:
            cwd_candidates.append(entry.resolve())
    if len(cwd_candidates) == 1:
        return cwd_candidates[0]
    if len(cwd_candidates) > 1:
        names = ", ".join(p.name for p in cwd_candidates)
        _die(
            f"multiple ceremony yamls in cwd ({names}). Pass --yaml to disambiguate."
        )
    _die(
        "no ceremony found here. Looked at $TN_YAML, ./tn.yaml, "
        "~/.tn/tn.yaml, and any *.yaml in the cwd with a ceremony: block.\n"
        "  - Restoring a downloaded seed (.tnpkg)?  run: tn import <seed.tnpkg>\n"
        "  - Starting a brand-new project?          run: tn init <name>\n"
        "  - Ceremony lives elsewhere?              pass --yaml <path>, or cd "
        "into its directory."
    )
