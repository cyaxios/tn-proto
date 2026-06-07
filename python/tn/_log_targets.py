"""Shared resolver for ``tn.read(log=...)`` and ``tn.watch(log=...)``.

Both verbs accept the same kinds of ``log`` argument:

* ``None``                 — caller's default (typically the main log).
* ``"admin"``              — the ceremony's admin log location (alias).
* ``Path`` / literal string — a single file path.
* a template string         — e.g. ``"./.tn/admin/{event_type}.ndjson"``.
                              Expanded via ``{event_type}`` / ``{event_class}``
                              / ``{date}`` / ``{yaml_dir}`` / ``{ceremony_id}``
                              / ``{did}`` glob-substitution, returning every
                              matching existing file.

By centralising the resolver here, the two public verbs stay
symmetric and the template-glob capability that was previously
internal to ``_pel_glob_files`` becomes addressable from the public
surface. Anyone wanting to read back the admin log writes
``tn.read(log="admin")`` (sugar) or ``tn.read(log=cfg.admin_log_location)``
(explicit). The default ``tn.read()`` / ``tn.watch()`` stays main-log
only — admin events are addressed explicitly, never merged
implicitly.
"""
from __future__ import annotations

import re as _re
from pathlib import Path
from typing import Any

_ADMIN_ALIAS = "admin"


def _has_template_tokens(s: str) -> bool:
    """True iff ``s`` contains any ``{token}`` substitution placeholder."""
    return bool(_re.search(r"\{[^}]+\}", s))


def _expand_template_to_existing_files(template: str, yaml_dir: Path) -> list[Path]:
    """Substitute every ``{token}`` with a glob wildcard and return
    matching existing files under ``yaml_dir``.

    Mirrors the legacy ``_pel_glob_files`` logic so callers that
    previously got merged template-globbed reads via the internal
    helper get the same set of files back when addressing the same
    template through the public API.
    """
    pat = template.replace("{yaml_dir}", str(yaml_dir))
    pat = _re.sub(r"\{[^}]+\}", "*", pat)
    p = Path(pat)
    if p.is_absolute():
        if "*" not in pat and "?" not in pat:
            return [p] if p.is_file() else []
        parts = p.parts
        i = next(
            (j for j, part in enumerate(parts) if "*" in part or "?" in part),
            len(parts),
        )
        base = Path(*parts[:i]) if i > 0 else p.parent
        rel = str(Path(*parts[i:]))
        return list(base.glob(rel)) if base.exists() else []
    rel_parts = Path(pat).parts
    rel = (
        str(Path(*rel_parts[1:]))
        if rel_parts and rel_parts[0] == "."
        else str(Path(pat))
    )
    return list(yaml_dir.glob(rel)) if rel and yaml_dir.exists() else []


def resolve_log_target(target: Any, cfg: Any) -> list[Path]:
    """Resolve a public ``log=`` argument to a concrete file list.

    Returns an empty list when nothing matches; the caller decides
    whether that's fatal or just "no events yet" — both verbs treat it
    as the latter (they yield nothing rather than raising, matching
    today's behaviour for a missing log file).

    Recognised forms:

    * ``"admin"`` — sugar for the ceremony's admin log address. If
      that address is templated, glob it. If it's the legacy
      ``"main_log"`` sentinel, fall back to the main log.
    * ``str`` / ``Path`` containing ``{token}`` placeholders — glob
      expansion under ``cfg.yaml_path.parent``.
    * ``str`` / ``Path`` without template tokens — returned as a
      single-entry list (existence check is the caller's job).

    The yaml-dir anchoring matches ``_pel_glob_files``: relative
    templates resolve against the ceremony's yaml directory, not the
    process CWD, so a `tn.read(log="...")` call gives the same answer
    no matter where the script runs from.
    """
    if target is None:
        return []

    yaml_dir = Path(cfg.yaml_path).parent if cfg is not None else Path.cwd()

    # 1. ``"admin"`` alias.
    if isinstance(target, str) and target == _ADMIN_ALIAS:
        admin = getattr(cfg, "admin_log_location", None) if cfg is not None else None
        if not admin or admin == "main_log":
            # Operator folded admin events back into the main log, or
            # cfg doesn't carry an admin address. Fall back to main log.
            main = cfg.resolve_log_path() if cfg is not None else None
            return [main] if main else []
        return _admin_to_paths(admin, yaml_dir)

    # 2. Templated path (literal containing {tokens}).
    if isinstance(target, str) and _has_template_tokens(target):
        return _expand_template_to_existing_files(target, yaml_dir)

    # 3. Plain path (str or Path). Closes #59:
    #
    #    * Absolute path: used as-is.
    #    * Relative path that EXISTS under CWD: use it (matches every
    #      other Python file-API).
    #    * Relative path that doesn't exist under CWD but DOES under
    #      yaml_dir: use the yaml_dir form (so config-supplied paths
    #      like ``cfg.admin_log_location == "./admin/admin.ndjson"``
    #      keep working when fed back to ``tn.read(log=...)``).
    #    * Neither exists: return the CWD form so the downstream
    #      ``FileNotFoundError`` points the operator at the path
    #      they actually typed.
    p = Path(target)
    if p.is_absolute():
        return [p]
    cwd_anchored = (Path.cwd() / p).resolve()
    if cwd_anchored.exists():
        return [cwd_anchored]
    if cfg is not None:
        yaml_anchored = (yaml_dir / p).resolve()
        if yaml_anchored.exists():
            return [yaml_anchored]
    return [cwd_anchored]


def _admin_to_paths(admin_location: str, yaml_dir: Path) -> list[Path]:
    """Resolve a stored ``admin_log_location`` (possibly templated) to
    a file list. Pulled out so ``"admin"`` alias and explicit-template
    callers share one code path.
    """
    if _has_template_tokens(admin_location):
        return _expand_template_to_existing_files(admin_location, yaml_dir)
    p = Path(admin_location)
    if not p.is_absolute():
        p = (yaml_dir / p).resolve()
    return [p]
