"""Emit verbs: log, debug, info, warning, error.

Mirrors stdlib `logging` mental model. The level-filter threshold
short-circuits sub-threshold emits before any work happens (no
encryption, no chain advance, no I/O). The severity-less
:func:`log` always emits regardless of threshold.

Hot path note (0.4.2a7): every per-emit decision that doesn't change
during a process is bound at module load — the late ``from . import
_emit_with_splice, _resolve_sign`` that the previous verbs did on
every call is gone. ``tn/__init__.py`` calls
:func:`_bind_dependencies` once at the tail of its own load, which
replaces the placeholders below with the real callables.

Structure note (0.4.2a7): ``debug`` / ``info`` / ``warning`` / ``error``
share one body via a closure factory (:func:`_make_levelled_verb`).
``log`` is its own function because it carries the caller-chosen
``level=`` kwarg and has no threshold check. ``error`` runs the
diagnostic-surface emit *before* the threshold check (errors are
always interesting to the surface logger even when the main-log
threshold drops them); the standard verbs run it *after*.
"""
from __future__ import annotations

import logging
from typing import Any

from . import _session
from ._autoinit import maybe_autoinit as _maybe_autoinit

# ---------------------------------------------------------------------------
# Module-level cached state. Populated at package load by
# ``_bind_dependencies()`` so the verbs avoid a late ``from . import ...``
# on every call. The placeholders are set during emit.py's own load so
# the names exist for the linter; they're overwritten before any verb
# runs.
# ---------------------------------------------------------------------------
_emit_with_splice: Any = None
_resolve_sign: Any = None
_tn_module: Any = None
_surface = logging.getLogger("tn.surface")
# Cache the bound method so a verb just does ``_surface_enabled(20)``
# instead of two attribute lookups (._surface.isEnabledFor) every call.
_surface_enabled = _surface.isEnabledFor

# Level constants (mirror logging.{DEBUG,INFO,...}) inlined locally to
# skip the ``logging.`` attribute lookup the disabled-fast-path
# previously paid every emit.
_DEBUG = 10
_INFO = 20
_WARNING = 30
_ERROR = 40


def _bind_dependencies() -> None:
    """Bind the callables that emit.py needs from the parent package.

    Called once from ``tn/__init__.py`` at the bottom of its own load,
    after ``_emit_with_splice`` / ``_resolve_sign`` are defined. We
    can't do a normal module-level ``from . import _emit_with_splice``
    inside emit.py because emit.py is imported during ``tn/__init__``'s
    own initialization — the names aren't bound yet at that point.
    """
    global _emit_with_splice, _resolve_sign, _tn_module
    import tn as _tn

    _tn_module = _tn
    _emit_with_splice = _tn._emit_with_splice  # type: ignore[attr-defined]
    _resolve_sign = _tn._resolve_sign  # type: ignore[attr-defined]


def _raise_extra_positionals(verb: str, args: tuple) -> None:
    """Raise the helpful TypeError when a caller passed extra positionals.

    Split out of the per-emit hot path so the common ``args == ()``
    case doesn't pay for the format string + raise machinery. DX
    review #3: the previous behaviour silently folded any extra
    positionals into a joined ``message`` field, destroying the
    user's structured intent. The five verbs now take only
    ``event_type`` positionally plus keyword fields; messages go
    through the explicit ``message=`` kwarg.
    """
    raise TypeError(
        f"tn.{verb}(event_type, **fields) — got {len(args)} extra "
        f"positional argument(s) after event_type: {args!r}. "
        f"For structured data use kwargs: "
        f"tn.{verb}('evt', user='alice', amount=4999). "
        f"For a free-text message use the 'message' kwarg: "
        f"tn.{verb}('evt', message='hello world')."
    )


def _surface_diag(verb: str, event_type: str, fields: dict[str, Any]) -> None:
    """Diagnostic record emission (only called when the surface logger
    is actually enabled at INFO). The verb-side fast path skips this
    call entirely when ``_surface_enabled(_INFO)`` is False.
    """
    _surface.info(
        "tn.%s(%r, fields=%s) dispatch=%s run_id=%s",
        verb, event_type, sorted(fields.keys()),
        "set" if _tn_module._dispatch_rt is not None else "None",
        _tn_module._run_id,
    )


# ---------------------------------------------------------------------------
# Verb factory.
#
# `debug`, `info`, `warning`, `error` differ only in (a) the name they
# pass into diagnostics, (b) the integer level used for the threshold
# check, and (c) whether `error` runs `_surface_diag` BEFORE the
# threshold (so errors hit the surface logger even when the main log
# is filtering them out). One factory captures all three differences
# in a closure so the per-verb function has identical body shape and
# zero parameter-passing overhead at call time.
# ---------------------------------------------------------------------------

def _make_levelled_verb(name: str, level_int: int, *, surface_first: bool = False):
    """Return a verb function bound to (name, level_int).

    The returned function is a regular module-level callable; the
    closure-captured ``name``, ``level_int``, ``surface_first`` are
    constants for that callable's lifetime so the body acts like a
    hand-rolled per-level function with no extra dispatch hop.

    ``surface_first=True`` mirrors ``error``'s historical ordering:
    even when the main-log threshold drops the emit, the diagnostic
    surface still gets it.
    """
    if surface_first:
        def verb(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
            if args:
                _raise_extra_positionals(name, args)
            if _surface_enabled(_INFO):
                _surface_diag(name, event_type, fields)
            if level_int < _session._log_level_threshold:
                return
            if _tn_module._dispatch_rt is None:
                _maybe_autoinit()
            sign = _sign if _sign is not None else _session._sign_override
            _emit_with_splice(name, event_type, fields, sign)
    else:
        def verb(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
            if args:
                _raise_extra_positionals(name, args)
            if level_int < _session._log_level_threshold:
                return
            if _surface_enabled(_INFO):
                _surface_diag(name, event_type, fields)
            if _tn_module._dispatch_rt is None:
                _maybe_autoinit()
            sign = _sign if _sign is not None else _session._sign_override
            _emit_with_splice(name, event_type, fields, sign)
    verb.__name__ = name
    verb.__qualname__ = name
    return verb


debug = _make_levelled_verb("debug", _DEBUG)
info = _make_levelled_verb("info", _INFO)
warning = _make_levelled_verb("warning", _WARNING)
error = _make_levelled_verb("error", _ERROR, surface_first=True)


def log(
    event_type: str,
    *args: Any,
    level: str = "",
    _sign: bool | None = None,
    **fields: Any,
) -> None:
    """Emit an entry with a caller-chosen level (default: severity-less).

    DX review #13: ``tn.log`` is **not** an alias of ``tn.info`` — it
    emits with whatever ``level=`` you pass, defaulting to ``""``
    (the severity-less slot on ``Entry.level``). Use it when:

      * You want a level outside the standard four
        (``tn.log("scan.start", level="trace")``).
      * You want an explicit severity-less event
        (``tn.log("system.boot")``).
      * You're bridging from a foreign logger and want the level
        string verbatim (``tn.log("e", level=loguru_record["level"])``).

    ``log`` has no threshold check — the caller-chosen level isn't on
    the standard four-rung ladder, so there's nothing to compare
    against. For threshold-aware emits use the named verbs.
    """
    if args:
        _raise_extra_positionals("log", args)
    if _surface_enabled(_INFO):
        _surface_diag("log", event_type, fields)
    if _tn_module._dispatch_rt is None:
        _maybe_autoinit()
    sign = _sign if _sign is not None else _session._sign_override
    _emit_with_splice(level, event_type, fields, sign)
