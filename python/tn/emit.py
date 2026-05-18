"""Emit verbs: log, debug, info, warning, error.

Mirrors stdlib `logging` mental model. The level-filter threshold
short-circuits sub-threshold emits before any work happens (no
encryption, no chain advance, no I/O). The severity-less
:func:`log` always emits regardless of threshold.
"""
from __future__ import annotations

import logging
from typing import Any

# Re-import the dispatch + helpers from the package init so the runtime
# state stays a single source of truth. emit.py is a presentation layer.
from . import _session
from ._autoinit import maybe_autoinit as _maybe_autoinit

_surface = logging.getLogger("tn.surface")


def _surface_log_emit(verb: str, event_type: str, fields: dict[str, Any]) -> None:
    """Compact diagnostic record for every emit verb."""
    if not _surface.isEnabledFor(logging.INFO):
        return
    # Local import to avoid circular: __init__ -> emit -> __init__
    from . import _dispatch_rt, _run_id  # noqa: PLC0415
    _surface.info(
        "tn.%s(%r, fields=%s) dispatch=%s run_id=%s",
        verb, event_type, sorted(fields.keys()),
        "set" if _dispatch_rt is not None else "None",
        _run_id,
    )


def _reject_extra_positionals(verb: str, args: tuple) -> None:
    """Raise TypeError if positional args were passed after event_type.

    DX review #3: the previous behaviour silently folded any extra
    positionals into a joined ``message`` field, destroying the
    user's structured intent. The five verbs now take only
    ``event_type`` positionally plus keyword fields; messages go
    through the explicit ``message=`` kwarg.
    """
    if not args:
        return
    raise TypeError(
        f"tn.{verb}(event_type, **fields) — got {len(args)} extra "
        f"positional argument(s) after event_type: {args!r}. "
        f"For structured data use kwargs: "
        f"tn.{verb}('evt', user='alice', amount=4999). "
        f"For a free-text message use the 'message' kwarg: "
        f"tn.{verb}('evt', message='hello world')."
    )


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

    For the common cases, prefer the level-named verbs
    (``tn.info`` / ``.warning`` / ``.error`` / ``.debug``) — they
    short-circuit below the active threshold; ``tn.log`` always
    emits.
    """
    _reject_extra_positionals("log", args)
    _surface_log_emit("log", event_type, fields)
    _maybe_autoinit()
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice(level, event_type, fields, _resolve_sign(_sign))


def debug(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    _reject_extra_positionals("debug", args)
    if 10 < _session._log_level_threshold:
        return
    _surface_log_emit("debug", event_type, fields)
    _maybe_autoinit()
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("debug", event_type, fields, _resolve_sign(_sign))


def info(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    _reject_extra_positionals("info", args)
    if 20 < _session._log_level_threshold:
        return
    _surface_log_emit("info", event_type, fields)
    _maybe_autoinit()
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("info", event_type, fields, _resolve_sign(_sign))


def warning(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    _reject_extra_positionals("warning", args)
    if 30 < _session._log_level_threshold:
        return
    _surface_log_emit("warning", event_type, fields)
    _maybe_autoinit()
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("warning", event_type, fields, _resolve_sign(_sign))


def error(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    _reject_extra_positionals("error", args)
    _surface_log_emit("error", event_type, fields)
    if 40 < _session._log_level_threshold:
        return
    _maybe_autoinit()
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("error", event_type, fields, _resolve_sign(_sign))
