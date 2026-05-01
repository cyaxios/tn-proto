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


def _absorb_positional_message(args: tuple, fields: dict) -> None:
    """If positional args are passed after event_type, join them with
    spaces and store under 'message' (stdlib-style brevity)."""
    if not args:
        return
    if "message" in fields:
        fields["message"] = fields["message"] + " " + " ".join(str(a) for a in args)
    else:
        fields["message"] = " ".join(str(a) for a in args)


def log(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    """Severity-less log."""
    _surface_log_emit("log", event_type, fields)
    _maybe_autoinit()
    _absorb_positional_message(args, fields)
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("", event_type, fields, _resolve_sign(_sign))


def debug(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    if 10 < _session._log_level_threshold:
        return
    _surface_log_emit("debug", event_type, fields)
    _maybe_autoinit()
    _absorb_positional_message(args, fields)
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("debug", event_type, fields, _resolve_sign(_sign))


def info(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    if 20 < _session._log_level_threshold:
        return
    _surface_log_emit("info", event_type, fields)
    _maybe_autoinit()
    _absorb_positional_message(args, fields)
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("info", event_type, fields, _resolve_sign(_sign))


def warning(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    if 30 < _session._log_level_threshold:
        return
    _surface_log_emit("warning", event_type, fields)
    _maybe_autoinit()
    _absorb_positional_message(args, fields)
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("warning", event_type, fields, _resolve_sign(_sign))


def error(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
    _surface_log_emit("error", event_type, fields)
    if 40 < _session._log_level_threshold:
        return
    _maybe_autoinit()
    _absorb_positional_message(args, fields)
    from . import _emit_with_splice, _resolve_sign  # noqa: PLC0415
    _emit_with_splice("error", event_type, fields, _resolve_sign(_sign))
