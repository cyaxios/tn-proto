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

import json
import logging
from typing import Any

from . import _session
from ._autoinit import maybe_autoinit as _maybe_autoinit


class WrittenRecord(dict):
    """The signed, encrypted envelope returned by :func:`tn.log`.

    Behaves as the on-wire envelope ``dict`` (so ``json=tn.log(...)`` and
    normal item access keep working), but ``str()`` renders valid JSON rather
    than Python ``repr`` (single quotes). That makes the attested record easy
    to *send* verbatim, e.g. ``requests.post(url, data=str(tn.log(...)))``.
    """

    __slots__ = ()

    def __str__(self) -> str:
        return json.dumps(self)

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

# Per-level docstrings — synthesised onto the closure verbs below so
# `help(tn.info)`, Pylance hover, and LLM RAG see real documentation
# instead of empty bodies. Each template is a Google-style docstring
# (Pylance renders these natively). The factory below substitutes
# `{summary}` and `{see_also_peers}` per level.
_VERB_DOC_TEMPLATE = """{summary}

{detail}

Args:
    event_type: Dotted event identifier matching
        ``[A-Za-z0-9._-]{{1,64}}``. Examples: ``"user.signed_in"``,
        ``"payment.captured"``, ``"schema.migrated"``.
    _sign: Per-call override for envelope signing. ``None`` (the
        default) falls through to the session-level / yaml-level
        ``sign`` flag; ``True`` forces a signature on this row;
        ``False`` skips signing.
    **fields: Plaintext fields to encrypt into the configured groups
        and chain into the log. Values are JSON-shaped: str, int,
        float, bool, None, list, dict, plus TN-specific sentinels
        for bytes (``$b64``), :class:`decimal.Decimal` (string), and
        :class:`datetime.datetime` (ISO-8601 UTC).

Raises:
    TypeError: If positional arguments other than ``event_type`` are
        supplied. Use keyword arguments for fields.
    RuntimeError: If :func:`tn.init` hasn't been called yet AND
        auto-init is blocked by ``TN_STRICT=1``.

Example:
    >>> import tn
    >>> tn.init()
    >>> tn.{name}("hello.world", who="alice")
    >>> tn.{name}("startup")  # no fields is OK

See Also:
    {see_also_peers}
    :func:`tn.read`: Read entries back.
    :func:`tn.log`: Severity-less variant — always emits regardless
        of the level threshold.
    `docs/spec/envelope.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/envelope.md>`_: The wire shape this emit produces.
    `docs/spec/row-hash.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/row-hash.md>`_: The chain-link hash inside each envelope.
"""


def _docstring_for(name: str) -> str:
    """Build the Google-style docstring for one of the level verbs.

    Factored out of :func:`_make_levelled_verb` so the templates stay
    readable and each level can carry its own summary + peer
    cross-references in ``See Also`` without nested f-string mess.
    """
    summary = {
        "debug": "DEBUG-level attested event (level 10).",
        "info": "INFO-level attested event (level 20).",
        "warning": "WARNING-level attested event (level 30).",
        "error": "ERROR-level attested event (level 40).",
    }[name]
    detail = {
        "debug": (
            "Verbose diagnostic events: cache lookups, trace markers,\n"
            "internal state. Suppressed when the process-wide level\n"
            "threshold (via :func:`tn.set_level`) is above DEBUG."
        ),
        "info": (
            "The most common emit verb — use for routine business\n"
            "events that should be visible on stdout and persisted to\n"
            "the chain. Suppressed when the process-wide level\n"
            "threshold is above INFO."
        ),
        "warning": (
            "Recoverable anomalies: rate limits approaching, retries,\n"
            "degraded paths. Suppressed when the process-wide level\n"
            "threshold is above WARNING."
        ),
        "error": (
            "Unrecoverable failures: caught exceptions, terminal\n"
            "protocol errors, integrity check failures. Writes to the\n"
            "diagnostic surface FIRST (before the threshold check) so\n"
            "error-level events show in stderr even when the main-log\n"
            "threshold drops them."
        ),
    }[name]
    peers = {
        "debug": ":func:`tn.info`, :func:`tn.warning`, :func:`tn.error`",
        "info": ":func:`tn.debug`, :func:`tn.warning`, :func:`tn.error`",
        "warning": ":func:`tn.debug`, :func:`tn.info`, :func:`tn.error`",
        "error": ":func:`tn.debug`, :func:`tn.info`, :func:`tn.warning`",
    }[name]
    return _VERB_DOC_TEMPLATE.format(
        summary=summary,
        detail=detail,
        name=name,
        see_also_peers=peers,
    )


def _make_levelled_verb(name: str, level_int: int, *, surface_first: bool = False):
    """Return a verb function bound to ``(name, level_int)``.

    The returned function is a regular module-level callable; the
    closure-captured ``name``, ``level_int``, ``surface_first`` are
    constants for that callable's lifetime so the body acts like a
    hand-rolled per-level function with no extra dispatch hop.

    ``surface_first=True`` mirrors ``error``'s historical ordering:
    even when the main-log threshold drops the emit, the diagnostic
    surface still gets it.

    The synthesised verb carries ``__doc__``, ``__name__``, and
    ``__qualname__`` so ``help(tn.info)``, Pylance / PyCharm hover,
    and LLM RAG over source all see real documentation — the closure
    is invisible at the IDE / introspection layer.
    """
    if surface_first:
        def verb(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
            if args:
                _raise_extra_positionals(name, args)
            if _surface_enabled(_INFO):
                _surface_diag(name, event_type, fields)
            if level_int < _session._log_level_threshold:
                return None
            if _tn_module._dispatch_rt is None:
                _maybe_autoinit()
            sign = _sign if _sign is not None else _session._sign_override
            # Fire-and-forget: dispatch the emit and discard the envelope.
            # Only ``tn.log`` returns the written record (for forwarding).
            _emit_with_splice(name, event_type, fields, sign)
    else:
        def verb(event_type: str, *args: Any, _sign: bool | None = None, **fields: Any) -> None:
            if args:
                _raise_extra_positionals(name, args)
            if level_int < _session._log_level_threshold:
                return None
            if _surface_enabled(_INFO):
                _surface_diag(name, event_type, fields)
            if _tn_module._dispatch_rt is None:
                _maybe_autoinit()
            sign = _sign if _sign is not None else _session._sign_override
            # Fire-and-forget: dispatch the emit and discard the envelope.
            # Only ``tn.log`` returns the written record (for forwarding).
            _emit_with_splice(name, event_type, fields, sign)
    verb.__name__ = name
    verb.__qualname__ = name
    verb.__doc__ = _docstring_for(name)
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
) -> WrittenRecord | None:
    """Emit an attested event with a caller-chosen level (default: severity-less).

    ``tn.log`` is **not** an alias of ``tn.info`` — it emits with
    whatever ``level=`` you pass, defaulting to ``""`` (the
    severity-less slot on :class:`tn.Entry`). ``log`` has NO threshold
    check — the caller-chosen level isn't on the standard four-rung
    ladder, so there's nothing to compare against. For
    threshold-aware emits use :func:`tn.debug` / :func:`tn.info` /
    :func:`tn.warning` / :func:`tn.error`.

    Args:
        event_type: Dotted event identifier matching
            ``[A-Za-z0-9._-]{1,64}``. Examples: ``"system.boot"``,
            ``"scan.start"``, ``"audit.checkpoint"``.
        level: Level string written verbatim into the envelope's
            ``level`` field. Default ``""`` (severity-less). Use
            arbitrary strings like ``"trace"`` or pass through a
            foreign logger's level name (``loguru_record["level"]``).
        _sign: Per-call signing override. ``None`` falls through to
            the session/yaml default; ``True`` forces signing;
            ``False`` skips it.
        **fields: Plaintext fields to encrypt into the configured
            groups and chain into the log. JSON-shaped values plus
            TN sentinels (bytes -> ``$b64``, Decimal -> string,
            datetime -> ISO-8601 UTC).

    Returns:
        The signed on-wire envelope that was written — the parsed
        canonical record (``device_identity``, ``event_type``,
        ``sequence``, ``prev_hash``, ``row_hash``, ``signature``, the
        encrypted per-group blocks, and the equality-index tokens) as a
        JSON-ready ``dict`` — or ``None`` if the emit was filtered. Because
        it's the verbatim attested record, you can forward it downstream
        directly, e.g.
        ``requests.post(url, json=tn.log("audit.checkpoint", row=42))``.

        ``tn.log`` is the ONLY verb that returns the record. The
        threshold-aware verbs (:func:`tn.info`, :func:`tn.warning`,
        :func:`tn.debug`, :func:`tn.error`) are fire-and-forget and
        return ``None``.

    Raises:
        TypeError: If positional args other than ``event_type`` are
            supplied.
        RuntimeError: If :func:`tn.init` hasn't been called and
            ``TN_STRICT=1`` blocks auto-init.

    Example:
        >>> import tn
        >>> tn.init()
        >>> tn.log("system.boot")              # severity-less
        >>> tn.log("scan.start", level="trace")  # custom level
        >>> envelope = tn.log("audit.checkpoint", level="audit", row=42)
        >>> # forward the attested record to a downstream collector
        >>> # requests.post("https://collector.example/ingest", json=envelope)

    See Also:
        :func:`tn.info`: Threshold-aware INFO emit.
        :func:`tn.warning`: Threshold-aware WARNING emit.
        :func:`tn.set_level`: Process-wide threshold control.
        `docs/spec/envelope.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/envelope.md>`_: The wire shape this emit produces.
    """
    if args:
        _raise_extra_positionals("log", args)
    if _surface_enabled(_INFO):
        _surface_diag("log", event_type, fields)
    if _tn_module._dispatch_rt is None:
        _maybe_autoinit()
    sign = _sign if _sign is not None else _session._sign_override
    rec = _emit_with_splice(level, event_type, fields, sign)
    return WrittenRecord(rec) if rec is not None else None
