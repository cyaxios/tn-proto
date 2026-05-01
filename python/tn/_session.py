"""Session-level toggles + module-global state.

Underscore-prefixed because the public-facing surface is the four
verbs (set_signing, set_level, get_level, is_enabled_for) re-exported
flat at the top of `tn/`. Importing from `tn._session` directly is
not part of the public API.
"""
from __future__ import annotations

import logging

_surface = logging.getLogger("tn.surface")

_LEVEL_VALUES: dict[str, int] = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
}

# Module-global state. Re-exported by tn/__init__.py.
_log_level_threshold: int = 10  # default = DEBUG (everything emits)
_sign_override: bool | None = None  # None = use yaml default


def _level_value(level) -> int:
    if isinstance(level, int) and not isinstance(level, bool):
        return level
    if isinstance(level, str):
        s = level.lower().strip()
        if s == "":
            return -1  # severity-less; below every meaningful threshold
        if s in _LEVEL_VALUES:
            return _LEVEL_VALUES[s]
        raise ValueError(
            f"unknown level {level!r}; expected one of "
            f"{sorted(_LEVEL_VALUES)} or an int"
        )
    raise TypeError(f"level must be str or int, got {type(level).__name__}")


def set_signing(enabled: bool | None) -> None:
    """Session-level signing override.

    - ``tn.set_signing(True)``  — force every emit to sign (overrides yaml).
    - ``tn.set_signing(False)`` — skip signing on every emit. Entries still
      get row_hash + prev_hash (chain integrity), but no Ed25519 signature.
    - ``tn.set_signing(None)``  — revert to the ceremony's yaml ``ceremony.sign``
      default.

    Only takes effect on Rust-routed btn ceremonies (the default for btn).
    JWE/BGW ceremonies always sign — the feature is a Rust-path-only flag
    until the legacy logger gains it.
    """
    global _sign_override
    _surface.info("tn.set_signing(%r) prior=%r", enabled, _sign_override)
    _sign_override = enabled


def set_level(level) -> None:
    """Set the active log-level threshold for this process.

    Verbs whose level is below the threshold short-circuit before any
    work happens — no encryption, no chain advance, no I/O. Use this
    in hot loops to cheaply gate ``tn.debug`` instrumentation.

    Mirrors ``logging.Logger.setLevel`` (AVL J3.2): a fresh process
    starts at ``"debug"`` so every emit fires; raise it to ``"info"``,
    ``"warning"``, or ``"error"`` to drop lower-priority verbs.

    The severity-less ``tn.log()`` (no level= kwarg) always emits
    regardless of the threshold — it's an explicit "this is a fact"
    primitive whose semantics shouldn't depend on the filter.
    """
    global _log_level_threshold
    new_threshold = _level_value(level)
    _surface.info(
        "tn.set_level(%r) prior_threshold=%d new_threshold=%d",
        level, _log_level_threshold, new_threshold,
    )
    _log_level_threshold = new_threshold


def get_level() -> str:
    """Return the active threshold as a level name, or stringified int
    when the value isn't one of the four standard names."""
    inv = {v: k for k, v in _LEVEL_VALUES.items()}
    return inv.get(_log_level_threshold, str(_log_level_threshold))


def is_enabled_for(level) -> bool:
    """True iff the given level would currently emit. Use as a guard
    around expensive log-arg construction — e.g. dumping a large
    structure that's only useful when DEBUG is on. Mirrors stdlib
    ``logging.Logger.isEnabledFor``.
    """
    return _level_value(level) >= _log_level_threshold


def _resolve_sign(call_override: bool | None) -> bool | None:
    """Merge per-call override with session-level override.

    Per-call ``_sign=`` wins over session-level ``tn.set_signing(...)``. Both
    fall through to the ceremony's yaml flag when None.
    """
    if call_override is not None:
        return call_override
    return _sign_override
