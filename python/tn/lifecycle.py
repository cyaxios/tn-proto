"""Lifecycle verbs: init, flush_and_close, session, current_config, using_rust.

The high-frequency control-plane verbs that bracket every TN session.
The module-level dispatch runtime (`_dispatch_rt`) and `_run_id` still
live in `tn/__init__.py` — lifecycle.py imports them back where needed.
"""
from __future__ import annotations

from typing import Any  # noqa: F401 — used in `session(...)` annotation below


def init(
    yaml_path=None,
    *,
    log_path=None,
    pool_size: int = 4,
    cipher: str = "btn",
    identity=None,
    extra_handlers=None,
    stdout: bool | None = None,
    link: bool | None = None,
) -> None:
    """Initialize TN for this process. See tn/__init__.py:_init_impl for the
    full discovery chain behavior; this is the same function, relocated.

    ``link`` controls the post-init vault upload + claim URL surfacing
    (parity with the ``tn init`` CLI verb).

      * ``None`` (default) — run iff inside an IPython/Jupyter/Databricks
        kernel; plain Python callers (scripts, tests, library use) get
        a clean ceremony with no vault contact.
      * ``True`` — force run regardless of context.
      * ``False`` — never run (CLI uses this to keep its own block).

    Env opt-out: ``TN_NO_LINK=1`` skips the upload even when ``link=True``."""
    from . import _init_impl
    return _init_impl(
        yaml_path,
        log_path=log_path,
        pool_size=pool_size,
        cipher=cipher,
        identity=identity,
        extra_handlers=extra_handlers,
        stdout=stdout,
        link=link,
    )


def flush_and_close(*, timeout: float = 30.0) -> None:
    """Close all handlers (drains async outboxes best-effort)."""
    from . import _flush_and_close_impl
    return _flush_and_close_impl(timeout=timeout)


def current_config():
    """Return the LoadedConfig for the active ceremony."""
    from . import _current_config_impl
    return _current_config_impl()


def using_rust() -> bool:
    """Diagnostic: True iff the current runtime is routed through tn_core (Rust)."""
    from . import _using_rust_impl
    return _using_rust_impl()


def session(yaml_or_tmpdir: Any = None):
    """Open a TN session as a context manager."""
    from . import _session_impl
    return _session_impl(yaml_or_tmpdir)
