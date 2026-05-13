"""Lifecycle verbs: flush_and_close, session, current_config, using_rust.

The high-frequency control-plane verbs that bracket every TN session.
The module-level dispatch runtime (`_dispatch_rt`) and `_run_id` still
live in `tn/__init__.py` — lifecycle.py imports them back where needed.

Note: ``init`` previously lived here as a thin wrapper around
``tn._init_impl``. That wrapper was removed when the init chain was
flattened (see [tn-proto#36](https://github.com/cyaxios/tn-proto/issues/36));
callers now use ``tn.init`` (the public entry) or ``tn._init_impl``
(internal). ``flush_and_close`` is itself tracked for removal in
[tn-proto#35](https://github.com/cyaxios/tn-proto/issues/35).
"""
from __future__ import annotations

from typing import Any  # noqa: F401 — used in `session(...)` annotation below


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
