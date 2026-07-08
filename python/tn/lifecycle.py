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

from typing import Any


def flush_and_close(*, timeout: float = 30.0) -> None:
    """Close all handlers and release the active runtime.

    Drains async outboxes on a best-effort basis (Kafka / S3 / Delta
    exporters write pending events out before shutdown), then
    releases the in-memory runtime so the next :func:`tn.init` mints
    fresh.

    You usually don't need to call this explicitly — :func:`tn.init`
    registers an ``atexit`` hook that drains handlers on normal
    interpreter shutdown. Call this only when you need deterministic
    flush *before* the process exits (e.g., before forking, before
    assertions in tests, or in long-running services that re-init
    periodically). For deterministic scoping use
    ``with tn.session(): ...`` instead.

    Idempotent — safe to call multiple times; calling on a
    never-initialised process is a no-op.

    Args:
        timeout: Maximum seconds to wait for each async outbox to
            drain. Per-handler; total wall-clock can be up to
            ``timeout * len(async_handlers)``. Default 30.

    Example:
        >>> import tn
        >>> tn.init()
        >>> tn.info("checkout.completed", order_id="o_456")
        >>> tn.flush_and_close()  # ensures the event ships before exit

    See Also:
        :func:`tn.init`: The constructor side of the lifecycle.
        :func:`tn.session`: Context manager that auto-flushes on exit.
        :func:`tn.current_config`: Read the active ceremony config.
    """
    from . import _flush_and_close_impl
    return _flush_and_close_impl(timeout=timeout)


def current_config():
    """Return the :class:`LoadedConfig` for the active ceremony.

    Read-only snapshot of the yaml that was loaded at :func:`tn.init`
    time — ceremony id, cipher, groups, public-fields set, handler
    specs, device identity, log paths, keystore paths. Mutating the
    returned object won't propagate to the live runtime; for that
    use :func:`tn.logger.reload_from_yaml` after editing the yaml on
    disk.

    Returns:
        LoadedConfig: The active ceremony's in-memory config.

    Raises:
        RuntimeError: If no runtime is active. Call :func:`tn.init`
            (or :func:`tn.absorb` for a freshly-downloaded
            ``project_seed`` / ``identity_seed``) first.

    Example:
        >>> import tn
        >>> tn.init()
        >>> cfg = tn.current_config()
        >>> cfg.ceremony_id
        'local_a1b2c3d4'
        >>> list(cfg.groups.keys())
        ['default', 'tn.agents']

    See Also:
        :func:`tn.using_rust`: Diagnostic — is the Rust runtime active?
        :func:`tn.init`: How the config gets loaded.
    """
    from . import _current_config_impl
    return _current_config_impl()


def using_rust() -> bool:
    """Whether emit / read are currently routed through the Rust runtime.

    Diagnostic helper. Returns ``True`` when the active ceremony uses
    cipher ``btn`` on every group AND the ``tn_core`` Rust extension
    is loaded AND the ``TN_FORCE_PYTHON`` env var is unset. Returns
    ``False`` when emit/read fall back to the pure-Python path.

    The Rust path is a transparent performance optimisation; the
    public verb surface (``tn.info``, ``tn.read``, etc.) behaves
    identically either way. Use this only for tracing / benchmarking.

    Returns:
        bool: ``True`` if Rust is active, ``False`` if Python.

    Example:
        >>> import tn
        >>> tn.init()
        >>> tn.using_rust()
        True

    See Also:
        :func:`tn.current_config`: Inspect the loaded ceremony.
    """
    from . import _using_rust_impl
    return _using_rust_impl()


def session(yaml_or_tmpdir: Any = None):
    """Open a TN session as a context manager.

    Recommended way to scope a TN init — auto-cleans up on context
    exit (flushes handlers, releases the runtime). Nested sessions
    save and restore the parent's runtime so inner blocks don't leak.

    Args:
        yaml_or_tmpdir: Optional ceremony yaml path OR a tempdir
            override. ``None`` uses the standard discovery chain.
            Strings ending in ``.yaml`` / ``.yml`` are treated as
            yaml paths; other strings are treated as tempdir roots
            for an ephemeral session.

    Returns:
        Context manager. The ``as`` value is a session handle
        exposing the same verbs as the module-level ``tn.*``.

    Example:
        >>> import tn
        >>> with tn.session() as t:
        ...     t.info("scoped.event", key="value")
        ...     # auto-flushed on exit; outer state restored

        >>> # Ephemeral session against a tempdir:
        >>> import tempfile
        >>> with tempfile.TemporaryDirectory() as td:
        ...     with tn.session(td) as t:
        ...         t.info("test.event")

    See Also:
        :func:`tn.init`: The non-scoped constructor.
        :func:`tn.flush_and_close`: Manual lifecycle alternative.
    """
    from . import _session_impl
    return _session_impl(yaml_or_tmpdir)
