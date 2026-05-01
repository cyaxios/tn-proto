"""Session context manager + handle.

Mutates the runtime singleton on the ``tn`` module via late imports so a
``with tn.session(...)`` block isolates its ceremony from the surrounding
process and restores the prior runtime on exit.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_logger = logging.getLogger("tn")


class _SessionHandle:
    """Object yielded from ``tn.session()``. Exposes the same verb set as
    the module-level ``tn.*`` API but bound to the session's ceremony.

    Inside the ``with`` block, ``tn.info(...)`` (etc.) ALSO routes through
    the session because the session swaps ``tn._dispatch_rt`` to its
    runtime; restoration happens on exit. This handle exists so callers
    that prefer the explicit ``with tn.session() as t: t.info(...)``
    style work too.
    """

    def __init__(self, yaml_path: Path) -> None:
        self.yaml_path = yaml_path

    @property
    def did(self) -> str:
        from . import current_config
        return current_config().device.did

    def log(self, event_type: str, *args: Any, **fields: Any) -> None:
        from . import log
        log(event_type, *args, **fields)

    def debug(self, event_type: str, *args: Any, **fields: Any) -> None:
        from . import debug
        debug(event_type, *args, **fields)

    def info(self, event_type: str, *args: Any, **fields: Any) -> None:
        from . import info
        info(event_type, *args, **fields)

    def warning(self, event_type: str, *args: Any, **fields: Any) -> None:
        from . import warning
        warning(event_type, *args, **fields)

    def error(self, event_type: str, *args: Any, **fields: Any) -> None:
        from . import error
        error(event_type, *args, **fields)

    def read(self, *args: Any, **kwargs: Any):
        from . import read
        return read(*args, **kwargs)

    def read_raw(self, *args: Any, **kwargs: Any):
        from . import read_raw
        return read_raw(*args, **kwargs)

    def recipients(self, group: str, **kwargs: Any):
        from . import admin as _admin
        return _admin.recipients(group, **kwargs)

    def admin_state(self, group: str | None = None) -> dict:
        from . import admin as _admin
        return _admin.state(group)


class _Session:
    """Context manager produced by ``tn.session()``.

    On enter:
      * snapshot the current ``_dispatch_rt`` (often None),
      * call ``flush_and_close()`` if a runtime was already bound — we
        swap it out cleanly so the inner ceremony is fully isolated,
      * resolve the yaml path (caller-supplied or a fresh
        ``TemporaryDirectory``), call ``tn.init(path)``.

    On exit:
      * ``flush_and_close()`` to release the inner ceremony,
      * if the snapshot was a real runtime, re-init at its yaml so the
        outer code keeps working. (Restoring the exact runtime instance
        would be cleaner but the lazy-cached LKV state lives behind it;
        re-init is the safe path that exercises the same code as init.)
      * always tear down the tempdir if we created one.

    Nesting works because each context records its own snapshot.
    """

    def __init__(self, yaml_or_tmpdir: Any) -> None:
        self._user_arg = yaml_or_tmpdir
        self._tempdir = None  # type: Any
        self._prior_yaml: Path | None = None

    def __enter__(self) -> _SessionHandle:
        import tn
        from . import current_config, flush_and_close, init
        # Snapshot the prior runtime's yaml so we can re-init on exit.
        if tn._dispatch_rt is not None:
            try:
                self._prior_yaml = current_config().yaml_path
            except RuntimeError:
                # current_config() raises RuntimeError when no init has happened.
                self._prior_yaml = None
            flush_and_close()

        if self._user_arg is None:
            import tempfile

            self._tempdir = tempfile.TemporaryDirectory(prefix="tn-session-")
            yaml_path = Path(self._tempdir.name) / "tn.yaml"
        else:
            arg = self._user_arg
            p = Path(arg)
            # Accept either a directory (we'll create tn.yaml inside) or
            # an explicit yaml file path.
            if p.suffix in {".yaml", ".yml"}:
                yaml_path = p
            else:
                p.mkdir(parents=True, exist_ok=True)
                yaml_path = p / "tn.yaml"

        # Always use btn for sessions: hermetic, no JWE keypair wiring,
        # matches what test_logger.py and the rest of the test suite use.
        init(yaml_path, cipher="btn")
        return _SessionHandle(yaml_path)

    def __exit__(self, exc_type, exc, tb) -> None:
        from . import flush_and_close, init
        try:
            flush_and_close()
        finally:
            if self._tempdir is not None:
                try:
                    self._tempdir.cleanup()
                except OSError:
                    # Tempdir cleanup races with file handles on Windows.
                    # Swallow; ``TemporaryDirectory.__del__`` will retry.
                    pass
            if self._prior_yaml is not None and self._prior_yaml.exists():
                # Best-effort restore of the outer runtime. If it fails
                # (yaml moved, keystore deleted), the next module-level
                # call will hit auto-init or raise the standard
                # "tn.init(yaml_path) must be called before tn.log"
                # error — same surface either way.
                try:
                    init(self._prior_yaml)
                except Exception:
                    _logger.exception(
                        "session exit: failed to restore prior runtime at %s",
                        self._prior_yaml,
                    )


def _session_impl(yaml_or_tmpdir: Any = None) -> _Session:
    """Open a TN session. Use as a context manager in tests:

    ```python
    with tn.session(tmp_path) as t:
        t.info("evt.test", k=1)
    ```

    No-arg form spins up a ``tempfile.TemporaryDirectory()`` and cleans
    it up on exit:

    ```python
    with tn.session() as t:
        t.info("evt.test", k=1)
    ```

    Inside the ``with`` block the module-level ``tn.info(...)`` also
    routes through the session; on exit, the prior runtime (if any) is
    restored.

    Sessions nest: the inner block's exit re-initializes the outer
    block's ceremony. ``yaml_or_tmpdir`` may be a directory (we'll
    create ``tn.yaml`` inside) or an explicit ``.yaml`` path.
    """
    return _Session(yaml_or_tmpdir)
