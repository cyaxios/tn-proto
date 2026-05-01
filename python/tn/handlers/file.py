"""File handlers backed by stdlib rotation logic.

These subclass logging.handlers.*RotatingFileHandler so we inherit the
rotation math (file renaming, size/time checks, fsync on rotate). We
override emit() to take raw bytes directly instead of LogRecords, so
there's no round-trip through the logging module's formatting machinery.
"""

from __future__ import annotations

import logging.handlers
import threading
from pathlib import Path
from typing import Any

from pathvalidate import sanitize_filename

from .base import SyncHandler


class _BytesRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """stdlib RotatingFileHandler with a raw-bytes emit path."""

    def emit_bytes(self, data: bytes) -> None:
        if self.stream is None:  # opened lazily by stdlib
            self.stream = self._open()
        # Rotate BEFORE the write would push us over maxBytes.
        if self.maxBytes and self.stream.tell() + len(data) >= self.maxBytes:
            self.doRollover()
            self.stream = self.stream or self._open()
        self.stream.write(data.decode("utf-8"))
        self.stream.flush()


class _BytesTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """stdlib TimedRotatingFileHandler with a raw-bytes emit path."""

    def emit_bytes(self, data: bytes) -> None:
        if self.stream is None:
            self.stream = self._open()
        if self.shouldRollover(None):  # type: ignore[arg-type]
            self.doRollover()
            self.stream = self.stream or self._open()
        self.stream.write(data.decode("utf-8"))
        self.stream.flush()


class FileRotatingHandler(SyncHandler):
    """Size-based rotation. Default 5 MB x 5 backups.

    By default also rotates **at session start**: when a new process
    constructs the handler against an existing non-empty file, the
    current file rolls to ``<name>.1`` (shifting older backups
    forward up to ``backup_count``) and the new session writes a
    fresh file. Matches stdlib ``logging`` mental model — every run
    gets its own log, history preserved as numbered backups —
    instead of the old "append forever" behavior. Pass
    ``rotate_on_init=False`` to keep the legacy append-everything
    semantics (e.g. tests that need cross-init continuity).
    """

    def __init__(
        self,
        name: str,
        path: str | Path,
        *,
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 5,
        rotate_on_init: bool = False,  # default off: TN log is a chain; rotation breaks verification
        filter_spec: dict[str, Any] | None = None,
    ):
        super().__init__(name, filter_spec)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._h = _BytesRotatingFileHandler(
            filename=str(self.path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
            delay=True,
        )
        # Session-start rotation: if the file exists and has content
        # from a prior session, perform one rollover so the new session
        # writes a fresh file and the prior content is preserved at
        # `<name>.1`. Stdlib's `doRollover()` walks the existing
        # backups (`.1` → `.2`, etc.) so we don't have to reimplement
        # that. Skip when the file doesn't exist or is zero-length —
        # there's no prior session to preserve.
        if rotate_on_init:
            try:
                if self.path.exists() and self.path.stat().st_size > 0:
                    # Force the underlying stdlib handler to open the
                    # stream, then rotate. After rotation, `_open()`
                    # creates a fresh empty file the new session
                    # writes into.
                    if self._h.stream is None:
                        self._h.stream = self._h._open()
                    self._h.doRollover()
            except OSError:
                # Best-effort: if rotation fails (permissions, race
                # against another process, etc.) fall through and let
                # writes go to the existing file. Operator can rotate
                # manually after the fact.
                pass

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        with self._lock:
            self._h.emit_bytes(raw_line)

    def close(self, *, timeout: float = 30.0) -> None:
        with self._lock:
            self._h.close()


class FileTimedRotatingHandler(SyncHandler):
    """Time-based rotation. `when` follows stdlib conventions: 'midnight',
    'H' (hourly), 'D' (daily), 'W0'-'W6' (weekly, Monday=0), etc."""

    def __init__(
        self,
        name: str,
        path: str | Path,
        *,
        when: str = "midnight",
        backup_count: int = 30,
        filter_spec: dict[str, Any] | None = None,
    ):
        super().__init__(name, filter_spec)
        # sanitize any templated chars in path basename but keep path hierarchy
        p = Path(path)
        safe_name = sanitize_filename(p.name, platform="auto")
        self.path = p.with_name(safe_name)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._h = _BytesTimedRotatingFileHandler(
            filename=str(self.path),
            when=when,
            backupCount=backup_count,
            encoding="utf-8",
            delay=True,
        )

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        with self._lock:
            self._h.emit_bytes(raw_line)

    def close(self, *, timeout: float = 30.0) -> None:
        with self._lock:
            self._h.close()
