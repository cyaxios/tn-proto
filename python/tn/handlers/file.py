"""File handlers backed by stdlib rotation logic.

These subclass logging.handlers.*RotatingFileHandler so we inherit the
rotation math (file renaming, size/time checks, fsync on rotate). We
override emit() to take raw bytes directly instead of LogRecords, so
there's no round-trip through the logging module's formatting machinery.

Deprecation note (0.4.2a7): the canonical write path for TN ceremonies
is now the Rust runtime — ``DispatchRuntime`` marks the yaml-declared
``kind: file.rotating`` handler ``_tn_default=True`` and skips it
because Rust appends to the same file. These classes remain in place
only because:

  1. ``FileTemplatedRotatingHandler`` renders ``{event_type}`` /
     ``{date}`` tokens in the main-log path — the Rust runtime
     doesn't yet support templated main-log paths, only the admin
     PEL.
  2. Direct ``FileRotatingHandler(...)``  /  ``FileTimedRotatingHandler(...)``
     usage from Python tests + scripts (outside any ceremony) needs a
     working sink, and these are the cheapest option.

The size-based rotation underneath
(``_BytesRotatingFileHandler.doRollover()``) is dead in the
Rust-default flow: rotation will live in the Rust runtime once the
commit-envelope work in
``docs/superpowers/specs/2026-05-19-commit-envelopes-and-rotation.md``
lands. Until then, expect these handlers' rotation to fire only in
pure-Python tests that bypass the Rust runtime.
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

    def resolved_address(self) -> str:
        """File handlers dedup by resolved absolute path."""
        return str(self.path.resolve())


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

    def resolved_address(self) -> str:
        return str(self.path.resolve())


class FileTemplatedRotatingHandler(SyncHandler):
    """Main-log handler that renders a path template per envelope.

    Used when ``logs.path`` in the ceremony yaml contains any of the
    TN path tokens (``{event_type}``, ``{event_class}``, ``{event_id}``,
    ``{date}``, ``{yaml_dir}``, ``{ceremony_id}``, ``{did}``). On every
    :meth:`emit` the template is rendered against the envelope's
    ``event_type`` / ``event_id`` plus the cermony's static identity,
    producing a concrete absolute path. The handler caches one inner
    :class:`_BytesRotatingFileHandler` per rendered path so file
    descriptors aren't reopened on every write — except for
    ``{event_id}`` templates (unique path per emit), which use an
    open-write-close path so the descriptor count stays bounded.

    Mirrors the admin log's per-event-type fan-out (see
    :meth:`LoadedConfig.resolve_protocol_events_path`) so a single
    ceremony can split its main log by event class, date, etc.

    Read-side glob expansion is handled by
    ``tn._log_targets.resolve_log_target`` — passing the same
    template to ``tn.read(log=template)`` returns the merged stream.

    Falls back gracefully for envelopes with no ``event_type`` field
    (writes go to a single ``<template>.unrouted`` sibling) so a
    malformed emit doesn't crash the handler.
    """

    def __init__(
        self,
        name: str,
        template: str,
        cfg: Any,
        *,
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 5,
        rotate_on_init: bool = False,
        filter_spec: dict[str, Any] | None = None,
    ):
        super().__init__(name, filter_spec)
        # ``template`` is the raw path string (possibly with tokens);
        # ``cfg`` is the LoadedConfig so we can call
        # ``cfg.resolve_log_path_for(event_type)`` per envelope.
        self._template = template
        self._cfg = cfg
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._rotate_on_init = rotate_on_init
        self._lock = threading.Lock()
        # ``{event_id}`` is unique per emit, so a template containing it
        # renders to a distinct file for every event. Caching a writer
        # per rendered path (as the pooled path below does) would grow
        # ``self._handlers`` — and the open file-handle count — without
        # bound. For those templates we open-write-close each row
        # instead (rotation / backup_count are moot for one-row files).
        # Mirrors the Rust runtime's per-event writer policy
        # (``LogWriters::writer_for`` in crypto/tn-core/src/log_file.rs).
        self._per_event = "{event_id}" in template
        # path-string -> handler. Bounded by the cardinality of the
        # template's expansion (event_type * date * ...). Per-day per-
        # event-type traffic should never blow this up; if it ever
        # does, an LRU eviction layer is a one-screen addition. Stays
        # empty for ``{event_id}`` templates (write-once-close).
        self._handlers: dict[str, _BytesRotatingFileHandler] = {}

    def _handler_for(self, event_type: str) -> _BytesRotatingFileHandler:
        """Return (or open) the inner rotating handler for a given
        event_type's rendered path. Thread-safety: caller holds
        ``self._lock``.
        """
        path = self._cfg.resolve_log_path_for(event_type or "tn.unrouted")
        key = str(path)
        h = self._handlers.get(key)
        if h is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            h = _BytesRotatingFileHandler(
                filename=str(path),
                maxBytes=self._max_bytes,
                backupCount=self._backup_count,
                encoding="utf-8",
                delay=True,
            )
            if self._rotate_on_init:
                try:
                    if path.exists() and path.stat().st_size > 0:
                        if h.stream is None:
                            h.stream = h._open()
                        h.doRollover()
                except OSError:
                    pass
            self._handlers[key] = h
        return h

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        event_type = (
            envelope.get("event_type") if isinstance(envelope, dict) else None
        )
        if not isinstance(event_type, str):
            event_type = "tn.unrouted"
        if self._per_event:
            event_id = (
                envelope.get("event_id") if isinstance(envelope, dict) else None
            )
            if not isinstance(event_id, str) or not event_id:
                event_id = "tn.unrouted"
            path = self._cfg.resolve_log_path_for(event_type, event_id=event_id)
            with self._lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                # Open-write-close: one row, then release the handle so
                # a long run can't accumulate one descriptor per event.
                # Append mode is defensive — a re-emitted event_id keeps
                # both rows rather than clobbering the first.
                with open(path, "ab") as f:
                    f.write(raw_line)
            return
        with self._lock:
            self._handler_for(event_type).emit_bytes(raw_line)

    def close(self, *, timeout: float = 30.0) -> None:
        with self._lock:
            for h in self._handlers.values():
                try:
                    h.close()
                except OSError:
                    pass
            self._handlers.clear()

    def resolved_address(self) -> str:
        """Template itself is the dedup key — two handlers with the
        same template render the same set of files, so they're
        equivalent for handler-list dedupe purposes. Resolves the
        ``{yaml_dir}`` token so the address is stable across
        cwd changes; other tokens stay literal.
        """
        addr = self._template.replace(
            "{yaml_dir}", str(self._cfg.yaml_path.parent.resolve())
        )
        return f"templated:{addr}"
