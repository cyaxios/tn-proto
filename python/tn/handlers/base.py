"""Handler base classes.

Split into SyncHandler (file sinks: call through on the emitting thread)
and AsyncHandler (network sinks: enqueue then drain in a background
worker). All handlers share the same filter evaluation.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from ..filters import Predicate, _compile_filter

_log = logging.getLogger("tn.handlers")


class TNHandler(ABC):
    """Common handler contract. Subclasses implement _emit_sync or an
    async variant via AsyncHandler."""

    def __init__(self, name: str, filter_spec: dict[str, Any] | None = None):
        self.name = name
        self.filter: Predicate = _compile_filter(filter_spec)

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return self.filter(envelope)

    @abstractmethod
    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        """Deliver a fully-sealed envelope. `raw_line` is the canonical
        newline-terminated JSON bytes as written to disk (handlers may
        choose to send raw bytes or the envelope dict — whichever is
        more efficient)."""

    def close(self, *, timeout: float = 30.0) -> None:  # noqa: B027 — intentional default no-op (see docstring)
        """Flush and release resources.

        Default implementation is intentionally a no-op: many handlers
        (in-memory, stdout, etc.) hold no resources and don't need to
        override. Not marked @abstractmethod because subclasses should
        be free to inherit the no-op rather than forced to restate it.
        """


class SyncHandler(TNHandler):
    """File-like handler: emit synchronously on the caller thread."""


class AsyncHandler(TNHandler):
    """Network-like handler. Emit enqueues to a durable outbox; a
    background worker drains it with exponential-backoff retries.

    Subclasses implement:
        _publish(envelope, raw_line) -> None   # raises on failure
    """

    # Set in __init__ to avoid circular import with outbox module.
    _outbox = None
    _worker = None

    def __init__(
        self,
        name: str,
        outbox_path,
        *,
        filter_spec: dict[str, Any] | None = None,
        max_retries: int = 10,
        backoff_initial: float = 1.0,
        backoff_max: float = 60.0,
    ):
        super().__init__(name, filter_spec)
        # Lazy import to keep base clean of queue-library deps during
        # unit tests that don't exercise async handlers.
        from .outbox import DurableOutbox, OutboxWorker

        self._outbox = DurableOutbox(outbox_path)
        self._worker = OutboxWorker(
            outbox=self._outbox,
            publish=self._publish,
            name=name,
            max_retries=max_retries,
            backoff_initial=backoff_initial,
            backoff_max=backoff_max,
        )
        self._worker.start()

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        if self._outbox is None:
            raise RuntimeError(
                f"handler {self.name!r}: emit called before outbox was initialized"
            )
        self._outbox.put({"envelope": envelope, "raw": raw_line})

    @abstractmethod
    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        """Actually send to the network. Raise on failure -> nack + retry."""

    def _final_flush(self) -> None:
        """Hook called AFTER the worker has drained the outbox but BEFORE
        we close the outbox. Subclasses that buffer (S3, Delta, blob
        handlers) override this to emit the final partial batch. Default:
        no-op — handlers that publish-per-item have nothing to flush."""

    def close(self, *, timeout: float = 30.0) -> None:
        """Stop the worker (drains outbox into buffer via _publish), then
        call _final_flush() so buffering handlers can emit their last
        partial batch, then close the outbox."""
        if self._worker is not None:
            self._worker.stop(timeout=timeout)
        try:
            self._final_flush()
        except Exception:
            import logging as _logging

            _logging.getLogger("tn.handler").exception(
                "handler %r: _final_flush failed during close", self.name
            )
        if self._outbox is not None:
            self._outbox.close()
