"""Log output handlers — fan-out from tn._emit.

Architecture:
    - File handlers are sync: write-and-flush on the caller thread.
    - Network handlers are async: enqueue to a persist-queue outbox,
      a background worker drains it with retries. Crash-safe — items
      stay in the SQLite-backed queue until successfully published.

Handlers are instantiated from `tn.yaml`'s `handlers:` section. If the
section is absent, a single `file.rotating` at `./.tn/logs/tn.ndjson`
(5 MB, 5 backups) is synthesized automatically.

Future blob-store handlers (S3, Azure Blob, GCS, R2) will subclass
AsyncHandler just like KafkaHandler and PDSHandler — the outbox shape
is already right for them.
"""

from __future__ import annotations

from .base import AsyncHandler, SyncHandler, TNHandler
from .file import FileRotatingHandler, FileTimedRotatingHandler
from .registry import build_handlers, default_file_handler

__all__ = [
    "AsyncHandler",
    "FileRotatingHandler",
    "FileTimedRotatingHandler",
    "SyncHandler",
    "TNHandler",
    "build_handlers",
    "default_file_handler",
]
