"""Durable outbox + background worker for async handlers.

Uses persist-queue's SQLiteAckQueue: crash-safe, thread-safe, acknowledges
only after successful publish. On crash mid-publish, the item reappears at
next start.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from persistqueue import SQLiteAckQueue
    from persistqueue.exceptions import Empty as PQEmpty
except ImportError as e:
    raise ImportError(
        "persist-queue is required for async handlers. "
        "Install via `pip install tn-protocol` (the base install includes it)."
    ) from e

_log = logging.getLogger("tn.handlers.outbox")


class DurableOutbox:
    """Thin typed wrapper around SQLiteAckQueue."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # SQLiteAckQueue takes a directory path; creates `data.db` inside.
        self._q = SQLiteAckQueue(
            path=str(self._path),
            auto_commit=True,
            multithreading=True,
        )

    def put(self, item: dict[str, Any]) -> None:
        self._q.put(item)

    def get(self, block: bool = True, timeout: float = 1.0) -> Any:
        """Returns the raw queue item (which we later ack/nack). Raises
        persistqueue.Empty on timeout."""
        return self._q.get(block=block, timeout=timeout)

    def ack(self, item: Any) -> None:
        self._q.ack(item)

    def nack(self, item: Any) -> None:
        self._q.nack(item)

    def size(self) -> int:
        return self._q.size

    def close(self) -> None:
        self._q.close()


class OutboxWorker:
    """Background thread that drains the outbox with retries."""

    def __init__(
        self,
        outbox: DurableOutbox,
        publish: Callable[[dict[str, Any], bytes], None],
        *,
        name: str,
        max_retries: int = 10,
        backoff_initial: float = 1.0,
        backoff_max: float = 60.0,
    ):
        self._outbox = outbox
        self._publish = publish
        self._stop_ev = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"tn-outbox-{name}",
            daemon=True,
        )
        self._max_retries = max_retries
        self._backoff_init = backoff_initial
        self._backoff_max = backoff_max
        self._name = name

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while not self._stop_ev.is_set():
            try:
                item = self._outbox.get(block=True, timeout=0.5)
            except PQEmpty:
                continue
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                _log.exception("[%s] outbox.get failed", self._name)
                time.sleep(self._backoff_init)
                continue
            # Note: persist-queue passes the stored payload straight back.
            # We wrapped it as {"envelope":..., "raw":...} in AsyncHandler.emit.
            self._deliver(item)

    def _deliver(self, item: Any) -> None:
        payload = item
        envelope = payload["envelope"]
        raw = payload["raw"]

        attempt = 0
        while not self._stop_ev.is_set():
            try:
                self._publish(envelope, raw)
                self._outbox.ack(item)
                return
            except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
                attempt += 1
                if attempt >= self._max_retries:
                    _log.error(
                        "[%s] publish failed after %d attempts, giving up: %s",
                        self._name,
                        attempt,
                        e,
                    )
                    # Leave nacked — it'll come back when the queue next iterates,
                    # but we want to avoid tight-looping forever. A future
                    # improvement: move to a dead-letter queue after max_retries.
                    self._outbox.nack(item)
                    return
                delay = min(
                    self._backoff_max,
                    self._backoff_init * (2 ** (attempt - 1)),
                )
                # jitter ±20% to avoid thundering herd on shared broker hiccups
                delay *= 1.0 + random.uniform(-0.2, 0.2)
                _log.warning(
                    "[%s] publish attempt %d failed: %s — retry in %.1fs",
                    self._name,
                    attempt,
                    e,
                    delay,
                )
                if self._stop_ev.wait(delay):
                    # stop requested while backing off
                    self._outbox.nack(item)
                    return

    def stop(self, *, timeout: float = 30.0) -> None:
        """Let the worker drain the outbox, then signal stop and join.

        The worker checks _stop_ev between iterations, so if we set it
        first the in-flight item completes but queued items behind it
        are left for next process start. That's correct for crashes;
        for a clean shutdown we want to wait for the outbox to empty.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._outbox.size() == 0:
                break
            time.sleep(0.1)
        self._stop_ev.set()
        remaining = max(0.5, deadline - time.time())
        self._thread.join(timeout=remaining)
