"""tn_btn — Python bindings + TN-style Runtime for broadcast-transaction encryption.

Direct access to the underlying primitives lives in ``tn_btn._core``
(the Rust extension). Most users should prefer the :class:`Runtime`
here, which bundles state persistence and append-only log I/O into
the shape of a TN-style logger::

    import tn_btn

    # One-time setup (or reopen an existing ceremony):
    rt = tn_btn.init("./my-ceremony")

    # Mint readers; their kit bytes are what you hand out to readers.
    alice = rt.mint()
    bob = rt.mint()

    # Log events. Each call encrypts + appends to the log file.
    rt.log(b"event 1")
    rt.log(b"event 2")

    rt.close()

    # Later, from anywhere:
    for index, plaintext in tn_btn.read("./my-ceremony/log.btn", alice):
        print(index, plaintext)

Or the publisher reads their own log without a kit (they have the
master seed)::

    rt = tn_btn.init("./my-ceremony")
    for index, plaintext in rt.read():
        print(index, plaintext)
"""
from __future__ import annotations

import os
import struct
import time
from pathlib import Path
from typing import Iterator, Optional, Tuple, Union

from tn_btn._core import (
    PublisherState,
    NotEntitled,
    BtnRuntimeError,
    decrypt,
    ciphertext_publisher_id,
    kit_publisher_id,
    kit_leaf,
    tree_height,
    max_leaves,
)

__all__ = [
    "PublisherState",
    "NotEntitled",
    "BtnRuntimeError",
    "decrypt",
    "ciphertext_publisher_id",
    "kit_publisher_id",
    "kit_leaf",
    "tree_height",
    "max_leaves",
    "Runtime",
    "init",
    "read",
]


_STATE_FILENAME = "state.btn"
_LOG_FILENAME = "log.btn"
_LEN_FMT = ">I"  # big-endian u32 length prefix per log record


class Runtime:
    """Stateful publisher runtime: persistent state + append-only log.

    One :class:`Runtime` per ceremony directory. Call :meth:`close`
    (or use as a context manager) to flush state + log to disk.
    Re-opening the same directory later loads the state and appends
    to the existing log.

    Directory layout::

        <dir>/
          state.btn   # serialized PublisherState (SECRET)
          log.btn     # length-prefixed sequence of ciphertext bytes
    """

    def __init__(
        self,
        dir_path: Union[str, os.PathLike[str]],
        *,
        flush_every: int = 10,
        flush_interval_secs: float = 1.0,
        persist_state_on_mint: bool = False,
    ):
        """Open or create a ceremony at `dir_path`.

        Flush policy (log file):
          - ``flush_every=N`` — call ``fsync``-style flush after every N
            ``log()`` calls. Default 10. Pass ``1`` for per-write durability
            (safest, slowest). Pass ``0`` to disable count-based flushing.
          - ``flush_interval_secs=T`` — additionally flush if at least T
            seconds have elapsed since the last flush. Default 1.0. Pass
            0 to disable time-based flushing.
          - Either trigger flushes; whichever fires first wins. A final
            flush always happens on ``close()``.

        State persistence policy:
          - ``persist_state_on_mint=False`` (default) — batch mint/revoke
            changes in memory and only write ``state.btn`` on ``close()``.
            Losing the process before close loses the new mints/revokes.
          - ``persist_state_on_mint=True`` — write ``state.btn`` on every
            mint/revoke (pre-optimization behavior; safest against crashes).
        """
        self._dir = Path(dir_path)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._state_path = self._dir / _STATE_FILENAME
        self._log_path = self._dir / _LOG_FILENAME
        self._flush_every = max(0, int(flush_every))
        self._flush_interval_secs = max(0.0, float(flush_interval_secs))
        self._persist_state_on_mint = bool(persist_state_on_mint)

        if self._state_path.exists():
            self._state = PublisherState.from_bytes(self._state_path.read_bytes())
        else:
            self._state = PublisherState()
            self._save_state()

        # Open log for append. We don't hold a long-lived file handle
        # on read; each .read() opens fresh, so there's no coordination
        # needed between readers on disk.
        self._log_fh = open(self._log_path, "ab")
        self._writes_since_flush = 0
        self._last_flush_ts = time.monotonic()
        # Track the next log-record index in memory. Initialize by
        # counting existing records on open (cheap, one-time O(n)),
        # then maintain incrementally. Prior versions recomputed this
        # from disk on every log() call, which made log() O(existing).
        self._next_index = _count_records(self._log_path)

    # ---- context manager ----------------------------------------------

    def __enter__(self) -> "Runtime":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ---- state passthrough --------------------------------------------

    @property
    def publisher_id(self) -> bytes:
        return self._state.publisher_id

    @property
    def epoch(self) -> int:
        return self._state.epoch

    @property
    def issued_count(self) -> int:
        return self._state.issued_count

    @property
    def revoked_count(self) -> int:
        return self._state.revoked_count

    def mint(self) -> bytes:
        """Mint a fresh reader kit. Returns the kit bytes.

        State is persisted only if ``persist_state_on_mint=True`` was
        passed to the constructor; otherwise changes are batched and
        only written on :meth:`close`.
        """
        kit = self._state.mint()
        if self._persist_state_on_mint:
            self._save_state()
        return kit

    def revoke_kit(self, kit_bytes: bytes) -> None:
        """Revoke a reader by their kit bytes. Idempotent.

        Persists per :attr:`persist_state_on_mint`.
        """
        self._state.revoke_kit(kit_bytes)
        if self._persist_state_on_mint:
            self._save_state()

    def revoke_by_leaf(self, leaf: int) -> None:
        """Revoke a reader by leaf index. Idempotent.

        Persists per :attr:`persist_state_on_mint`.
        """
        self._state.revoke_by_leaf(leaf)
        if self._persist_state_on_mint:
            self._save_state()

    # ---- log ----------------------------------------------------------

    def log(self, plaintext: bytes) -> int:
        """Encrypt and append `plaintext` to the log.

        Returns the 0-based index of the record in the log (useful for
        correlating with downstream consumers).

        Flushes to disk according to the policy set at construction
        (see ``flush_every`` / ``flush_interval_secs``). Buffered writes
        live in the OS file-buffer cache until flushed.
        """
        ct = self._state.encrypt(plaintext)
        record = struct.pack(_LEN_FMT, len(ct)) + ct
        index = self._next_index
        self._next_index += 1
        self._log_fh.write(record)
        self._writes_since_flush += 1
        self._maybe_flush()
        return index

    def _maybe_flush(self) -> None:
        """Flush the log handle if either policy threshold is met."""
        should_flush = False
        if self._flush_every > 0 and self._writes_since_flush >= self._flush_every:
            should_flush = True
        if self._flush_interval_secs > 0:
            if time.monotonic() - self._last_flush_ts >= self._flush_interval_secs:
                should_flush = True
        if should_flush:
            self._log_fh.flush()
            self._writes_since_flush = 0
            self._last_flush_ts = time.monotonic()

    def read(self, kit_bytes: Optional[bytes] = None) -> Iterator[Tuple[int, bytes]]:
        """Iterate the log, decrypting each entry.

        If `kit_bytes` is supplied, decrypts with that reader kit and
        yields only the entries that reader is entitled to. Otherwise
        uses a publisher-self kit (minted from the master seed) so the
        publisher can read everything they wrote.
        """
        self._log_fh.flush()  # ensure any in-memory appends are on disk
        if kit_bytes is None:
            kit_bytes = self._self_kit()
        yield from _iter_log(self._log_path, kit_bytes)

    def _self_kit(self) -> bytes:
        """Mint a throwaway kit for publisher self-reads.

        Uses the next available leaf. This is wasteful (consumes a
        leaf slot) but simplest. For realistic use, the publisher
        should mint a persistent self-kit at setup time and cache it.
        """
        if not hasattr(self, "_cached_self_kit"):
            self._cached_self_kit = self._state.mint()
            self._save_state()
        return self._cached_self_kit

    def close(self) -> None:
        """Flush log and state to disk. Idempotent."""
        if self._log_fh is not None and not self._log_fh.closed:
            self._log_fh.flush()
            self._log_fh.close()
        self._save_state()

    def _save_state(self) -> None:
        # Write-temp-then-rename for atomicity on crash.
        tmp = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
        tmp.write_bytes(self._state.to_bytes())
        tmp.replace(self._state_path)


# ---- free-function convenience --------------------------------------


def init(dir_path: Union[str, os.PathLike[str]]) -> Runtime:
    """Open (or create) a ceremony directory. Equivalent to
    ``Runtime(dir_path)``."""
    return Runtime(dir_path)


def read(
    log_path: Union[str, os.PathLike[str]],
    kit_bytes: bytes,
) -> Iterator[Tuple[int, bytes]]:
    """Iterate a log file, decrypting each entry with `kit_bytes`.

    Yields ``(index, plaintext)`` pairs. Entries the reader is not
    entitled to (revocations) are silently skipped — they show up as
    ``NotEntitled`` internally and are filtered out of the iteration.
    """
    yield from _iter_log(Path(log_path), kit_bytes)


# ---- internal -------------------------------------------------------


def _iter_log(log_path: Path, kit_bytes: bytes) -> Iterator[Tuple[int, bytes]]:
    if not log_path.exists():
        return
    with open(log_path, "rb") as f:
        index = 0
        while True:
            prefix = f.read(4)
            if not prefix:
                return
            if len(prefix) != 4:
                raise BtnRuntimeError(
                    f"log {log_path} truncated at record {index}: "
                    f"expected 4-byte length prefix, got {len(prefix)} bytes"
                )
            (ct_len,) = struct.unpack(_LEN_FMT, prefix)
            ct_bytes = f.read(ct_len)
            if len(ct_bytes) != ct_len:
                raise BtnRuntimeError(
                    f"log {log_path} truncated at record {index}: "
                    f"expected {ct_len} bytes, got {len(ct_bytes)}"
                )
            try:
                pt = decrypt(kit_bytes, ct_bytes)
                yield (index, pt)
            except NotEntitled:
                pass  # reader not entitled to this entry; skip silently
            index += 1


def _count_records(log_path: Path) -> int:
    """Count how many records exist in a log file. Called once at
    Runtime construction to initialize the in-memory index counter.
    After that, log() maintains the counter incrementally.
    """
    if not log_path.exists():
        return 0
    count = 0
    with open(log_path, "rb") as f:
        while True:
            prefix = f.read(4)
            if len(prefix) != 4:
                return count
            (ct_len,) = struct.unpack(_LEN_FMT, prefix)
            f.seek(ct_len, 1)
            count += 1
