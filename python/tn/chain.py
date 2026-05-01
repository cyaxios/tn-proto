"""Chain state and row_hash construction (PRD §5).

The chain binds each log entry to the previous one via prev_hash. row_hash
covers the whole envelope (public fields + field_hashes + ciphertexts) so
any tamper breaks the chain.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any

ZERO_HASH = "sha256:" + "0" * 64


@dataclass
class _EventChain:
    seq: int = 0
    prev_hash: str = ZERO_HASH


class ChainState:
    """Per-event_type chain state. Thread-safe via a single lock.

    PRD §5: every event_type has its own append-only chain. Two unrelated
    event streams (say `order.created` and `auth.login`) do not interleave
    their sequence numbers.
    """

    def __init__(self):
        self._chains: dict[str, _EventChain] = {}
        self._lock = threading.Lock()

    def advance(self, event_type: str) -> tuple[int, str]:
        """Return (next_seq, prev_hash) and reserve the slot."""
        with self._lock:
            chain = self._chains.setdefault(event_type, _EventChain())
            chain.seq += 1
            return chain.seq, chain.prev_hash

    def commit(self, event_type: str, new_row_hash: str) -> None:
        """Called after the row has been materialized; updates prev_hash."""
        with self._lock:
            self._chains[event_type].prev_hash = new_row_hash

    def seed(self, entries: dict[str, tuple[int, str]]) -> None:
        """Populate chain state from a prior log scan.

        `entries` maps event_type to its most recent (sequence, row_hash).
        Used at init() to pick up where the process left off on restart,
        so the first emit after reinit writes the correct prev_hash and
        sequence rather than starting over at ZERO_HASH / 1. Without this,
        any process restart creates a chain discontinuity that breaks the
        reader's tamper-evidence check.
        """
        with self._lock:
            for event_type, (seq, row_hash) in entries.items():
                self._chains[event_type] = _EventChain(seq=seq, prev_hash=row_hash)


def _compute_row_hash(
    *,
    did: str,
    timestamp: str,
    event_id: str,
    event_type: str,
    level: str,
    prev_hash: str,
    public_fields: dict[str, Any],
    groups: dict[str, dict[str, Any]],
) -> str:
    """row_hash covers:
    did + timestamp + event_id + event_type + level + prev_hash +
    sorted(public_fields) + sorted(groups: ciphertext + field_hashes)
    """
    h = hashlib.sha256()
    h.update(did.encode("utf-8"))
    h.update(b"\x00")
    h.update(timestamp.encode("utf-8"))
    h.update(b"\x00")
    h.update(event_id.encode("utf-8"))
    h.update(b"\x00")
    h.update(event_type.encode("utf-8"))
    h.update(b"\x00")
    h.update(level.encode("utf-8"))
    h.update(b"\x00")
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\x00")

    for k in sorted(public_fields):
        h.update(k.encode("utf-8"))
        h.update(b"=")
        v = public_fields[k]
        h.update(str(v).encode("utf-8") if not isinstance(v, bytes) else v)
        h.update(b"\x00")

    for group_name in sorted(groups):
        g = groups[group_name]
        h.update(b"group:")
        h.update(group_name.encode("utf-8"))
        h.update(b"\x00")
        h.update(b"ct:")
        h.update(g["ciphertext"])
        h.update(b"\x00")
        for fname in sorted(g.get("field_hashes", {})):
            h.update(fname.encode("utf-8"))
            h.update(b"=")
            h.update(g["field_hashes"][fname].encode("utf-8"))
            h.update(b"\x00")

    return "sha256:" + h.hexdigest()
