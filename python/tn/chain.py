"""Chain state and ``row_hash`` construction.

The chain binds each log entry to the previous one via ``prev_hash``.
``row_hash`` covers the whole envelope (mandatory keys + public
fields + per-group ciphertexts + field hashes) so any tamper breaks
the chain. Reference Python implementation; mirrored byte-for-byte
in Rust (``crypto/tn-core/src/chain.rs``) and re-exported by wasm.

The first entry in any (publisher, event_type) chain uses
:data:`ZERO_HASH` as its ``prev_hash``. Subsequent entries chain
``row_hash`` -> ``prev_hash`` -> ``row_hash``.

See Also:
    `docs/spec/row-hash.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/row-hash.md>`_:
        Authoritative wire spec for the hash algorithm.
    `docs/spec/envelope.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/envelope.md>`_:
        Envelope layout the hash commits to.
    ``crypto/tn-core/src/chain.rs``: Rust mirror.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any

#: The ``prev_hash`` value for the first entry in any
#: ``(publisher, event_type)`` chain. Format: ``"sha256:"`` + 64 zero
#: hex chars. Recognised across every TN implementation as the
#: chain-start sentinel. See
#: `docs/spec/row-hash.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/row-hash.md>`_.
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
    device_identity: str,
    timestamp: str,
    event_id: str,
    event_type: str,
    level: str,
    prev_hash: str,
    public_fields: dict[str, Any],
    groups: dict[str, dict[str, Any]],
) -> str:
    """Compute an envelope's ``row_hash``.

    The chain-link hash that commits to every field of an envelope
    EXCEPT ``sequence`` (metadata, not content), ``row_hash`` itself,
    and ``signature`` (which signs this hash).

    Layout::

        SHA-256(
            device_identity || \\x00 ||
            timestamp || \\x00 ||
            event_id || \\x00 ||
            event_type || \\x00 ||
            level || \\x00 ||
            prev_hash || \\x00 ||
            sorted_public_fields(public_fields) || \\x00 ||
            sorted_groups(groups)
        )

    Public fields are sorted by key. Groups are sorted by group name;
    each contributes ``"group:" + name + "\\x00 ct:" + ciphertext + "\\x00"``
    followed by its field hashes (also sorted).

    Args:
        device_identity: ``did:key:z…`` of the publisher.
        timestamp: ISO-8601 UTC with microseconds + ``Z`` suffix.
        event_id: UUID v4 string.
        event_type: Dotted event name (``[A-Za-z0-9._-]{1,64}``).
        level: ``"debug"`` / ``"info"`` / ``"warning"`` / ``"error"``
            / ``""`` (severity-less).
        prev_hash: ``"sha256:<64-hex>"`` of the previous row in this
            ``(device_identity, event_type)`` chain. First row uses
            :data:`ZERO_HASH`.
        public_fields: Plaintext top-level fields.
        groups: Per-group dict with ``ciphertext`` bytes + optional
            ``field_hashes`` dict.

    Returns:
        ``"sha256:" + hex(digest)`` — 71 chars total.

    Example:
        >>> from tn.chain import _compute_row_hash, ZERO_HASH
        >>> h = _compute_row_hash(
        ...     device_identity="did:key:zEd25519Pub",
        ...     timestamp="2026-05-22T00:00:00.000000Z",
        ...     event_id="00000000-0000-4000-8000-000000000000",
        ...     event_type="hello.world",
        ...     level="info",
        ...     prev_hash=ZERO_HASH,
        ...     public_fields={"who": "alice"},
        ...     groups={},
        ... )
        >>> h.startswith("sha256:")
        True

    See Also:
        `docs/spec/row-hash.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/row-hash.md>`_:
            Authoritative wire spec — implementations MUST match.
        `docs/spec/envelope.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/envelope.md>`_:
            What ``row_hash`` lives inside.
    """
    h = hashlib.sha256()
    h.update(device_identity.encode("utf-8"))
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
