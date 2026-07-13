"""
tn.btn - a broadcast encrypt/decrypt surface over the native BTN cipher.

A small ergonomic wrapper around the compiled NNL broadcast cipher
(``tn._native.btn``). One producer owns a group and mints a per-reader kit for
each reader; it seals one block the whole group can open, and revoking a reader
only affects future seals - no re-encryption for anyone else. Reading needs
only a reader's own kit: no server, no producer online, no recipient list at
encrypt time.

    from tn import btn

    p    = btn.setup()
    kit  = p.mint()                 # hand this to a reader
    ct   = p.encrypt(data)          # seal for everyone minted, minus revoked
    p.decrypt(ct)                   # producer reads its own
    p.revoke(kit)                   # forward-only cutoff

    sub  = btn.subscribe(kit)       # a reader holds one or more kits
    sub.decrypt(ct)

Kits and ciphertexts are ``bytes`` - the cipher's native wire form, readable by
any binding. Producer state serializes with ``to_bytes()``/``from_bytes()``; it
holds the master seed, so treat it as secret. ``aad`` is optional
additional-authenticated-data: authenticated into the ciphertext but not
encrypted; the same ``aad`` must be supplied to decrypt.

This is the group cipher on its own, without the TN log envelope (signing,
hash-chaining, index tokens). For attested, chained records use the top-level
``tn`` verbs; reach for this when you want broadcast sealing as a primitive.
"""

from __future__ import annotations

from . import _native as _native

_btn = _native.btn
NotEntitled = _btn.NotEntitled

__all__ = ["setup", "subscribe", "Producer", "Subscriber", "NotEntitled"]


class Producer:
    """Owns one group's publisher state. Wraps a native PublisherState."""

    def __init__(self, state=None):
        self._state = state if state is not None else _btn.PublisherState()
        self._self_kit: bytes | None = None   # minted lazily so a write-only producer wastes no leaf

    def mint(self) -> bytes:
        """Mint a reader kit at the next free leaf and return its bytes."""
        return self._state.mint()

    def encrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        """Seal for the current audience (everyone minted, minus revoked)."""
        return self._state.encrypt(data, aad) if aad else self._state.encrypt(data)

    def decrypt(self, ct: bytes, aad: bytes = b"") -> bytes:
        """Read a ciphertext with the producer's own self-kit (minted once)."""
        if self._self_kit is None:
            self._self_kit = self._state.mint()
        return _btn.decrypt(self._self_kit, ct, aad) if aad else _btn.decrypt(self._self_kit, ct)

    def revoke(self, kit: bytes) -> None:
        """Forward-only: exclude this kit's reader from future seals."""
        self._state.revoke_kit(kit)

    def revoke_by_leaf(self, leaf: int) -> None:
        self._state.revoke_by_leaf(leaf)

    def rotate(self) -> None:
        """Start a new generation. Old kits stop opening new seals; survivors
        must be re-minted and re-issued. Consumes and replaces the state."""
        outcome = self._state.rotate()
        self._state = outcome.active
        self._self_kit = None

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

    def to_bytes(self) -> bytes:
        """Serialize the publisher state (holds the master seed - secret)."""
        return self._state.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Producer":
        return cls(_btn.PublisherState.from_bytes(data))


class Subscriber:
    """Holds reader kits and opens ciphertexts. No seed, no producer powers."""

    def __init__(self):
        self._kits: list[bytes] = []

    def add_key(self, kit: bytes) -> None:
        self._kits.append(kit)

    def decrypt(self, ct: bytes, aad: bytes = b"") -> bytes:
        for kit in self._kits:
            try:
                return _btn.decrypt(kit, ct, aad) if aad else _btn.decrypt(kit, ct)
            except NotEntitled:
                continue
        raise NotEntitled("no held kit opens this ciphertext")


def setup() -> Producer:
    """Create a producer for one group (fresh master seed)."""
    return Producer()


def subscribe(*kits: bytes) -> Subscriber:
    """Create a reader holding zero or more kits; add more with .add_key()."""
    s = Subscriber()
    for k in kits:
        s.add_key(k)
    return s
