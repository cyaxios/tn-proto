"""Strict trusted-principal primitives shared by enrollment ceremonies.

The general :class:`tn.signing.DeviceKey` verifier intentionally retains its
legacy multi-curve, boolean API.  Ceremony code uses the helpers in this module
instead: only canonical Ed25519 ``did:key`` identifiers are accepted and all
failures carry a stable :class:`TrustReason`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {character: index for index, character in enumerate(_BASE58_ALPHABET)}
_ED25519_MULTICODEC = b"\xed\x01"


class TrustReason(str, Enum):
    """Stable machine-readable reasons for trust-boundary rejection."""

    STATEMENT_INVALID = "statement_invalid"
    STATEMENT_EXPIRED = "statement_expired"
    SIGNATURE_INVALID = "signature_invalid"
    DID_INVALID = "did_invalid"
    DID_SIGNER_MISMATCH = "did_signer_mismatch"
    OUTER_INNER_SIGNER_MISMATCH = "outer_inner_signer_mismatch"
    WRONG_RECIPIENT = "wrong_recipient"
    SCOPE_MISMATCH = "scope_mismatch"
    BODY_DIGEST_MISMATCH = "body_digest_mismatch"
    CHALLENGE_MISSING = "challenge_missing"
    CHALLENGE_EXPIRED = "challenge_expired"
    CHALLENGE_REPLAYED = "challenge_replayed"
    REPLAY_CONFLICT = "replay_conflict"
    BINDING_INVALID = "binding_invalid"
    UNTRUSTED_PRINCIPAL = "untrusted_principal"
    EPOCH_ROLLBACK = "epoch_rollback"
    EPOCH_CONFLICT = "epoch_conflict"


class TrustError(ValueError):
    """A rejected trust statement with a stable reason and human detail."""

    reason: TrustReason
    detail: str

    def __init__(self, reason: TrustReason, detail: str) -> None:
        self.reason = TrustReason(reason)
        self.detail = str(detail)
        super().__init__(f"{self.reason.value}: {self.detail}")


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    """Identity and scope established by a verified key-binding proof."""

    did: str
    purpose: Literal["jwe-reader", "hibe-reader", "hibe-authority"]
    audience_did: str
    ceremony_id: str
    group: str
    proof_digest: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedJweBinding:
    """A verified principal together with its bound X25519 public key."""

    principal: VerifiedPrincipal
    public_key: bytes
    public_key_sha256: str
    proof_digest: str
    challenge_digest: str | None


@dataclass(frozen=True, slots=True)
class AcceptedOffer:
    """Digest-bound result of accepting an authenticated JWE offer."""

    binding: VerifiedJweBinding
    offer_digest: str
    artifact_digest: str


def _b58encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    zeroes = len(value) - len(value.lstrip(b"\0"))
    return "1" * zeroes + encoded


def _b58decode(value: str) -> bytes:
    if not value:
        raise TrustError(TrustReason.DID_INVALID, "did:key multibase payload is empty")
    number = 0
    for character in value:
        try:
            digit = _BASE58_INDEX[character]
        except KeyError as exc:
            raise TrustError(
                TrustReason.DID_INVALID,
                "did:key contains a non-base58btc character",
            ) from exc
        number = number * 58 + digit
    zeroes = len(value) - len(value.lstrip("1"))
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * zeroes + decoded


def parse_ed25519_did_key(did: str) -> bytes:
    """Return the raw key from a canonical Ed25519 ``did:key`` identifier.

    Only base58btc multibase, the Ed25519 multicodec (``0xed``), and an
    exactly 32-byte raw public key are accepted.
    """

    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise TrustError(
            TrustReason.DID_INVALID,
            "expected an Ed25519 did:key with a base58btc multibase payload",
        )
    payload = did[len("did:key:z") :]
    decoded = _b58decode(payload)
    if _b58encode(decoded) != payload:
        raise TrustError(TrustReason.DID_INVALID, "did:key base58btc payload is not canonical")
    if decoded[:2] != _ED25519_MULTICODEC:
        raise TrustError(
            TrustReason.DID_INVALID,
            "did:key does not use the Ed25519 multicodec",
        )
    public_key = decoded[2:]
    if len(public_key) != 32:
        raise TrustError(
            TrustReason.DID_INVALID,
            f"Ed25519 did:key must contain 32 public-key bytes, got {len(public_key)}",
        )
    return public_key


def verify_ed25519_did_signature(did: str, message: bytes, signature: bytes) -> None:
    """Strictly verify a 64-byte Ed25519 signature for ``did``.

    The function returns ``None`` on success and raises :class:`TrustError`
    with ``did_invalid`` or ``signature_invalid`` on failure.
    """

    public_key = parse_ed25519_did_key(did)
    if not isinstance(message, bytes):
        raise TrustError(TrustReason.STATEMENT_INVALID, "signed message must be bytes")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise TrustError(
            TrustReason.SIGNATURE_INVALID,
            "Ed25519 signature must contain exactly 64 bytes",
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise TrustError(TrustReason.SIGNATURE_INVALID, "Ed25519 signature is invalid") from exc


__all__ = [
    "AcceptedOffer",
    "TrustError",
    "TrustReason",
    "VerifiedJweBinding",
    "VerifiedPrincipal",
    "parse_ed25519_did_key",
    "verify_ed25519_did_signature",
]
