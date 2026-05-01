"""Ed25519 signing + did:key derivation for TN device identities.

Entries are signed by the device's long-lived Ed25519 key; the signature
covers the row hash that transitively covers every other envelope field.
did:key encoding uses the Ed25519 multicodec (0xed) so readers can extract
the verifying public key from the DID alone with no external resolver.

We use the `cryptography` package which ships as a binary wheel on every
platform we target. Ed25519 signing runs at approximately 50 to 100
microseconds per call on commodity CPUs, an order of magnitude faster
than ECDSA over secp256k1 and with deterministic signatures (no per-call
nonce entropy requirement).

did:key encoding:
    did:key:<multibase-base58btc>(<multicodec-pub>|<raw-pub-bytes>)

    Ed25519:    multicodec 0xed, varint 2 bytes: 0xed 0x01, pub = 32 bytes
    secp256k1:  multicodec 0xe7, varint 2 bytes: 0xe7 0x01, pub = 33 bytes compressed

TN signs only with Ed25519. The verify path additionally accepts secp256k1
DIDs so that readers receiving entries whose publisher holds a secp256k1
identity (for example, an ATProto-federated party) can verify without a
translation layer. The sign path is deliberately single-curve to keep the
hot code-path simple.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from typing_extensions import Self

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    # bitcoin-style base58 (no 0OIl)
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_BASE58_ALPHABET[r])
    # preserve leading zeros as '1's
    for b in data:
        if b == 0:
            out.append(_BASE58_ALPHABET[0])
        else:
            break
    return out[::-1].decode("ascii")


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _BASE58_ALPHABET.index(ord(ch))
    # count leading '1's
    pad = len(s) - len(s.lstrip("1"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + raw


# Multicodec prefixes (varint-encoded, 2 bytes each).
_ED25519_MULTICODEC = b"\xed\x01"  # Ed25519 public key, 32 bytes raw
_SECP256K1_MULTICODEC = b"\xe7\x01"  # secp256k1 public key, 33 bytes compressed


@dataclass
class DeviceKey:
    """Ed25519 keypair + cached DID encoding.

    `private_bytes` is the 32-byte Ed25519 seed. `public_bytes` is the
    32-byte public key in raw encoding. `did` is the did:key form of the
    public key with the Ed25519 multicodec prefix.
    """

    private_bytes: bytes  # 32-byte Ed25519 seed
    public_bytes: bytes  # 32-byte public key, raw
    did: str  # did:key:z...

    @classmethod
    def generate(cls) -> Self:
        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(priv_bytes, pub_bytes, cls._did_key(pub_bytes))

    @classmethod
    def from_private_bytes(cls, priv_bytes: bytes) -> Self:
        if len(priv_bytes) != 32:
            raise ValueError("Ed25519 private key seed must be 32 bytes")
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(priv_bytes, pub_bytes, cls._did_key(pub_bytes))

    @staticmethod
    def _did_key(pub_bytes: bytes) -> str:
        return "did:key:z" + _b58encode(_ED25519_MULTICODEC + pub_bytes)

    def sign(self, message: bytes) -> bytes:
        """Produce a 64-byte Ed25519 signature over `message`."""
        priv = Ed25519PrivateKey.from_private_bytes(self.private_bytes)
        return priv.sign(message)

    def signing_key(self) -> Ed25519PrivateKey:
        """Return the underlying Ed25519PrivateKey for callers that need it.

        Most callers should use .sign(message). This accessor exists for
        places that pass the key to lower-level primitives (e.g. package
        signing in tn/packaging.py).
        """
        return Ed25519PrivateKey.from_private_bytes(self.private_bytes)

    @staticmethod
    def verify(did: str, message: bytes, signature: bytes) -> bool:
        """Verify `signature` against `message` for a did:key identity.

        Accepts two curve families:
          Ed25519 (multicodec 0xed): 32-byte public key, 64-byte raw signature.
          secp256k1 (multicodec 0xe7): 33-byte compressed public key, 64-byte
              raw (r||s) ECDSA signature over SHA-256(message). Kept for
              interop with federated identity systems that standardised on
              secp256k1 (notably ATProto). TN itself signs only Ed25519.
        """
        if not did.startswith("did:key:z"):
            return False
        multicodec = _b58decode(did[len("did:key:z") :])
        prefix, pub_bytes = multicodec[:2], multicodec[2:]

        if prefix == _ED25519_MULTICODEC:
            if len(pub_bytes) != 32:
                return False
            try:
                Ed25519PublicKey.from_public_bytes(pub_bytes).verify(signature, message)
                return True
            except InvalidSignature:
                return False
            except (ValueError, TypeError):
                # Malformed key bytes / invalid types → not verifiable.
                return False

        if prefix == _SECP256K1_MULTICODEC:
            if len(pub_bytes) != 33 or len(signature) != 64:
                return False
            try:
                pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:], "big")
                der = asym_utils.encode_dss_signature(r, s)
                pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature:
                return False
            except (ValueError, TypeError):
                # Malformed key / invalid types → not verifiable.
                return False

        return False


def _signature_b64(sig: bytes) -> str:
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def _signature_from_b64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
