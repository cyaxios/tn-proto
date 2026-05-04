"""Sealed-box recipient wrap over Ed25519 device keys.

Per the second-release encrypted-kit-bundle spec
(``docs/superpowers/specs/2026-05-03-encrypted-kit-bundle-design.md``),
publishers can lock a kit_bundle's body for a specific recipient using
the same primitive libsodium calls a "sealed box" — anonymous-sender
public-key encryption — built on top of X25519 ECDH and AES-256-GCM.

The recipient's only existing asymmetric key is the Ed25519 device key
encoded into their ``did:key:z...`` identifier. Ed25519 is signing-only,
but its keys can be losslessly converted to the corresponding Curve25519
(X25519) keypair via the standard birational map. We use libsodium's
audited ``crypto_sign_ed25519_pk_to_curve25519`` and
``crypto_sign_ed25519_sk_to_curve25519`` for both halves.

This is **not JWE.** Same primitives, smaller frame.

Wire shape (lives in ``manifest.state.body_encryption.recipient_wrap``)::

    {
        "frame": "tn-sealed-box-v1",
        "recipient_did": "did:key:z...",
        "ephemeral_x25519_pub_b64": <base64 32 bytes>,
        "wrap_nonce_b64": <base64 12 bytes>,
        "wrapped_bek_b64": <base64 ciphertext + 16-byte tag>,
    }

The wrap binds to the manifest via AAD: the AES-GCM AAD is the canonical
bytes of the manifest with both ``manifest_signature_b64`` and the
``recipient_wrap`` block itself excluded. Lifting a wrap from one
manifest into another fails decryption because the AAD differs.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from .canonical import _canonical_bytes
from .signing import _b58decode, _ED25519_MULTICODEC

WRAP_FRAME = "tn-sealed-box-v1"
WRAP_HKDF_INFO = b"tn-kit-seal-v1"


class UnsealError(RuntimeError):
    """Raised when a sealed-box recipient wrap fails to unseal.

    Reasons include: recipient_did mismatch, AEAD auth failure (key /
    AAD / ciphertext disagreement), malformed wrap fields, or wrong DID
    curve family.
    """


# ---------------------------------------------------------------------------
# Ed25519 -> X25519 key conversion (via libsodium, through pynacl)
# ---------------------------------------------------------------------------


def _ed25519_pub_to_x25519_pub(ed25519_pub: bytes) -> bytes:
    """Convert a 32-byte Ed25519 public key to the corresponding 32-byte
    X25519 public key. Implemented via libsodium's
    ``crypto_sign_ed25519_pk_to_curve25519``.
    """
    if len(ed25519_pub) != 32:
        raise ValueError(
            f"_ed25519_pub_to_x25519_pub: expected 32-byte Ed25519 pub, "
            f"got {len(ed25519_pub)}"
        )
    # Late import so the SDK can import without pynacl available at type
    # check time (pynacl is a hard dep at runtime).
    from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519

    return crypto_sign_ed25519_pk_to_curve25519(ed25519_pub)


def _ed25519_priv_to_x25519_priv(ed25519_seed: bytes) -> bytes:
    """Convert a 32-byte Ed25519 seed to the corresponding 32-byte X25519
    private scalar. Implemented via libsodium's
    ``crypto_sign_ed25519_sk_to_curve25519``.

    Note: libsodium expects the 64-byte expanded Ed25519 secret key
    (seed || public_key), not the 32-byte seed alone. We reconstruct
    that here.
    """
    if len(ed25519_seed) != 32:
        raise ValueError(
            f"_ed25519_priv_to_x25519_priv: expected 32-byte Ed25519 seed, "
            f"got {len(ed25519_seed)}"
        )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expanded = ed25519_seed + pub  # 64 bytes: seed || public_key
    from nacl.bindings import crypto_sign_ed25519_sk_to_curve25519

    return crypto_sign_ed25519_sk_to_curve25519(expanded)


def _did_key_to_ed25519_pub(did: str) -> bytes:
    """Extract the raw Ed25519 public key bytes from a did:key:z... string.

    Mirrors ``tnpkg._did_key_pub`` but lives here so the sealed-box
    code path doesn't pull in the manifest-shape module.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(
            f"sealed-box recipient must be a did:key Ed25519 identity; "
            f"got {did!r}"
        )
    multicodec = _b58decode(did[len("did:key:z") :])
    prefix, pub_bytes = multicodec[:2], multicodec[2:]
    if prefix != _ED25519_MULTICODEC:
        raise ValueError(
            f"sealed-box requires Ed25519 (multicodec 0xed) recipient DID; "
            f"got prefix {prefix!r} on {did!r}"
        )
    if len(pub_bytes) != 32:
        raise ValueError(
            f"DID {did!r} carries non-32-byte Ed25519 pubkey ({len(pub_bytes)} bytes)"
        )
    return pub_bytes


# ---------------------------------------------------------------------------
# AAD: manifest minus signature minus recipient_wrap
# ---------------------------------------------------------------------------


def manifest_aad_for_wrap(manifest_dict: dict[str, Any]) -> bytes:
    """Compute the AES-GCM AAD that binds a recipient_wrap to its manifest.

    The AAD is the canonical bytes of the manifest dict with the
    following keys removed:

    * ``manifest_signature_b64`` — the signature is set AFTER the wrap is
      built; can't be in AAD.
    * ``state.body_encryption.recipient_wrap`` — the wrap binds to
      everything in the manifest EXCEPT itself; otherwise it'd be
      self-referential.

    Everything else (kind, from_did, to_did, ceremony_id, scope, clock,
    event_count, head_row_hash, the rest of body_encryption) is bound.
    """
    # Deep-copy so the caller's dict is not mutated.
    m = json.loads(json.dumps(manifest_dict, sort_keys=True))
    m.pop("manifest_signature_b64", None)
    state = m.get("state")
    if isinstance(state, dict):
        be = state.get("body_encryption")
        if isinstance(be, dict):
            be.pop("recipient_wrap", None)
    return _canonical_bytes(m)


# ---------------------------------------------------------------------------
# Wrap / unwrap
# ---------------------------------------------------------------------------


def seal_bek_for_recipient(
    bek: bytes,
    recipient_did: str,
    aad: bytes,
) -> dict[str, str]:
    """Wrap ``bek`` so only ``recipient_did``'s holder can recover it.

    Returns the dict suitable for embedding directly into
    ``manifest.state.body_encryption.recipient_wrap``.
    """
    if len(bek) != 32:
        raise ValueError(
            f"seal_bek_for_recipient: BEK must be 32 bytes; got {len(bek)}"
        )

    recipient_ed_pub = _did_key_to_ed25519_pub(recipient_did)
    recipient_x_pub = _ed25519_pub_to_x25519_pub(recipient_ed_pub)

    # Generate ephemeral X25519 keypair via the cryptography library
    # so we don't depend on pynacl for keygen.
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(recipient_x_pub))

    # HKDF salt = eph_pub || recipient_x_pub binds the derived key to
    # both halves of this specific exchange.
    salt = eph_pub_bytes + recipient_x_pub
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=WRAP_HKDF_INFO,
    ).derive(shared)

    import os as _os

    nonce = _os.urandom(12)
    aesgcm = AESGCM(key)
    wrapped = aesgcm.encrypt(nonce, bek, aad)

    return {
        "frame": WRAP_FRAME,
        "recipient_did": recipient_did,
        "ephemeral_x25519_pub_b64": base64.b64encode(eph_pub_bytes).decode("ascii"),
        "wrap_nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "wrapped_bek_b64": base64.b64encode(wrapped).decode("ascii"),
    }


def unseal_bek_from_wrap(
    wrap: dict[str, Any],
    device_priv_seed: bytes,
    aad: bytes,
) -> bytes:
    """Recover the BEK from a recipient_wrap dict.

    ``device_priv_seed`` is the 32-byte Ed25519 seed (the bytes stored
    in ``<keystore>/local.private``).

    Raises ``UnsealError`` on any failure.
    """
    if not isinstance(wrap, dict):
        raise UnsealError(f"recipient_wrap is not an object: {type(wrap).__name__}")

    frame = wrap.get("frame")
    if frame != WRAP_FRAME:
        raise UnsealError(
            f"unsupported sealed-box frame {frame!r}; expected {WRAP_FRAME!r}"
        )

    recipient_did = wrap.get("recipient_did")
    if not isinstance(recipient_did, str):
        raise UnsealError("recipient_wrap.recipient_did missing or not a string")

    try:
        eph_pub_bytes = base64.b64decode(wrap["ephemeral_x25519_pub_b64"])
        wrap_nonce = base64.b64decode(wrap["wrap_nonce_b64"])
        wrapped = base64.b64decode(wrap["wrapped_bek_b64"])
    except (KeyError, ValueError, TypeError) as exc:
        raise UnsealError(f"recipient_wrap fields malformed: {exc}") from exc

    if len(eph_pub_bytes) != 32:
        raise UnsealError(
            f"ephemeral_x25519_pub_b64 decoded to {len(eph_pub_bytes)} bytes; expected 32"
        )
    if len(wrap_nonce) != 12:
        raise UnsealError(
            f"wrap_nonce_b64 decoded to {len(wrap_nonce)} bytes; expected 12"
        )

    # Convert recipient's Ed25519 priv seed to X25519 private bytes.
    try:
        x_priv_bytes = _ed25519_priv_to_x25519_priv(device_priv_seed)
    except Exception as exc:  # noqa: BLE001 — wrap any libsodium / size issue
        raise UnsealError(f"could not derive X25519 priv from device seed: {exc}") from exc

    # We also need the recipient's X25519 PUBLIC key to reconstruct the
    # HKDF salt that the producer used. Derive from the recipient_did
    # in the wrap (NOT from the device seed) — defending against a
    # malicious wrap that names a different DID than the one the
    # recipient holds.
    try:
        recipient_ed_pub = _did_key_to_ed25519_pub(recipient_did)
        recipient_x_pub = _ed25519_pub_to_x25519_pub(recipient_ed_pub)
    except Exception as exc:  # noqa: BLE001
        raise UnsealError(f"could not derive recipient X25519 pub: {exc}") from exc

    x_priv = X25519PrivateKey.from_private_bytes(x_priv_bytes)
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub_bytes))

    salt = eph_pub_bytes + recipient_x_pub
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=WRAP_HKDF_INFO,
    ).derive(shared)

    aesgcm = AESGCM(key)
    try:
        bek = aesgcm.decrypt(wrap_nonce, wrapped, aad)
    except Exception as exc:  # noqa: BLE001 — InvalidTag etc.
        raise UnsealError(f"sealed-box decrypt failed: {exc}") from exc

    if len(bek) != 32:
        raise UnsealError(f"recovered BEK is not 32 bytes (got {len(bek)})")
    return bek


__all__ = [
    "UnsealError",
    "WRAP_FRAME",
    "WRAP_HKDF_INFO",
    "manifest_aad_for_wrap",
    "seal_bek_for_recipient",
    "unseal_bek_from_wrap",
]
