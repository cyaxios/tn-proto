"""Sealed-box recipient wrap over Ed25519 device keys.

Publishers can lock a kit_bundle's body for a specific recipient using
the same primitive libsodium calls a "sealed box" — anonymous-sender
public-key encryption — built on top of X25519 ECDH and AES-256-GCM.

The recipient's only existing asymmetric key is the Ed25519 device key
encoded into their ``did:key:z...`` identifier. Ed25519 is signing-only,
but its keys can be losslessly converted to the corresponding Curve25519
(X25519) keypair via the standard birational map. We use libsodium's
``crypto_sign_ed25519_pk_to_curve25519`` and
``crypto_sign_ed25519_sk_to_curve25519`` for both halves.

This is **not JWE.** Same primitives, smaller frame.

Wire shape (lives in ``manifest.state.body_encryption.recipient_wrap``)::

    {
        "frame": "tn-sealed-box-v1",
        "recipient_identity": "did:key:z...",
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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import _canonical_bytes
from .trust import parse_ed25519_did_key

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
            f"_ed25519_pub_to_x25519_pub: expected 32-byte Ed25519 pub, got {len(ed25519_pub)}"
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
            f"_ed25519_priv_to_x25519_priv: expected 32-byte Ed25519 seed, got {len(ed25519_seed)}"
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


def recipient_key_is_resolvable(did: str | None) -> bool:
    """True when ``did`` is a ``did:key`` with an embedded Ed25519 public key the
    sealed-box path can wrap the BEK under.

    Synthetic / placeholder DIDs (no embedded key) return False so a caller can
    seal ONLY when there is a real key to seal to, and fall back to a plaintext
    hand-off otherwise. Mirrors TS ``recipientKeyIsResolvable``.
    """
    if not did:
        return False
    try:
        parse_ed25519_did_key(did)
        return True
    except Exception:  # noqa: BLE001 — any parse failure means "can't seal to this"
        return False


# ---------------------------------------------------------------------------
# AAD: manifest minus signature minus recipient_wrap
# ---------------------------------------------------------------------------


def manifest_aad_for_wrap(manifest_dict: dict[str, Any]) -> bytes:
    """Compute the AES-GCM AAD that binds a recipient_wrap to its manifest.

    The AAD is the canonical bytes of the manifest dict with the
    following keys removed:

    * ``manifest_signature_b64`` — the signature is set AFTER the wrap is
      built; can't be in AAD.
    * ``state.body_encryption.recipient_wrap`` — singular, single-key
      wrap. Removed because the wrap binds to everything in the
      manifest EXCEPT itself.
    * ``state.body_encryption.recipient_wraps`` — plural, multi-key
      array (federation work). Same reasoning. Each entry binds against
      the same AAD; the holder of any single matching key can recover
      the BEK independently.

    Everything else (kind, from_did, to_did, ceremony_id, scope, clock,
    event_count, head_row_hash, the rest of body_encryption) is bound.

    Args:
        manifest_dict: The full manifest dict as it will land on the
            wire, possibly carrying an in-progress ``recipient_wrap``
            and/or signature — both are stripped in a defensive copy
            before canonical encoding. The caller's dict is NOT
            mutated.

    Returns:
        The byte-stable AAD ready to pass to
        :func:`seal_bek_for_recipient` (producer side) or
        :func:`unseal_bek_from_wrap` (recipient side).

    See Also:
        :func:`seal_bek_for_recipient`, :func:`unseal_bek_from_wrap`.
        :func:`tn.canonical._canonical_bytes`: The byte-stable JSON
            encoding the AAD relies on.
    """
    # Deep-copy so the caller's dict is not mutated.
    m = json.loads(json.dumps(manifest_dict, sort_keys=True))
    m.pop("manifest_signature_b64", None)
    state = m.get("state")
    if isinstance(state, dict):
        be = state.get("body_encryption")
        if isinstance(be, dict):
            be.pop("recipient_wrap", None)
            be.pop("recipient_wraps", None)
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

    Generates a fresh ephemeral X25519 keypair, runs ECDH against the
    recipient's X25519 pubkey (birationally derived from their Ed25519
    DID), feeds the shared secret through HKDF-SHA256 with salt
    ``ephemeral_pub || recipient_x_pub`` and info :data:`WRAP_HKDF_INFO`,
    then AES-256-GCM-encrypts ``bek`` under the derived key with ``aad``
    bound in.

    Args:
        bek: The 32-byte Body Encryption Key (or seed) to wrap. Caller
            is responsible for generating this — typically via
            ``os.urandom(32)`` or a deterministic ceremony seed.
        recipient_did: The recipient's ``did:key:z...`` identifier.
            Must be an Ed25519 DID (multicodec 0xed). Raises
            :class:`ValueError` for secp256k1 or malformed DIDs.
        aad: Additional authenticated data — typically the output of
            :func:`manifest_aad_for_wrap` so the wrap binds to its
            manifest and can't be lifted to a different one.

    Returns:
        Dict with five string fields suitable for direct embedding into
        ``manifest.state.body_encryption.recipient_wrap``. See module
        docstring for the wire shape.

    Raises:
        ValueError: If ``bek`` is not 32 bytes, or if ``recipient_did``
            is malformed or uses a non-Ed25519 curve.

    Example:
        >>> import os
        >>> wrap = seal_bek_for_recipient(
        ...     bek=os.urandom(32),
        ...     recipient_did="did:key:z6Mk...",  # doctest: +SKIP
        ...     aad=b"manifest-canonical-bytes",
        ... )

    See Also:
        :func:`unseal_bek_from_wrap`: The inverse.
        :func:`manifest_aad_for_wrap`: Build the right AAD.
    """
    if len(bek) != 32:
        raise ValueError(f"seal_bek_for_recipient: BEK must be 32 bytes; got {len(bek)}")

    recipient_ed_pub = parse_ed25519_did_key(recipient_did)
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
        "recipient_identity": recipient_did,
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

    Inverse of :func:`seal_bek_for_recipient`. Validates the wrap's
    frame, decodes the ephemeral X25519 pubkey and the wrapped
    ciphertext, converts the caller's Ed25519 seed to its X25519
    counterpart, runs ECDH against the embedded ephemeral pub, derives
    the same HKDF key the producer used, and AES-256-GCM-decrypts
    with ``aad`` bound in.

    The recipient's X25519 PUBLIC key used in the HKDF salt is
    rederived from the wrap's ``recipient_identity`` field — not from
    ``device_priv_seed`` — so a malicious wrap that names a different
    DID than the one the recipient holds fails authentication rather
    than silently succeeding under the wrong identity.

    Args:
        wrap: The :data:`WRAP_FRAME` dict as embedded in
            ``manifest.state.body_encryption.recipient_wrap``.
        device_priv_seed: The 32-byte Ed25519 seed (the bytes stored
            in ``<keystore>/local.private``). Not the expanded 64-byte
            secret key, not a hex string.
        aad: Additional authenticated data — must match what the
            producer passed to :func:`seal_bek_for_recipient`.
            Typically the output of :func:`manifest_aad_for_wrap`
            against the same manifest the wrap was embedded in.

    Returns:
        The 32-byte BEK.

    Raises:
        UnsealError: For every failure mode — unknown frame,
            malformed wrap fields, DID/seed shape mismatch, AEAD
            authentication failure (wrong key, wrong AAD, tampered
            ciphertext), or recovered BEK with wrong length.

    See Also:
        :func:`seal_bek_for_recipient`: The inverse.
        :func:`manifest_aad_for_wrap`: Build the right AAD.
    """
    if not isinstance(wrap, dict):
        raise UnsealError(f"recipient_wrap is not an object: {type(wrap).__name__}")

    frame = wrap.get("frame")
    if frame != WRAP_FRAME:
        raise UnsealError(f"unsupported sealed-box frame {frame!r}; expected {WRAP_FRAME!r}")

    recipient_did = wrap.get("recipient_identity")
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
        raise UnsealError(f"wrap_nonce_b64 decoded to {len(wrap_nonce)} bytes; expected 12")

    # Convert recipient's Ed25519 priv seed to X25519 private bytes.
    try:
        x_priv_bytes = _ed25519_priv_to_x25519_priv(device_priv_seed)
    except Exception as exc:
        raise UnsealError(f"could not derive X25519 priv from device seed: {exc}") from exc

    # We also need the recipient's X25519 PUBLIC key to reconstruct the
    # HKDF salt that the producer used. Derive from the recipient_did
    # in the wrap (NOT from the device seed) — defending against a
    # malicious wrap that names a different DID than the one the
    # recipient holds.
    try:
        recipient_ed_pub = parse_ed25519_did_key(recipient_did)
        recipient_x_pub = _ed25519_pub_to_x25519_pub(recipient_ed_pub)
    except Exception as exc:
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
    except Exception as exc:
        raise UnsealError(f"sealed-box decrypt failed: {exc}") from exc

    if len(bek) != 32:
        raise UnsealError(f"recovered BEK is not 32 bytes (got {len(bek)})")
    return bek


__all__ = [
    "WRAP_FRAME",
    "WRAP_HKDF_INFO",
    "UnsealError",
    "manifest_aad_for_wrap",
    "seal_bek_for_recipient",
    "unseal_bek_from_wrap",
]
