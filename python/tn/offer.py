"""tn.offer — JWE recipient bootstrap verb.

Generates an X25519 keypair for this party (if absent), emits a signed
offer package addressed to a publisher_did. The publisher absorbs the
package and wires the recipient's pub into their JWE group's
recipients JSON, enabling the recipient to decrypt future entries.

The package signature is self-consistent transport integrity. A publisher
must separately authenticate that the asserted recipient DID owns the signing
key and that the signed offer binds this X25519 enrollment before admitting it.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._keystore_backend import atomic_write_bytes
from .compile import _now_iso, _signing_key, emit_to_outbox
from .config import LoadedConfig
from .packaging import Package, sign


def _ensure_mykey(cfg: LoadedConfig, group: str) -> bytes:
    """Return the reader X25519 pub, atomically persisting its secret if absent."""
    mykey_path = cfg.keystore / f"{group}.jwe.mykey"
    if mykey_path.exists():
        sk = X25519PrivateKey.from_private_bytes(mykey_path.read_bytes())
    else:
        sk = X25519PrivateKey.generate()
        atomic_write_bytes(mykey_path, sk.private_bytes_raw())
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def offer(
    cfg: LoadedConfig,
    publisher_did: str,
    *,
    group: str = "default",
) -> Package:
    """Emit an `offer` package addressed to publisher_did.

    Generates an X25519 keypair for this recipient if none exists for
    `group`. Writes the package to <yaml_dir>/outbox/. Returns the Package.

    If the publisher_did doesn't look like a DID, raises ValueError with
    a pointed message.
    """
    if not publisher_did.startswith("did:"):
        raise ValueError(
            f"offer: publisher_did {publisher_did!r} must be a DID string "
            f"(start with 'did:'). Ask the publisher to share their ceremony's "
            f"device DID — it's written in their tn.yaml under the `me:` block."
        )
    pub = _ensure_mykey(cfg, group)
    pkg = Package(
        package_version=1,
        package_kind="offer",
        ceremony_id=cfg.ceremony_id,
        group=group,
        group_epoch=0,
        device_identity=cfg.device.device_identity,
        signer_verify_pub_b64="",
        recipient_identity=publisher_did,
        payload={"x25519_pub_b64": base64.b64encode(pub).decode("ascii")},
        compiled_at=_now_iso(),
    )
    signed = sign(pkg, _signing_key(cfg))
    emit_to_outbox(cfg, signed)
    return signed
