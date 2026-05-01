"""Keyed equality index tokens for envelope fields.

Replaces the raw SHA-256 field digest with an HMAC-SHA256 tag under a
per-group key derived from the ceremony's master index secret. Equality
search still works (same input ⇒ same token); raw log files are no longer
enough to mount an offline dictionary attack on indexed values.

Key hierarchy
-------------
    master_index_secret   (32 bytes, per-ceremony, in keystore/index_master.key)
        │
        └── HKDF-SHA256(info = "tn-index:v1:<ceremony_id>:<group_name>")
              │
              └── group_index_key  (32 bytes)
                    │
                    └── HMAC-SHA256(field_name || 0x00 || canonical(value))
                          │
                          └── token  ("hmac-sha256:v1:<64 hex chars>")

Scope rationale
---------------
The derived key is bound to (ceremony, group). A member of a group can
search any indexed field in that group — there is no per-recipient
search restriction. If a publisher wants a narrower search boundary
(some recipients can decrypt but not cross-search) they should write
the field into a separate group with a distinct recipient set. The
protocol does not try to give cryptographic search entitlements below
the group level.

Non-goals
---------
  * Does not hide equality from a holder of the group's index key.
  * Does not hide value frequency inside the indexed scope.
  * Does not protect small-domain fields (e.g. booleans) from a curious
    holder of the index key. Choose what to index accordingly.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import _canonical_bytes

MASTER_KEY_BYTES = 32
GROUP_KEY_BYTES = 32
INDEX_TOKEN_PREFIX = "hmac-sha256:v1:"
_HKDF_INFO_PREFIX = b"tn-index:v1:"


def _new_master_key() -> bytes:
    """Generate a fresh 32-byte master index secret for a ceremony."""
    return secrets.token_bytes(MASTER_KEY_BYTES)


def _derive_group_index_key(
    master: bytes, ceremony_id: str, group_name: str, epoch: int = 0
) -> bytes:
    """HKDF-SHA256 derive a per-group index key.

    Info string binds the output to the (ceremony, group, epoch) scope.
    `epoch` is incremented by `tn.admin.rotate()` so that rotating a
    group's BGW keys also invalidates its search index — old index
    holders cannot search new entries.
    """
    if len(master) != MASTER_KEY_BYTES:
        raise ValueError(f"master index key must be {MASTER_KEY_BYTES} bytes, got {len(master)}")
    info = (
        _HKDF_INFO_PREFIX
        + ceremony_id.encode("utf-8")
        + b":"
        + group_name.encode("utf-8")
        + b":"
        + str(int(epoch)).encode("ascii")
    )
    hk = HKDF(
        algorithm=hashes.SHA256(),
        length=GROUP_KEY_BYTES,
        salt=None,
        info=info,
    )
    return hk.derive(master)


def _index_token(group_index_key: bytes, field_name: str, value: object) -> str:
    """Compute the keyed equality token for a field within a group.

    The HMAC input is `field_name || 0x00 || _canonical_bytes(value)`, so
    collisions between distinct (field, value) pairs under the same key
    require either an HMAC forgery or a canonical-encoding collision.
    """
    if len(group_index_key) != GROUP_KEY_BYTES:
        raise ValueError(
            f"group index key must be {GROUP_KEY_BYTES} bytes, got {len(group_index_key)}"
        )
    msg = field_name.encode("utf-8") + b"\x00" + _canonical_bytes(value)
    tag = hmac.new(group_index_key, msg, hashlib.sha256).hexdigest()
    return INDEX_TOKEN_PREFIX + tag
