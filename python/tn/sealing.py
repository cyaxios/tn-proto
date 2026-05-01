"""Client-side AES-GCM sealing for vault blob uploads.

**DEPRECATED (2026-04-29) pending review.** Per D-23 in
``docs/superpowers/specs/2026-04-28-vault-decisions-log.md``, the
per-file sealing model implemented here is superseded by the
whole-body encryption model in the new vault flow (per-account AWK
+ per-project BEK; D-20). New code MUST NOT call this module's
``seal()`` / ``_unseal()``. Existing callers and tests stay until
the legacy ``PUT /api/v1/projects/{id}/files/{name}`` route is
removed in a future cycle. The TS / Rust ports of this module
(originally tracked as §10 item 2 sealing parity) are explicitly
NOT being built; that workstream is dropped.

Every file uploaded to the vault passes through `seal()` first, and
every file downloaded passes through `_unseal()`. The vault sees
ciphertext only.

The AAD (Additional Authenticated Data) binds the ciphertext to its
logical path inside the user's ceremony:

    aad = f"{did}/{ceremony_id}/{file_name}"

So if the vault operator (or an attacker with DB access) tries to
rename a blob — e.g., swap Alice's `default.jwe.sender` into Bob's
project under the same name — AES-GCM auth tag verification fails on
_unseal. The key alone isn't enough; the blob has to land at the
right logical address.

Wire format (v1), all fields base64url (unpadded) when serialized:

    {
      "v": 1,
      "nonce": "<12-byte random>",
      "ct": "<AES-GCM ciphertext + 16-byte tag>",
      "aad": "<plaintext AAD string>"
    }

The AAD is stored in the blob so the recipient knows what string to
pass back into AES-GCM; the vault's filesystem / DB metadata is
untrusted.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEAL_VERSION = 1
NONCE_SIZE = 12
AES_KEY_SIZE = 32


class SealingError(RuntimeError):
    """Raised on _unseal failure (bad key, tampered ct, bad version, etc.)."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _make_aad(did: str, ceremony_id: str, file_name: str) -> str:
    """Build the AAD string. Used by both seal and _unseal."""
    if "/" in ceremony_id or "/" in file_name:
        raise ValueError("ceremony_id and file_name must not contain '/'")
    return f"{did}/{ceremony_id}/{file_name}"


@dataclass
class SealedBlob:
    """Serializable sealed blob."""

    v: int
    nonce: bytes
    ct: bytes
    aad: str

    def to_bytes(self) -> bytes:
        """Serialize to the wire JSON."""
        return json.dumps(
            {
                "v": self.v,
                "nonce": _b64e(self.nonce),
                "ct": _b64e(self.ct),
                "aad": self.aad,
            },
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> SealedBlob:
        try:
            d = json.loads(data)
        except json.JSONDecodeError as e:
            raise SealingError(f"not valid sealed blob JSON: {e}") from e
        try:
            v = int(d["v"])
            nonce = _b64d(d["nonce"])
            ct = _b64d(d["ct"])
            aad = str(d["aad"])
        except (KeyError, TypeError, ValueError) as e:
            raise SealingError(f"malformed sealed blob fields: {e}") from e
        if v != SEAL_VERSION:
            raise SealingError(
                f"sealed blob version {v} unsupported (this build expects {SEAL_VERSION})",
            )
        if len(nonce) != NONCE_SIZE:
            raise SealingError(
                f"sealed blob nonce size {len(nonce)} != {NONCE_SIZE}",
            )
        return cls(v=v, nonce=nonce, ct=ct, aad=aad)


def _seal(
    plaintext: bytes,
    *,
    wrap_key: bytes,
    did: str,
    ceremony_id: str,
    file_name: str,
) -> SealedBlob:
    """Seal `plaintext` under `wrap_key` bound to the logical path."""
    if len(wrap_key) != AES_KEY_SIZE:
        raise ValueError(
            f"wrap_key must be {AES_KEY_SIZE} bytes (got {len(wrap_key)})",
        )
    aad = _make_aad(did, ceremony_id, file_name)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(wrap_key)
    ct = aesgcm.encrypt(nonce, plaintext, aad.encode("utf-8"))
    return SealedBlob(v=SEAL_VERSION, nonce=nonce, ct=ct, aad=aad)


def _unseal(
    blob: SealedBlob | bytes,
    *,
    wrap_key: bytes,
    expected_did: str | None = None,
    expected_ceremony_id: str | None = None,
    expected_file_name: str | None = None,
) -> bytes:
    """Unseal a blob. Optionally verify the AAD matches expected values.

    Raises SealingError on any failure: wrong key, tampered ciphertext,
    version mismatch, unexpected logical path.
    """
    if isinstance(blob, (bytes, bytearray)):
        blob = SealedBlob.from_bytes(bytes(blob))

    if len(wrap_key) != AES_KEY_SIZE:
        raise ValueError(
            f"wrap_key must be {AES_KEY_SIZE} bytes (got {len(wrap_key)})",
        )

    if (
        expected_did is not None
        or expected_ceremony_id is not None
        or expected_file_name is not None
    ):
        if expected_did is None or expected_ceremony_id is None or expected_file_name is None:
            raise ValueError(
                "expected_did/ceremony_id/file_name must be specified together or not at all",
            )
        expected_aad = _make_aad(
            expected_did,
            expected_ceremony_id,
            expected_file_name,
        )
        if blob.aad != expected_aad:
            raise SealingError(
                f"AAD mismatch: blob claims {blob.aad!r}, expected {expected_aad!r}",
            )

    try:
        aesgcm = AESGCM(wrap_key)
        return aesgcm.decrypt(
            blob.nonce,
            blob.ct,
            blob.aad.encode("utf-8"),
        )
    except Exception as e:
        raise SealingError(f"AES-GCM decrypt failed: {type(e).__name__}") from e
