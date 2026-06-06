"""Supported AWK/BEK whole-body PUSH (D-20 / D-22) — the inverse of
:mod:`tn.wallet_restore_passphrase`.

This is the headless producer the SDK was missing: where
``wallet_restore_passphrase._derive_bek_via_passphrase`` UNWRAPS the
project BEK (credential key -> AWK -> BEK) and
``wallet_restore._decrypt_blob_with_bek`` DECRYPTS the body frame, this
module does the exact reverse so a body pushed here round-trips through
``tn wallet restore --passphrase``:

  1. derive the AWK from the account passphrase + credential wrap
     (PBKDF2-SHA256 credential key, AES-GCM unwrap, AAD ``tn-vault-awk-wrap-v1``),
  2. derive the existing project BEK when the project already has a
     wrapped-key row, else MINT a fresh 32-byte BEK and wrap it under the
     AWK (AES-GCM, AAD ``tn-vault-bek-wrap-v1``) and PUT wrapped-key,
  3. pack the ceremony body (keystore files + ``tn.yaml``) into a STORED
     zip keyed ``body/<name>`` and AES-256-GCM encrypt it under the BEK as
     a no-AAD ``nonce||ct`` frame (the shape
     ``wallet_restore._decrypt_blob_with_bek`` reads), then
  4. PUT the frame to ``encrypted-blob-account`` with ``If-Match`` (the
     current generation, or ``*`` for the first write).

1:1 with the TS reference ``ts-sdk/src/cli/wallet_sync.ts::pushCeremonyBody``
and the browser minter (``tnproto-org/static/account/project_minter.js``
steps 5-6). The crypto primitives are NOT reimplemented — the wrap/unwrap
helpers and AAD constants are reused from
:mod:`tn.wallet_restore_passphrase`, and the STORED-zip + AES-GCM body
frame matches :func:`tn.export._encrypt_body_in_place`.

We use stdlib ``urllib`` (mirroring the restore module) rather than the
httpx VaultClient so the push works against the account bearer JWT the
same way restore does — the vault's account routes
(``credentials?include=wrap``, ``projects/{id}/wrapped-key``,
``projects/{id}/encrypted-blob[-account]``) resolve the account from the
bearer (``require_account_id``), so no DID-challenge handshake is needed.
"""

from __future__ import annotations

import io
import json
import os
import urllib.error
import urllib.request
import zipfile
from base64 import b64encode
from urllib.parse import urljoin

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .wallet_restore import RestoreError
from .wallet_restore_passphrase import (
    AAD_AWK_WRAP,
    AAD_BEK_WRAP,
    _aes_gcm_unwrap,
    _derive_credential_key_pbkdf2,
    _fetch_credential_with_wrap,
    _fetch_wrapped_key,
)


class PushError(RuntimeError):
    """Raised on any failure during the AWK/BEK whole-body push."""


def _b64(data: bytes) -> str:
    """Standard-padded base64, matching the wire shape the restore side
    feeds through ``_b64decode_loose``."""
    return b64encode(data).decode("ascii")


def _bearer_request(
    *,
    method: str,
    url: str,
    bearer: str,
    json_body: dict | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, bytes]:
    """One bearer-authed JSON request. Returns ``(status, body)``; raises
    :class:`PushError` only on transport failure (a non-2xx status is
    returned for the caller to interpret, mirroring the restore helpers)."""
    data = None
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json",
    }
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url=url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b"")
    except urllib.error.URLError as e:
        raise PushError(f"could not reach {url}: {e.reason}") from e


# ── AWK derivation (the unwrap leg shared with restore) ───────────────


def _derive_awk_via_passphrase(
    *,
    vault_url: str,
    bearer: str,
    passphrase: str,
    credential_id: str | None = None,
) -> bytes:
    """Derive the 32-byte Account Wrapping Key from the passphrase.

    The first half of :func:`wallet_restore_passphrase._derive_bek_via_passphrase`
    (credential key -> AWK), factored out so the push can mint+wrap a
    fresh BEK under the SAME AWK the restore side will later recover.
    """
    cred = _fetch_credential_with_wrap(
        vault_url=vault_url,
        bearer=bearer,
        credential_id=credential_id,
    )
    kdf = cred.get("kdf")
    if kdf != "pbkdf2-sha256":
        raise PushError(
            f"credential KDF {kdf!r} not supported in CLI; use the "
            "browser flow to push",
        )
    params = cred.get("kdf_params") or {}
    salt = params.get("salt_b64")
    iters = params.get("iterations") or params.get("iter") or 300_000
    if not salt:
        raise PushError("credential row missing kdf_params.salt_b64")

    cred_key = _derive_credential_key_pbkdf2(
        passphrase=passphrase,
        salt_b64=salt,
        iterations=int(iters),
    )
    try:
        awk = _aes_gcm_unwrap(
            key=cred_key,
            wrapped_b64=cred["wrapped_account_key_b64"],
            nonce_b64=cred["wrap_nonce_b64"],
            aad=AAD_AWK_WRAP,
        )
    except RestoreError as e:
        raise PushError(str(e)) from e
    if len(awk) != 32:
        raise PushError(f"unwrapped AWK has wrong length ({len(awk)})")
    return awk


def _wrap_bek_under_awk(awk: bytes, bek: bytes) -> tuple[str, str]:
    """AES-256-GCM wrap ``bek`` under ``awk`` with AAD ``tn-vault-bek-wrap-v1``.

    Inverse of the restore side's BEK unwrap. Returns
    ``(wrapped_bek_b64, wrap_nonce_b64)`` — the wire fields
    ``PUT /projects/{id}/wrapped-key`` expects. Mirrors TS
    ``wrapBekUnderAwk``.
    """
    if len(awk) != 32:
        raise PushError(f"AWK must be 32 bytes (got {len(awk)})")
    if len(bek) != 32:
        raise PushError(f"BEK must be 32 bytes (got {len(bek)})")
    nonce = os.urandom(12)
    wrapped = AESGCM(awk).encrypt(nonce, bek, AAD_BEK_WRAP)
    return _b64(wrapped), _b64(nonce)


# ── Body frame (the encrypt leg, inverse of _decrypt_blob_with_bek) ───


def encrypt_body_blob(body: dict[str, bytes], bek: bytes) -> bytes:
    """Pack ``body`` into a STORED zip and AES-256-GCM encrypt it.

    Produces the exact ``nonce||ct`` frame
    :func:`tn.wallet_restore._decrypt_blob_with_bek` reads back and whose
    STORED-zip plaintext :func:`tn.wallet_restore._try_unpack_export_frame`
    unpacks. Keys arrive as ``body/<name>`` and are sorted so the
    plaintext is deterministic (byte-equal to the TS
    ``core/body_encryption.encryptBodyBlob`` and Python
    ``export._encrypt_body_in_place`` for the same body).
    """
    if len(bek) != 32:
        raise PushError(f"BEK must be 32 bytes (AES-256); got {len(bek)}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in sorted(body.keys()):
            zf.writestr(name, body[name])
    plaintext = buf.getvalue()

    nonce = os.urandom(12)
    # AAD is empty — only the two WRAP layers are AAD-pinned (see
    # wallet_restore_passphrase AAD constants); the body frame is plain
    # nonce||ct so it round-trips through _decrypt_blob_with_bek.
    ciphertext = AESGCM(bek).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


# ── Wrapped-key + encrypted-blob routes ───────────────────────────────


def _put_wrapped_key(
    *,
    vault_url: str,
    bearer: str,
    project_id: str,
    wrapped_bek_b64: str,
    wrap_nonce_b64: str,
) -> None:
    url = urljoin(
        vault_url.rstrip("/") + "/",
        f"api/v1/projects/{project_id}/wrapped-key",
    )
    code, body = _bearer_request(
        method="PUT",
        url=url,
        bearer=bearer,
        json_body={
            "wrapped_bek_b64": wrapped_bek_b64,
            "wrap_nonce_b64": wrap_nonce_b64,
            "cipher_suite": "aes-256-gcm",
        },
    )
    if code != 200:
        raise PushError(
            f"PUT wrapped-key returned HTTP {code}: "
            f"{body[:200].decode('utf-8', errors='replace')}",
        )


def _current_blob_generation(
    *,
    vault_url: str,
    bearer: str,
    project_id: str,
) -> str:
    """If-Match value: the current encrypted-blob ``generation``, or ``*``
    when the project has no blob yet (404). Mirrors TS ``getEncryptedBlob``
    + the ``ifMatch`` resolution in ``pushCeremonyBody``."""
    url = urljoin(
        vault_url.rstrip("/") + "/",
        f"api/v1/projects/{project_id}/encrypted-blob",
    )
    code, body = _bearer_request(method="GET", url=url, bearer=bearer)
    if code == 404:
        return "*"
    if code != 200:
        raise PushError(
            f"GET encrypted-blob returned HTTP {code}: "
            f"{body[:200].decode('utf-8', errors='replace')}",
        )
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return "*"
    gen = doc.get("generation")
    if isinstance(gen, int) or (isinstance(gen, str) and gen != ""):
        return str(gen)
    return "*"


def _put_encrypted_blob_account(
    *,
    vault_url: str,
    bearer: str,
    project_id: str,
    frame: bytes,
    if_match: str,
) -> dict:
    """PUT the no-AAD ``nonce||ct`` body frame to encrypted-blob-account.

    ``ciphertext_b64`` carries the WHOLE frame so the restore side reads
    it as the blob; ``nonce_b64`` is the 12-byte prefix (the server
    requires the field). ``salt``/``kdf`` are informational on the server
    (it stores the BEK-wrap separately) — we match the browser minter.
    """
    url = urljoin(
        vault_url.rstrip("/") + "/",
        f"api/v1/projects/{project_id}/encrypted-blob-account",
    )
    code, body = _bearer_request(
        method="PUT",
        url=url,
        bearer=bearer,
        json_body={
            "ciphertext_b64": _b64(frame),
            "nonce_b64": _b64(frame[:12]),
            "salt_b64": _b64(os.urandom(16)),
            "kdf": "pbkdf2-sha256",
            "kdf_params": {"iterations": 1},
            "cipher_suite": "aes-256-gcm",
            "bundle_kind": "project-body-v1",
        },
        extra_headers={"If-Match": if_match},
    )
    if code == 412:
        raise PushError(
            "encrypted-blob PUT precondition failed (concurrent writer "
            f"bumped the generation): {body[:200].decode('utf-8', errors='replace')}",
        )
    if code != 200:
        raise PushError(
            f"PUT encrypted-blob-account returned HTTP {code}: "
            f"{body[:200].decode('utf-8', errors='replace')}",
        )
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}


# ── Top-level push ────────────────────────────────────────────────────


def push_ceremony_body(
    *,
    vault_url: str,
    bearer: str,
    project_id: str,
    passphrase: str,
    body: dict[str, bytes],
    credential_id: str | None = None,
    if_match: str | None = None,
) -> dict:
    """Mint-or-derive the project BEK, encrypt + PUT the ceremony body.

    The full inverse of the passphrase restore chain. ``body`` maps
    ``body/<name>`` keys to raw file bytes (keystore files + ``tn.yaml``).

    Returns the parsed ``encrypted-blob-account`` PUT response
    (``{project_id, generation, size_bytes, stored_at}``). Raises
    :class:`PushError` on any failure (so the caller can record it per the
    ``SyncResult.errors`` contract).

    ``if_match`` overrides the auto-resolved generation (used by the
    concurrent-conflict test to force a stale precondition).
    """
    # 1. Derive the AWK, then derive-or-mint the BEK.
    awk = _derive_awk_via_passphrase(
        vault_url=vault_url,
        bearer=bearer,
        passphrase=passphrase,
        credential_id=credential_id,
    )

    wrapped = None
    try:
        wrapped = _fetch_wrapped_key(
            vault_url=vault_url,
            bearer=bearer,
            project_id=project_id,
        )
    except RestoreError:
        # No wrapped-key row yet (404 surfaces as RestoreError from the
        # restore helper) -> mint path below.
        wrapped = None

    if wrapped and wrapped.get("wrapped_bek_b64"):
        try:
            bek = _aes_gcm_unwrap(
                key=awk,
                wrapped_b64=wrapped["wrapped_bek_b64"],
                nonce_b64=wrapped["wrap_nonce_b64"],
                aad=AAD_BEK_WRAP,
            )
        except RestoreError as e:
            raise PushError(f"could not unwrap existing BEK: {e}") from e
        if len(bek) != 32:
            raise PushError(f"unwrapped BEK has wrong length ({len(bek)})")
    else:
        # MINT: fresh BEK, wrap under the AWK, register the project by
        # PUTting the wrapped-key FIRST (the encrypted-blob PUT checks
        # ownership against project_wrapped_keys — order matters, per
        # project_minter.js step 5).
        bek = os.urandom(32)
        wrapped_bek_b64, wrap_nonce_b64 = _wrap_bek_under_awk(awk, bek)
        _put_wrapped_key(
            vault_url=vault_url,
            bearer=bearer,
            project_id=project_id,
            wrapped_bek_b64=wrapped_bek_b64,
            wrap_nonce_b64=wrap_nonce_b64,
        )

    # 2. Encrypt the body as the no-AAD nonce||ct frame.
    frame = encrypt_body_blob(body, bek)

    # 3. Resolve If-Match (current generation or "*") unless overridden.
    resolved_if_match = (
        if_match
        if if_match is not None
        else _current_blob_generation(
            vault_url=vault_url,
            bearer=bearer,
            project_id=project_id,
        )
    )

    # 4. PUT the frame.
    return _put_encrypted_blob_account(
        vault_url=vault_url,
        bearer=bearer,
        project_id=project_id,
        frame=frame,
        if_match=resolved_if_match,
    )


__all__ = [
    "PushError",
    "encrypt_body_blob",
    "push_ceremony_body",
]
