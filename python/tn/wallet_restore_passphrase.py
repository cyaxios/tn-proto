"""Passphrase-fallback restore path (D-22).

When the user can't run a browser (headless server, no display), we
let them derive the credential key from a passphrase and unwrap the
project BEK directly in the CLI. Only PBKDF2-SHA256 is supported here;
Argon2id KDFs require the browser path because we don't ship an
argon2 dependency in the Python SDK.

Refs: D-20 (per-account AWK / per-project BEK), D-22 (passphrase
fallback). Plan:
``docs/superpowers/plans/2026-04-29-multi-device-restore.md``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urljoin

from .wallet_restore import RestoreError, _b64decode_loose


# AAD strings used by the browser registration_flow / wrap_unwrap. They
# MUST match the ones in tnproto-org/static/credentials/wrap_unwrap.js
# or unwrapping fails.
AAD_BEK_WRAP = b"tn-vault-bek-wrap-v1"
AAD_AWK_WRAP = b"tn-vault-awk-wrap-v1"


def _bearer_get(url: str, bearer: str, timeout: float = 30.0) -> tuple[int, bytes]:
    req = urllib.request.Request(url=url, method="GET")
    req.add_header("Authorization", f"Bearer {bearer}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b"")
    except urllib.error.URLError as e:
        raise RestoreError(f"could not reach {url}: {e.reason}") from e


def _derive_credential_key_pbkdf2(
    *,
    passphrase: str,
    salt_b64: str,
    iterations: int,
) -> bytes:
    """Derive a 32-byte AES key from passphrase + PBKDF2-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = _b64decode_loose(salt_b64)
    if iterations < 10_000:
        # Defense against test fixtures that accidentally ship low
        # iteration counts. The browser flow uses >=300k.
        raise RestoreError(
            f"refusing PBKDF2 with iterations={iterations} (<10000)",
        )
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _aes_gcm_unwrap(
    *,
    key: bytes,
    wrapped_b64: str,
    nonce_b64: str,
    aad: bytes,
) -> bytes:
    """AES-256-GCM decrypt with the given AAD."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(key) != 32:
        raise RestoreError(f"unwrap key must be 32 bytes (got {len(key)})")
    nonce = _b64decode_loose(nonce_b64)
    if len(nonce) != 12:
        raise RestoreError(f"AES-GCM nonce must be 12 bytes (got {len(nonce)})")
    ct = _b64decode_loose(wrapped_b64)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, aad)
    except Exception as e:  # noqa: BLE001 — surface a clean error
        raise RestoreError(
            f"unwrap failed (wrong passphrase or KDF mismatch): {type(e).__name__}",
        ) from e


def _fetch_credential_with_wrap(
    *,
    vault_url: str,
    bearer: str,
    credential_id: str | None = None,
) -> dict:
    """Pull a credential row including the wrapping material.

    If ``credential_id`` is None, returns the unique row marked
    ``is_primary=true`` from the list endpoint, or raises if there
    are zero/multiple primary rows.
    """
    base = vault_url.rstrip("/") + "/"
    if credential_id is None:
        list_url = urljoin(base, "api/v1/account/credentials?include=wrap")
        code, body = _bearer_get(list_url, bearer)
        if code != 200:
            raise RestoreError(
                f"credentials list returned HTTP {code}: "
                f"{body[:200].decode('utf-8', errors='replace')}",
            )
        rows = json.loads(body.decode("utf-8"))
        primary = [r for r in rows if r.get("is_primary")]
        candidates = primary if primary else rows
        if not candidates:
            raise RestoreError(
                "no credentials registered for this account — re-run "
                "with the browser flow so a passkey can be created",
            )
        if len(candidates) > 1:
            raise RestoreError(
                f"{len(candidates)} primary credentials found; pass "
                "--credential-id to choose one explicitly",
            )
        return candidates[0]

    wrap_url = urljoin(base, f"api/v1/account/credentials/{credential_id}/wrap")
    code, body = _bearer_get(wrap_url, bearer)
    if code != 200:
        raise RestoreError(
            f"credential wrap returned HTTP {code}: "
            f"{body[:200].decode('utf-8', errors='replace')}",
        )
    return json.loads(body.decode("utf-8"))


def _fetch_wrapped_key(
    *,
    vault_url: str,
    bearer: str,
    project_id: str,
) -> dict:
    """GET /api/v1/projects/{id}/wrapped-key as a parsed dict."""
    url = urljoin(
        vault_url.rstrip("/") + "/",
        f"api/v1/projects/{project_id}/wrapped-key",
    )
    code, body = _bearer_get(url, bearer)
    if code != 200:
        raise RestoreError(
            f"wrapped-key returned HTTP {code}: "
            f"{body[:200].decode('utf-8', errors='replace')}",
        )
    return json.loads(body.decode("utf-8"))


def _derive_bek_via_passphrase(
    *,
    vault_url: str,
    bearer: str,
    project_id: str,
    passphrase: str,
    credential_id: str | None = None,
) -> bytes:
    """Full passphrase-only derivation chain.

    Returns the raw 32-byte BEK so the caller can hand it to
    :func:`tn.wallet_restore._decrypt_blob_with_bek`.
    """
    cred = _fetch_credential_with_wrap(
        vault_url=vault_url,
        bearer=bearer,
        credential_id=credential_id,
    )
    kdf = cred.get("kdf")
    if kdf != "pbkdf2-sha256":
        raise RestoreError(
            f"credential KDF {kdf!r} not supported in CLI; use the "
            "browser flow (`tn wallet restore` without --passphrase)",
        )
    params = cred.get("kdf_params") or {}
    salt = params.get("salt_b64")
    iters = params.get("iterations") or params.get("iter") or 300_000
    if not salt:
        raise RestoreError("credential row missing kdf_params.salt_b64")

    cred_key = _derive_credential_key_pbkdf2(
        passphrase=passphrase,
        salt_b64=salt,
        iterations=int(iters),
    )

    awk = _aes_gcm_unwrap(
        key=cred_key,
        wrapped_b64=cred["wrapped_account_key_b64"],
        nonce_b64=cred["wrap_nonce_b64"],
        aad=AAD_AWK_WRAP,
    )
    if len(awk) != 32:
        raise RestoreError(f"unwrapped AWK has wrong length ({len(awk)})")

    wrapped = _fetch_wrapped_key(
        vault_url=vault_url,
        bearer=bearer,
        project_id=project_id,
    )
    bek = _aes_gcm_unwrap(
        key=awk,
        wrapped_b64=wrapped["wrapped_bek_b64"],
        nonce_b64=wrapped["wrap_nonce_b64"],
        aad=AAD_BEK_WRAP,
    )
    if len(bek) != 32:
        raise RestoreError(f"unwrapped BEK has wrong length ({len(bek)})")
    return bek


__all__ = [
    "_aes_gcm_unwrap",
    "_derive_bek_via_passphrase",
    "_derive_credential_key_pbkdf2",
    "_fetch_credential_with_wrap",
    "_fetch_wrapped_key",
]
