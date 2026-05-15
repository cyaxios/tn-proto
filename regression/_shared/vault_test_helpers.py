"""Helpers for silos that need to drive a live vault (C7, C8).

Three operations a silo needs once `vault_server` is running:

* **Mint a vault bearer JWT for a persona.** `dev_auth_login(base_url,
  handle)` POSTs to `/api/v1/dev/login` and returns the bearer token.
  This is the ONE automated encryption-exercising auth path per the
  crawl rule — other paths (OAuth, WebAuthn-PRF, passphrase-PBKDF2,
  mnemonic-as-backup-of-backups) get tested via Playwright (walk tier)
  or manual scripts (documented), not here.

* **Fetch a pending-claim blob as a vault user.** `fetch_pending_claim
  (base_url, vault_id, token)` GETs `/api/v1/pending-claims/{vault_id}`
  with the bearer token and returns the encrypted .tnpkg bytes the
  vault stored at INIT-UPLOAD time.

* **Decrypt + lay out the keystore on machine B.** `restore_keystore_to
  (target_dir, ciphertext, bek)` runs `decrypt_body_blob(...)` to peel
  the body, then writes the files into the conventional layout (`<B>/
  tn.yaml` at root, `<B>/keys/<basename>` for everything else). This
  is the bit that lets a fresh `tn.init(yaml_path=<B>/tn.yaml)` come
  back with the same ceremony DID as machine A.

All three are deliberately thin: each is a few lines of HTTP + a few
lines of file layout. Tests should be able to read one and immediately
see what's going on without chasing through layers of abstraction.

For background on the encrypted .tnpkg body layout (`body/` prefixed
flat dict), see `decrypt_body_blob` in `python/tn/export.py`.
"""
from __future__ import annotations

import base64
import io
import json
import urllib.error  # for HTTPError in except clauses
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Dev-auth login (rung-1 auth)
# ---------------------------------------------------------------------------


def dev_auth_login(base_url: str, handle: str = "alice") -> dict[str, Any]:
    """POST `/api/v1/dev/login` with `{handle: <handle>}`.

    Returns the full response dict — at minimum it has:

    * `token` (str): the bearer JWT to put in `Authorization: Bearer ...`.
    * `account_id` (str): the persona's vault account ID.
    * `expires_at` (str): ISO-8601 expiry.
    * `passphrase` (str, optional): the deterministic dev passphrase
      seeded against this account. Format `tn-dev-<handle>`.

    Raises:
      RuntimeError: if the vault returned non-2xx.

    Caller MUST have booted a vault subprocess with
    `TN_DEV_AUTH_BYPASS=1` (the `vault_server` fixture sets this).
    Production builds 404 on this route.
    """
    payload = json.dumps({"handle": handle}).encode("utf-8")
    req = urllib.request.Request(
        url=f"{base_url}/api/v1/dev/login",
        method="POST",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"dev_auth_login: vault returned {exc.code} {exc.reason} for "
            f"POST /api/v1/dev/login. Is TN_DEV_AUTH_BYPASS=1 on the "
            f"subprocess? Body: {exc.read()[:300]!r}"
        ) from exc
    return json.loads(body.decode("utf-8"))


# ---------------------------------------------------------------------------
# Pending-claim fetch (machine B / claim page would do this in production)
# ---------------------------------------------------------------------------


def fetch_pending_claim(base_url: str, vault_id: str, token: str) -> bytes:
    """GET `/api/v1/pending-claims/{vault_id}` with the bearer token.

    Returns the raw encrypted .tnpkg bytes (`application/octet-stream`)
    that the vault stored at INIT-UPLOAD time. The body is opaque to
    the vault — it's encrypted under a BEK that travels in the URL
    fragment, not on the server.

    Caller decrypts via `restore_keystore_to(...)` below.
    """
    req = urllib.request.Request(
        url=f"{base_url}/api/v1/pending-claims/{vault_id}",
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read()


def fetch_pending_claim_404_ok(
    base_url: str, vault_id: str, token: str
) -> bytes | None:
    """Variant that returns None on a 404 instead of raising. Useful for
    "did the early-delete actually delete?" assertions.
    """
    try:
        return fetch_pending_claim(base_url, vault_id, token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def delete_pending_claim(base_url: str, vault_id: str, token: str) -> bool:
    """Best-effort DELETE of a pending-claim row.

    Used by the `vault_cleanup` fixture to scrub test-created pending
    claims off a live vault we don't own. The endpoint is idempotent
    server-side (deleting a missing row is a 204 no-op).

    Returns:
      True on success (204), False if the row was already gone or the
      DELETE was rejected (e.g. bound/expired — server returns 4xx).
      Never raises — cleanup must not mask the underlying test failure.
    """
    req = urllib.request.Request(
        url=f"{base_url}/api/v1/pending-claims/{vault_id}",
        method="DELETE",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 204
    except urllib.error.HTTPError:
        return False
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Claim-URL parsing
# ---------------------------------------------------------------------------


def parse_claim_url(claim_url: str) -> tuple[str, bytes]:
    """Split a claim URL into `(vault_id, bek_bytes)`.

    Shape produced by `tn.init(link=True)`:

        https://vault.example/claim/<vault_id>#k=<bek_b64url>

    The BEK travels in the URL fragment so the vault never sees it. The
    fragment is base64url-encoded without padding (per Session 5 spec);
    we re-pad on decode.

    Raises:
      ValueError: on malformed URLs (missing #k=, vault_id not parseable).
    """
    parsed = urllib.parse.urlparse(claim_url)
    # Path is `/claim/<vault_id>`. Strip the prefix robustly.
    path = parsed.path.rstrip("/")
    if "/claim/" not in path:
        raise ValueError(
            f"parse_claim_url: expected '/claim/<vault_id>' in URL path, "
            f"got {parsed.path!r}"
        )
    vault_id = path.rsplit("/claim/", 1)[1]
    if not vault_id:
        raise ValueError(f"parse_claim_url: empty vault_id in {claim_url!r}")

    # Fragment is `k=<b64url>` (may also include other params; spec
    # currently only defines k=).
    frag_kvs = dict(urllib.parse.parse_qsl(parsed.fragment))
    if "k" not in frag_kvs:
        raise ValueError(
            f"parse_claim_url: no '#k=' in fragment {parsed.fragment!r}"
        )
    bek_b64 = frag_kvs["k"]
    # base64url with optional padding.
    bek = base64.urlsafe_b64decode(bek_b64 + "==")
    if len(bek) != 32:
        raise ValueError(
            f"parse_claim_url: BEK is {len(bek)} bytes, expected 32"
        )
    return vault_id, bek


# ---------------------------------------------------------------------------
# Decrypt + lay out the keystore on machine B
# ---------------------------------------------------------------------------


def restore_keystore_to(
    target_dir: Path,
    ciphertext_tnpkg: bytes,
    bek: bytes,
) -> Path:
    """Decrypt a vault-fetched .tnpkg + lay it out on disk.

    1. Parse the outer .tnpkg (it's a zip — body/ + manifest.json).
    2. Pull `body/encrypted.bin` (the AES-GCM blob).
    3. Call `decrypt_body_blob(...)` to get a flat `{name: bytes}` dict
       of `body/...` files.
    4. Write each into `target_dir`:
       - `body/tn.yaml` -> `target_dir/tn.yaml`
       - `body/WARNING_CONTAINS_PRIVATE_KEYS` -> `target_dir/
         WARNING_CONTAINS_PRIVATE_KEYS` (just a marker file)
       - `body/<anything-else>` -> `target_dir/keys/<basename>`

    Returns the path to the laid-out `target_dir/tn.yaml` so the
    caller can `tn.init(yaml_path=...)` immediately.

    Raises:
      ValueError: if the tnpkg doesn't contain `body/encrypted.bin`
        (means the export wasn't encrypted — wrong shape for this
        helper) or the body lacks `body/tn.yaml`.

    Assumes the caller has already created `target_dir`. The `keys/`
    subdir is auto-created.
    """
    # tn.export.decrypt_body_blob is the canonical reader for the
    # inner encrypted body. The outer .tnpkg envelope is just a zip —
    # we read it directly here because `_read_manifest` only accepts a
    # filesystem path, and writing the ciphertext to a temp file just
    # to pass it through would be ceremony for no gain.
    import zipfile as _zipfile

    from tn.export import decrypt_body_blob

    with _zipfile.ZipFile(io.BytesIO(ciphertext_tnpkg)) as zf:
        body_files = {name: zf.read(name) for name in zf.namelist()}
    if "body/encrypted.bin" not in body_files:
        raise ValueError(
            "restore_keystore_to: tnpkg has no 'body/encrypted.bin'. "
            "Was the export encrypted? Init-upload always encrypts; an "
            "unencrypted .tnpkg here means a code path drifted."
        )

    plaintext_files = decrypt_body_blob(body_files["body/encrypted.bin"], bek)

    yaml_dst: Path | None = None
    keys_dir = target_dir / "keys"

    for name, data in plaintext_files.items():
        # The body layout always uses 'body/...' as the inner prefix.
        # Defensively strip it if present.
        rel = name[len("body/"):] if name.startswith("body/") else name

        if rel == "tn.yaml":
            dst = target_dir / "tn.yaml"
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            yaml_dst = dst
        elif rel == "WARNING_CONTAINS_PRIVATE_KEYS":
            dst = target_dir / "WARNING_CONTAINS_PRIVATE_KEYS"
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
        else:
            # Anything else is keystore material. Flatten into keys/
            # using just the basename — the tnpkg's directory structure
            # is an internal detail; the ceremony's yaml + keystore
            # loader expects everything in one directory.
            keys_dir.mkdir(parents=True, exist_ok=True)
            basename = Path(rel).name
            (keys_dir / basename).write_bytes(data)

    if yaml_dst is None:
        raise ValueError(
            "restore_keystore_to: decrypted body has no 'body/tn.yaml'. "
            f"Inventory: {sorted(plaintext_files.keys())!r}"
        )
    return yaml_dst


# ---------------------------------------------------------------------------
# Convenience: load a persisted pending-claim record from sync_state
# ---------------------------------------------------------------------------


def read_pending_claim_record(yaml_path: Path) -> Mapping[str, Any] | None:
    """Convenience wrapper around `tn.sync_state.get_pending_claim` for
    silo tests that want to inspect what the SDK persisted to disk.

    Returns the dict (vault_id, expires_at, claim_url, password_b64) or
    None if the ceremony hasn't done an init-upload yet.
    """
    from tn.sync_state import get_pending_claim

    return get_pending_claim(yaml_path)


