"""Multi-device restore (account-bound flow).

Implements the CLI side of the loopback dance from
``docs/superpowers/plans/2026-04-29-multi-device-restore.md``. The
browser does the WebAuthn-PRF unwrap; we receive the raw BEK over
loopback, fetch the encrypted blob from the vault, AES-GCM decrypt,
and write the resulting bytes to the user's chosen output directory.

Refs: D-3 (account vs package), D-19 (handler-driven sync), D-20
(account/project key hierarchy), spec section 9.9.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import urllib.error
import urllib.request

from .wallet_restore_loopback import TransferToken


# ── Errors ────────────────────────────────────────────────────────────


class RestoreError(RuntimeError):
    """Raised on any failure during the account-bound restore flow."""


# ── Result ────────────────────────────────────────────────────────────


@dataclass
class RestoreResult:
    out_dir: Path
    project_id: str
    account_id: str
    files_written: list[Path] = field(default_factory=list)
    raw_blob_path: Path | None = None
    notes: list[str] = field(default_factory=list)


# ── Base64 helper ─────────────────────────────────────────────────────


def _b64decode_loose(value: str) -> bytes:
    """Decode base64 (standard or url-safe, with or without padding)."""
    if not isinstance(value, str):
        raise RestoreError("expected base64 string")
    s = value.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    s += "=" * pad
    try:
        return base64.b64decode(s, validate=False)
    except Exception as e:  # noqa: BLE001 — cleanup the message for callers
        raise RestoreError(f"invalid base64: {e}") from e


# ── Vault HTTP helpers ────────────────────────────────────────────────
#
# We use stdlib urllib (no extra deps) so this module loads even on
# minimal environments. The CLI's pre-existing VaultClient uses
# requests; we deliberately avoid it here to keep restore self-
# contained and to leave the ergonomics of "should we add requests as
# a hard dep?" alone.


def _http_request(
    *,
    method: str,
    url: str,
    bearer: str,
    timeout: float = 30.0,
) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url=url, method=method)
    req.add_header("Authorization", f"Bearer {bearer}")
    req.add_header("Accept", "application/json, application/octet-stream")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.getcode(), body, headers
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, body, headers
    except urllib.error.URLError as e:
        raise RestoreError(f"could not reach vault at {url}: {e.reason}") from e


def _fetch_encrypted_blob(
    *,
    vault_url: str,
    project_id: str,
    bearer: str,
) -> bytes:
    """GET the encrypted-blob ciphertext bytes for ``project_id``.

    Per the plan, the new endpoint is
    ``GET /api/v1/projects/{id}/encrypted-blob`` and returns the raw
    ciphertext (nonce||ct+tag) as base64 inside JSON. We accept
    either a JSON body with ``ciphertext_b64`` or the existing
    ``encrypted-backup`` JSON shape (``ciphertext_b64`` field, same
    name) so this works against the still-DID-auth backup endpoint
    on older deployments.
    """
    base = vault_url.rstrip("/") + "/"
    url = urljoin(base, f"api/v1/projects/{project_id}/encrypted-blob")
    code, body, _hdrs = _http_request(method="GET", url=url, bearer=bearer)

    # 404 from the new endpoint -> try the legacy encrypted-backup. The
    # legacy one auths via DID, which our OAuth-only JWT may fail; we
    # surface the nicer error if both fail.
    if code == 404:
        legacy_url = urljoin(base, f"api/v1/projects/{project_id}/encrypted-backup")
        legacy_code, legacy_body, _ = _http_request(
            method="GET", url=legacy_url, bearer=bearer,
        )
        if legacy_code == 200:
            code, body = legacy_code, legacy_body
        else:
            raise RestoreError(
                f"encrypted blob not found for project {project_id} "
                f"(both /encrypted-blob and /encrypted-backup returned 404)",
            )

    if code != 200:
        snippet = body[:200].decode("utf-8", errors="replace")
        raise RestoreError(
            f"vault returned HTTP {code} for encrypted blob: {snippet}",
        )

    # Parse JSON body. We accept either ``{"ciphertext_b64": "..."}`` or
    # ``{"ciphertext": "..."}`` for forward compat.
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise RestoreError(f"vault returned non-JSON for encrypted blob: {e}") from e
    if not isinstance(doc, dict):
        raise RestoreError("encrypted blob response is not a JSON object")
    ct_b64 = doc.get("ciphertext_b64") or doc.get("ciphertext")
    if not ct_b64:
        raise RestoreError("encrypted blob response missing ciphertext field")
    return _b64decode_loose(ct_b64)


# ── AES-GCM decrypt ───────────────────────────────────────────────────


def _decrypt_blob_with_bek(blob: bytes, bek: bytes) -> bytes:
    """Decrypt ``blob`` (nonce||ciphertext+tag) under a 32-byte BEK.

    Mirrors the encryption shape produced by ``tn.export(...,
    encrypt_body_with=BEK)`` in :mod:`tn.export` and the browser
    publisher orchestration. Raises :class:`RestoreError` on any
    structural or AEAD failure.
    """
    if not isinstance(bek, (bytes, bytearray)) or len(bek) != 32:
        raise RestoreError("BEK must be 32 bytes")
    if len(blob) < 12 + 16:
        raise RestoreError(
            f"ciphertext too short ({len(blob)} bytes; need nonce+tag)",
        )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(bytes(bek))
    try:
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:  # noqa: BLE001 — surface a clean failure
        raise RestoreError(
            "decryption failed (wrong BEK or corrupted blob): "
            f"{type(e).__name__}",
        ) from e


# ── Plaintext unpack ──────────────────────────────────────────────────


def _try_unpack_export_frame(plaintext: bytes) -> dict[str, bytes] | None:
    """Try to parse the tn.export combined-blob plaintext.

    As of 2026-04-29 (D-31) the plaintext is a STORED zip; we try that
    first by sniffing the ``PK\\x03\\x04`` magic. If the magic doesn't
    match we fall back to Session 4's custom binary frame, kept here as
    LEGACY-COMPAT-2026-04-29 for in-flight bodies (drop after next state
    wipe):

        uint32_be member_count
        for each member:
          uint32_be name_len  || utf-8 name
          uint32_be data_len  || raw bytes

    Returns ``None`` if the bytes don't look like either shape —
    the caller should treat them as opaque tnpkg bytes instead.
    """
    import io
    import struct
    import zipfile

    if len(plaintext) >= 4 and plaintext[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(plaintext)) as zf:
                return {name: zf.read(name) for name in zf.namelist()}
        except (zipfile.BadZipFile, OSError):
            return None

    # LEGACY-COMPAT-2026-04-29 — drop after next state wipe.
    out: dict[str, bytes] = {}
    if len(plaintext) < 4:
        return None
    try:
        (count,) = struct.unpack_from(">I", plaintext, 0)
    except struct.error:
        return None
    # Sanity check: the export wrapper currently emits at most a
    # handful of files. Anything claiming hundreds of thousands is
    # almost certainly not an export frame and we should treat the
    # plaintext as raw tnpkg bytes instead.
    if count == 0 or count > 4096:
        return None

    pos = 4
    for _ in range(count):
        if pos + 4 > len(plaintext):
            return None
        (name_len,) = struct.unpack_from(">I", plaintext, pos)
        pos += 4
        if name_len == 0 or name_len > 1024 or pos + name_len > len(plaintext):
            return None
        try:
            name = plaintext[pos:pos + name_len].decode("utf-8")
        except UnicodeDecodeError:
            return None
        pos += name_len

        if pos + 4 > len(plaintext):
            return None
        (data_len,) = struct.unpack_from(">I", plaintext, pos)
        pos += 4
        if pos + data_len > len(plaintext):
            return None
        out[name] = bytes(plaintext[pos:pos + data_len])
        pos += data_len

    if pos != len(plaintext):
        return None
    return out


def _write_restored_bytes(
    *,
    plaintext: bytes,
    out_dir: Path,
    project_id: str,
) -> tuple[list[Path], Path | None, list[str]]:
    """Write decrypted plaintext to ``out_dir``.

    If the plaintext looks like a tn.export combined-blob frame, we
    write each member by name (e.g. ``project.tnpkg``,
    ``manifest.json``). Otherwise we write a single
    ``<project_id>.tnpkg`` next to a note that the SDK should be
    invoked to absorb it.

    Returns ``(files_written, raw_blob_path, notes)``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    files_written: list[Path] = []
    notes: list[str] = []

    members = _try_unpack_export_frame(plaintext)
    if members is not None:
        for name, data in sorted(members.items()):
            # Don't let exotic member names escape the out_dir.
            safe = name.replace("..", "").lstrip("/").replace("\\", "/")
            target = out_dir / safe
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files_written.append(target)
        notes.append(
            f"unpacked {len(members)} member(s) from tn.export combined frame",
        )
        return files_written, None, notes

    # Treat as opaque tnpkg.
    raw_path = out_dir / f"{project_id}.tnpkg"
    raw_path.write_bytes(plaintext)
    notes.append(
        "plaintext didn't match the tn.export frame layout; wrote raw "
        "bytes — run `tn` to absorb if appropriate",
    )
    return [raw_path], raw_path, notes


# ── Top-level orchestration ───────────────────────────────────────────


def _restore_with_token(
    *,
    vault_url: str,
    token: TransferToken,
    out_dir: Path,
) -> RestoreResult:
    """Full account-bound restore using a transfer token.

    Steps:
      1. Decode the raw BEK from the token.
      2. GET the encrypted-blob bytes from the vault using the JWT.
      3. AES-GCM decrypt with the BEK.
      4. Write plaintext to ``out_dir``.
    """
    bek = _b64decode_loose(token.raw_bek_b64)
    if len(bek) != 32:
        raise RestoreError(
            f"raw_bek_b64 decoded to {len(bek)} bytes; expected 32",
        )

    blob = _fetch_encrypted_blob(
        vault_url=vault_url,
        project_id=token.project_id,
        bearer=token.vault_jwt,
    )
    plaintext = _decrypt_blob_with_bek(blob, bek)
    out_dir = Path(out_dir).resolve()
    files_written, raw_blob_path, notes = _write_restored_bytes(
        plaintext=plaintext,
        out_dir=out_dir,
        project_id=token.project_id,
    )
    return RestoreResult(
        out_dir=out_dir,
        project_id=token.project_id,
        account_id=token.account_id,
        files_written=files_written,
        raw_blob_path=raw_blob_path,
        notes=notes,
    )


# ── HTTP helpers (test seam) ──────────────────────────────────────────
#
# Tests can monkeypatch ``_http_request`` to inject fake responses
# without spinning up a full HTTP server. We deliberately keep a
# module-level reference so test code can patch in one place.

__all__ = [
    "RestoreError",
    "RestoreResult",
    "_decrypt_blob_with_bek",
    "_fetch_encrypted_blob",
    "_restore_with_token",
    "_write_restored_bytes",
]
