"""``tn.export(out_path, *, kind=...)`` — single producer entry for `.tnpkg`s.

This is the unified replacement for the old ad-hoc producer functions
(``packaging.dump_tnpkg``, ``compile.compile_kit_bundle``,
``compile.compile_enrolment``, ``compile.emit_to_outbox``,
``offer.offer``). The wire format is the universal `.tnpkg` defined in
``tn.tnpkg``: a zip with ``manifest.json`` + ``body/...``. Every kind
ships through here so we have one place to update when the manifest
schema evolves.

All exports require an active ``LoadedConfig`` (the producer's ceremony)
unless the caller passes a sufficient set of explicit ``cfg=...`` /
``keystore=...`` overrides. The signing identity is always the producer's
``cfg.device``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .config import LoadedConfig
from .packaging import Package
from .tnpkg import (
    KNOWN_KINDS,
    TnpkgManifest,
    _write_tnpkg,
)

# All kinds the producer side knows how to build a body for. ``recipient_invite``
# is reserved in KNOWN_KINDS but not yet wired up; calling it raises
# NotImplementedError so absorb-side tests can still reference the dispatcher
# cleanly.
ExportKind = Literal[
    "admin_log_snapshot",
    "offer",
    "enrolment",
    "kit_bundle",
    "full_keystore",
    "recipient_invite",
]


def _now_iso() -> str:
    """RFC 3339 / ISO 8601 UTC timestamp with milliseconds."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------
# Body builders, one per kind. Each returns ``(body_files, extras_for_manifest)``
# where ``body_files`` is the dict written into the zip and
# ``extras_for_manifest`` is a dict merged into the manifest (clock,
# event_count, head_row_hash, state, ...).
# --------------------------------------------------------------------------


def _scan_admin_envelopes(sources: list[Path]) -> tuple[bytes, dict[str, Any]]:
    """Walk every source ndjson, filter to admin event types, and produce
    a single ndjson body plus per-(did, event_type) clock metadata.

    Admin events may live in the dedicated admin log (when configured),
    or in the main log (the historical default — and the path the Rust
    runtime writes to today). We scan both and dedupe by ``row_hash``.
    """
    from .admin.log import is_admin_event_type

    seen: set[str] = set()
    out_lines: list[bytes] = []
    clock: dict[str, dict[str, int]] = {}
    head_row_hash: str | None = None

    for path in sources:
        if not path.exists():
            continue
        raw = path.read_bytes()
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                env = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            et = env.get("event_type")
            if not isinstance(et, str) or not is_admin_event_type(et):
                continue
            rh = env.get("row_hash")
            if isinstance(rh, str) and rh in seen:
                continue
            did = env.get("did")
            seq = env.get("sequence")
            if not (isinstance(did, str) and isinstance(seq, int) and isinstance(rh, str)):
                continue
            seen.add(rh)
            out_lines.append(stripped + b"\n")
            slot = clock.setdefault(did, {})
            cur = slot.get(et, 0)
            if seq > cur:
                slot[et] = seq
            head_row_hash = rh

    body = b"".join(out_lines)
    return body, {
        "clock": clock,
        "event_count": len(out_lines),
        "head_row_hash": head_row_hash,
    }


def _build_admin_log_snapshot_body(
    cfg: LoadedConfig,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Body for ``kind=admin_log_snapshot`` — every admin envelope plus the
    materialized AdminState at point-of-export.

    Sources scanned (in order, deduped by ``row_hash``):

    * The main log (``cfg.resolve_log_path()``) — admin events ride here
      today on every configured ceremony, and the Rust runtime writes
      here unconditionally.
    * The dedicated admin log (``resolve_admin_log_path(cfg)``), if it
      differs from the main log — picked up once we wire admin emit
      routing to it in a follow-up session.
    """
    from .admin import state as _admin_state  # late import to avoid cycles
    from .admin.log import resolve_admin_log_path

    main_log = cfg.resolve_log_path()
    admin_log = resolve_admin_log_path(cfg)
    sources: list[Path] = [main_log]
    if admin_log != main_log:
        sources.append(admin_log)
    ndjson, extras = _scan_admin_envelopes(sources)
    body: dict[str, bytes] = {"body/admin.ndjson": ndjson}
    # Materialize current AdminState. Requires an active runtime — the
    # producer is by definition online. Best-effort: if admin_state() is
    # unavailable we ship an empty state so the manifest still validates.
    try:
        state = _admin_state()
    except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
        state = None
    if state is not None:
        extras["state"] = state
    return body, extras


def _package_to_body_bytes(pkg: Package) -> bytes:
    """Serialize a ``Package`` to the canonical body bytes used by offer /
    enrolment kinds. Identical layout to the old ``dump_tnpkg`` writer
    (sorted keys, indented JSON), so signatures verify byte-for-byte
    after a round trip."""
    return (json.dumps(asdict(pkg), sort_keys=True, indent=2) + "\n").encode("utf-8")


def _build_offer_body(pkg: Package) -> dict[str, bytes]:
    return {"body/package.json": _package_to_body_bytes(pkg)}


def _build_enrolment_body(pkg: Package) -> dict[str, bytes]:
    return {"body/package.json": _package_to_body_bytes(pkg)}


def _build_kit_bundle_body(
    cfg: LoadedConfig | None,
    keystore: Path,
    *,
    full: bool,
    groups_filter: list[str] | None,
    confirm_includes_secrets: bool,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Body for ``kit_bundle`` and ``full_keystore``.

    For ``full_keystore``, ``confirm_includes_secrets`` MUST be True;
    enforcement happens in the public ``export()`` entry. The body
    composition logic mirrors the legacy ``compile_kit_bundle`` layout
    so the chrome extension / tn-js readers continue to work after the
    new manifest header is added.
    """
    import re as _re

    keystore = Path(keystore).resolve()
    if not keystore.is_dir():
        raise FileNotFoundError(f"kit_bundle: keystore directory not found: {keystore}")

    group_filter = set(groups_filter) if groups_filter else None
    kit_re = _re.compile(r"^(.+?)\.btn\.(mykit|mykit\.revoked\.\d+)$")

    body: dict[str, bytes] = {}
    kits_meta: list[dict[str, Any]] = []

    for entry in sorted(keystore.iterdir()):
        if not entry.is_file():
            continue
        m = kit_re.match(entry.name)
        if m:
            group = m.group(1)
            if group_filter is not None and group not in group_filter:
                continue
            data = entry.read_bytes()
            # Kits live at the body root with their original filenames so
            # downstream readers (Chrome extension, tn-js CLI) can scan
            # the archive without learning about ``body/`` prefixes.
            body[f"body/{entry.name}"] = data
            kits_meta.append(
                {
                    "name": entry.name,
                    "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
        elif full:
            if entry.name in ("local.private", "local.public", "index_master.key"):
                body[f"body/{entry.name}"] = entry.read_bytes()
            elif entry.name.endswith(".btn.state"):
                group = entry.name[: -len(".btn.state")]
                if group_filter is None or group in group_filter:
                    body[f"body/{entry.name}"] = entry.read_bytes()

    if not kits_meta:
        suffix = f" matching groups {sorted(group_filter)}" if group_filter else ""
        raise RuntimeError(
            f"kit_bundle: no *.btn.mykit files in {keystore}{suffix}. "
            f"Build a btn ceremony with at least one group before exporting."
        )

    if full and cfg is not None and cfg.yaml_path is not None and cfg.yaml_path.exists():
        body["body/tn.yaml"] = cfg.yaml_path.read_bytes()

    if full:
        # Loud zero-byte marker. Keeping it under ``body/`` matches the new
        # zip layout; chrome-ext / tn-js readers that look at the *root*
        # for the marker will be updated when they migrate to the new
        # layout. Until then, also keep a top-level marker for safety.
        body["body/WARNING_CONTAINS_PRIVATE_KEYS"] = b""

    extras: dict[str, Any] = {
        "scope": "full" if full else "kit_bundle",
        "state": {
            "kits": kits_meta,
            "kind": "full-keystore" if full else "readers-only",
        },
    }
    return body, extras


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def export(
    out_path: Path | str,
    *,
    kind: ExportKind,
    cfg: LoadedConfig | None = None,
    to_did: str | None = None,
    scope: str | None = None,
    confirm_includes_secrets: bool = False,
    package: Package | None = None,
    keystore: Path | str | None = None,
    groups: list[str] | None = None,
    encrypt_body_with: bytes | None = None,
) -> Path:
    """Pack a `.tnpkg` from local ceremony state.

    Parameters
    ----------
    out_path:
        Destination file (zip). Parent dirs are created on demand.
    kind:
        Dispatch discriminator (see ``ExportKind``).
    cfg:
        The producer's ``LoadedConfig``. Required for every kind that
        needs identity / ceremony context. Pass explicitly so tests can
        skip the runtime singleton.
    to_did:
        Optional point-to-point address. Stored verbatim in the manifest.
    scope:
        Optional scope override. Defaults vary per kind: admin snapshots
        use ``"admin"``; kit bundles use ``"kit_bundle"`` / ``"full"``.
    confirm_includes_secrets:
        REQUIRED True for ``kind="full_keystore"`` — the export bundles
        the publisher's raw private keys (``local.private``,
        ``index_master.key``). Misuse is a foot-gun, so the gate is
        explicit.
    package:
        For ``kind="offer"`` / ``"enrolment"``: the already-built and
        signed ``Package`` to wrap. We do not rebuild the package here
        so callers retain control over the package signature domain.
    keystore:
        For ``kind="kit_bundle"`` / ``"full_keystore"``: override the
        keystore directory. Defaults to ``cfg.keystore``.
    groups:
        For ``kind="kit_bundle"`` / ``"full_keystore"``: optional list of
        group names to include. None means all groups.
    encrypt_body_with:
        Optional 32-byte AES-256-GCM key. When supplied, every body file
        is concatenated, AES-GCM encrypted under this key, and replaced
        in the zip with a single ``body/encrypted.bin`` member (12-byte
        random nonce prepended to ciphertext). The manifest's
        ``state.body_encryption`` block records the cipher suite + the
        encrypted-blob hash so a downstream consumer can verify the
        ciphertext byte-for-byte without holding the key.

        Used by the ``vault.push`` handler in init-upload mode (per D-19
        / plan ``2026-04-28-pending-claim-flow.md`` §"How the handler
        distinguishes…"): the handler generates a fresh BEK per upload,
        passes it here, and that key travels in the URL fragment to the
        browser claim page (D-5). The vault stores ciphertext only (D-1).
    """
    if kind not in KNOWN_KINDS:
        raise ValueError(f"export: unknown kind {kind!r}; expected one of {sorted(KNOWN_KINDS)}")

    if kind == "full_keystore" and not confirm_includes_secrets:
        raise ValueError(
            "export(kind='full_keystore') writes the publisher's raw private keys "
            "(local.private + index_master.key) into the zip. This is intended for "
            "publisher-to-self backup only. Pass confirm_includes_secrets=True to "
            "acknowledge."
        )

    if cfg is None and kind in {"admin_log_snapshot", "offer", "enrolment"}:
        raise ValueError(f"export(kind={kind!r}) requires cfg=...")

    body: dict[str, bytes] = {}
    extras: dict[str, Any] = {}

    if kind == "admin_log_snapshot":
        if cfg is None:  # guarded above; defensive
            raise ValueError("export(kind='admin_log_snapshot') requires cfg=...")
        body, extras = _build_admin_log_snapshot_body(cfg)
    elif kind == "offer":
        if package is None or package.package_kind != "offer":
            raise ValueError("export(kind='offer') requires package=<signed offer Package>")
        body = _build_offer_body(package)
    elif kind == "enrolment":
        if package is None or package.package_kind != "enrolment":
            raise ValueError(
                "export(kind='enrolment') requires package=<signed enrolment Package>"
            )
        body = _build_enrolment_body(package)
    elif kind in ("kit_bundle", "full_keystore"):
        ks = (
            Path(keystore).resolve()
            if keystore is not None
            else (Path(cfg.keystore).resolve() if cfg is not None else None)
        )
        if ks is None:
            raise ValueError(
                f"export(kind={kind!r}) requires keystore=... or cfg=... so the keystore is known"
            )
        body, extras = _build_kit_bundle_body(
            cfg,
            ks,
            full=(kind == "full_keystore"),
            groups_filter=groups,
            confirm_includes_secrets=confirm_includes_secrets,
        )
    elif kind == "recipient_invite":
        raise NotImplementedError(
            f"export(kind={kind!r}) is reserved in the manifest schema but not "
            f"implemented in this Python session — see the plan doc for next steps."
        )

    # Build manifest. The producer's DID is the signing authority; we
    # always sign with cfg.device. For kits-without-cfg (rare) the caller
    # passes a keystore-only path; we still need an Ed25519 signer, so
    # require cfg in those cases too.
    if cfg is None:
        raise ValueError(f"export(kind={kind!r}) requires cfg=... for manifest signing")

    # Body-level encryption (per D-19 / D-5 / plan §"Body wrapping").
    # We do this BEFORE the manifest is built so the manifest can record
    # the encrypted-blob hash + cipher suite. AAD is empty here (the
    # manifest is what's signed; the manifest itself records the
    # ciphertext hash, which acts as the integrity binding).
    if encrypt_body_with is not None:
        if not isinstance(encrypt_body_with, (bytes, bytearray)) or len(encrypt_body_with) != 32:
            raise ValueError(
                "export(encrypt_body_with=...) requires a 32-byte AES-256-GCM key"
            )
        body, extras = _encrypt_body_in_place(body, extras, bytes(encrypt_body_with))

    manifest = TnpkgManifest(
        kind=str(kind),
        from_did=cfg.device.did,
        ceremony_id=cfg.ceremony_id,
        as_of=_now_iso(),
        scope=str(scope or extras.get("scope") or _default_scope(kind)),
        to_did=to_did,
        clock=dict(extras.get("clock", {})),
        event_count=int(extras.get("event_count", 0)),
        head_row_hash=extras.get("head_row_hash"),
        state=extras.get("state"),
    )
    manifest.sign(cfg.device.signing_key())
    return _write_tnpkg(Path(out_path), manifest, body)


def _encrypt_body_in_place(
    body: dict[str, bytes],
    extras: dict[str, Any],
    key: bytes,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Combine all body files and encrypt under ``key``.

    Resolves the "Open #1" decision from
    ``2026-04-28-pending-claim-flow.md``: combined-blob (one
    ``body/encrypted.bin``) over per-file encryption. Combining is
    simpler, matches the "vault sees one opaque blob" spirit (D-1).

    Layout:
      body/encrypted.bin   = 12-byte AES-GCM nonce || ciphertext+tag

    The plaintext we encrypt is a STORED zip (no compression) of the
    body files at their original names. STORED is chosen so the
    plaintext is identifiable by the standard `PK\\x03\\x04` magic
    bytes, can be popped open with stock unzip tools by an advanced
    user, and aligns the inner-layer format with the OUTER tnpkg
    envelope (also STORED). fflate is already vendored on the browser
    side; Python ``zipfile`` is stdlib; the format is a one-liner in
    every language we ship.

    See D-N (body plaintext is a STORED zip) in the decisions log.
    """
    import io as _io
    import os as _os
    import zipfile as _zipfile

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Pack the body files into a STORED zip. Sort entries by name so the
    # plaintext bytes are deterministic for a given body, which is
    # desirable for tests + ciphertext-hash equality.
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w", compression=_zipfile.ZIP_STORED) as zf:
        for name in sorted(body.keys()):
            zf.writestr(name, body[name])
    plaintext = buf.getvalue()

    nonce = _os.urandom(12)
    aesgcm = AESGCM(key)
    # AAD is empty here (the manifest is what's signed; the manifest itself
    # records the ciphertext hash, which acts as the integrity binding).
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    encrypted = nonce + ciphertext

    new_body: dict[str, bytes] = {"body/encrypted.bin": encrypted}
    new_extras = dict(extras)
    state = dict(new_extras.get("state") or {})
    state["body_encryption"] = {
        "cipher_suite": "aes-256-gcm",
        "nonce_bytes": 12,
        "frame": "tn-encrypted-body-v2-zip",
        "ciphertext_sha256": "sha256:"
        + hashlib.sha256(encrypted).hexdigest(),
    }
    new_extras["state"] = state
    return new_body, new_extras


def decrypt_body_blob(blob: bytes, key: bytes) -> dict[str, bytes]:
    """Inverse of :func:`_encrypt_body_in_place`. Public helper for tests
    and future ``tn absorb`` / browser parity.

    Returns a ``{name: bytes}`` dict. Tries the new STORED-zip plaintext
    format first (PK\\x03\\x04 magic). Falls back to the legacy custom
    binary frame for ciphertexts produced before commit 2026-04-29.
    """
    import io as _io
    import struct as _struct
    import zipfile as _zipfile

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(blob) < 12 + 16:  # nonce + minimum tag
        raise ValueError("decrypt_body_blob: input too short")
    nonce, ciphertext = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # New shape: STORED zip.
    if len(plaintext) >= 4 and plaintext[:4] == b"PK\x03\x04":
        out: dict[str, bytes] = {}
        with _zipfile.ZipFile(_io.BytesIO(plaintext)) as zf:
            for name in zf.namelist():
                out[name] = zf.read(name)
        return out

    # LEGACY-COMPAT-2026-04-29 — drop after next state wipe.
    # Custom binary frame produced by Session 4's _encrypt_body_in_place
    # (uint32_be member_count; per member: uint32_be name_len, name,
    #  uint32_be data_len, data). In-flight projects on the live vault
    # were sealed under this format; this fallback keeps them readable
    # until the user re-claims under the new format.
    out: dict[str, bytes] = {}
    pos = 0
    if len(plaintext) < 4:
        raise ValueError("decrypt_body_blob: plaintext too short for any known format")
    (count,) = _struct.unpack_from(">I", plaintext, pos)
    pos += 4
    for _ in range(count):
        (name_len,) = _struct.unpack_from(">I", plaintext, pos)
        pos += 4
        name = plaintext[pos : pos + name_len].decode("utf-8")
        pos += name_len
        (data_len,) = _struct.unpack_from(">I", plaintext, pos)
        pos += 4
        data = bytes(plaintext[pos : pos + data_len])
        pos += data_len
        out[name] = data
    return out


def _default_scope(kind: str) -> str:
    if kind == "admin_log_snapshot":
        return "admin"
    if kind == "kit_bundle":
        return "kit_bundle"
    if kind == "full_keystore":
        return "full"
    return "admin"


# Helper exposed for the absorb side: turn a body's package.json bytes
# back into a ``Package`` dataclass. Lives here because the byte layout
# is owned by the producer module; pulling it into ``tn.absorb`` would
# hide the round-trip invariant.


def package_from_body_bytes(body_bytes: bytes) -> Package:
    """Inverse of ``_package_to_body_bytes``. Used by the absorb side for
    offer / enrolment kinds."""
    doc = json.loads(body_bytes.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"package body is not a JSON object: {type(doc).__name__}")
    return Package(**doc)


# Re-exported so callers can do ``tn.export.canonical_manifest_bytes(m)``
# for diagnostics. Internal use only.
def canonical_manifest_bytes(manifest: TnpkgManifest) -> bytes:
    return manifest.signing_bytes()


__all__ = [
    "ExportKind",
    "canonical_manifest_bytes",
    "decrypt_body_blob",
    "export",
    "package_from_body_bytes",
]


# Pull in `asdict` is used by `_package_to_body_bytes`; the linter
# already sees that. No further unused-import shims required.
_ = asdict  # keep visible for linter
_ = hashlib
