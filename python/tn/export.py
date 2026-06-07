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

Body-encryption layer
=====================

Two non-overlapping paths can lock the body bytes:

* **BYOK** (``encrypt_body_with=`` 32 bytes): caller brings their own
  AES-256-GCM key. Used by the init-upload self-backup flow where the
  vault must see ciphertext only and the BEK travels in the URL
  fragment to the recipient's browser.
* **Recipient-direction sealed-box** (``seal_for_recipient=True``):
  ``export`` mints a fresh BEK per call, encrypts the body in place,
  then wraps the BEK for each recipient DID via the X25519 sealed-box
  construction in :mod:`tn.recipient_seal`. Wraps land in
  ``manifest.state.body_encryption.recipient_wraps`` (canonical
  plural) and additionally ``recipient_wrap`` (singular shadow for
  pre-multi absorbers when there's exactly one recipient).

The two modes are mutually exclusive — ``export`` raises if both are
supplied.

See Also:
    `docs/spec/body-encryption.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md>`_:
        Wire spec for the encrypted-body layer (AES-256-GCM frame,
        STORED-zip plaintext, ciphertext_sha256 binding in the
        manifest).
    `docs/spec/recipient-wraps.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/recipient-wraps.md>`_:
        Sealed-box wrap shape + AAD construction.
    `docs/spec/manifest.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/manifest.md>`_:
        Manifest schema (every kind this module emits).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from ._defaults import DEFAULT_CEREMONY_NAME
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
    "identity_seed",
]

# Sentinel ceremony_id for identity_seed bundles. The kind doesn't belong
# to any ceremony — the bundle is the operator's per-device identity, not
# a per-publisher artifact. The string is lowercase + underscore so it
# passes the inbox CEREMONY_RE (``^[a-z0-9_]{1,128}$``) without special
# routing.
IDENTITY_SEED_CEREMONY_PLACEHOLDER = "_identity_seed"


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
            did = env.get("device_identity")
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
    """Body for ``kind=admin_log_snapshot`` — every admin envelope plus
    the materialized AdminState at point-of-export.

    Single source: the dedicated admin log
    (``resolve_admin_log_path(cfg)``). With the Rust runtime now routing
    ``tn.*`` events to the admin log natively (#26), the historical
    dual-scan-and-dedup of main+admin is no longer needed. The "vault
    never sees user content" invariant is now a property of the source
    list, not of the ``is_admin_event_type`` filter.
    """
    from .admin import state as _admin_state  # late import to avoid cycles
    from .admin.log import resolve_admin_log_path

    admin_log = resolve_admin_log_path(cfg)
    sources: list[Path] = [admin_log]
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


# A keystore self-kit file: ``<group>.btn.mykit`` or a rotation backup
# ``<group>.btn.mykit.revoked.<ts>``. group(1) is the group name.
_KIT_RE = re.compile(r"^(.+?)\.btn\.(mykit|mykit\.revoked\.\d+)$")
# Private/identity material packed only for a full_keystore export.
_FULL_KEYSTORE_FILES = ("local.private", "local.public", "index_master.key")


def _collect_kit_files(
    keystore: Path, group_filter: set[str] | None, full: bool
) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    """Scan the keystore for self-kit files (and, for ``full``, the private
    identity + per-group ``.btn.state`` material). Returns the body members
    (keyed ``body/<name>``) and the per-kit metadata list."""
    body: dict[str, bytes] = {}
    kits_meta: list[dict[str, Any]] = []
    for entry in sorted(keystore.iterdir()):
        if not entry.is_file():
            continue
        m = _KIT_RE.match(entry.name)
        if m:
            group = m.group(1)
            if group_filter is not None and group not in group_filter:
                continue
            data = entry.read_bytes()
            # Kits live at the body root with their original filenames so
            # downstream readers (Chrome extension, tn-js CLI) can scan the
            # archive without learning about ``body/`` prefixes.
            body[f"body/{entry.name}"] = data
            kits_meta.append(
                {
                    "name": entry.name,
                    "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
        elif full:
            if entry.name in _FULL_KEYSTORE_FILES:
                body[f"body/{entry.name}"] = entry.read_bytes()
            elif entry.name.endswith(".btn.state"):
                group = entry.name[: -len(".btn.state")]
                if group_filter is None or group in group_filter:
                    body[f"body/{entry.name}"] = entry.read_bytes()
    return body, kits_meta


def _pack_stream_yamls(cfg: LoadedConfig) -> dict[str, bytes]:
    """Pack the default yaml plus every named stream's yaml verbatim so absorb
    can restore the same chain identities. Streams hold no key material of
    their own (they extend default), so logs/ and admin/ are not recursed.

    Project root depends on the on-disk layout:
      * New (preferred): ``<root>/default/tn.yaml`` -> root is parent.parent
      * Legacy:          ``<root>/tn.yaml``         -> root is parent
    """
    out: dict[str, bytes] = {"body/tn.yaml": cfg.yaml_path.read_bytes()}
    default_dir = cfg.yaml_path.parent
    if default_dir.name == DEFAULT_CEREMONY_NAME:
        project_root = default_dir.parent
        default_dir_name: str | None = default_dir.name
    else:
        project_root = default_dir
        default_dir_name = None
    if project_root.is_dir():
        for entry in sorted(project_root.iterdir()):
            if not entry.is_dir():
                continue
            if default_dir_name is not None and entry.name == default_dir_name:
                continue
            stream_yaml = entry / "tn.yaml"
            if stream_yaml.is_file():
                out[f"body/streams/{entry.name}/tn.yaml"] = stream_yaml.read_bytes()
    return out


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
    keystore = Path(keystore).resolve()
    if not keystore.is_dir():
        raise FileNotFoundError(f"kit_bundle: keystore directory not found: {keystore}")

    group_filter = set(groups_filter) if groups_filter else None
    body, kits_meta = _collect_kit_files(keystore, group_filter, full)

    if not kits_meta:
        suffix = f" matching groups {sorted(group_filter)}" if group_filter else ""
        raise RuntimeError(
            f"kit_bundle: no *.btn.mykit files in {keystore}{suffix}. "
            f"Build a btn ceremony with at least one group before exporting."
        )

    if full and cfg is not None and cfg.yaml_path is not None and cfg.yaml_path.exists():
        body.update(_pack_stream_yamls(cfg))

    if full:
        # Loud zero-byte marker. Keeping it under ``body/`` matches the new
        # zip layout; chrome-ext / tn-js readers that look at the *root*
        # for the marker will be updated when they migrate to the new layout.
        body["body/WARNING_CONTAINS_PRIVATE_KEYS"] = b""

    extras: dict[str, Any] = {
        "scope": "full" if full else "kit_bundle",
        "state": {
            "kits": kits_meta,
            "kind": "full-keystore" if full else "readers-only",
        },
    }
    return body, extras


def _build_identity_seed_body(
    device: Any,
    *,
    nickname: str | None = None,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Body for ``kind="identity_seed"`` — minimal "this is who I am" bundle.

    Body shape:

    ``body/local.private`` (32 bytes)
        Ed25519 seed. Treat as secret. The ABSORB side installs this verbatim
        into ``<keystore>/local.private``.

    ``body/local.public`` (utf-8 text)
        The bundle's ``did:key:z...`` string. Mirrors the convention used
        by ``config._create_fresh()`` so a freshly-installed keystore is
        indistinguishable from one created by ``tn init``.

    ``body/tn.yaml`` (utf-8 text)
        A minimal stub that names the DID and leaves group/cipher/etc.
        unspecified. The host running absorb is expected to either accept
        the stub as the ceremony skeleton or to overlay it during a later
        ceremony enrolment. The stub is written so the absorb branch can
        drop a complete tn.yaml + keystore pair without requiring the
        caller to construct one themselves.

    Extras carried into the manifest:

    ``state.identity = {"nickname": ..., "minted_at": ..., "schema": "tn-identity-seed-v1"}``

    Reads ``device`` ducktyped — anything exposing ``.did`` and
    ``.private_bytes`` works (the ``DeviceKey`` shape from
    ``tn.signing``).
    """
    if device is None:
        raise ValueError("_build_identity_seed_body: device is required")

    private_bytes = bytes(device.private_bytes)
    if len(private_bytes) != 32:
        raise ValueError(
            f"_build_identity_seed_body: device.private_bytes must be 32 bytes "
            f"(Ed25519 seed); got {len(private_bytes)}"
        )

    did = str(device.did)
    if not did.startswith("did:key:z"):
        raise ValueError(
            f"_build_identity_seed_body: device.did must be a did:key:z... "
            f"identifier; got {did!r}"
        )

    # tn.yaml stub. Keep this minimal — anything more would lock a fresh
    # absorb into a particular cipher / group shape that the operator
    # may not want.
    stub_yaml = (
        "# Identity seed stub written by tn.export(kind='identity_seed').\n"
        "# Replace this file with a real ceremony tn.yaml when joining one.\n"
        f"identity:\n"
        f"  did: {did}\n"
    )
    if nickname:
        stub_yaml += f"  nickname: {json.dumps(nickname)}\n"

    body: dict[str, bytes] = {
        "body/local.private": private_bytes,
        "body/local.public": did.encode("utf-8"),
        "body/tn.yaml": stub_yaml.encode("utf-8"),
    }

    extras: dict[str, Any] = {
        "scope": "identity",
        "state": {
            "identity": {
                "schema": "tn-identity-seed-v1",
                "nickname": nickname,
                "minted_at": _now_iso(),
            },
        },
    }
    return body, extras


def export_identity_seed(
    out_path: Path | str,
    *,
    device: Any | None = None,
    nickname: str | None = None,
    ceremony_id_stub: str | None = None,
) -> Path:
    """Convenience wrapper for the identity_seed kind.

    If ``device`` is None, generate a fresh ``DeviceKey`` and use it. The
    caller can recover the freshly-generated DID by reading
    ``manifest.publisher_identity`` from the resulting tnpkg, or by passing in their
    own DeviceKey if they already have one.

    Returns the output path. The caller is responsible for protecting the
    file (it carries a private Ed25519 seed).
    """
    from .signing import DeviceKey as _DeviceKey

    if device is None:
        device = _DeviceKey.generate()
    return export(
        out_path,
        kind="identity_seed",
        device=device,
        nickname=nickname,
        ceremony_id_stub=ceremony_id_stub,
    )


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def _validate_export_args(
    *,
    kind: ExportKind,
    cfg: LoadedConfig | None,
    confirm_includes_secrets: bool,
    device: Any | None,
) -> None:
    """Pre-flight validation for :func:`export`.

    All checks raise ``ValueError`` so the operator gets a single,
    deterministic failure point before any zip is touched. The
    ``full_keystore`` gate is intentionally explicit — that kind
    bundles the publisher's raw private keys (``local.private`` +
    ``index_master.key``) and is for self-backup only.
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
    if kind == "identity_seed" and device is None:
        raise ValueError(
            "export(kind='identity_seed') requires device=<DeviceKey>; the bundle "
            "is self-issued by the carried Ed25519 key (from_did == to_did)."
        )


def _build_export_body(
    *,
    kind: ExportKind,
    cfg: LoadedConfig | None,
    package: Package | None,
    keystore: Path | str | None,
    groups: list[str] | None,
    device: Any | None,
    nickname: str | None,
    confirm_includes_secrets: bool,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Per-kind body construction. Returns ``(body, extras)``.

    Dispatches to the right ``_build_*_body`` helper based on ``kind``.
    Kinds without a body (``recipient_invite``) raise
    :class:`NotImplementedError` so callers can't silently produce an
    empty zip.
    """
    if kind == "admin_log_snapshot":
        if cfg is None:  # pragma: no cover - guarded by _validate_export_args
            raise ValueError("export(kind='admin_log_snapshot') requires cfg=...")
        return _build_admin_log_snapshot_body(cfg)
    if kind == "offer":
        if package is None or package.package_kind != "offer":
            raise ValueError("export(kind='offer') requires package=<signed offer Package>")
        return _build_offer_body(package), {}
    if kind == "enrolment":
        if package is None or package.package_kind != "enrolment":
            raise ValueError(
                "export(kind='enrolment') requires package=<signed enrolment Package>"
            )
        return _build_enrolment_body(package), {}
    if kind in ("kit_bundle", "full_keystore"):
        ks = (
            Path(keystore).resolve()
            if keystore is not None
            else (Path(cfg.keystore).resolve() if cfg is not None else None)
        )
        if ks is None:
            raise ValueError(
                f"export(kind={kind!r}) requires keystore=... or cfg=... so the keystore is known"
            )
        return _build_kit_bundle_body(
            cfg,
            ks,
            full=(kind == "full_keystore"),
            groups_filter=groups,
            confirm_includes_secrets=confirm_includes_secrets,
        )
    if kind == "identity_seed":
        if device is None:  # pragma: no cover - guarded by _validate_export_args
            raise ValueError("export(kind='identity_seed') requires device=...")
        return _build_identity_seed_body(device, nickname=nickname)
    if kind == "recipient_invite":
        raise NotImplementedError(
            f"export(kind={kind!r}) is reserved in the manifest schema but not "
            f"implemented in this Python session — see the plan doc for next steps."
        )
    # Unreachable: _validate_export_args already screened kind.
    raise ValueError(f"export: unhandled kind {kind!r}")


def _resolve_export_signer(
    *,
    kind: ExportKind,
    cfg: LoadedConfig | None,
    device: Any | None,
    ceremony_id_stub: str | None,
) -> tuple[Any, str, str]:
    """Return ``(signing_key_priv, signer_did, signer_ceremony)``.

    For most kinds the producer (``cfg.device``) signs the manifest.
    ``identity_seed`` is the one exception: it's self-issued — the
    Ed25519 key being bundled IS the manifest signer (from_did ==
    to_did), and there's no enclosing ceremony, so we substitute the
    placeholder ``ceremony_id``.
    """
    if kind == "identity_seed":
        if device is None:
            raise ValueError("export(kind='identity_seed') requires device=...")
        return (
            device.signing_key(),
            device.did,
            ceremony_id_stub or IDENTITY_SEED_CEREMONY_PLACEHOLDER,
        )
    if cfg is None:
        raise ValueError(f"export(kind={kind!r}) requires cfg=... for manifest signing")
    return cfg.device.signing_key(), cfg.device.device_identity, cfg.ceremony_id


def _merge_recipient_dids(
    to_did: str | None, to_dids: list[str] | None
) -> list[str]:
    """Combine and validate ``to_did`` + ``to_dids`` into a deduped list.

    Used by the seal-for-recipient path, which can mint multiple wraps
    against one body. The singular ``to_did`` is listed first so it
    becomes the canonical display addressee on the final manifest.
    """
    merged: list[str] = []
    if to_did is not None:
        if not str(to_did).startswith("did:key:z"):
            raise ValueError(
                f"export(seal_for_recipient=True): to_did={to_did!r} is not a "
                f"did:key string."
            )
        merged.append(str(to_did))
    if to_dids:
        for d in to_dids:
            if not isinstance(d, str) or not d.startswith("did:key:z"):
                raise ValueError(
                    f"export(seal_for_recipient=True): to_dids contains "
                    f"non-did:key entry {d!r}."
                )
            if d not in merged:
                merged.append(d)
    if not merged:
        raise ValueError(
            "export(seal_for_recipient=True) requires at least one "
            "recipient_identity in to_did=... or to_dids=[...]."
        )
    return merged


def _apply_seal_for_recipient(
    *,
    kind: ExportKind,
    cfg: LoadedConfig | None,
    body: dict[str, bytes],
    extras: dict[str, Any],
    scope: str | None,
    to_did: str | None,
    to_dids: list[str] | None,
) -> tuple[dict[str, bytes], dict[str, Any], str, str]:
    """Mint a fresh BEK, encrypt the body, and wrap the BEK per recipient.

    The recipient-direction sealed-box path. Per the second-release
    encrypted-kit-bundle spec, only callers who hold a recipient's
    device key can recover the BEK and decrypt the body. Always emits
    the plural ``recipient_wraps`` array (canonical forward shape) and
    additionally the singular ``recipient_wrap`` shadow when there's
    exactly one entry — back-compat for older absorbers that only know
    the singular shape.

    Args:
        kind: Export kind. Must be ``"kit_bundle"`` or
            ``"full_keystore"`` today; other kinds raise.
        cfg: Producer's :class:`LoadedConfig`. Used for the preview
            manifest's ``publisher_identity`` / ``ceremony_id`` so the
            AAD matches the final signed manifest.
        body: Plaintext body-file map. Mutated in place via
            :func:`_encrypt_body_in_place`.
        extras: Manifest extras dict. The returned copy gains
            ``state.body_encryption.recipient_wraps`` (and the singular
            ``recipient_wrap`` shadow when ``len == 1``).
        scope: Optional manifest scope override (cascades into the
            preview manifest the AAD is computed against).
        to_did: Primary recipient DID. Becomes the manifest's display
            ``recipient_identity``.
        to_dids: Optional additional recipient DIDs. Each gets its own
            entry in the ``recipient_wraps`` array.

    Returns:
        ``(body, extras, to_did, sealed_as_of)``.

        * ``to_did`` is the canonical display addressee (first entry
          in the merged recipient list) — the caller overrides its
          own ``to_did`` with this.
        * ``sealed_as_of`` MUST be reused on the final manifest so its
          canonical bytes match the AAD computed against the preview.

    Raises:
        ValueError: If ``kind`` doesn't support sealed-box export, or
            if no recipient DIDs were supplied.

    See Also:
        :func:`_encrypt_body_in_place`: Step 1 (body encryption).
        :func:`tn.recipient_seal.seal_bek_for_recipient`: Step 2 (per-recipient wrap).
        :func:`tn.recipient_seal.manifest_aad_for_wrap`: AAD construction.
        `docs/spec/recipient-wraps.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/recipient-wraps.md>`_:
            Wire spec.
    """
    if kind not in ("kit_bundle", "full_keystore"):
        raise ValueError(
            f"export(seal_for_recipient=True) is currently scoped to "
            f"kit_bundle / full_keystore; got kind={kind!r}."
        )
    import secrets as _secrets

    from .recipient_seal import (
        manifest_aad_for_wrap as _aad_for_wrap,
    )
    from .recipient_seal import (
        seal_bek_for_recipient as _seal_bek,
    )

    merged_dids = _merge_recipient_dids(to_did, to_dids)
    bek = _secrets.token_bytes(32)
    body, extras = _encrypt_body_in_place(body, extras, bek)

    # AAD = canonical(manifest_dict_without_signature_or_wrap-set).
    # Build a preview manifest so the canonical bytes match what the
    # consumer will compute against the final signed manifest. The AAD
    # function strips both ``recipient_wrap`` and ``recipient_wraps``
    # from the canonical bytes, so each entry binds against the same
    # AAD.
    preview = TnpkgManifest(
        kind=str(kind),
        publisher_identity=cfg.device.device_identity if cfg is not None else "",
        ceremony_id=cfg.ceremony_id if cfg is not None else "",
        as_of=_now_iso(),
        scope=str(scope or extras.get("scope") or _default_scope(kind)),
        recipient_identity=merged_dids[0],
        clock=dict(extras.get("clock", {})),
        event_count=int(extras.get("event_count", 0)),
        head_row_hash=extras.get("head_row_hash"),
        state=extras.get("state"),
    )
    aad = _aad_for_wrap(preview.to_dict())
    wraps_array = [_seal_bek(bek, did, aad) for did in merged_dids]

    state = dict(extras.get("state") or {})
    body_enc = dict(state.get("body_encryption") or {})
    body_enc["recipient_wraps"] = wraps_array
    if len(wraps_array) == 1:
        # Singular shadow for older absorbers; the plural array is the
        # canonical forward shape.
        body_enc["recipient_wrap"] = wraps_array[0]
    state["body_encryption"] = body_enc
    extras["state"] = state
    return body, extras, merged_dids[0], preview.as_of


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
    device: Any | None = None,
    nickname: str | None = None,
    ceremony_id_stub: str | None = None,
    seal_for_recipient: bool = False,
    to_dids: list[str] | None = None,
) -> Path:
    """Pack a `.tnpkg` from local ceremony state.

    The single producer entry for every `.tnpkg` kind. Dispatches on
    ``kind`` into the per-kind body builder, optionally encrypts the
    body (BYOK or recipient-direction sealed-box — see the module
    docstring), signs the manifest with the producer's device key,
    and writes the zip.

    Args:
        out_path: Destination file (zip). Parent directories are
            created on demand.
        kind: Dispatch discriminator. See :data:`ExportKind` for the
            allowed values.
        cfg: The producer's :class:`LoadedConfig`. Required for every
            kind that needs identity / ceremony context. Pass
            explicitly so tests can skip the runtime singleton.
        to_did: Optional point-to-point address. Stored verbatim in
            the manifest's ``recipient_identity`` field.
        scope: Optional scope override. Defaults vary per kind: admin
            snapshots use ``"admin"``; kit bundles use ``"kit_bundle"``
            / ``"full"``.
        confirm_includes_secrets: REQUIRED ``True`` for
            ``kind="full_keystore"`` — the export bundles the
            publisher's raw private keys (``local.private``,
            ``index_master.key``). Foot-gun gate; misuse otherwise.
        package: For ``kind="offer"`` / ``"enrolment"``: the
            already-built and signed :class:`Package` to wrap.
            ``export`` does not rebuild the package so callers retain
            control over the package signature domain.
        keystore: For ``kind="kit_bundle"`` / ``"full_keystore"``:
            override the keystore directory. Defaults to
            ``cfg.keystore``.
        groups: For ``kind="kit_bundle"`` / ``"full_keystore"``:
            optional list of group names to include. ``None`` means
            all groups.
        encrypt_body_with: BYOK path. 32-byte AES-256-GCM key. When
            supplied, every body file is rolled into a STORED zip,
            AES-GCM encrypted under this key, and the body becomes a
            single ``body/encrypted.bin`` member (12-byte random nonce
            prepended to ciphertext). ``manifest.state.body_encryption``
            records the cipher suite + ciphertext SHA-256 so a consumer
            can verify the ciphertext byte-for-byte without holding the
            key. Mutually exclusive with ``seal_for_recipient``.
        device: Required for ``kind="identity_seed"``. A
            :class:`DeviceKey` whose Ed25519 keypair becomes BOTH the
            bundle's ``from_did`` / ``to_did`` AND the manifest signer
            (self-issued).
        nickname: Optional human-readable label for
            ``kind="identity_seed"``. Lands in
            ``manifest.state.identity.nickname``.
        ceremony_id_stub: Optional ``ceremony_id`` for
            ``kind="identity_seed"``. Defaults to
            :data:`IDENTITY_SEED_CEREMONY_PLACEHOLDER`
            (``"_identity_seed"``). Identity bundles aren't tied to a
            real ceremony — the operator picks one once a host installs
            the identity and starts a ceremony.
        seal_for_recipient: Recipient-direction sealed-box path. Mints
            a fresh per-export BEK, encrypts the body, AND wraps the
            BEK to each recipient via :mod:`tn.recipient_seal`.
            Requires ``to_did`` (and/or ``to_dids``). Mutually
            exclusive with ``encrypt_body_with``.
        to_dids: Optional additional recipient DIDs alongside
            ``to_did``. Each gets its own entry in the
            ``recipient_wraps`` array. Only meaningful with
            ``seal_for_recipient=True``.

    Returns:
        ``Path`` of the written `.tnpkg` (equal to ``Path(out_path)``).

    Raises:
        ValueError: On invalid argument combinations (e.g. both
            ``encrypt_body_with=`` and ``seal_for_recipient=True``,
            ``encrypt_body_with=`` not 32 bytes,
            ``seal_for_recipient=True`` on a kind that doesn't
            support it).
        NotImplementedError: For reserved-but-unwired kinds (e.g.
            ``"recipient_invite"``).

    Example:
        >>> from tn.export import export
        >>> from pathlib import Path
        >>> export(  # doctest: +SKIP
        ...     Path("alice.tnpkg"),
        ...     kind="kit_bundle",
        ...     cfg=cfg,
        ...     to_did="did:key:z6Mk...",
        ...     seal_for_recipient=True,
        ... )

    See Also:
        :func:`decrypt_body_blob`: Inverse of the body-encryption
            layer.
        :mod:`tn.recipient_seal`: Sealed-box wrap primitives.
        `docs/spec/body-encryption.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md>`_:
            Wire spec.
        `docs/spec/manifest.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/manifest.md>`_:
            Manifest schema.
    """
    # 1. Pre-flight validation (single deterministic failure point
    #    before we touch a zip).
    _validate_export_args(
        kind=kind,
        cfg=cfg,
        confirm_includes_secrets=confirm_includes_secrets,
        device=device,
    )

    # 2. Build the per-kind body.
    body, extras = _build_export_body(
        kind=kind,
        cfg=cfg,
        package=package,
        keystore=keystore,
        groups=groups,
        device=device,
        nickname=nickname,
        confirm_includes_secrets=confirm_includes_secrets,
    )

    # 3. Resolve the manifest signer (cfg.device for most kinds; the
    #    bundled device key for identity_seed).
    signing_key_priv, signer_did, signer_ceremony = _resolve_export_signer(
        kind=kind, cfg=cfg, device=device, ceremony_id_stub=ceremony_id_stub
    )

    # 4. Body encryption — the two paths are mutually exclusive (caller
    #    either brings their own BEK for init-upload self-backup, or
    #    asks the export to mint+wrap one for the recipient).
    if encrypt_body_with is not None and seal_for_recipient:
        raise ValueError(
            "export: encrypt_body_with= and seal_for_recipient= are mutually "
            "exclusive. Either bring your own BEK (init-upload pattern) or ask "
            "the export to mint+wrap one (recipient-direction pattern)."
        )

    # 4a. BYOK (init-upload pattern, D-19 / D-5).
    if encrypt_body_with is not None:
        if not isinstance(encrypt_body_with, (bytes, bytearray)) or len(encrypt_body_with) != 32:
            raise ValueError(
                "export(encrypt_body_with=...) requires a 32-byte AES-256-GCM key"
            )
        body, extras = _encrypt_body_in_place(body, extras, bytes(encrypt_body_with))

    # 4b. Recipient-direction sealed-box wrap (second-release spec).
    #     Mint+encrypt+wrap, then reuse the preview ``as_of`` on the
    #     final manifest so its canonical bytes match the AAD.
    sealed_as_of: str | None = None
    if seal_for_recipient:
        body, extras, to_did, sealed_as_of = _apply_seal_for_recipient(
            kind=kind,
            cfg=cfg,
            body=body,
            extras=extras,
            scope=scope,
            to_did=to_did,
            to_dids=to_dids,
        )

    # 5. Build, sign, write. identity_seed self-addresses
    #    (from_did == to_did); other kinds use whatever the caller
    #    passed for to_did.
    manifest = TnpkgManifest(
        kind=str(kind),
        publisher_identity=signer_did,
        ceremony_id=signer_ceremony,
        as_of=sealed_as_of or _now_iso(),
        scope=str(scope or extras.get("scope") or _default_scope(kind)),
        recipient_identity=signer_did if kind == "identity_seed" else to_did,
        clock=dict(extras.get("clock", {})),
        event_count=int(extras.get("event_count", 0)),
        head_row_hash=extras.get("head_row_hash"),
        state=extras.get("state"),
    )
    manifest.sign(signing_key_priv)
    return _write_tnpkg(Path(out_path), manifest, body)


def _encrypt_body_in_place(
    body: dict[str, bytes],
    extras: dict[str, Any],
    key: bytes,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Combine all body files into a STORED zip and AES-256-GCM encrypt.

    Resolves the "Open #1" decision from
    ``2026-04-28-pending-claim-flow.md``: combined-blob (one
    ``body/encrypted.bin``) over per-file encryption. Combining is
    simpler, matches the "vault sees one opaque blob" spirit (D-1).

    Layout::

        body/encrypted.bin   = 12-byte AES-GCM nonce || ciphertext+tag

    The plaintext is a STORED zip (no compression) of the body files
    at their original names. STORED is chosen so the plaintext is
    identifiable by the standard ``PK\\x03\\x04`` magic bytes, can be
    popped open with stock unzip tools by an advanced user, and
    aligns the inner-layer format with the OUTER tnpkg envelope (also
    STORED). fflate is already vendored on the browser side; Python
    ``zipfile`` is stdlib; the format is a one-liner in every language
    we ship.

    Args:
        body: ``{path_inside_zip: bytes}`` map of plaintext body
            files. Replaced wholesale by a single ``body/encrypted.bin``
            in the returned ``body``.
        extras: Manifest extras dict. The returned copy gains a
            ``state.body_encryption`` block carrying ``cipher_suite``,
            ``nonce_bytes``, ``frame``, and ``ciphertext_sha256`` so
            the consumer can verify the ciphertext without holding
            the key.
        key: 32-byte AES-256-GCM key (the BEK). Caller is responsible
            for sourcing the key (BYOK path: explicit user-supplied;
            recipient-direction path: minted by
            :func:`_apply_seal_for_recipient`).

    Returns:
        ``(new_body, new_extras)`` — ready to feed into the manifest
        builder + zip writer.

    See Also:
        :func:`decrypt_body_blob`: The inverse.
        :func:`_apply_seal_for_recipient`: Wraps the BEK for
            recipients after this step.
        `docs/spec/body-encryption.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md>`_:
            Wire spec.
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
    """Decrypt an encrypted-body blob back into its body-file map.

    Inverse of :func:`_encrypt_body_in_place`. Public helper for
    tests, ``tn absorb``, and browser parity.

    Args:
        blob: Raw bytes of ``body/encrypted.bin`` — 12-byte nonce
            followed by ciphertext + 16-byte AES-GCM tag.
        key: 32-byte AES-256-GCM key (the BEK). For BYOK exports this
            is the same key the caller passed to ``encrypt_body_with=``;
            for recipient-direction exports this is the BEK recovered
            via :func:`tn.recipient_seal.unseal_bek_from_wrap`.

    Returns:
        ``{path_inside_zip: bytes}`` — the original body files.

    Raises:
        ValueError: If ``blob`` is shorter than the nonce+tag minimum,
            if the plaintext is too short for any known frame, or if
            the legacy frame is malformed.
        cryptography.exceptions.InvalidTag: If ``key`` is wrong or the
            ciphertext was tampered with.

    Note:
        Tries the canonical STORED-zip plaintext frame first
        (``PK\\x03\\x04`` magic). Falls back to the legacy custom
        binary frame for ciphertexts produced before commit
        2026-04-29 — kept until the next state wipe.

    See Also:
        :func:`_encrypt_body_in_place`: The inverse.
        :mod:`tn.recipient_seal`: BEK recovery for sealed exports.
        `docs/spec/body-encryption.md <https://github.com/cyaxios/tn-proto/blob/main/docs/spec/body-encryption.md>`_:
            Wire spec.
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


def export_group_keys(
    out_path: Path | str,
    *,
    cfg: LoadedConfig,
    groups: list[str] | None = None,
    sign_with: Any | None = None,
    author_did: str | None = None,
) -> Path:
    """Pack a ``group_keys`` ``.tnpkg`` carrying this ceremony's group KEY
    material so a SECOND device on the same account can INSTALL + ROUTE the
    groups after ``pull -> absorb``.

    1:1 with the TS reference ``node_runtime.exportGroupKeys``.

    Body  : ``body/keys/<group>.btn.state`` + ``body/keys/<group>.btn.mykit``
            for every btn group (minus ``tn.agents``, which every ceremony
            mints locally).
    State : ``{"groups": {<name>: <yaml-block>}, "kind": "group-keys-v1"}`` —
            the EXACT authoritative ``groups.<name>`` block so absorb
            re-registers the group without re-deriving it.

    Self-addressed (from_did == to_did == the author DID) — it rides the
    OWN-account inbox. NO device secret (``local.private``) is carried; the
    two devices keep distinct identities, only the shared group publisher
    keys travel.

    Wire kind: ``full_keystore`` with ``scope="group_keys"``. The vault's
    inbox route accepts ``full_keystore`` (a known kind) and does NOT
    enforce its body contents; the ``scope`` marker + ``state.groups`` block
    tell the consumer to route this to the group-key installer
    (``_absorb_group_keys``) rather than the blanket keystore overwrite — so
    no new server-side kind is required.

    ``sign_with`` / ``author_did`` let the caller author the snapshot AS the
    account-bound IDENTITY device key (the vault's inbox POST requires
    ``manifest.publisher_identity == auth_did``). When omitted, the
    ceremony's own device key signs (self-contained / test path).

    Raises ``RuntimeError`` when the ceremony has no btn group with key
    material (e.g. only ``tn.agents``) — the caller treats this as
    "nothing to publish".
    """
    keystore = Path(cfg.keystore).resolve()
    if not keystore.is_dir():
        raise FileNotFoundError(f"group_keys: keystore directory not found: {keystore}")

    # Resolve the authoritative groups.<name> blocks once (head of the
    # extends: chain — mirrors TS authoritativeYamlFor(..., "groups")).
    import yaml as _yaml

    from .config import authoritative_yaml_for

    auth_yaml = authoritative_yaml_for(cfg.yaml_path, "groups")
    auth_doc: dict[str, Any] = {}
    if auth_yaml.exists():
        try:
            auth_doc = _yaml.safe_load(auth_yaml.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001 — best-effort yaml read
            auth_doc = {}
    auth_groups = auth_doc.get("groups") if isinstance(auth_doc, dict) else None
    if not isinstance(auth_groups, dict):
        auth_groups = {}

    requested = set(groups) if groups else None

    body: dict[str, bytes] = {}
    blocks: dict[str, Any] = {}
    carried: list[str] = []

    for group, gcfg in cfg.groups.items():
        if group == "tn.agents":  # minted locally on every ceremony
            continue
        cipher_name = getattr(getattr(gcfg, "cipher", None), "name", None)
        if cipher_name is not None and cipher_name != "btn":
            continue
        if requested is not None and group not in requested:
            continue
        state_path = keystore / f"{group}.btn.state"
        mykit_path = keystore / f"{group}.btn.mykit"
        if not state_path.exists() or not mykit_path.exists():
            continue
        body[f"body/keys/{group}.btn.state"] = state_path.read_bytes()
        body[f"body/keys/{group}.btn.mykit"] = mykit_path.read_bytes()
        # Carry the authoritative yaml block if present, else a minimal one.
        block = auth_groups.get(group)
        if not isinstance(block, dict):
            self_did = cfg.device.device_identity if cfg.device is not None else None
            block = {
                "policy": getattr(gcfg, "policy", None) or "private",
                "cipher": "btn",
                "recipients": (
                    [{"recipient_identity": self_did}] if self_did else []
                ),
            }
        blocks[group] = block
        carried.append(group)

    if not carried:
        suffix = f" matching {sorted(requested)}" if requested else ""
        raise RuntimeError(
            f"group_keys: no btn groups with key material in {keystore}{suffix}"
        )

    if sign_with is not None:
        signing_key = sign_with.signing_key()
        signer_did = author_did or sign_with.did
    else:
        signing_key = cfg.device.signing_key()
        signer_did = author_did or cfg.device.device_identity

    manifest = TnpkgManifest(
        # full_keystore is a server-known kind; the scope marker below routes
        # the absorb to the group-key installer (no new wire kind needed).
        kind="full_keystore",
        publisher_identity=signer_did,
        ceremony_id=cfg.ceremony_id,
        as_of=_now_iso(),
        scope="group_keys",
        recipient_identity=signer_did,  # self-addressed (from_did == to_did)
        state={"groups": blocks, "kind": "group-keys-v1"},
    )
    manifest.sign(signing_key)
    return _write_tnpkg(Path(out_path), manifest, body)


def _default_scope(kind: str) -> str:
    if kind == "admin_log_snapshot":
        return "admin"
    if kind == "kit_bundle":
        return "kit_bundle"
    if kind == "full_keystore":
        return "full"
    if kind == "identity_seed":
        return "identity"
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
    "IDENTITY_SEED_CEREMONY_PLACEHOLDER",
    "ExportKind",
    "canonical_manifest_bytes",
    "decrypt_body_blob",
    "export",
    "export_group_keys",
    "export_identity_seed",
    "package_from_body_bytes",
]


# Pull in `asdict` is used by `_package_to_body_bytes`; the linter
# already sees that. No further unused-import shims required.
_ = asdict  # keep visible for linter
_ = hashlib
