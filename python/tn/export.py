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
        # Pack every named stream's yaml verbatim. Streams live in named
        # sibling subdirectories of the project root, each with its own
        # ``tn.yaml`` carrying the chain's ``ceremony.id``. We pack the
        # yaml as-is so absorb can restore the same chain identity on
        # the receiving node. Streams have no key material of their own
        # (they extend default), so we don't recurse into logs/ or admin/.
        #
        # Project root location depends on the on-disk layout:
        # * New (preferred): ``<root>/default/tn.yaml`` → root is parent.parent
        # * Legacy: ``<root>/tn.yaml`` → root is parent
        # We pick the root by walking up until we find subdirs with
        # tn.yaml siblings (other than default's own dir).
        from ._defaults import DEFAULT_CEREMONY_NAME

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
                    body[f"body/streams/{entry.name}/tn.yaml"] = stream_yaml.read_bytes()

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
        assert cfg is not None  # guarded by _validate_export_args
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
        assert device is not None  # guarded by _validate_export_args
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
            "export(seal_for_recipient=True) requires at least one recipient "
            "in to_did=... or to_dids=[...]."
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
    """Mint a fresh per-export BEK, encrypt the body, wrap the BEK for
    each recipient DID.

    Returns ``(body, extras, to_did, sealed_as_of)``. The ``to_did``
    return is the canonical display addressee (first entry in the
    merged recipient list) — the caller overrides its own ``to_did``
    with this. The ``sealed_as_of`` return must be reused on the final
    manifest so its canonical bytes match the AAD we computed against
    the preview.

    Per the second-release encrypted-kit-bundle spec: only callers who
    hold a recipient's device key can recover the BEK and decrypt the
    body. We always emit the plural ``recipient_wraps`` array (canonical
    forward shape) and additionally emit the singular ``recipient_wrap``
    shadow when there's exactly one entry — back-compat for older
    absorbers that only know the singular shape.
    """
    if kind not in ("kit_bundle", "full_keystore"):
        raise ValueError(
            f"export(seal_for_recipient=True) is currently scoped to "
            f"kit_bundle / full_keystore; got kind={kind!r}."
        )
    import secrets as _secrets

    from .recipient_seal import (
        manifest_aad_for_wrap as _aad_for_wrap,
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
        from_did=cfg.device.device_identity if cfg is not None else "",
        ceremony_id=cfg.ceremony_id if cfg is not None else "",
        as_of=_now_iso(),
        scope=str(scope or extras.get("scope") or _default_scope(kind)),
        to_did=merged_dids[0],
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
    device:
        Required for ``kind="identity_seed"``. A ``DeviceKey`` whose
        Ed25519 keypair becomes BOTH the bundle's ``from_did`` /
        ``to_did`` AND the manifest signer. The bundle is self-issued.
    nickname:
        Optional human-readable label for ``kind="identity_seed"``. Lands
        in ``manifest.state.identity.nickname``.
    ceremony_id_stub:
        Optional ``ceremony_id`` for ``kind="identity_seed"``. Defaults to
        ``IDENTITY_SEED_CEREMONY_PLACEHOLDER`` ("_identity_seed"). Identity
        bundles aren't tied to a real ceremony — the operator picks one
        once a host installs the identity and starts a ceremony.
    seal_for_recipient:
        For ``kind="kit_bundle"`` (and conceivably future kinds): mint a
        fresh per-export AES-256-GCM BEK, encrypt the body with it via
        the existing ``_encrypt_body_in_place`` machinery, AND wrap the
        BEK to the recipient's identity (named by ``to_did``) using the
        sealed-box construction in ``tn.recipient_seal``. The result is a
        ``.tnpkg`` whose body is unreadable to anyone but the holder of
        ``to_did``'s device key. Requires ``to_did`` to be set.
        Mutually exclusive with ``encrypt_body_with``: caller can either
        bring their own BEK (init-upload self-backup pattern) or ask the
        export to mint+wrap one (recipient-direction pattern), not both.
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
        from_did=signer_did,
        ceremony_id=signer_ceremony,
        as_of=sealed_as_of or _now_iso(),
        scope=str(scope or extras.get("scope") or _default_scope(kind)),
        to_did=signer_did if kind == "identity_seed" else to_did,
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
    "ExportKind",
    "IDENTITY_SEED_CEREMONY_PLACEHOLDER",
    "canonical_manifest_bytes",
    "decrypt_body_blob",
    "export",
    "export_identity_seed",
    "package_from_body_bytes",
]


# Pull in `asdict` is used by `_package_to_body_bytes`; the linter
# already sees that. No further unused-import shims required.
_ = asdict  # keep visible for linter
_ = hashlib
