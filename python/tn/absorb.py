"""Idempotent merge of incoming ``.tnpkg`` packages into local TN state.

This is the unified consumer side. It accepts the universal `.tnpkg`
wrapper (zip with signed manifest + body) and dispatches on
``manifest.kind``::

    admin_log_snapshot   -> append envelopes to <yaml_dir>/.tn/admin/admin.ndjson
                            (idempotent dedupe by row_hash)
    offer                -> pending_offers/<signer_did>.json (legacy behavior)
    enrolment            -> wire publisher pub into local yaml + jwe state
    kit_bundle           -> install kit files into <keystore>/
    full_keystore        -> install kit files + private material into <keystore>/

The function exposes two call shapes for back-compat:

    tn.absorb(source)           # new 1-arg API (uses tn.current_config)
    tn.absorb(cfg, source)      # legacy 2-arg API used by tests

Both return either an ``AbsorbReceipt`` (new) or an ``AbsorbResult``
(legacy). The legacy 2-arg form keeps yielding ``AbsorbResult`` so
existing tests don't break.
"""

from __future__ import annotations

import base64
import hashlib as _hashlib
import json
import logging as _logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from datetime import timezone as _tz
from pathlib import Path
from typing import Any, overload

from .admin.log import (
    append_admin_envelopes,
    existing_row_hashes,
    resolve_admin_log_path,
)
from .config import LoadedConfig
from .conventions import pending_offers_dir
from .packaging import Package, verify
from .signing import DeviceKey, _signature_from_b64
from .tnpkg import (
    TnpkgManifest,
    _clock_dominates,
    _read_manifest,
    _verify_manifest_signature,
)

_DID_SAFE = re.compile(r"[^A-Za-z0-9._-]")


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------


@dataclass
class LeafReuseAttempt:
    """Recorded when a `recipient_added` envelope arrives for a leaf that
    is already revoked / retired in local state. The envelope is still
    appended (append-only invariant) but excluded from the materialized
    AdminState. Surfaced in ``AbsorbReceipt.conflicts``.

    ``informed`` distinguishes the two causal cases (Design A): when the
    incoming snapshot's vector clock already COVERED the revoke, the
    publisher knew the leaf was dead and re-added it anyway — an
    equivocation (``informed=True``). When the clock did NOT cover it,
    the reuse is a benign concurrent race (``informed=False``). Either
    way the leaf stays revoked in derived state; the flag drives
    alerting/audit, not state.
    """

    group: str
    leaf_index: int
    attempted_row_hash: str
    revoked_row_hash: str | None = None
    informed: bool = False


@dataclass
class AbsorbReceipt:
    """Result of a new-style ``tn.absorb(source)`` call.

    Fields
    ------
    kind:
        Manifest discriminator that drove dispatch.
    accepted_count:
        Envelopes / units newly applied to local state.
    deduped_count:
        Envelopes / units skipped because we already had them.
    noop:
        True iff the receiver's clock dominates the manifest's clock and
        no work was done.
    derived_state:
        For admin snapshots: the AdminState reduced from the local log
        after absorb. None for non-admin kinds (or when state derivation
        fails).
    conflicts:
        Equivocation signals — currently ``LeafReuseAttempt``. Empty by
        default.
    legacy_status:
        Status string from the legacy AbsorbResult shape (``"offer_stashed"``,
        ``"enrolment_applied"``, ...). Populated when dispatch hits an
        offer / enrolment / kit kind so old call sites can read it.
    legacy_reason:
        Free-text explanation when ``legacy_status == "rejected"``.
    replaced_kit_paths:
        Paths in the local keystore whose existing contents were renamed
        to a ``.previous.<UTC_TS>`` sidecar to make room for kits from
        the absorbed package. Empty list when nothing was overwritten.
        Closes FINDINGS #6 — the legacy ``print()`` notice on stdout
        only reached human callers; programmatic callers reading
        ``receipt.accepted_count`` had no way to learn that their own
        kit had been displaced. Iterate this field after absorb to
        decide whether to alert / restore / accept the swap.
    """

    kind: str
    accepted_count: int = 0
    deduped_count: int = 0
    noop: bool = False
    derived_state: dict[str, Any] | None = None
    conflicts: list[LeafReuseAttempt] = field(default_factory=list)
    legacy_status: str = ""
    legacy_reason: str = ""
    replaced_kit_paths: list[Path] = field(default_factory=list)


# Legacy result shape kept for back-compat with existing tests / callers
# that match on ``.status`` and ``.reason``.
@dataclass
class AbsorbResult:
    status: str  # offer_stashed | enrolment_applied | coupon_applied | no_op | rejected
    reason: str = ""
    peer_did: str | None = None


# ---------------------------------------------------------------------------
# Public entry — supports new (source) and legacy (cfg, source) signatures
# ---------------------------------------------------------------------------


@overload
def absorb(source: Path | str | bytes | bytearray, /) -> AbsorbReceipt: ...
@overload
def absorb(cfg: LoadedConfig, source: Path | str | bytes | bytearray, /) -> AbsorbResult: ...
@overload
def absorb(*, source: Path | str | bytes | bytearray) -> AbsorbReceipt: ...
@overload
def absorb(
    *, cfg: LoadedConfig, source: Path | str | bytes | bytearray
) -> AbsorbResult: ...
def absorb(
    *args: Any,
    **kwargs: Any,
) -> AbsorbReceipt | AbsorbResult:
    """Absorb a `.tnpkg`. Accepts two call shapes::

        absorb(source)             # returns AbsorbReceipt; uses tn.current_config()
        absorb(cfg, source)        # returns AbsorbResult (legacy behavior)

    The legacy two-arg form still pulls a ``LoadedConfig`` explicitly
    and returns the original ``AbsorbResult`` shape. The new one-arg form
    is the canonical surface and always returns an ``AbsorbReceipt``.
    """
    cfg: LoadedConfig | None
    source: Any
    legacy = False
    if len(args) == 1 and not kwargs:
        source = args[0]
        cfg = None
    elif len(args) == 2:
        cfg = args[0]
        source = args[1]
        legacy = True
    elif "source" in kwargs:
        source = kwargs.pop("source")
        cfg = kwargs.pop("cfg", None)
        legacy = cfg is not None
    else:
        raise TypeError(
            "absorb: call as absorb(source) or absorb(cfg, source). "
            f"Got args={args!r} kwargs={list(kwargs)!r}."
        )

    if cfg is None:
        # Late import to avoid pulling tn.__init__ during module init.
        from . import current_config as _current_config

        try:
            cfg = _current_config()
        except RuntimeError as exc:
            # If the bundle is a self-contained bootstrap kind
            # (identity_seed / project_seed), derive a synthetic cfg
            # from the cwd + bundle's body/tn.yaml so absorb installs
            # everything end-to-end without a prior tn.init(). The
            # caller's subsequent tn.init() then picks up the
            # freshly-absorbed yaml.
            cfg = _try_bootstrap_cfg(source)
            if cfg is None:
                # No bootstrap shortcut available. Auto-create a fresh
                # ceremony in the cwd (same path tn.info(...) takes when
                # called with no prior init). This prints the standard
                # autoinit banner so the caller knows a new identity was
                # minted. Then retry the config lookup.
                from ._autoinit import maybe_autoinit as _maybe_autoinit
                _maybe_autoinit()
                try:
                    cfg = _current_config()
                except RuntimeError:
                    raise RuntimeError(
                        "absorb: no LoadedConfig available. Call "
                        "tn.init(yaml_path) first, or pass cfg explicitly "
                        "via the legacy two-arg form."
                    ) from exc

    receipt = _absorb_dispatch(cfg, source)

    if legacy:
        # Translate to the older shape so existing tests keep working.
        if receipt.legacy_status:
            # peer_did is populated by handlers that have one (e.g. _absorb_offer,
            # _absorb_enrolment populate it via the dedicated wrapper paths).
            # Snapshot/seed kinds don't carry a single peer_did, so leave it None
            # on the legacy shape and let callers read receipt fields if needed.
            return AbsorbResult(
                status=receipt.legacy_status,
                reason=receipt.legacy_reason,
                peer_did=None,
            )
        # Default mapping for snapshot kinds the old callers never saw.
        if receipt.kind == "admin_log_snapshot":
            status = "no_op" if receipt.noop else "enrolment_applied"
            return AbsorbResult(status=status, reason=receipt.legacy_reason)
        return AbsorbResult(status="rejected", reason=receipt.legacy_reason or "unknown kind")
    return receipt


def _try_bootstrap_cfg(source: Path | str | bytes | bytearray) -> LoadedConfig | None:
    """If ``source`` is an ``identity_seed`` or ``project_seed`` tnpkg,
    synthesize a minimal ``LoadedConfig`` from the current working
    directory + the bundle's ``body/tn.yaml`` so absorb can install
    everything without a prior ``tn.init()``.

    Returns ``None`` if the bundle is not a recognised bootstrap kind
    (in which case the caller raises the original "call tn.init() first"
    error).

    The synthesized cfg only needs to satisfy what the bootstrap
    handlers (`_absorb_identity_seed`, `_absorb_project_seed`) read:
    ``yaml_path``, ``keystore``, and ``resolve_log_path()``. Everything
    else stays at field-level defaults — the handlers don't touch them.
    """
    import os as _os

    try:
        manifest, body = _read_manifest(source)
    except (ValueError, FileNotFoundError):
        return None

    if manifest.kind not in ("identity_seed", "project_seed"):
        return None

    cwd = Path(_os.getcwd()).resolve()
    yaml_path = cwd / "tn.yaml"

    # Default keystore + log paths. Read the bundle's body/tn.yaml when
    # present so we honor whatever layout the dashboard / minter chose
    # (project_seed bundles say ``keystore.path: ./.tn/tn/keys``;
    # identity_seed stubs don't carry a keystore block, so we fall back
    # to the create_fresh-style ``./.tn/tn/keys``).
    keystore_rel = "./.tn/tn/keys"
    log_rel = "./.tn/tn/logs/tn.ndjson"
    admin_rel = "./.tn/tn/admin/admin.ndjson"

    yaml_blob = body.get("body/tn.yaml")
    if yaml_blob is not None:
        try:
            import yaml as _yaml

            doc = _yaml.safe_load(yaml_blob.decode("utf-8")) or {}
            if isinstance(doc, dict):
                ks_block = doc.get("keystore") or {}
                if isinstance(ks_block, dict) and isinstance(ks_block.get("path"), str):
                    keystore_rel = ks_block["path"]
                logs_block = doc.get("logs") or {}
                if isinstance(logs_block, dict) and isinstance(logs_block.get("path"), str):
                    log_rel = logs_block["path"]
                cer_block = doc.get("ceremony") or {}
                if isinstance(cer_block, dict) and isinstance(
                    cer_block.get("admin_log_location"), str
                ):
                    admin_rel = cer_block["admin_log_location"]
        except Exception:  # noqa: BLE001 — synthetic-cfg derivation is best-effort
            pass

    keystore = (yaml_path.parent / keystore_rel).resolve()

    # Build a minimal LoadedConfig. The bootstrap handlers only read
    # `yaml_path`, `keystore`, and `resolve_log_path()` — everything else
    # is filled with placeholder defaults that won't be touched.
    from .signing import DeviceKey as _DeviceKey

    placeholder_priv = b"\x00" * 32
    return LoadedConfig(
        yaml_path=yaml_path,
        keystore=keystore,
        device=_DeviceKey.from_private_bytes(placeholder_priv),
        ceremony_id="_bootstrap_absorb",
        master_index_key=b"",
        cipher_name="btn",
        public_fields=[],
        default_policy="private",
        groups={},
        field_to_groups={},
        handler_specs=None,
        admin_log_location=admin_rel,
        log_path=log_rel,
    )


# ---------------------------------------------------------------------------
# Internal dispatch
# ---------------------------------------------------------------------------


def _absorb_dispatch(cfg: LoadedConfig, source: Path | str | bytes | bytearray) -> AbsorbReceipt:
    """Open the zip, verify the manifest, and dispatch on ``manifest.kind``.

    Falls back to the legacy ``Package`` JSON path when the source is not
    a zip — the codebase still has a few callers that pass an unwrapped
    ``Package``-shaped JSON file.
    """
    try:
        manifest, body = _read_manifest(source)
    except (ValueError, FileNotFoundError) as exc:
        # Legacy fallback: the old ``dump_tnpkg`` produced a flat JSON
        # ``Package`` (no zip header). Honor it when we can; otherwise
        # surface the error.
        legacy = _try_legacy_json_package(cfg, source)
        if legacy is not None:
            return legacy
        return AbsorbReceipt(
            kind="unknown",
            legacy_status="rejected",
            legacy_reason=f"absorb: not a `.tnpkg` zip and not a legacy JSON Package: {exc}",
        )

    if not _verify_manifest_signature(manifest):
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"manifest signature does not verify against from_did "
                f"{manifest.publisher_identity!r}. The package is corrupt, truncated, or "
                f"tampered with. Ask the sender to re-export and re-send."
            ),
        )

    # Recipient-direction sealed-box unwrap. If the manifest carries
    # state.body_encryption.recipient_wrap, the body was encrypted by
    # the producer with a fresh BEK that's been wrapped to this
    # recipient's identity. Unwrap before kind-specific dispatch so
    # downstream branches see the body in the clear.
    body, unwrap_err = _maybe_unseal_recipient_wrap(cfg, manifest, body)
    if unwrap_err is not None:
        return unwrap_err

    kind = manifest.kind
    if kind == "admin_log_snapshot":
        return _absorb_admin_log_snapshot(cfg, manifest, body)
    if kind == "offer":
        return _absorb_offer_kind(cfg, manifest, body)
    if kind == "enrolment":
        return _absorb_enrolment_kind(cfg, manifest, body)
    if kind in ("kit_bundle", "full_keystore"):
        return _absorb_kit_bundle(cfg, manifest, body)
    if kind == "contact_update":
        return _absorb_contact_update(cfg, manifest, body)
    if kind == "identity_seed":
        return _absorb_identity_seed(cfg, manifest, body)
    if kind == "project_seed":
        return _absorb_project_seed(cfg, manifest, body)
    if kind == "recipient_invite":
        return AbsorbReceipt(
            kind=kind,
            legacy_status="rejected",
            legacy_reason=(
                f"absorb: kind {kind!r} is reserved in the manifest schema but "
                f"this Python version does not yet implement absorb for it."
            ),
        )
    return AbsorbReceipt(
        kind=kind,
        legacy_status="rejected",
        legacy_reason=f"absorb: unknown manifest kind {kind!r}",
    )


# ---------------------------------------------------------------------------
# Legacy JSON fallback
# ---------------------------------------------------------------------------


def _try_legacy_json_package(
    cfg: LoadedConfig, source: Path | str | bytes | bytearray
) -> AbsorbReceipt | None:
    """If ``source`` is a flat ``Package`` JSON (the pre-manifest layout),
    parse it and route to the offer / enrolment handlers. Returns None
    if the input doesn't look like a legacy package."""
    try:
        if isinstance(source, (bytes, bytearray)):
            doc = json.loads(bytes(source).decode("utf-8"))
        else:
            doc = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict) or "package_kind" not in doc:
        return None
    try:
        pkg = Package(**doc)
    except TypeError:
        return None
    if not verify(pkg):
        return AbsorbReceipt(
            kind=pkg.package_kind,
            legacy_status="rejected",
            legacy_reason=(
                f"signature verification failed for {source}: the package "
                f"claims signer {pkg.device_identity!r} but its Ed25519 sig does "
                f"not verify against its signer_verify_pub_b64."
            ),
        )
    if pkg.package_kind == "offer":
        return _stash_offer(cfg, pkg)
    if pkg.package_kind == "enrolment":
        return _apply_enrolment(cfg, pkg)
    return AbsorbReceipt(
        kind=pkg.package_kind,
        legacy_status="rejected",
        legacy_reason=(
            f"unsupported package_kind: {pkg.package_kind!r}. Known kinds in "
            f"this TN version: offer, enrolment."
        ),
    )


# ---------------------------------------------------------------------------
# Kind handlers
# ---------------------------------------------------------------------------


def _absorb_offer_kind(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    """Body is ``body/package.json`` containing the existing Package shape."""
    pkg_bytes = body.get("body/package.json")
    if pkg_bytes is None:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="offer body missing `body/package.json`",
        )
    try:
        pkg = Package(**json.loads(pkg_bytes.decode("utf-8")))
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=f"offer body is not a valid Package JSON: {exc}",
        )
    if not verify(pkg):
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="inner Package signature failed verification",
        )
    return _stash_offer(cfg, pkg)


def _absorb_enrolment_kind(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    pkg_bytes = body.get("body/package.json")
    if pkg_bytes is None:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="enrolment body missing `body/package.json`",
        )
    try:
        pkg = Package(**json.loads(pkg_bytes.decode("utf-8")))
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=f"enrolment body is not a valid Package JSON: {exc}",
        )
    if not verify(pkg):
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="inner Package signature failed verification",
        )
    return _apply_enrolment(cfg, pkg)


def _maybe_unseal_recipient_wrap(
    cfg: LoadedConfig,
    manifest: TnpkgManifest,
    body: dict[str, bytes],
) -> tuple[dict[str, bytes], AbsorbReceipt | None]:
    """If the manifest carries a sealed-box recipient wrap, unseal it and
    replace ``body['body/encrypted.bin']`` with the decrypted body files.

    Supports both wire shapes:

    * ``state.body_encryption.recipient_wrap`` — singular, single-key.
      Existing shape from the original second-release encrypted-kit-bundle
      spec; still emitted by producers when there's exactly one
      recipient.
    * ``state.body_encryption.recipient_wraps`` — plural, array.
      Federation work (decisions log
      2026-05-04-federation-and-management-decisions.md D-5). Producer
      emits one entry per recipient key. Consumer walks the array and
      uses the entry whose ``recipient_did`` matches this device.

    When both are present, plural wins (it's the canonical form).

    Returns ``(new_body, None)`` on success or pass-through.
    Returns ``(body, AbsorbReceipt[rejected])`` on failure.

    Pass-through cases (no unsealing attempted, body unchanged):
      * No ``state`` on the manifest.
      * ``state.body_encryption`` absent.
      * Both ``recipient_wrap`` and ``recipient_wraps`` absent (e.g. the
        init-upload pattern where the BEK rides in the URL fragment;
        absorb on that path doesn't reach here in normal flow, but if
        it did we'd let the kind-specific handler see the still-encrypted
        body and reject it).
    """
    state = manifest.state or {}
    body_encryption = state.get("body_encryption") if isinstance(state, dict) else None
    if not isinstance(body_encryption, dict):
        return body, None
    wraps_array = body_encryption.get("recipient_wraps")
    wrap_singular = body_encryption.get("recipient_wrap")
    if wraps_array is None and wrap_singular is None:
        return body, None

    # Late import — recipient_seal pulls in pynacl.bindings; we only want
    # to take that hit on the unwrap path.
    from .export import decrypt_body_blob
    from .recipient_seal import (
        UnsealError,
        manifest_aad_for_wrap,
        unseal_bek_from_wrap,
    )

    our_did = getattr(getattr(cfg, "device", None), "did", None)
    device_priv = getattr(cfg.device, "private_bytes", None)
    if not isinstance(our_did, str):
        return body, AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="cfg.device has no DID; cannot match a sealed-box wrap.",
        )
    if not isinstance(device_priv, (bytes, bytearray)) or len(device_priv) != 32:
        return body, AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                "cfg.device does not expose a 32-byte Ed25519 private seed; "
                "cannot unwrap sealed-box body."
            ),
        )

    # Build the candidate-wrap list. Plural takes precedence if both
    # are present. Plural items are dicts with a recipient_did field;
    # we filter to entries that name this device.
    candidates: list[dict[str, Any]] = []
    if isinstance(wraps_array, list):
        for entry in wraps_array:
            if not isinstance(entry, dict):
                continue
            rdid = entry.get("recipient_identity")
            if rdid == our_did:
                candidates.append(entry)
    elif isinstance(wrap_singular, dict):
        rdid = wrap_singular.get("recipient_identity")
        if rdid == our_did:
            candidates.append(wrap_singular)

    if not candidates:
        # Wire shape was present but no entry names us. The publisher
        # didn't intend us as a recipient. We can't open the body — but
        # this isn't a "tampered" rejection, just "not for me." Surface
        # a clear reason.
        if isinstance(wraps_array, list):
            recipients = [
                e.get("recipient_identity")
                for e in wraps_array
                if isinstance(e, dict)
            ]
        else:
            recipients = [
                wrap_singular.get("recipient_identity")
                if isinstance(wrap_singular, dict)
                else None
            ]
        return body, AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"sealed-box wrap is addressed to {recipients!r}; this "
                f"runtime is {our_did!r}. Refusing to attempt unwrap."
            ),
        )

    aad = manifest_aad_for_wrap(manifest.to_dict())

    # Try each matching candidate. First successful unwrap wins. With
    # the AAD binding the manifest, an attacker can't usefully forge a
    # wrap that names us — the AEAD will reject it.
    bek: bytes | None = None
    last_err: str = ""
    for cand in candidates:
        try:
            bek = unseal_bek_from_wrap(cand, bytes(device_priv), aad)
            break
        except UnsealError as exc:
            last_err = str(exc)
            continue
    if bek is None:
        return body, AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=f"sealed-box unwrap failed: {last_err}",
        )

    encrypted = body.get("body/encrypted.bin")
    if encrypted is None:
        return body, AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                "manifest declares body_encryption but body/encrypted.bin is "
                "missing from the zip."
            ),
        )

    try:
        decoded = decrypt_body_blob(encrypted, bek)
    except Exception as exc:  # noqa: BLE001 — wrap any decrypt error
        return body, AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=f"body decrypt with unwrapped BEK failed: {exc}",
        )

    # Replace body with the decrypted member dict. Keys come back as
    # body/<name> (stored zip preserves the original layout).
    return decoded, None


def _absorb_identity_seed(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    """Install a freshly-minted identity into ``cfg.keystore``.

    The identity_seed bundle contains exactly:

    ``body/local.private`` — the 32-byte Ed25519 seed.
    ``body/local.public``  — the matching ``did:key:z...`` string.
    ``body/tn.yaml``       — a stub yaml naming the DID.

    Behavior:

    * If the keystore has no ``local.private`` yet, install the bundle
      and return ``accepted_count=1``.
    * If ``local.private`` already exists AND matches the bundle's bytes
      byte-for-byte (idempotent re-absorb of the same identity), return
      ``noop=True``, ``accepted_count=0``.
    * Otherwise (different identity already present) reject. We don't
      silently overwrite an existing device key — that would orphan
      every signed log entry.

    The manifest's signature has already been verified by the caller
    (``_absorb_dispatch``). One extra cross-check we do here: the
    manifest's ``from_did`` MUST match the public key derived from the
    body's ``local.private`` AND must equal the contents of
    ``body/local.public``. This guards against a tampered body
    (signature still valid, body privately swapped to a different key).
    """
    priv_bytes = body.get("body/local.private")
    pub_text = body.get("body/local.public")
    yaml_bytes = body.get("body/tn.yaml")
    if priv_bytes is None or pub_text is None or yaml_bytes is None:
        missing = [
            name
            for name, present in (
                ("body/local.private", priv_bytes),
                ("body/local.public", pub_text),
                ("body/tn.yaml", yaml_bytes),
            )
            if present is None
        ]
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"identity_seed body is missing required members: {missing}"
            ),
        )

    if len(priv_bytes) != 32:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"identity_seed body/local.private must be 32 bytes (Ed25519 "
                f"seed); got {len(priv_bytes)}"
            ),
        )

    # Cross-check: the bundle's body must agree with the manifest's
    # from_did. This is the load-bearing tamper guard for identity_seed.
    from .signing import DeviceKey as _DeviceKey

    derived = _DeviceKey.from_private_bytes(priv_bytes)
    bundle_did = pub_text.decode("utf-8").strip()
    if derived.did != bundle_did or derived.did != manifest.publisher_identity:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"identity_seed integrity check failed: manifest.from_did="
                f"{manifest.publisher_identity!r}, body/local.public={bundle_did!r}, "
                f"derived-from-private={derived.did!r}. The bundle's body and "
                f"manifest disagree about which identity this is — refuse to "
                f"install."
            ),
        )
    if manifest.publisher_identity != manifest.recipient_identity:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"identity_seed must be self-addressed (from_did == to_did); "
                f"got from_did={manifest.publisher_identity!r}, to_did={manifest.recipient_identity!r}."
            ),
        )

    keystore = cfg.keystore
    keystore.mkdir(parents=True, exist_ok=True)
    priv_path = keystore / "local.private"
    pub_path = keystore / "local.public"
    yaml_target = cfg.yaml_path

    if priv_path.exists():
        existing = priv_path.read_bytes()
        if existing == priv_bytes:
            return AbsorbReceipt(
                kind=manifest.kind,
                noop=True,
                legacy_status="no_op",
                legacy_reason=(
                    f"identity_seed already installed at {priv_path} (same "
                    f"DID, bytes match)."
                ),
            )
        # Bug 3 — UX trap. The local.private differs, but if no user events
        # have ever been emitted under this ceremony, the active "identity"
        # is just whatever tn.init() minted on a fresh directory. There is
        # nothing meaningful to orphan, so let absorb overwrite. Admin-only
        # events (event_type starting with "tn.") are emitted by init itself
        # and don't count as user activity.
        if _user_event_count(cfg) == 0:
            # Best-effort: rename the prior keys aside so a confused operator
            # can recover. We don't bother with a backup if the rename fails.
            ts = datetime.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")
            try:
                priv_path.rename(priv_path.with_name(f"local.private.previous.{ts}"))
            except OSError:
                pass
            try:
                if pub_path.exists():
                    pub_path.rename(pub_path.with_name(f"local.public.previous.{ts}"))
            except OSError:
                pass
        else:
            return AbsorbReceipt(
                kind=manifest.kind,
                legacy_status="rejected",
                legacy_reason=(
                    f"refusing to overwrite existing identity at {priv_path}. The "
                    f"keystore already has a different device key and the local "
                    f"log already contains user-emitted entries signed by it. "
                    f"To replace, delete the keystore directory first; the "
                    f"existing identity's signed log entries will become "
                    f"unverifiable."
                ),
            )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_text(bundle_did, encoding="utf-8")

    # tn.yaml: write if missing OR when the local ceremony has no user
    # events yet (the dirt-easy fresh-init case — see Bug 3). Don't
    # clobber an existing ceremony yaml that's already accumulated user
    # activity.
    if not yaml_target.exists():
        yaml_target.parent.mkdir(parents=True, exist_ok=True)
        yaml_target.write_bytes(yaml_bytes)
    elif _user_event_count(cfg) == 0 and yaml_target.read_bytes() != yaml_bytes:
        ts = datetime.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            yaml_target.rename(yaml_target.with_name(f"{yaml_target.name}.previous.{ts}"))
        except OSError:
            pass
        yaml_target.parent.mkdir(parents=True, exist_ok=True)
        yaml_target.write_bytes(yaml_bytes)

    return AbsorbReceipt(
        kind=manifest.kind,
        accepted_count=1,
        legacy_status="enrolment_applied",
        legacy_reason=f"installed identity {bundle_did} into {keystore}",
    )


def _absorb_kit_bundle(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    """Install kit files (and, for full_keystore, private material) into
    the local keystore. Idempotent: existing files are renamed to
    ``.previous.<UTC_TS>`` before writing."""
    keystore = cfg.keystore
    keystore.mkdir(parents=True, exist_ok=True)
    accepted = 0
    skipped = 0
    replaced: list[Path] = []
    ts = datetime.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")
    for name, data in body.items():
        if not name.startswith("body/"):
            continue
        rel = name[len("body/") :]
        if not rel:
            continue
        if rel.startswith("streams/"):
            # Stream-yaml entries are absorbed below in a dedicated
            # block; skip them in the flat keystore-install path.
            continue
        # We only honor a flat layout (no nested directories) for kit
        # bundles. Skip anything that smuggles in a path separator.
        if "/" in rel or "\\" in rel:
            continue
        dest = keystore / rel
        if dest.exists() and dest.read_bytes() == data:
            skipped += 1
            continue
        if dest.exists():
            backup = dest.with_name(f"{rel}.previous.{ts}")
            dest.rename(backup)
            # Surface the swap on the receipt (FINDINGS #6). The
            # original bytes are preserved at ``backup``; we record the
            # destination path the absorbed kit landed at so the caller
            # can map it back to the .previous file by appending the
            # same UTC timestamp suffix.
            replaced.append(dest)
        dest.write_bytes(data)
        accepted += 1
    # Stream yamls: restore each ``body/streams/<name>/tn.yaml`` to
    # ``<project_root>/<name>/tn.yaml`` verbatim, preserving the
    # packed ``ceremony.id``. See #33.
    _restore_stream_yamls(cfg, body, ts)
    # Best-effort: tell the vault we materialized this kit so the
    # dashboard's /projects -> Received tab surfaces it next to the
    # ones absorbed in-browser. No-op when the ceremony isn't bound
    # to a vault account (the common offline / pre-`tn account
    # connect` case). Failures are logged and swallowed — local
    # materialization already succeeded, the vault row is metadata.
    _maybe_post_received_kit(cfg, manifest, body)
    return AbsorbReceipt(
        kind=manifest.kind,
        accepted_count=accepted,
        deduped_count=skipped,
        legacy_status="enrolment_applied" if accepted else "no_op",
        replaced_kit_paths=replaced,
    )


def _maybe_post_received_kit(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> None:
    """Best-effort POST to ``/api/v1/account/received-kits`` after a
    successful ``kit_bundle`` / ``full_keystore`` absorb.

    The dashboard's "Absorb" action does this from the browser; the CLI
    counterpart calls it here so a CLI-only operator sees the same
    "Received project" tile on the /projects view that a browser-side
    absorb produces. Without this hook, ``tn sync --pull && tn absorb``
    materializes the keystore but leaves the dashboard blank.

    Wire shape (matches routes_received_kits.ReceivedKitCreate exactly):

        {
            "project_id":        manifest.ceremony_id,
            "publisher_identity": manifest.publisher_identity,
            "recipient_identity": cfg.device.device_identity,
            "label":              <scope or publisher DID prefix>,
            "kit_blob_b64":       base64 of body/<group>.btn.mykit,
            "manifest":           full manifest.json dict,
            "source_ts":          manifest.as_of,
            "source_ceremony_id": manifest.ceremony_id,
        }

    Auth: a fresh VaultClient using the DID-challenge JWT for this
    device's DID. The route accepts that token because ``tn account
    connect`` $addToSet'd this DID into the account's minted_dids[].

    Skipped silently when:
      - ``tn account connect`` has not bound this ceremony to a vault
        account (no account_id in sync state);
      - the absorbing identity is ephemeral / has no on-disk
        identity.json (we don't have keys to authenticate with);
      - the network / vault is unreachable. Local absorb already
        succeeded; we don't want the absence of an internet to
        invalidate the keystore install.
    """
    import logging

    _log = logging.getLogger("tn.absorb.received_kits")
    try:
        from .sync_state import get_account_id, is_account_bound
    except ImportError:
        return  # extremely defensive: shouldn't happen in-tree

    try:
        if not is_account_bound(cfg.yaml_path):
            return
        account_id = get_account_id(cfg.yaml_path)
        if not account_id:
            return
    except Exception:  # noqa: BLE001 — best-effort lookup
        return

    # Pick the kit_blob to ship. The body carries one
    # body/<group>.btn.mykit per group in the bundle; prefer
    # ``default.btn.mykit`` (the most common single-group case) and
    # otherwise pick the first kit-shaped body entry deterministically.
    kit_blob: bytes | None = None
    for name in ("body/default.btn.mykit",):
        if name in body:
            kit_blob = body[name]
            break
    if kit_blob is None:
        for name in sorted(body.keys()):
            if name.startswith("body/") and name.endswith(".btn.mykit"):
                kit_blob = body[name]
                break

    import base64 as _b64

    kit_blob_b64 = (
        _b64.b64encode(kit_blob).decode("ascii") if kit_blob is not None else None
    )

    # Identity load: we need the device key to DID-challenge auth. If
    # there's no on-disk identity, skip the vault POST entirely (the
    # operator is using an ephemeral runtime, the dashboard-row hook
    # doesn't apply).
    try:
        from .identity import Identity, _default_identity_path

        identity = Identity.load(_default_identity_path())
    except Exception:  # noqa: BLE001 — no identity.json = ephemeral runtime
        return

    try:
        from .vault_client import VaultClient, resolve_vault_url
    except ImportError:
        return

    publisher_did = manifest.publisher_identity
    recipient_did = cfg.device.device_identity if cfg.device is not None else (
        manifest.recipient_identity or ""
    )
    label = manifest.scope or (publisher_did[:24] if publisher_did else None)
    base_url = identity.linked_vault or resolve_vault_url(None)

    try:
        client = VaultClient.for_identity(identity, base_url)
    except Exception as exc:  # noqa: BLE001 — auth/transport non-fatal
        # Surface the real failure (typed exception + first ~120 chars of
        # any vault response body) so operators don't have to monkey-patch
        # this function to debug 4xx/5xx. Local absorb already succeeded
        # so we stay best-effort.
        exc_type = type(exc).__name__
        detail = _short_exc_detail(exc)
        _log.warning(
            "received-kits POST skipped: vault auth failed "
            "(account_id=%s, publisher=%s, exc=%s%s)",
            account_id,
            publisher_did,
            exc_type,
            f": {detail}" if detail else "",
        )
        return
    try:
        client.post_received_kit(
            project_id=manifest.ceremony_id,
            publisher_identity=publisher_did,
            recipient_identity=recipient_did,
            label=label,
            kit_blob_b64=kit_blob_b64,
            manifest=manifest.to_dict(),
            source_ts=manifest.as_of,
            source_ceremony_id=manifest.ceremony_id,
        )
        _log.info(
            "received-kits POST ok (account_id=%s, project_id=%s, publisher=%s)",
            account_id,
            manifest.ceremony_id,
            publisher_did,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; local absorb wins
        # Same diagnostic shape as the auth failure above. If the vault
        # returned a typed VaultError, status code + body excerpt are
        # included so a 4xx vs 5xx vs network error is distinguishable.
        exc_type = type(exc).__name__
        detail = _short_exc_detail(exc)
        _log.warning(
            "received-kits POST failed (account_id=%s, publisher=%s, "
            "exc=%s%s)",
            account_id,
            publisher_did,
            exc_type,
            f": {detail}" if detail else "",
        )
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def _short_exc_detail(exc: BaseException) -> str:
    """Format an exception for one-line log inclusion.

    For ``VaultError`` (status + body), returns ``HTTP <status>: <body
    excerpt>``. For everything else, the first ~120 chars of ``str(exc)``.
    Returns ``""`` when there's nothing useful to say.
    """
    status = getattr(exc, "status", None)
    body = getattr(exc, "body", None)
    if isinstance(status, int) and body:
        snippet = body if len(body) <= 120 else body[:117] + "..."
        return f"HTTP {status}: {snippet}"
    if isinstance(status, int):
        return f"HTTP {status}"
    msg = str(exc).strip()
    if not msg:
        return ""
    return msg if len(msg) <= 120 else msg[:117] + "..."


def _restore_stream_yamls(
    cfg: LoadedConfig,
    body: dict[str, bytes],
    ts: str,
) -> None:
    """Restore stream yamls packed under ``body/streams/<name>/tn.yaml``
    into ``<project_root>/<name>/tn.yaml`` verbatim.

    Project root resolution mirrors the packer: if cfg.yaml_path lives
    under a ``default/`` subdir, root = cfg.yaml_path.parent.parent;
    otherwise root = cfg.yaml_path.parent.

    Existing stream yamls (e.g. older versions absorbed earlier) are
    renamed to ``tn.yaml.previous.<UTC_TS>`` before overwrite, matching
    the keystore behavior elsewhere in this module.

    Stream names are validated against ``is_valid_ceremony_name`` to
    refuse path-smuggling entries (``..``, ``/``, etc.).
    """
    from ._defaults import DEFAULT_CEREMONY_NAME
    from ._layout import is_valid_ceremony_name

    default_dir = cfg.yaml_path.parent
    if default_dir.name == DEFAULT_CEREMONY_NAME:
        project_root = default_dir.parent
    else:
        project_root = default_dir

    for name, data in body.items():
        if not name.startswith("body/streams/"):
            continue
        rel = name[len("body/streams/") :]
        # Shape we accept: ``<stream-name>/tn.yaml``. Anything else is
        # skipped to refuse smuggling.
        parts = rel.split("/")
        if len(parts) != 2 or parts[1] != "tn.yaml":
            continue
        stream_name = parts[0]
        if not is_valid_ceremony_name(stream_name):
            continue
        stream_dir = project_root / stream_name
        stream_dir.mkdir(parents=True, exist_ok=True)
        # Structural contract from _create_stream_yaml
        (stream_dir / "logs").mkdir(exist_ok=True)
        (stream_dir / "admin").mkdir(exist_ok=True)
        dest = stream_dir / "tn.yaml"
        if dest.exists():
            existing = dest.read_bytes()
            if existing == data:
                continue
            backup = dest.with_name(f"tn.yaml.previous.{ts}")
            try:
                dest.rename(backup)
            except OSError:
                pass
        dest.write_bytes(data)


def _absorb_contact_update(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    """Reduce a ``contact_update`` body into ``contacts.yaml``.

    Body shape (Session 8 plan
    ``docs/superpowers/plans/2026-04-29-contact-update-tnpkg.md`` §
    "Body schema"; spec §4.6):

        body/contact_update.json: {
            account_id, label, package_did, x25519_pub_b64,
            claimed_at, source_link_id
        }

    Idempotency on ``(account_id, package_did)`` per **D-25**. Errors
    surface as ``rejected`` receipts; the caller can read
    ``legacy_reason`` to see what was malformed.
    """
    from .contacts import _apply_contact_update, _validate_contact_update_body

    pkg_bytes = body.get("body/contact_update.json")
    if pkg_bytes is None:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="contact_update body missing `body/contact_update.json`",
        )
    try:
        doc = json.loads(pkg_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=f"contact_update body is not valid JSON: {exc}",
        )
    errors = _validate_contact_update_body(doc)
    if errors:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="contact_update body invalid: " + "; ".join(errors),
        )
    _apply_contact_update(cfg.yaml_path, doc)
    return AbsorbReceipt(
        kind=manifest.kind,
        accepted_count=1,
        legacy_status="enrolment_applied",
    )


def _build_local_admin_clock(
    admin_log: Path,
) -> dict[str, dict[str, int]]:
    """Compute the receiver's per-DID per-event_type vector clock by
    scanning the local admin log.

    Returns a mapping ``{did: {event_type: max_sequence}}``. Used to
    detect whether an incoming snapshot is already fully covered by
    the receiver's local state (the ``_clock_dominates`` check).
    """
    clock: dict[str, dict[str, int]] = {}
    if not admin_log.exists():
        return clock
    with admin_log.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
            except json.JSONDecodeError:
                continue
            did = env.get("device_identity")
            et = env.get("event_type")
            seq = env.get("sequence")
            if isinstance(did, str) and isinstance(et, str) and isinstance(seq, int):
                slot = clock.setdefault(did, {})
                if seq > slot.get(et, 0):
                    slot[et] = seq
    return clock


_REVOKED_EVENT = "tn.recipient.revoked"


@dataclass
class _RevokedLeaf:
    """The revoke event that retired a (group, leaf): its row_hash plus
    the authoring ``(did, sequence)`` so a reuse attempt can be judged
    against an incoming snapshot's vector clock (see
    :func:`_reuse_is_informed`).
    """

    row_hash: str | None
    did: str | None
    sequence: int | None


def _reuse_is_informed(
    revoked_did: str | None,
    revoked_seq: int | None,
    manifest_clock: dict[str, dict[str, int]] | None,
) -> bool:
    """Did the publisher of a snapshot already KNOW about a revoke?

    True iff the snapshot's vector clock covers the revoke event — i.e.
    ``manifest_clock[revoked_did]['tn.recipient.revoked'] >=
    revoked_seq``. That means the publisher had absorbed the revocation
    before shipping the snapshot, so an ``added`` for that leaf in the
    same snapshot is an informed equivocation, not a concurrent race.

    Conservative by construction: a missing did/event_type/seq coordinate
    counts as 0, and an unknown ``revoked_seq`` returns False — we never
    accuse a publisher of equivocation we can't prove.
    """
    if not isinstance(revoked_did, str) or not isinstance(revoked_seq, int):
        return False
    if not isinstance(manifest_clock, dict):
        return False
    seen = manifest_clock.get(revoked_did, {})
    if not isinstance(seen, dict):
        return False
    return int(seen.get(_REVOKED_EVENT, 0)) >= revoked_seq


def _build_revoked_leaves(
    admin_log: Path,
) -> dict[tuple[str, int], _RevokedLeaf]:
    """Scan the local admin log for ``tn.recipient.revoked`` events
    and return a ``{(group, leaf_index): _RevokedLeaf}`` map.

    Used as the equivocation-detection set when absorbing an admin
    log snapshot: any inbound ``tn.recipient.added`` whose
    ``(group, leaf_index)`` collides with a previously-revoked leaf is
    surfaced as a ``LeafReuseAttempt`` conflict, classified informed vs
    concurrent against the snapshot clock.
    """
    revoked: dict[tuple[str, int], _RevokedLeaf] = {}
    if not admin_log.exists():
        return revoked
    with admin_log.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                env = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if env.get("event_type") != _REVOKED_EVENT:
                continue
            g = env.get("group")
            li = env.get("leaf_index")
            if isinstance(g, str) and isinstance(li, int):
                seq = env.get("sequence")
                revoked[(g, li)] = _RevokedLeaf(
                    row_hash=env.get("row_hash"),
                    did=env.get("device_identity"),
                    sequence=seq if isinstance(seq, int) else None,
                )
    return revoked


def _accept_admin_envelope(
    env: dict[str, Any],
    seen_row_hashes: set[str],
    revoked_leaves: dict[tuple[str, int], _RevokedLeaf],
    manifest_clock: dict[str, dict[str, int]] | None = None,
) -> tuple[str, LeafReuseAttempt | None]:
    """Decide what to do with one inbound admin envelope.

    Returns ``(decision, conflict_or_none)`` where ``decision`` is one
    of ``"drop"`` (malformed / bad sig / no row_hash), ``"dedupe"``
    (already seen), or ``"accept"`` (append + update tracking).

    Mutates ``revoked_leaves`` in place when this envelope is itself
    a revocation so a same-batch add-after-revoke is flagged. A reuse of
    a revoked leaf is classified informed vs concurrent against
    ``manifest_clock`` (the snapshot publisher's causal view).
    """
    if not _envelope_well_formed(env):
        return "drop", None
    if not _verify_envelope_signature(env):
        # Tampered/unsigned: drop. Append-only invariant only applies
        # to envelopes whose signature already passed.
        return "drop", None

    rh = env.get("row_hash")
    if not isinstance(rh, str):
        return "drop", None

    if rh in seen_row_hashes:
        return "dedupe", None

    conflict: LeafReuseAttempt | None = None
    et = env.get("event_type")
    g = env.get("group")
    li = env.get("leaf_index")

    if isinstance(g, str) and isinstance(li, int):
        key = (g, li)
        if et == "tn.recipient.added" and key in revoked_leaves:
            rev = revoked_leaves[key]
            conflict = LeafReuseAttempt(
                group=g,
                leaf_index=li,
                attempted_row_hash=rh,
                revoked_row_hash=rev.row_hash,
                informed=_reuse_is_informed(rev.did, rev.sequence, manifest_clock),
            )
        elif et == _REVOKED_EVENT:
            # Track newly-arrived revocations so a later add in the
            # same batch is correctly flagged.
            seq = env.get("sequence")
            revoked_leaves[key] = _RevokedLeaf(
                row_hash=rh,
                did=env.get("device_identity"),
                sequence=seq if isinstance(seq, int) else None,
            )

    return "accept", conflict


def _absorb_admin_log_snapshot(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    """Apply an admin-log snapshot: validate each envelope, dedupe by
    row_hash, append new ones to the local admin log, and surface
    leaf-reuse attempts as ``conflicts``.
    """
    admin_log = resolve_admin_log_path(cfg)
    seen_row_hashes = existing_row_hashes(admin_log)
    local_clock = _build_local_admin_clock(admin_log)

    if _clock_dominates(local_clock, manifest.clock):
        # Receiver already has everything the manifest claims.
        return AbsorbReceipt(
            kind=manifest.kind,
            noop=True,
            derived_state=manifest.state,
        )

    raw = body.get("body/admin.ndjson")
    if raw is None:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason="admin_log_snapshot body missing `body/admin.ndjson`",
        )

    revoked_leaves = _build_revoked_leaves(admin_log)
    accepted_envs: list[dict[str, Any]] = []
    conflicts: list[LeafReuseAttempt] = []
    deduped = 0

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            env = json.loads(line)
        except json.JSONDecodeError:
            continue

        decision, conflict = _accept_admin_envelope(
            env, seen_row_hashes, revoked_leaves, manifest.clock,
        )
        if decision == "drop":
            continue
        if decision == "dedupe":
            deduped += 1
            continue
        # decision == "accept"
        if conflict is not None:
            conflicts.append(conflict)
        accepted_envs.append(env)
        seen_row_hashes.add(env["row_hash"])

    if accepted_envs:
        append_admin_envelopes(admin_log, accepted_envs)

    return AbsorbReceipt(
        kind=manifest.kind,
        accepted_count=len(accepted_envs),
        deduped_count=deduped,
        noop=False,
        derived_state=manifest.state,
        conflicts=conflicts,
    )


def _envelope_well_formed(env: dict[str, Any]) -> bool:
    """Coarse shape check before we reach for crypto primitives.

    0.4.3a1: the signer-identity key is ``device_identity``. Pre-rename
    snapshots that still carry ``"did"`` will fail well-formedness here
    and be silently dropped — operators must regenerate snapshots after
    the rename. The Mongo-style migration script in
    ``tn_proto_web/scripts/migrate_0_4_3a1_identity_naming.py`` handles
    the analogous flip on the broker side.
    """
    return all(
        isinstance(env.get(k), str)
        for k in (
            "device_identity",
            "timestamp",
            "event_id",
            "event_type",
            "row_hash",
            "signature",
        )
    )


def _verify_envelope_signature(env: dict[str, Any]) -> bool:
    try:
        return DeviceKey.verify(
            env["device_identity"],
            env["row_hash"].encode("ascii"),
            _signature_from_b64(env["signature"]),
        )
    except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
        return False


# ---------------------------------------------------------------------------
# Legacy offer / enrolment handlers (ported from the pre-manifest absorb.py)
# ---------------------------------------------------------------------------


def _stash_offer(cfg: LoadedConfig, pkg: Package) -> AbsorbReceipt:
    """Stash the offer in pending_offers/<signer_did>.json. Idempotent."""
    pending = pending_offers_dir(cfg.yaml_path.parent)
    pending.mkdir(parents=True, exist_ok=True)
    safe = _DID_SAFE.sub("_", pkg.device_identity)
    doc = {
        "device_identity": pkg.device_identity,
        "signer_verify_pub_b64": pkg.signer_verify_pub_b64,
        "group": pkg.group,
        "x25519_pub_b64": pkg.payload.get("x25519_pub_b64"),
        "compiled_at": pkg.compiled_at,
    }
    (pending / f"{safe}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return AbsorbReceipt(
        kind="offer",
        accepted_count=1,
        legacy_status="offer_stashed",
        legacy_reason=pkg.device_identity,
    )


def _apply_enrolment(cfg: LoadedConfig, pkg: Package) -> AbsorbReceipt:
    """Merge an enrolment package into local state. Same logic as the
    pre-manifest `_absorb_enrolment`, retained here for the new
    dispatcher. Replays the same _canonical_bytes-driven attestation so
    audit trails match historical behavior."""
    import yaml as _yaml
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    yaml_path = cfg.yaml_path
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}

    local_cid = (doc.get("ceremony") or {}).get("id")
    already_enrolled = any(
        isinstance(gspec, dict) and gspec.get("publisher_identity")
        for gspec in (doc.get("groups") or {}).values()
    )
    if local_cid and local_cid != pkg.ceremony_id and already_enrolled:
        return AbsorbReceipt(
            kind="enrolment",
            legacy_status="rejected",
            legacy_reason=(
                f"ceremony_id mismatch: local yaml says {local_cid!r} but "
                f"enrolment package is for {pkg.ceremony_id!r}."
            ),
        )
    if not local_cid or local_cid != pkg.ceremony_id:
        doc.setdefault("ceremony", {})["id"] = pkg.ceremony_id

    g = doc.setdefault("groups", {}).setdefault(pkg.group, {})
    g.setdefault("cipher", "jwe")
    if int(g.get("group_epoch", 0)) > pkg.group_epoch:
        return AbsorbReceipt(
            kind="enrolment",
            legacy_status="no_op",
            legacy_reason=(
                f"older epoch: local group {pkg.group!r} is at epoch "
                f"{g.get('group_epoch')!r}, package is {pkg.group_epoch!r}."
            ),
        )
    g["group_epoch"] = pkg.group_epoch
    g["publisher_identity"] = pkg.payload["publisher_identity"]
    g["sender_pub_b64"] = pkg.payload["sender_pub_b64"]

    mykey_path = cfg.keystore / f"{pkg.group}.jwe.mykey"
    if not mykey_path.exists():
        return AbsorbReceipt(
            kind="enrolment",
            legacy_status="rejected",
            legacy_reason=(
                f"no {pkg.group}.jwe.mykey in keystore {cfg.keystore} — run "
                f"tn.offer(cfg, publisher_did={pkg.payload.get('publisher_did')!r}) "
                f"first so a recipient X25519 keypair gets minted before absorbing."
            ),
        )
    sk = X25519PrivateKey.from_private_bytes(mykey_path.read_bytes())
    my_pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    recipients = g.setdefault("recipients", [])
    if not any(
        r.get("recipient_identity") == cfg.device.device_identity
        for r in recipients
        if isinstance(r, dict)
    ):
        recipients.append(
            {
                "recipient_identity": cfg.device.device_identity,
                "pub_b64": base64.b64encode(my_pub).decode("ascii"),
            }
        )

    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    sender_pub_bytes = base64.b64decode(pkg.payload["sender_pub_b64"])
    (cfg.keystore / f"{pkg.group}.jwe.sender_pub").write_bytes(sender_pub_bytes)

    # Attested event: recipient absorbed an enrolment package. Uses the
    # legacy ``packaging._canonical_bytes`` (not the manifest's canonical
    # bytes) so the package_sha256 still matches what compile_enrolment
    # emitted on the other side.
    from . import logger as _lg
    from .packaging import _canonical_bytes as _pkg_canonical

    if _lg._runtime is not None:
        try:
            pkg_sha = "sha256:" + _hashlib.sha256(_pkg_canonical(pkg)).hexdigest()
            _lg._require_init().emit(
                "info",
                "tn.enrolment.absorbed",
                {
                    "group": pkg.group,
                    "publisher_identity": pkg.device_identity,
                    "package_sha256": pkg_sha,
                    "absorbed_at": datetime.now(_tz.utc).isoformat(),
                },
            )
        except Exception as _emit_err:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _logging.getLogger("tn.absorb").warning(
                "enrolment.absorbed attestation failed for group=%s from=%s: %s",
                pkg.group,
                pkg.device_identity,
                _emit_err,
            )

    return AbsorbReceipt(
        kind="enrolment",
        accepted_count=1,
        legacy_status="enrolment_applied",
        legacy_reason=pkg.device_identity,
    )


def _user_event_count(cfg: LoadedConfig) -> int:
    """Count user-emitted entries in the local main log.

    A user entry is anything whose ``event_type`` does NOT start with
    ``tn.``. The ``tn.*`` namespace is reserved for admin / protocol
    bookkeeping (group.added, ceremony.init, ...) and gets emitted by
    ``tn.init()`` itself — those don't represent meaningful user
    activity.

    Used by absorb's Bug-3 UX fix: when the user calls
    ``tn.init()`` and *then* ``tn.pkg.absorb(<identity_seed>)``, we
    detect "the local log only has init-time admin events" and treat
    that as a fresh ceremony — proceeding with the overwrite rather
    than refusing because ``local.private`` exists.

    Reads cfg.resolve_log_path() — the main log file. Admin (``tn.*``)
    events live in a separate ``./.tn/admin/admin.ndjson`` by default,
    so the main log already excludes them; the explicit
    ``startswith("tn.")`` filter is belt-and-braces for the legacy
    ``protocol_events_location: main_log`` ceremony shape.
    """
    # Walk the main log plus any rotated backups (.1, .2, ...). Some
    # ceremonies enable session-start rotation, in which case the
    # previous session's content moves to ``<logPath>.1``; just looking
    # at ``<logPath>`` after a re-init would undercount.
    log_path = cfg.resolve_log_path()
    candidates: list[Path] = [log_path]
    for n in range(1, 11):
        backup = log_path.with_name(f"{log_path.name}.{n}")
        if not backup.exists():
            break
        candidates.append(backup)

    count = 0
    for path in candidates:
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        env = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    et = env.get("event_type")
                    if isinstance(et, str) and not et.startswith("tn."):
                        count += 1
        except OSError:
            continue
    return count


def _absorb_project_seed(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    """Install a project-seed bundle (dashboard "Create Project" flow).

    The dashboard mints these with body shape::

        body/tn.yaml
        body/keys/local.private
        body/keys/local.public
        body/keys/index_master.key
        body/keys/<group>.btn.mykit
        body/keys/<group>.btn.state
        body/keys/tn.agents.btn.mykit
        body/keys/tn.agents.btn.state

    Files are nested under ``body/keys/`` (not flat under ``body/`` like
    ``kit_bundle``). This handler:

    1. Validates ``body/tn.yaml`` and at least
       ``body/keys/local.private`` + ``body/keys/local.public`` are
       present.
    2. Cross-checks: the manifest must be self-addressed
       (``from_did == to_did``), the body's local.public must equal the
       manifest's from_did, and the DID derived from
       ``body/keys/local.private`` must match — same tamper guard as
       ``identity_seed``.
    3. Installs ``body/tn.yaml`` to ``cfg.yaml_path`` (idempotent if
       byte-identical; refuses on a different existing yaml unless the
       local log has zero user events — see Bug 3 in the brief).
    4. Installs every ``body/keys/<rel>`` flat-path entry into
       ``cfg.keystore / <rel>``. Existing files are renamed to
       ``.previous.<UTC_TS>`` (same semantics as
       ``_absorb_kit_bundle``). Deeper nesting (``body/keys/foo/bar``)
       is skipped.
    5. Returns an ``AbsorbReceipt(kind="project_seed", ...)`` with the
       count of installed vs deduped files.
    """
    yaml_bytes = body.get("body/tn.yaml")
    priv_bytes = body.get("body/keys/local.private")
    pub_text = body.get("body/keys/local.public")
    if yaml_bytes is None or priv_bytes is None or pub_text is None:
        missing = [
            name
            for name, present in (
                ("body/tn.yaml", yaml_bytes),
                ("body/keys/local.private", priv_bytes),
                ("body/keys/local.public", pub_text),
            )
            if present is None
        ]
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"project_seed body is missing required members: {missing}"
            ),
        )

    if len(priv_bytes) != 32:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"project_seed body/keys/local.private must be 32 bytes "
                f"(Ed25519 seed); got {len(priv_bytes)}"
            ),
        )

    # Cross-check: tamper guard. Same logic as _absorb_identity_seed —
    # the manifest's signature already verified, but a tampered body
    # could still swap in a different private key. Catch it here.
    from .signing import DeviceKey as _DeviceKey

    derived = _DeviceKey.from_private_bytes(priv_bytes)
    bundle_did = pub_text.decode("utf-8").strip()
    if derived.did != bundle_did or derived.did != manifest.publisher_identity:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"project_seed integrity check failed: manifest.from_did="
                f"{manifest.publisher_identity!r}, body/keys/local.public={bundle_did!r}, "
                f"derived-from-private={derived.did!r}. The bundle's body and "
                f"manifest disagree about which identity this is — refuse to "
                f"install."
            ),
        )
    if manifest.publisher_identity != manifest.recipient_identity:
        return AbsorbReceipt(
            kind=manifest.kind,
            legacy_status="rejected",
            legacy_reason=(
                f"project_seed must be self-addressed (from_did == to_did); "
                f"got from_did={manifest.publisher_identity!r}, to_did={manifest.recipient_identity!r}."
            ),
        )

    accepted = 0
    deduped = 0
    replaced: list[Path] = []
    ts = datetime.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")

    # Step A: tn.yaml. Idempotent if byte-identical. Different yaml +
    # zero user events → fresh ceremony, overwrite. Different yaml +
    # user events → refuse (would orphan signed log entries).
    yaml_target = cfg.yaml_path
    yaml_action = "deduped"
    if yaml_target.exists():
        existing_yaml = yaml_target.read_bytes()
        if existing_yaml == yaml_bytes:
            deduped += 1
        elif _user_event_count(cfg) == 0:
            backup = yaml_target.with_name(f"{yaml_target.name}.previous.{ts}")
            try:
                yaml_target.rename(backup)
            except OSError:
                pass
            replaced.append(yaml_target)
            yaml_target.parent.mkdir(parents=True, exist_ok=True)
            yaml_target.write_bytes(yaml_bytes)
            accepted += 1
            yaml_action = "replaced"
        else:
            return AbsorbReceipt(
                kind=manifest.kind,
                legacy_status="rejected",
                legacy_reason=(
                    f"refusing to overwrite existing tn.yaml at {yaml_target}: "
                    f"contents differ from the project_seed bundle and the local "
                    f"log already contains user-emitted entries. Delete the "
                    f"directory or absorb in a fresh location."
                ),
            )
    else:
        yaml_target.parent.mkdir(parents=True, exist_ok=True)
        yaml_target.write_bytes(yaml_bytes)
        accepted += 1
        yaml_action = "written"

    _ = yaml_action  # currently unused; keeps the branch labels readable

    # Step B: keys. body/keys/<rel> -> cfg.keystore / <rel>. Flat
    # under keys/ only — deeper nesting is skipped (the spec doesn't
    # ship anything nested, but we don't want to silently install a
    # smuggled-in path).
    keystore = cfg.keystore
    keystore.mkdir(parents=True, exist_ok=True)

    # Special case: local.private. Same tamper guard as identity_seed —
    # if the keystore already has a different local.private, refuse
    # unless _user_event_count is 0 (fresh-ceremony, see Bug 3).
    existing_priv = keystore / "local.private"
    if existing_priv.exists():
        existing_priv_bytes = existing_priv.read_bytes()
        if existing_priv_bytes != priv_bytes and _user_event_count(cfg) > 0:
            return AbsorbReceipt(
                kind=manifest.kind,
                legacy_status="rejected",
                legacy_reason=(
                    f"refusing to overwrite existing identity at "
                    f"{existing_priv}: a different device key is already "
                    f"installed and the local log contains user events "
                    f"signed by it. To replace, delete {keystore} first."
                ),
            )

    for name, data in body.items():
        if not name.startswith("body/keys/"):
            continue
        rel = name[len("body/keys/"):]
        if not rel:
            continue
        # Reject deeper nesting — body/keys/foo/bar would smuggle a
        # path. The dashboard only emits flat names under keys/.
        if "/" in rel or "\\" in rel:
            continue
        dest = keystore / rel
        if dest.exists() and dest.read_bytes() == data:
            deduped += 1
            continue
        if dest.exists():
            backup = dest.with_name(f"{rel}.previous.{ts}")
            try:
                dest.rename(backup)
            except OSError:
                pass
            replaced.append(dest)
        dest.write_bytes(data)
        accepted += 1

    # Restore stream yamls packed under body/streams/<name>/tn.yaml.
    # See _restore_stream_yamls for invariants. Project root resolves
    # off cfg.yaml_path. See #33.
    _restore_stream_yamls(cfg, body, ts)

    return AbsorbReceipt(
        kind=manifest.kind,
        accepted_count=accepted,
        deduped_count=deduped,
        legacy_status="enrolment_applied" if accepted else "no_op",
        legacy_reason=f"installed project seed for {bundle_did} into {keystore.parent}",
        replaced_kit_paths=replaced,
    )


__all__ = [
    "AbsorbReceipt",
    "AbsorbResult",
    "LeafReuseAttempt",
    "absorb",
]


