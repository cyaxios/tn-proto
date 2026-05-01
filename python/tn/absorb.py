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
from typing import Any

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
    """

    group: str
    leaf_index: int
    attempted_row_hash: str
    revoked_row_hash: str | None = None


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


def absorb(
    *args: Any,
    **kwargs: Any,
):
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
            raise RuntimeError(
                "absorb: no LoadedConfig available — call tn.init(yaml_path) "
                "first, or pass cfg explicitly via the legacy two-arg form."
            ) from exc

    receipt = _absorb_dispatch(cfg, source)

    if legacy:
        # Translate to the older shape so existing tests keep working.
        if receipt.legacy_status:
            return AbsorbResult(
                status=receipt.legacy_status,
                reason=receipt.legacy_reason,
                peer_did=_extract_peer_did(receipt),
            )
        # Default mapping for snapshot kinds the old callers never saw.
        if receipt.kind == "admin_log_snapshot":
            status = "no_op" if receipt.noop else "enrolment_applied"
            return AbsorbResult(status=status, reason=receipt.legacy_reason)
        return AbsorbResult(status="rejected", reason=receipt.legacy_reason or "unknown kind")
    return receipt


def _extract_peer_did(receipt: AbsorbReceipt) -> str | None:
    """For legacy AbsorbResult.peer_did: pull from the manifest's from_did."""
    return None  # set by individual handlers when they have one


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
                f"{manifest.from_did!r}. The package is corrupt, truncated, or "
                f"tampered with. Ask the sender to re-export and re-send."
            ),
        )

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
                f"claims signer {pkg.signer_did!r} but its Ed25519 sig does "
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
    return AbsorbReceipt(
        kind=manifest.kind,
        accepted_count=accepted,
        deduped_count=skipped,
        legacy_status="enrolment_applied" if accepted else "no_op",
        replaced_kit_paths=replaced,
    )


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


def _absorb_admin_log_snapshot(
    cfg: LoadedConfig, manifest: TnpkgManifest, body: dict[str, bytes]
) -> AbsorbReceipt:
    """Apply an admin-log snapshot: validate each envelope, dedupe by
    row_hash, append new ones to the local admin log, and surface
    leaf-reuse attempts as ``conflicts``.
    """
    admin_log = resolve_admin_log_path(cfg)

    # Build receiver's local clock from existing admin log.
    local_clock: dict[str, dict[str, int]] = {}
    seen_row_hashes = existing_row_hashes(admin_log)
    if admin_log.exists():
        with admin_log.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    env = json.loads(line)
                except json.JSONDecodeError:
                    continue
                did = env.get("did")
                et = env.get("event_type")
                seq = env.get("sequence")
                if isinstance(did, str) and isinstance(et, str) and isinstance(seq, int):
                    slot = local_clock.setdefault(did, {})
                    cur = slot.get(et, 0)
                    if seq > cur:
                        slot[et] = seq

    if _clock_dominates(local_clock, manifest.clock):
        # Receiver already has everything the manifest claims. Skip
        # work; receipt reflects a true noop.
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

    # Build the local revoked-leaf set for equivocation detection.
    revoked_leaves: dict[tuple[str, int], str | None] = {}
    if admin_log.exists():
        with admin_log.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    env = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if env.get("event_type") == "tn.recipient.revoked":
                    g = env.get("group")
                    li = env.get("leaf_index")
                    if isinstance(g, str) and isinstance(li, int):
                        revoked_leaves[(g, li)] = env.get("row_hash")

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

        if not _envelope_well_formed(env):
            continue

        if not _verify_envelope_signature(env):
            # Drop tampered / unsigned envelopes. The append-only invariant
            # is for envelopes whose signature already passed; an envelope
            # whose sig fails is data, not log.
            continue

        rh = env.get("row_hash")
        if not isinstance(rh, str):
            continue

        if rh in seen_row_hashes:
            deduped += 1
            continue

        # Equivocation: leaf-reuse attempts on a previously-revoked
        # (group, leaf_index). We still append (signed envelopes are
        # facts) but flag the conflict so callers can reason about it.
        if env.get("event_type") == "tn.recipient.added":
            g = env.get("group")
            li = env.get("leaf_index")
            if isinstance(g, str) and isinstance(li, int):
                key = (g, li)
                if key in revoked_leaves:
                    conflicts.append(
                        LeafReuseAttempt(
                            group=g,
                            leaf_index=li,
                            attempted_row_hash=rh,
                            revoked_row_hash=revoked_leaves[key],
                        )
                    )

        # Track newly-arrived revocations so a later add+revoke+add in
        # the same batch is correctly flagged.
        if env.get("event_type") == "tn.recipient.revoked":
            g = env.get("group")
            li = env.get("leaf_index")
            if isinstance(g, str) and isinstance(li, int):
                revoked_leaves[(g, li)] = rh

        accepted_envs.append(env)
        seen_row_hashes.add(rh)

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
    """Coarse shape check before we reach for crypto primitives."""
    return all(
        isinstance(env.get(k), str)
        for k in ("did", "timestamp", "event_id", "event_type", "row_hash", "signature")
    )


def _verify_envelope_signature(env: dict[str, Any]) -> bool:
    try:
        return DeviceKey.verify(
            env["did"],
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
    safe = _DID_SAFE.sub("_", pkg.signer_did)
    doc = {
        "signer_did": pkg.signer_did,
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
        legacy_reason=pkg.signer_did,
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
        isinstance(gspec, dict) and gspec.get("publisher_did")
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
    g["publisher_did"] = pkg.payload["publisher_did"]
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
    if not any(r.get("did") == cfg.device.did for r in recipients if isinstance(r, dict)):
        recipients.append(
            {
                "did": cfg.device.did,
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
                    "from_did": pkg.signer_did,
                    "package_sha256": pkg_sha,
                    "absorbed_at": datetime.now(_tz.utc).isoformat(),
                },
            )
        except Exception as _emit_err:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _logging.getLogger("tn.absorb").warning(
                "enrolment.absorbed attestation failed for group=%s from=%s: %s",
                pkg.group,
                pkg.signer_did,
                _emit_err,
            )

    return AbsorbReceipt(
        kind="enrolment",
        accepted_count=1,
        legacy_status="enrolment_applied",
        legacy_reason=pkg.signer_did,
    )


__all__ = [
    "AbsorbReceipt",
    "AbsorbResult",
    "LeafReuseAttempt",
    "absorb",
]


# Keep the old internal helper names available for any in-tree caller that
# imports them directly. Both still drive the legacy AbsorbResult shape.
def _absorb_offer(cfg: LoadedConfig, pkg: Package) -> AbsorbResult:
    receipt = _stash_offer(cfg, pkg)
    return AbsorbResult(
        status=receipt.legacy_status,
        reason=receipt.legacy_reason,
        peer_did=pkg.signer_did,
    )


def _absorb_enrolment(cfg: LoadedConfig, pkg: Package) -> AbsorbResult:
    receipt = _apply_enrolment(cfg, pkg)
    return AbsorbResult(
        status=receipt.legacy_status,
        reason=receipt.legacy_reason,
        peer_did=pkg.signer_did,
    )
