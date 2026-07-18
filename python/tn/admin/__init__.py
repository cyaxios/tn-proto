"""Ceremony admin: group + recipient + rotation management.

These are the code-level equivalents of the admin CLI commands. Exposing
them as functions means library users can drive ceremony changes from
their own scripts / admin tools without shelling out.

Ciphers: `jwe` (static-ECDH + AES-KW + AES-GCM, pure Python), `btn`
(NNL subset-difference broadcast, via the Rust `tn_core` extension), and
`hibe` (identity-path delegation, via `tn-hibe`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from ..canonical import _canonical_bytes
from ..config import (
    DEFAULT_POOL_SIZE,
    LoadedConfig,
    _create_group,
)
from ..key_binding import (
    EnrollmentChallengeV1,
    KeyBindingProofV1,
    verify_enrollment_challenge,
    verify_key_binding_proof,
)
from ..trust import (
    AcceptedOffer,
    TrustError,
    TrustReason,
    VerifiedPrincipal,
    parse_ed25519_did_key,
    verify_ed25519_did_signature,
)

_log = logging.getLogger("tn.admin")


# --------------------------------------------------------------------
# trusted enrollment approval / reconciliation
# --------------------------------------------------------------------


def reconcile_enrollment(
    offer_digest: str,
    *,
    approve: bool = False,
    cfg: LoadedConfig | None = None,
    now: datetime | None = None,
) -> AcceptedOffer:
    """Reverify and promote one retained JWE enrollment offer.

    ``approve=False`` accepts only a challenged offer whose exact reader,
    ceremony, and group were preauthorized. ``approve=True`` records approval
    for this exact signed offer/artifact digest and performs approval,
    challenge consumption, re-verification, and promotion under one lock.
    """
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    if now is None:
        from datetime import timezone

        now = datetime.now(timezone.utc)
    from ..enrollment import EnrollmentStore

    store = EnrollmentStore(cfg, cfg.device)
    if approve:
        return store.approve_and_reconcile(offer_digest, now=now)
    pending = store.pending_offer(offer_digest, now=now)
    return store.reconcile(pending, now=now)


def _add_field_route(cfg: LoadedConfig, field_name: str, group: str) -> None:
    """Append `group` to `cfg.field_to_groups[field_name]`, sorted + deduped.

    The list stays alphabetically sorted so canonical envelope encoding is
    stable regardless of insertion order.
    """
    current = cfg.field_to_groups.get(field_name) or []
    if group in current:
        return
    cfg.field_to_groups[field_name] = sorted(set(current) | {group})


def _rename_revoked(src: Path, ts: int) -> None:
    """Rename src to src.revoked.<ts>, appending a counter on collision (Windows)."""
    target = src.with_suffix(src.suffix + f".revoked.{ts}")
    n = 0
    while target.exists():
        n += 1
        target = src.with_suffix(src.suffix + f".revoked.{ts}_{n}")
    src.rename(target)


# --------------------------------------------------------------------
# ensure-group: add a group post-init
# --------------------------------------------------------------------


def ensure_group(
    cfg: LoadedConfig,
    group: str,
    *,
    pool_size: int = DEFAULT_POOL_SIZE,
    fields: list[str] | None = None,
    cipher: str | None = None,
) -> LoadedConfig:
    """Idempotently add a group to the ceremony.

    `cipher` is "jwe" or "btn". If omitted, falls back to the ceremony's
    default cipher. If `group` already exists (keys present + in YAML),
    return unchanged. Otherwise generate a fresh cipher instance + pool,
    write key files, and add `groups:` + `fields:` entries to tn.yaml.

    Hot-reload behaviour: when the in-process logger runtime is bound,
    ``ensure_group`` reloads its view of the yaml after the write so
    subsequent ``tn.info(...)`` calls in the same process see the new
    group's routing. Prior to 0.4.2a2 callers had to
    ``tn.flush_and_close()`` + ``tn.init()`` to pick up the change.
    """
    internal_cipher = cipher if cipher is not None else cfg.cipher_name
    if internal_cipher not in ("jwe", "btn", "hibe"):
        raise ValueError(
            f"ensure_group: unknown cipher {cipher!r}; expected 'jwe', 'btn', or 'hibe'"
        )

    # Presence check differs per cipher.
    if internal_cipher == "btn":
        key_exists = (cfg.keystore / f"{group}.btn.state").exists()
    elif internal_cipher == "hibe":
        key_exists = (cfg.keystore / f"{group}.hibe.mpk").exists()
    else:
        key_exists = (cfg.keystore / f"{group}.jwe.sender").exists()

    if group in cfg.groups and key_exists:
        if fields:
            _update_authoritative_yaml(
                cfg, lambda doc: _yaml_add_fields(doc, group, fields), key="groups"
            )
            # Keep the in-memory routing consistent with what we just wrote
            # to disk. Without this, a second ensure_group(..., fields=[...])
            # on an existing group updates tn.yaml but leaves
            # cfg.field_to_groups stale until the next flush_and_close + init.
            for f in fields:
                _add_field_route(cfg, f, group)
        return cfg

    new_group = _create_group(
        cfg.keystore,
        group,
        master_index_key=cfg.master_index_key,
        ceremony_id=cfg.ceremony_id,
        cipher_name=internal_cipher,
        pool_size=pool_size,
        recipient_dids=[cfg.device.device_identity],
    )
    cfg.groups[group] = new_group

    _update_authoritative_yaml(
        cfg,
        lambda doc: _yaml_add_group(
            doc,
            group,
            pool_size,
            cfg.device.device_identity,
            fields,
            cipher_name=internal_cipher,
        ),
        key="groups",
    )
    if fields:
        for f in fields:
            _add_field_route(cfg, f, group)

    # Attested event: publisher added a new group to the ceremony.
    # The emit runs after yaml is written so a yaml-write failure does not
    # produce a false attestation. Failure of the emit itself is non-fatal:
    # the group already exists on disk.
    from .. import logger as _lg

    if _lg._runtime is not None:
        try:
            from datetime import datetime
            from datetime import timezone as _tz

            group_cipher = cfg.groups[group].cipher.name  # "jwe" or "btn"
            _lg._require_init().emit(
                "info",
                "tn.group.added",
                {
                    "group": group,
                    "cipher": group_cipher,
                    "publisher_identity": cfg.device.device_identity,
                    "added_at": datetime.now(_tz.utc).isoformat(),
                },
            )
        except Exception as emit_err:  # noqa: BLE001 — preserve broad swallow; see body of handler
            import logging as _logging

            _logging.getLogger("tn.admin").warning(
                "group.added attestation failed for group=%s: %s",
                group,
                emit_err,
            )

    _maybe_autosync(cfg)

    # Rebind the live runtime's view of the yaml so the next write
    # routes through the new group without forcing a full
    # flush_and_close + tn.init round-trip. Best-effort; a failure
    # here doesn't undo the yaml + keystore writes above, and the
    # next process will load the new state fine.
    try:
        from .. import logger as _lg_reload

        _lg_reload.reload_from_yaml()
    except Exception:  # noqa: BLE001
        import logging as _logging

        _logging.getLogger("tn.admin").warning(
            "ensure_group: live-runtime reload failed; group=%s is on "
            "disk but in-process routing may be stale. Run "
            "`tn.flush_and_close(); tn.init()` to refresh.",
            group,
            exc_info=True,
        )

    return cfg


def _yaml_add_group(
    doc: dict[str, Any],
    group: str,
    pool_size: int,
    me_did: str,
    fields: list[str] | None,
    *,
    cipher_name: str,
) -> None:
    groups = doc.setdefault("groups", {})
    if group not in groups:
        # JWE stores the publisher's pub in <group>.jwe.recipients;
        # btn stores self-kit in <group>.btn.mykit. Either way the yaml
        # recipient entry only needs the DID.
        groups[group] = {
            "policy": "private",
            "pool_size": pool_size,
            "cipher": cipher_name,
            "recipients": [{"recipient_identity": me_did}],
        }
    if fields:
        _yaml_add_fields(doc, group, fields)


def _yaml_add_fields(doc: dict[str, Any], group: str, fields: list[str]) -> None:
    """Record fields under ``groups[<group>].fields`` (canonical, multi-group).

    For back-compat with older readers we also keep the flat ``fields:``
    block updated — single-route tools that haven't migrated yet still
    read it, with a deprecation warning at load time. New multi-group
    routing reads ``groups[<g>].fields`` first; the flat block is only
    consulted when no group declares its fields.
    """
    groups_block = doc.setdefault("groups", {})
    gspec = groups_block.setdefault(group, {})
    existing = gspec.get("fields") or []
    if not isinstance(existing, list):
        existing = []
    seen = set(existing)
    for f in fields:
        if f not in seen:
            existing.append(f)
            seen.add(f)
    gspec["fields"] = existing

    # Legacy flat block — keep up to date for single-route consumers.
    field_map = doc.setdefault("fields", {}) or {}
    for f in fields:
        field_map[f] = {"group": group}
    doc["fields"] = field_map


# --------------------------------------------------------------------
# rotate
# --------------------------------------------------------------------


def _rotate_impl(
    group: str,
    *,
    revoke_did: str | None = None,
    pool_size: int | None = None,
    cfg: LoadedConfig | None = None,
    btn_cipher_result: Any | None = None,
    renewed_recipients: list[str] | None = None,
    renewal_output_dir: Path | None = None,
) -> LoadedConfig:
    """Rotate a group's cipher: regenerate keys + bump index_epoch.

    Behavior differs per cipher:
      jwe: regenerates the sender X25519 key + recipient list. Old
           sender/mykey/recipients files are renamed `.revoked.<ts>`;
           the new list contains only the publisher self-recipient, so
           every external reader requires explicit re-enrollment.
      btn: the public `rotate()` verb (above) has already driven the
           btn cipher's forward-secret rotation via
           `BtnGroupCipher.rotate()` — new master_seed, new
           publisher_id, atomic promote on disk. This impl just bumps
           the yaml's `index_epoch` and emits the truth-telling
           `tn.rotation.completed` event. `btn_cipher_result` carries
           the prior/new publisher_id + epoch from the cipher layer.

    Index epoch always bumps, so the old index key is invalidated for
    search on future entries under both ciphers.

    If `revoke_did` is set, that recipient is dropped from tn.yaml's
    recipients list (new keys are not delivered to them).

    A `tn.rotation.completed` attestation is appended to the chain. Caller
    must re-init after rotation since the active cipher context changes.
    """
    import hashlib as _hashlib
    from datetime import datetime
    from datetime import timezone as _tz

    from .. import current_config
    from .. import logger as _lg

    cfg = cfg if cfg is not None else current_config()
    old = cfg.groups[group]
    pool = int(pool_size or old.pool_size)
    ts = int(time.time())

    # Capture the best-effort SHA-256 of the pre-rotation key material BEFORE
    # renaming. For btn the kit is now archived under
    # `<g>.btn.mykit.retired.<prior_epoch>` (already written by the
    # BtnGroupCipher.rotate() pipeline); read its sha256 from there.
    _prev_candidates: list[Path] = []
    if cfg.cipher_name == "btn":
        if btn_cipher_result is not None:
            _prev_candidates = [
                cfg.keystore / f"{group}.btn.mykit.retired.{btn_cipher_result.prior_epoch}",
                cfg.keystore / f"{group}.btn.mykit",
            ]
        else:
            _prev_candidates = [cfg.keystore / f"{group}.btn.mykit"]
    else:  # jwe
        _prev_candidates = [cfg.keystore / f"{group}.jwe.mykey"]

    prev_kit_sha = "sha256:unknown"
    for _candidate in _prev_candidates:
        if _candidate.exists():
            try:
                prev_kit_sha = "sha256:" + _hashlib.sha256(_candidate.read_bytes()).hexdigest()
            except OSError:
                # File raced with rename or read permission denied; keep
                # "unknown" so rotation proceeds, but surface why the prior
                # kit hash could not be captured.
                _log.warning(
                    "could not read prior kit %s to capture its hash "
                    "(raced rename or permission denied); recording "
                    "prev_kit_sha as 'unknown' for group=%s",
                    _candidate,
                    group,
                )
            break

    if cfg.cipher_name == "btn":
        # 0.4.3a1: btn rotation's disk side already happened in
        # BtnGroupCipher.rotate() before we got here. No file
        # renames needed; the cipher promoted pending → active and
        # archived prior → retired.<epoch> in one atomic dance.
        # We just need the yaml-side index_epoch bump (below) and
        # the admin event emit.
        pass
    else:  # jwe
        for suffix in ("jwe.sender", "jwe.recipients", "jwe.mykey"):
            src = cfg.keystore / f"{group}.{suffix}"
            if src.exists():
                _rename_revoked(src, ts)

    # Bump yaml-side index_epoch (HMAC search-key generation). For btn
    # this lives ALONGSIDE the cipher's own epoch which already bumped
    # in BtnGroupCipher.rotate(); they happen to advance in lockstep
    # but are conceptually distinct counters.
    if cfg.cipher_name == "btn":
        new_index_epoch = old.index_epoch + 1
        # Cipher already rotated; just refresh the index_epoch field
        # on the existing GroupConfig.
        from dataclasses import replace as _replace
        cfg.groups[group] = _replace(old, index_epoch=new_index_epoch)
    else:
        new_group = _create_group(
            cfg.keystore,
            group,
            master_index_key=cfg.master_index_key,
            ceremony_id=cfg.ceremony_id,
            cipher_name=cfg.cipher_name,
            pool_size=pool,
            epoch=old.index_epoch + 1,
            recipient_dids=[cfg.device.device_identity],
        )
        cfg.groups[group] = new_group
        new_index_epoch = new_group.index_epoch

    _update_authoritative_yaml(
        cfg,
        lambda doc: _yaml_rotate_group(
            doc,
            group,
            pool,
            cfg.device.device_identity,
            revoke_did,
            new_epoch=new_index_epoch,
        ),
        key="groups",
    )

    # Attested rotation event. Catalog-validated by the runtime before signing.
    if _lg._runtime is not None:
        # pool_size is not meaningful for jwe/btn; keep the field for schema
        # compat but omit actual values.
        _old_pool: int | None = None
        _new_pool: int | None = None
        event_fields: dict[str, Any] = {
            "group": group,
            "cipher": cfg.cipher_name,
            "generation": new_index_epoch,
            "previous_kit_sha256": prev_kit_sha,
            "old_pool_size": _old_pool,
            "new_pool_size": _new_pool,
            "rotated_at": datetime.now(_tz.utc).isoformat(),
        }
        # 0.4.3a1 truth-telling fields for btn. JWE rotations don't yet
        # surface their X25519 sender keypair as a publisher_identity
        # (separate naming work). For btn we have explicit prior/new
        # publisher_id values from BtnGroupCipher.rotate(), plus the
        # list of recipients whose kits were re-minted under the new
        # tree.
        if btn_cipher_result is not None:
            event_fields["cipher_actually_rotated"] = True
            event_fields["prior_epoch"] = btn_cipher_result.prior_epoch
            event_fields["new_epoch"] = btn_cipher_result.new_epoch
            event_fields["prior_publisher_id_hex"] = (
                btn_cipher_result.prior_publisher_id.hex()
            )
            event_fields["new_publisher_id_hex"] = (
                btn_cipher_result.new_publisher_id.hex()
            )
            event_fields["renewed_recipients"] = renewed_recipients or []
            event_fields["renewal_output_dir"] = (
                str(renewal_output_dir) if renewal_output_dir is not None else None
            )
        _lg._require_init().emit(
            "info",
            "tn.rotation.completed",
            event_fields,
        )

    _maybe_autosync(cfg)
    return cfg


# --------------------------------------------------------------------
# add_recipient (JWE only — post-init recipient addition)
# --------------------------------------------------------------------


def _add_recipient_jwe_impl(
    cfg: LoadedConfig,
    group: str,
    did: str,
    pub_bytes: bytes | None = None,
) -> LoadedConfig:
    """Add a recipient to a JWE group.

    - If pub_bytes is supplied: wire pub into the cipher immediately,
      attest tn.recipient.added, yaml records {did, pub_b64}.
    - If pub_bytes is None: yaml records {did} (pending state). Reconcile
      (see tn/_reconcile.py) promotes to full recipient when a matching
      offer arrives in pending_offers/.

    Raises RuntimeError if `group` uses a non-JWE cipher. For btn groups,
    use the btn admin verbs (tn.admin_add_recipient / admin_revoke_recipient)
    which route through the Rust runtime.
    """
    from .. import logger as _lg
    from ..cipher import JWEGroupCipher, NotAPublisherError

    # Per-group cipher dispatch: look at the target group's actual cipher,
    # not the ceremony-level default (which may differ in mixed ceremonies).
    if group not in cfg.groups:
        raise RuntimeError(
            f"add_recipient: group {group!r} is not in this ceremony "
            f"(known groups: {list(cfg.groups)}). Declare the group first "
            f"with admin.ensure_group(cfg, {group!r}, cipher='jwe')."
        )
    gcfg = cfg.groups[group]
    if not isinstance(gcfg.cipher, JWEGroupCipher):
        raise RuntimeError(
            f"add_recipient: group {group!r} uses cipher {gcfg.cipher.name!r}, "
            f"but this private impl is for JWE groups only. For btn "
            f"groups, call tn.admin.add_recipient(group, recipient_did=..., "
            f"out_path=...) which routes through the Rust runtime."
        )
    if not did.startswith("did:"):
        raise ValueError(
            f"add_recipient: did {did!r} must be a DID string (start with 'did:'). "
            f"If you meant an email or name, that's not supported; TN uses DIDs."
        )

    if pub_bytes is None:
        # Pending state — yaml only, no cipher update, no enrolment compile yet.
        def _mutate_pending(doc):
            g = doc.setdefault("groups", {}).setdefault(group, {})
            recipients = g.setdefault("recipients", [])
            if not any(
                r.get("recipient_identity") == did
                for r in recipients
                if isinstance(r, dict)
            ):
                recipients.append({"recipient_identity": did})

        _update_authoritative_yaml(cfg, _mutate_pending, key="groups")
        if _lg._runtime is not None:
            _lg._require_init().emit(
                "",
                "tn.recipient.intent_declared",
                {"group": group, "recipient_identity": did},
            )
        return cfg

    if len(pub_bytes) != 32:
        raise ValueError(
            f"add_recipient: pub_bytes must be 32 raw X25519 bytes; got "
            f"{len(pub_bytes)}. If you extracted the pub from an offer "
            f"package's `x25519_pub_b64` field, base64-decode it first."
        )

    try:
        gcfg.cipher.add_recipient(did, pub_bytes)
    except NotAPublisherError as e:
        raise RuntimeError(
            f"add_recipient: group {group!r} has no sender key in this keystore "
            f"({cfg.keystore}/{group}.jwe.sender). Only the publisher (ceremony "
            f"creator) can add recipients. Details: {e}"
        ) from e

    def _mutate(doc):
        import base64

        g = doc.setdefault("groups", {}).setdefault(group, {})
        recipients = g.setdefault("recipients", [])
        recipients = [r for r in recipients if r.get("recipient_identity") != did]
        recipients.append(
            {
                "recipient_identity": did,
                "pub_b64": base64.b64encode(pub_bytes).decode("ascii"),
            }
        )
        g["recipients"] = recipients

    _update_authoritative_yaml(cfg, _mutate, key="groups")

    if _lg._runtime is not None:
        _lg._require_init().emit(
            "",
            "tn.recipient.added",
            {"group": group, "recipient_identity": did},
        )
    # No enrolment package is emitted here. Post trusted-enrollment refactor an
    # enrolment package is a publisher-signed *response to a reader's proven
    # offer*: tn.compile.compile_enrolment requires a durable AcceptedOffer
    # (tn.enrollment.require_accepted_offer), which only exists after the reader
    # sends an offer carrying a KeyBindingProof. Directly wiring a caller-
    # supplied pubkey here registers the recipient (they can now be encrypted
    # to), but there is no such proven offer, so there is nothing to compile.
    # The recipient obtains a proof-backed enrolment through the reader-driven
    # offer -> absorb -> reconcile flow, not from this admin call.
    _maybe_autosync(cfg)
    return cfg


# --------------------------------------------------------------------
# revoke_recipient (JWE only — O(1) per-recipient revocation)
# --------------------------------------------------------------------


def _revoke_recipient_jwe_impl(cfg: LoadedConfig, group: str, did: str) -> LoadedConfig:
    """Drop `did` from a JWE group's recipient list. O(1).

    Does NOT bump index_epoch — remaining recipients' HMAC search tokens
    stay valid and no repackaging is required for them. Tradeoff: a
    revoked party who somehow obtains future ciphertexts out-of-band
    can still compute search tokens that match them (they cannot decrypt).
    If that threat matters, call rotate() instead.

    Raises RuntimeError if `group` uses a non-JWE cipher. For btn groups,
    use tn.admin.revoke_recipient(group, leaf_index=N) which routes through
    the Rust runtime's subset-difference revocation primitive.
    """
    from .. import logger as _lg
    from ..cipher import JWEGroupCipher, NotAPublisherError

    if group not in cfg.groups:
        raise RuntimeError(
            f"revoke_recipient: group {group!r} is not in this ceremony "
            f"(known groups: {list(cfg.groups)}). Nothing to revoke."
        )
    gcfg = cfg.groups[group]
    if not isinstance(gcfg.cipher, JWEGroupCipher):
        raise RuntimeError(
            f"revoke_recipient: group {group!r} uses cipher "
            f"{gcfg.cipher.name!r}, but this private impl is for JWE "
            f"groups only. For btn groups, call "
            f"tn.admin.revoke_recipient(group, leaf_index=N) instead."
        )

    try:
        gcfg.cipher.revoke_recipient(did)
    except NotAPublisherError as e:
        raise RuntimeError(
            f"revoke_recipient: group {group!r} has no sender key in this "
            f"keystore ({cfg.keystore}/{group}.jwe.sender). Only the "
            f"publisher (ceremony creator) can revoke. Details: {e}"
        ) from e

    def _mutate(doc):
        g = doc.setdefault("groups", {}).setdefault(group, {})
        g["recipients"] = [
            r
            for r in (g.get("recipients") or [])
            if r.get("recipient_identity") != did
        ]

    _update_authoritative_yaml(cfg, _mutate, key="groups")

    if _lg._runtime is not None:
        _lg._require_init().emit(
            "",
            "tn.recipient.revoked",
            {"group": group, "recipient_identity": did},
        )
    _maybe_autosync(cfg)
    return cfg


# --------------------------------------------------------------------
# Autosync hook (opt-in via TN_WALLET_AUTOSYNC=1)
# --------------------------------------------------------------------


def _maybe_autosync(cfg: LoadedConfig) -> None:
    """Best-effort sync after an admin state change, when every gate passes:

    1. ``TN_WALLET_AUTOSYNC`` — ``0`` force-off, ``1`` force-on, unset
       defers to the yaml ``vault.autosync`` opt-in.
    2. The ceremony is linked/vault-enabled AND claimed
       (``linked_project_id`` set) — an unclaimed ceremony has nothing
       vault-side to sync to, so it never touches the network.
    3. Throttle: at most one attempt per ``vault_sync_interval_seconds``
       per ceremony (explicit ``tn wallet sync`` is never throttled).

    Never raises. State-change operation has already succeeded locally
    before we're called; sync failures don't cascade. But unlike V1's
    silent-swallow, we WRITE failures to a queue file at
      $XDG_STATE_HOME/tn/sync_queue/<ceremony_id>.jsonl
    so the user can inspect failed syncs via `tn wallet status` and
    drain them via `tn wallet sync --drain-queue`.
    """
    import os

    env = os.environ.get("TN_WALLET_AUTOSYNC")
    if env == "0":
        return  # explicit force-off wins
    if env != "1" and not getattr(cfg, "vault_autosync", False):
        return  # default: sync only when the YAML opts in
    if not cfg.is_linked() and not getattr(cfg, "vault_enabled", False):
        return
    # An unclaimed ceremony (linked mode but no vault-side project yet) has
    # nothing to sync TO — sync_ceremony would only fail after burning two
    # challenge/verify pairs + a pickups-pending GET against the vault. The
    # 2026-07-02 call-home flood was exactly this state firing per admin op
    # from throwaway test ceremonies; short-circuit locally instead.
    if not getattr(cfg, "linked_project_id", None):
        return
    # Rate-limit: one attempt per vault_sync_interval_seconds per ceremony.
    # State-change ops already succeeded locally; the next op past the
    # interval (or an explicit `tn wallet sync`) pushes the full state.
    if _autosync_throttled(cfg):
        return
    _stamp_autosync_attempt(cfg.ceremony_id)

    err_msg: str | None = None
    try:
        # Inline imports here are deliberate: admin is imported early and
        # wallet/identity/vault_client form a cycle back through it. Keep the
        # AWK imports in the same block for consistency with that constraint.
        from .. import wallet as _wallet
        from ..awk_pickup import resolve_cached_awk
        from ..identity import Identity, _default_identity_path
        from ..signing import DeviceKey
        from ..sync_state import get_account_id
        from ..vault_client import VaultClient

        identity = Identity.load(_default_identity_path())
        link = _wallet.vault_link_info(cfg)
        if not link.enabled or not link.url:
            raise RuntimeError("ceremony has no vault.url; cannot sync")

        # One handshake per cycle: authenticate the client first, then let
        # the AWK drain below reuse its JWT instead of minting a second one.
        client = VaultClient.for_identity(identity, link.url)
        try:
            # The running-logger backup leg: drain this device's AWK inbox and
            # resolve the cached AWK exactly as `tn wallet sync` does. Without it
            # autosync called sync_ceremony() with no AWK, so the keystore body
            # backup was skipped on every flush and a browser-minted pickup was
            # never picked up while the logger ran.
            hint = get_account_id(cfg.yaml_path) or getattr(
                identity, "linked_account_id", None
            )
            awk, account_id = resolve_cached_awk(
                vault_url=link.url,
                device_seed=identity.device_private_key_bytes(),
                account_id_hint=hint,
                token=getattr(client, "token", None),
            )
            if account_id and getattr(identity, "linked_account_id", None) is None:
                identity.linked_account_id = account_id
                identity.ensure_written(_default_identity_path())

            signer = DeviceKey.from_private_bytes(identity.device_private_key_bytes())
            result = _wallet.sync_ceremony(
                cfg, client, awk=awk, sign_with=signer, author_did=identity.did,
            )
            if result.errors:
                err_msg = f"{len(result.errors)} per-file errors: {result.errors[:3]}"
        finally:
            client.close()
    except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
        err_msg = f"{type(e).__name__}: {e}"

    if err_msg is not None:
        _append_sync_queue(cfg.ceremony_id, err_msg)


def _tn_state_dir() -> Path:
    """Machine-local tn state root: $TN_STATE_DIR > $XDG_STATE_HOME/tn >
    %APPDATA%/tn (Windows) > ~/.local/state/tn."""
    import os as _os
    from pathlib import Path as _Path

    override = _os.environ.get("TN_STATE_DIR")
    if override:
        return _Path(override)
    xdg = _os.environ.get("XDG_STATE_HOME")
    if xdg:
        return _Path(xdg) / "tn"
    if _os.name == "nt":
        appdata = _os.environ.get("APPDATA") or str(_Path.home() / "AppData" / "Roaming")
        return _Path(appdata) / "tn"
    return _Path.home() / ".local" / "state" / "tn"


def _sync_queue_path(ceremony_id: str) -> Path:
    """$XDG_STATE_HOME/tn/sync_queue/<ceremony_id>.jsonl"""
    return _tn_state_dir() / "sync_queue" / f"{ceremony_id}.jsonl"


def _autosync_stamp_path(ceremony_id: str) -> Path:
    """Last-autosync-attempt marker; its mtime is the throttle clock."""
    return _tn_state_dir() / "autosync_last" / f"{ceremony_id}.stamp"


def _autosync_throttled(cfg: LoadedConfig) -> bool:
    """True when an autosync attempt for this ceremony ran within
    ``vault_sync_interval_seconds``. Never raises; on any doubt (missing or
    unreadable stamp) the sync proceeds."""
    import time

    try:
        interval = getattr(cfg, "vault_sync_interval_seconds", 600) or 600
        stamp = _autosync_stamp_path(cfg.ceremony_id)
        return (time.time() - stamp.stat().st_mtime) < interval
    except OSError:
        return False


def _stamp_autosync_attempt(ceremony_id: str) -> None:
    """Record that an autosync attempt started (success or not — the point
    is rate-limiting network traffic, not tracking outcomes). Never raises."""
    try:
        stamp = _autosync_stamp_path(ceremony_id)
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.touch()
        import os as _os
        import time

        now = time.time()
        _os.utime(stamp, (now, now))
    except OSError:
        pass


#: sync-queue failure records older than this are junk — the ceremony either
#: got fixed (queue drained on success) or was a throwaway that will never
#: sync. Pruned opportunistically on every append.
_SYNC_QUEUE_MAX_AGE_DAYS = 30


def _prune_sync_queue(max_age_days: int = _SYNC_QUEUE_MAX_AGE_DAYS) -> None:
    """Delete sync-queue files not touched in ``max_age_days``. Best-effort
    machine-wide sweep (all ceremonies, not just the appending one) so
    abandoned ceremonies don't accumulate stale failure records forever.
    Never raises."""
    import time

    try:
        qdir = _tn_state_dir() / "sync_queue"
        cutoff = time.time() - max_age_days * 86400
        for f in qdir.glob("*.jsonl"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
            except OSError:
                continue
    except OSError:
        pass


def _append_sync_queue(ceremony_id: str, err_msg: str) -> None:
    """Append a failure record. Never raises."""
    import json as _json
    import time

    try:
        path = _sync_queue_path(ceremony_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(
                _json.dumps(
                    {
                        "ceremony_id": ceremony_id,
                        "ts": time.time(),
                        "error": err_msg,
                    }
                )
                + "\n"
            )
        _prune_sync_queue()
    except OSError:
        # last-resort swallow — telemetry isn't critical, but the original
        # error being recorded is lost here, so surface that the failure
        # record could not be written.
        _log.warning(
            "could not write sync-failure record for ceremony=%s (the "
            "underlying error was: %s); sync telemetry for this ceremony is "
            "incomplete",
            ceremony_id,
            err_msg,
        )


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def _update_yaml(cfg: LoadedConfig, mutator) -> None:
    """Apply ``mutator`` to ``cfg.yaml_path`` (the loaded yaml itself).

    Use this for stream-local keys — e.g. the ``ceremony`` block, which
    is shallow-merged with the child winning. For parent-owned keys
    (``groups`` / ``fields`` / ``recipients``) use
    :func:`_update_authoritative_yaml`, which writes to the head of the
    ``extends:`` chain so the change is not discarded on the next load.
    """
    with open(cfg.yaml_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    mutator(doc)
    with open(cfg.yaml_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False)


def _update_authoritative_yaml(cfg: LoadedConfig, mutator, *, key: str = "groups") -> None:
    """Apply ``mutator`` to the yaml that authoritatively owns ``key``.

    Under the multi-ceremony layout a named stream's yaml carries
    ``extends: ../default/tn.yaml`` and inherits ``groups`` / ``fields`` /
    ``recipients`` from the project root. Those keys are parent-owned:
    writing them into the stream yaml (``cfg.yaml_path``) is silently
    discarded on the next load ("child sets parent-owned key 'groups';
    parent wins"), so the group / recipient never persists and a
    fresh-process ``add_recipient`` fails with "unknown group". Group and
    recipient mutations therefore target the chain root.

    For a ceremony with no ``extends:`` the authoritative yaml resolves
    back to ``cfg.yaml_path``, so the legacy single-file layout is
    unchanged.
    """
    from ..config import authoritative_yaml_for

    target = authoritative_yaml_for(cfg.yaml_path, key)
    with open(target, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    mutator(doc)
    with open(target, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False)


# --------------------------------------------------------------------
# Wallet link state
# --------------------------------------------------------------------


def set_link_state(
    cfg: LoadedConfig,
    *,
    mode: str,
    linked_vault: str | None = None,
    linked_project_id: str | None = None,
) -> LoadedConfig:
    """Flip a ceremony between `local` and `linked` modes.

    Writes the change to tn.yaml and mutates the in-memory cfg to match.
    When transitioning to `linked`, both `linked_vault` and
    `linked_project_id` must be provided.

    Idempotent: linking an already-linked ceremony with the same vault
    is a no-op. Re-linking to a different vault raises.
    """
    if mode not in ("local", "linked"):
        raise ValueError(f"mode must be 'local' or 'linked', got {mode!r}")

    if mode == "linked":
        if not linked_vault:
            raise ValueError("linked mode requires linked_vault")
        if cfg.mode == "linked" and cfg.linked_vault and cfg.linked_vault != linked_vault:
            raise RuntimeError(
                f"ceremony {cfg.ceremony_id} is already linked to "
                f"{cfg.linked_vault}; unlink first before re-linking",
            )

    def _mutate(doc: dict[str, Any]) -> None:
        ceremony_block = doc.setdefault("ceremony", {})
        vault_block = doc.setdefault("vault", {})
        ceremony_block["mode"] = mode
        if mode == "linked":
            ceremony_block["linked_vault"] = linked_vault
            if linked_project_id:
                ceremony_block["linked_project_id"] = linked_project_id
            vault_block["enabled"] = True
            vault_block["url"] = linked_vault
            current_project_id = vault_block.get("linked_project_id")
            if linked_project_id and not current_project_id:
                vault_block["linked_project_id"] = linked_project_id
            vault_block["autosync"] = bool(vault_block.get("autosync", True))
            vault_block.setdefault("sync_interval_seconds", 600)
        else:
            ceremony_block.pop("linked_vault", None)
            ceremony_block.pop("linked_project_id", None)
            vault_block["enabled"] = False
            vault_block["url"] = ""
            vault_block["linked_project_id"] = ""
            vault_block["autosync"] = False
            vault_block.setdefault("sync_interval_seconds", 600)

    # Link state is project-scoped: a named stream inherits its
    # ceremony/vault link from the default (the extends-chain root), so
    # the mutation must land at the root — otherwise unlinking a stream
    # only writes a stream-local override and leaves the project linked.
    # For a single-file ceremony the authoritative yaml resolves back to
    # cfg.yaml_path, so the legacy single-file layout is unchanged.
    _update_authoritative_yaml(cfg, _mutate, key="vault")

    cfg.mode = mode
    if mode == "linked":
        cfg.linked_vault = linked_vault
        if linked_project_id:
            cfg.linked_project_id = linked_project_id
        cfg.vault_enabled = True
        cfg.vault_url = linked_vault
        if linked_project_id and not cfg.vault_linked_project_id:
            cfg.vault_linked_project_id = linked_project_id
        cfg.vault_autosync = True
        cfg.vault_sync_interval_seconds = cfg.vault_sync_interval_seconds or 600
    else:
        cfg.linked_vault = None
        cfg.linked_project_id = None
        cfg.vault_enabled = False
        cfg.vault_url = None
        cfg.vault_linked_project_id = None
        cfg.vault_autosync = False
        cfg.vault_sync_interval_seconds = cfg.vault_sync_interval_seconds or 600
    return cfg


def _yaml_rotate_group(
    doc: dict[str, Any],
    group: str,
    pool_size: int,
    me_did: str,
    revoke_did: str | None,
    *,
    new_epoch: int,
) -> None:
    g = doc.setdefault("groups", {}).setdefault(group, {})
    g["pool_size"] = pool_size
    g["index_epoch"] = new_epoch

    # YAML recipient entry shape.
    me_entry: dict[str, Any] = {"recipient_identity": me_did}
    recipients: list[dict[str, Any]] = [me_entry]
    if revoke_did is not None:
        old_recipients = g.get("recipients") or []
        for r in old_recipients:
            r_id = r.get("recipient_identity")
            if r_id and r_id != revoke_did and r_id != me_did:
                recipients.append(r)
    g["recipients"] = recipients


# ====================================================================
# Cipher-agnostic unified API.
#
# These verbs branch on the target group's cipher and delegate to the
# right cipher-specific impl. New ciphers add a branch in one place.
# Callers pass keyword arguments only (the per-cipher arg shapes don't
# overlap, so positional ordering would be ambiguous).
# ====================================================================


@dataclass
class _ResolvedRecipient:
    """Canonical fields extracted from a polymorphic `recipient=` value."""

    recipient_did: str | None = None
    leaf_index: int | None = None
    public_key: bytes | None = None


def _resolve_recipient(value: Any) -> _ResolvedRecipient:
    """Normalize a polymorphic recipient value into canonical fields.

    Accepts:
      - ``str`` starting with ``did:`` -> ``recipient_did``
      - ``int`` (non-negative) -> ``leaf_index`` (btn only)
      - 32-byte ``bytes`` -> ``public_key`` (jwe X25519)
      - object with ``.recipient_did`` / ``.leaf_index`` / ``.public_key``
        attributes (e.g. ``AddRecipientResult``, a contacts.yaml row,
        any Contact-like)
      - ``dict`` with keys ``recipient_did``/``did``, ``leaf_index``,
        ``public_key``/``x25519_pub_b64`` (b64 decoded)

    Explicit keyword arguments to ``add_recipient`` / ``revoke_recipient``
    take precedence over fields resolved here.
    """
    out = _ResolvedRecipient()
    if isinstance(value, bool):
        raise TypeError(
            "tn.admin: recipient cannot be a bool (use an int leaf_index)"
        )
    if isinstance(value, str):
        if not value.startswith("did:"):
            raise ValueError(
                f"tn.admin: recipient string must be a DID (got {value!r})"
            )
        out.recipient_did = value
        return out
    if isinstance(value, int):
        if value < 0:
            raise ValueError(
                f"tn.admin: leaf_index must be non-negative (got {value})"
            )
        out.leaf_index = value
        return out
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        if len(b) != 32:
            raise ValueError(
                "tn.admin: raw recipient bytes must be a 32-byte X25519 "
                f"public key (got len={len(b)})"
            )
        out.public_key = b
        return out
    if isinstance(value, dict):
        did = value.get("recipient_identity") or value.get("did")
        leaf = value.get("leaf_index")
        pk = value.get("public_key")
        if pk is None and value.get("x25519_pub_b64") is not None:
            import base64 as _b64

            pk = _b64.b64decode(value["x25519_pub_b64"])
        if did is None and leaf is None and pk is None:
            raise ValueError(
                "tn.admin: recipient dict must contain at least one of "
                "recipient_did/did, leaf_index, public_key/x25519_pub_b64"
            )
        out.recipient_did = did
        out.leaf_index = leaf
        out.public_key = pk
        return out
    did = getattr(value, "recipient_identity", None)
    leaf = getattr(value, "leaf_index", None)
    pk = getattr(value, "public_key", None)
    if did is None and leaf is None and pk is None:
        raise TypeError(
            f"tn.admin: unsupported recipient type {type(value).__name__}; "
            "expected DID str, int leaf_index, 32-byte public_key bytes, "
            "AddRecipientResult-like, or dict"
        )
    out.recipient_did = did
    out.leaf_index = leaf
    out.public_key = pk
    return out


def _resolve_btn_did_to_leaf(group: str, recipient_did: str) -> int:
    """Look up the active leaf_index for ``recipient_did`` in a btn ``group``.

    Errors on zero matches; errors on ambiguity if a DID was somehow
    minted onto multiple active leaves (shouldn't happen, but guard it).
    """
    rows = recipients(group, include_revoked=False)
    matches = [r for r in rows if r.get("recipient_identity") == recipient_did]
    if not matches:
        raise ValueError(
            f"tn.admin.revoke_recipient: no active recipient with "
            f"recipient_did={recipient_did!r} in group {group!r}"
        )
    if len(matches) > 1:
        leaves = [m["leaf_index"] for m in matches]
        raise ValueError(
            f"tn.admin.revoke_recipient: recipient_did={recipient_did!r} "
            f"resolves to multiple leaves {leaves} in group {group!r}; "
            "pass leaf_index= explicitly"
        )
    return int(matches[0]["leaf_index"])


@dataclass
class AddRecipientResult:
    """Structured return from `tn.admin.add_recipient`.

    btn ceremonies populate `leaf_index` and `kit_path`.
    JWE ceremonies populate `updated_cfg`.
    Callers inspect what's relevant for their cipher.
    """

    leaf_index: int | None = None
    kit_path: Path | None = None
    updated_cfg: LoadedConfig | None = None
    unsafe: bool = False
    delegated_subauthority: bool = False


def add_recipient(
    group: str,
    *,
    recipient: Any | None = None,
    recipient_did: str | None = None,
    out_path: Path | str | None = None,
    public_key: bytes | None = None,
    raw: bool = False,
    cfg: Any | None = None,
    proof: KeyBindingProofV1 | VerifiedPrincipal | None = None,
    allow_subauthority: bool = False,
    unsafe_plaintext: bool = False,
) -> AddRecipientResult:
    """Register a new recipient on `group` and mint their reader kit.

    btn ceremonies:
        Mints a fresh kit, registers the recipient (emits
        `tn.recipient.added`), and writes an absorbable `.tnpkg`
        bundle to disk. `out_path` defaults to
        `<cwd>/<recipient_label>.tnpkg`. The recipient absorbs via
        `tn.absorb(<path>)`.

        For legacy scripted deployments that hand-copy raw kit
        bytes into the recipient's keystore, pass `raw=True` along
        with an `out_path` ending in `.btn.mykit`. The raw kit is
        the pre-0.4.2a10 default; .tnpkg is the new default.

        Either form registers the recipient and supports a later
        `revoke_recipient` call. The difference is purely the wire
        shape of the kit material.

    JWE ceremonies:
        Pass the required `recipient_did`, its authenticated 32-byte X25519
        `public_key`, and `cfg` (the LoadedConfig to mutate). Returns
        `AddRecipientResult(updated_cfg=cfg')`. `raw` is btn-only
        and ignored on JWE.

    HIBE ceremonies:
        Routes to `grant_reader`. Normal delivery requires a complete
        Ed25519 `did:key` and scoped reader proof and is always recipient-
        sealed. Plaintext bearer delivery requires the explicit audited
        `unsafe_plaintext=True` compatibility switch.

    For re-distributing BTN kit material to an already-known recipient
    WITHOUT a new attestation event, use
    `tn.pkg.bundle_for_recipient` instead. That helper is BTN-only; JWE
    readers generate and retain their own `.jwe.mykey`, and HIBE readers
    receive grants through `grant_reader`.

    `recipient_did` is optional only for BTN's low-level metadata path and an
    explicitly unsafe HIBE plaintext hand-off. It is required for JWE
    enrollment and normal HIBE grant delivery.

    `cfg` defaults to the runtime singleton's cfg.

    The polymorphic ``recipient=`` keyword accepts a DID string, a
    32-byte X25519 public key (jwe), an ``AddRecipientResult``, a
    contacts.yaml-style dict, or any object exposing
    ``recipient_did`` / ``public_key`` attributes. Explicit
    ``recipient_did=`` / ``public_key=`` kwargs override the resolved
    fields.
    """
    if recipient is not None:
        resolved = _resolve_recipient(recipient)
        if recipient_did is None:
            recipient_did = resolved.recipient_did
        if public_key is None:
            public_key = resolved.public_key

    if cfg is None:
        from .. import current_config

        cfg = current_config()

    group_spec = cfg.groups.get(group)
    if group_spec is None:
        raise KeyError(f"unknown group: {group!r}")
    cipher = group_spec.cipher.name

    if cipher == "btn":
        if public_key is not None:
            raise ValueError(
                "tn.admin.add_recipient: public_key is JWE-only and was "
                f"passed to a btn group {group!r}. For btn, pass out_path."
            )

        # 0.4.2a10: out_path defaults to <cwd>/<safe-label>.tnpkg
        # (absorbable bundle). Legacy raw .btn.mykit output stays
        # available via `raw=True` for scripted deployments.
        import re as _re
        if out_path is None:
            safe_stem = _re.sub(
                r"[^A-Za-z0-9._-]", "_",
                (recipient_did or "recipient").split(":")[-1],
            )
            out_path = Path.cwd() / f"{safe_stem}.tnpkg"
        out_path = Path(out_path)
        name = out_path.name

        from .. import _maybe_autoinit_load_only, _refresh_admin_cache_if_present, _require_dispatch
        _maybe_autoinit_load_only()

        # Branch on output shape.
        if raw or name.endswith(".btn.mykit"):
            # Legacy raw-kit path. Same as pre-0.4.2a10 behaviour.
            if not name.endswith(".btn.mykit") or name == ".btn.mykit":
                raise ValueError(
                    f"tn.admin.add_recipient: when raw=True or "
                    f"out_path ends in '.btn.mykit', the basename must "
                    f"match '<group>.btn.mykit' (e.g. "
                    f"{group!r}.btn.mykit), got {name!r}."
                )
            leaf = _require_dispatch().add_recipient_btn(
                group, str(out_path), recipient_did=recipient_did,
            )
            _refresh_admin_cache_if_present()
            return AddRecipientResult(
                leaf_index=leaf,
                kit_path=Path(out_path),
                updated_cfg=None,
            )

        # Default: absorbable .tnpkg. Mint into a temp keystore
        # directory under the canonical filename the kit_bundle
        # exporter expects, then export to the requested out_path
        # as a .tnpkg manifest.
        import tempfile as _tempfile
        with _tempfile.TemporaryDirectory(prefix="tn-add-recipient-") as td:
            td_path = Path(td)
            raw_kit_path = td_path / f"{group}.btn.mykit"
            leaf = _require_dispatch().add_recipient_btn(
                group, str(raw_kit_path), recipient_did=recipient_did,
            )
            from .._pkg_impl import _export_impl
            from ..recipient_seal import recipient_key_is_resolvable
            # Seal the btn reader kit to the recipient's device key when it has
            # a resolvable key (same rationale as hibe grant_reader: an unsealed
            # .tnpkg body is a bearer token). Falls back to plaintext for a
            # placeholder / did-less hand-off.
            _export_impl(
                out_path,
                kind="kit_bundle",
                cfg=cfg,
                to_did=recipient_did,
                keystore=td_path,
                groups=[group],
                seal_for_recipient=recipient_key_is_resolvable(recipient_did),
            )
        _refresh_admin_cache_if_present()
        return AddRecipientResult(
            leaf_index=leaf,
            kit_path=Path(out_path),
            updated_cfg=None,
        )

    elif cipher == "jwe":
        if out_path is not None:
            raise ValueError(
                "tn.admin.add_recipient: out_path is btn-only and was "
                f"passed to a JWE group {group!r}. For JWE, pass public_key."
            )
        if public_key is None or recipient_did is None:
            raise ValueError(
                "tn.admin.add_recipient: JWE groups require both "
                "recipient_did and public_key."
            )
        updated_cfg = _add_recipient_jwe_impl(cfg, group, recipient_did, public_key)
        return AddRecipientResult(
            leaf_index=None,
            kit_path=None,
            updated_cfg=updated_cfg,
        )

    elif cipher == "hibe":
        if public_key is not None:
            raise ValueError(
                "tn.admin.add_recipient: public_key is JWE-only and was "
                f"passed to a hibe group {group!r}. For hibe, pass out_path."
            )
        return grant_reader(
            group,
            reader_did=recipient_did,
            out_path=out_path,
            cfg=cfg,
            proof=proof,
            allow_subauthority=allow_subauthority,
            unsafe_plaintext=unsafe_plaintext,
        )

    else:
        raise NotImplementedError(
            f"tn.admin.add_recipient: cipher {cipher!r} not yet supported."
        )


def _require_hibe_cipher(
    group: str,
    cfg: Any,
    *,
    require_authority: bool = False,
):
    from ..enrollment import validate_enrollment_group

    validate_enrollment_group(group)
    group_spec = cfg.groups.get(group)
    if group_spec is None:
        raise KeyError(f"unknown group: {group!r}")
    cipher_inst = group_spec.cipher
    if cipher_inst.name != "hibe":
        raise ValueError(
            f"group {group!r} uses cipher {cipher_inst.name!r}; this operation is hibe-only"
        )
    if require_authority and not cipher_inst.is_authority():
        raise ValueError(
            f"HIBE: group {group!r} has no master secret; only its authority can issue this statement"
        )
    return cipher_inst


def _now_utc(now: datetime | None) -> datetime:
    value = datetime.now(timezone.utc) if now is None else now
    if value.tzinfo is None or value.utcoffset() is None:
        raise TrustError(TrustReason.STATEMENT_INVALID, "now must be timezone-aware")
    return value.astimezone(timezone.utc)


def _proof_digest(proof: KeyBindingProofV1) -> str:
    value = proof._wire_value(include_signature=True)
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _build_hibe_authority_assertion(
    group: str,
    *,
    audience_did: str,
    id_path: str,
    path_epoch: int,
    ttl: timedelta,
    cfg: LoadedConfig,
    issued_at: datetime,
) -> KeyBindingProofV1:
    """Sign an exact HIBE authority state, including a staged next epoch."""
    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
    mpk = cipher_inst.mpk()
    return KeyBindingProofV1(
        version=1,
        purpose="hibe-authority",
        subject_did=cfg.device.device_identity,
        audience_did=audience_did,
        ceremony_id=cfg.ceremony_id,
        group=group,
        issued_at=issued_at,
        expires_at=issued_at + ttl,
        nonce_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        binding={
            "algorithm": "TN-BBG-HIBE-BLS12-381",
            "mpk_sha256": "sha256:" + hashlib.sha256(mpk).hexdigest(),
            "max_depth": cipher_inst.max_depth(),
            "id_path": id_path,
            "path_epoch": path_epoch,
        },
        signature_b64="",
    ).sign(cfg.device)


def issue_authority_assertion(
    group: str,
    *,
    audience_did: str | None = None,
    ttl: timedelta = timedelta(minutes=10),
    cfg: LoadedConfig | None = None,
    now: datetime | None = None,
) -> KeyBindingProofV1:
    """Sign the current evaluation-only HIBE authority/path state.

    Assertions are audience-specific. Omitting ``audience_did`` is only a
    self-authority convenience; an external writer's complete Ed25519 DID must
    be supplied explicitly.
    """
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise TrustError(TrustReason.STATEMENT_INVALID, "authority assertion ttl must be positive")
    issued_at = _now_utc(now)
    audience = audience_did or cfg.device.device_identity
    parse_ed25519_did_key(audience)
    return _build_hibe_authority_assertion(
        group,
        audience_did=audience,
        id_path=cipher_inst.id_path(),
        path_epoch=cipher_inst.path_epoch(),
        ttl=ttl,
        cfg=cfg,
        issued_at=issued_at,
    )


def install_authority_assertion(
    group: str,
    *,
    mpk: bytes,
    assertion: KeyBindingProofV1,
    expected_authority_did: str,
    cfg: LoadedConfig | None = None,
    now: datetime | None = None,
) -> None:
    """Verify and atomically pin/update one external HIBE writer authority.

    A successful return is that writer's durable local acknowledgement of the
    exact signed path epoch. Fleet orchestration must collect this ACK from
    every writer before allowing writes to resume after a cutoff rotation.
    """
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    parse_ed25519_did_key(expected_authority_did)
    cipher_inst = _require_hibe_cipher(group, cfg)
    if cipher_inst.is_authority():
        raise ValueError("HIBE: install_authority_assertion is for external writers")
    if not isinstance(assertion, KeyBindingProofV1):
        raise TrustError(TrustReason.STATEMENT_INVALID, "authority assertion has the wrong type")
    if assertion.subject_did != expected_authority_did:
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "authority assertion signer does not match expected_authority_did",
        )
    verified_at = _now_utc(now)
    verify_key_binding_proof(
        assertion,
        expected_purpose="hibe-authority",
        expected_audience_did=cfg.device.device_identity,
        expected_ceremony_id=cfg.ceremony_id,
        expected_group=group,
        now=verified_at,
        challenge=None,
    )
    if not isinstance(mpk, bytes):
        raise TrustError(TrustReason.BINDING_INVALID, "HIBE authority MPK must be bytes")
    from .. import _hibe

    encoded_depth = int(_hibe.mpk_max_depth(mpk))
    binding = assertion.binding
    expected_mpk_sha256 = "sha256:" + hashlib.sha256(mpk).hexdigest()
    if binding["mpk_sha256"] != expected_mpk_sha256:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "HIBE authority MPK bytes do not match the signed fingerprint",
        )
    if binding["max_depth"] != encoded_depth:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "HIBE authority MPK encoded depth does not match the signed max_depth",
        )
    from ..cipher import _normalize_hibe_path

    try:
        id_path = _normalize_hibe_path(
            str(binding["id_path"]),
            what="signed authority id_path",
        )
    except ValueError as exc:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "HIBE authority assertion contains a noncanonical identity path",
        ) from exc
    if len(id_path.split("/")) > encoded_depth:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "HIBE writer path exceeds the authority MPK max_depth",
        )
    incoming_epoch = int(binding["path_epoch"])
    assertion_digest = _proof_digest(assertion)

    from .._keystore_backend import AdvisoryFileLock, atomic_write_bytes
    from ..cipher import (
        HibeGroupCipher,
        _hibe_authority_state_path,
        _hibe_path_epoch_path,
        _load_hibe_authority_state,
    )

    lock_path = Path(cfg.keystore) / f"{group}.hibe.authority.lock"
    with AdvisoryFileLock(lock_path):
        current = _load_hibe_authority_state(Path(cfg.keystore), group)
        if current is not None:
            if current["authority_did"] != expected_authority_did:
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    "HIBE update is not signed by the already pinned authority",
                )
            if current["audience_did"] != cfg.device.device_identity:
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    "installed HIBE authority pin names another writer",
                )
            current_epoch = int(current["path_epoch"])
            if incoming_epoch < current_epoch:
                raise TrustError(TrustReason.EPOCH_ROLLBACK, "HIBE path epoch moved backwards")
            if incoming_epoch == current_epoch:
                material_matches = (
                    current["mpk_sha256"] == expected_mpk_sha256
                    and current["max_depth"] == encoded_depth
                    and current["id_path"] == id_path
                )
                if not material_matches:
                    raise TrustError(
                        TrustReason.EPOCH_CONFLICT,
                        "different HIBE authority material reuses the installed path epoch",
                    )
                if current["assertion_digest"] == assertion_digest:
                    try:
                        disk_matches = (
                            (Path(cfg.keystore) / f"{group}.hibe.mpk").read_bytes() == mpk
                            and (Path(cfg.keystore) / f"{group}.hibe.idpath").read_text(
                                encoding="utf-8"
                            )
                            == id_path
                            and (Path(cfg.keystore) / f"{group}.hibe.path_epoch").read_text(
                                encoding="ascii"
                            )
                            == f"{incoming_epoch}\n"
                        )
                    except (OSError, UnicodeDecodeError):
                        disk_matches = False
                    if disk_matches:
                        return
                # A fresh assertion over identical material renews expiry at
                # the same path epoch. An exact repeat also repairs drifted
                # public files instead of trusting only the commit record.

        state = {
            "version": 1,
            "authority_did": expected_authority_did,
            "audience_did": cfg.device.device_identity,
            "mpk_sha256": expected_mpk_sha256,
            "max_depth": encoded_depth,
            "id_path": id_path,
            "path_epoch": incoming_epoch,
            "assertion_digest": assertion_digest,
            "expires_at": assertion.expires_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        # Public material first, signed commit record last. A crash before the
        # final replace leaves a mismatch that the cipher fences fail closed.
        atomic_write_bytes(Path(cfg.keystore) / f"{group}.hibe.mpk", mpk)
        atomic_write_bytes(
            Path(cfg.keystore) / f"{group}.hibe.idpath",
            id_path.encode("utf-8"),
        )
        atomic_write_bytes(
            _hibe_path_epoch_path(Path(cfg.keystore), group),
            f"{incoming_epoch}\n".encode("ascii"),
        )
        atomic_write_bytes(
            _hibe_authority_state_path(Path(cfg.keystore), group),
            json.dumps(state, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            ),
        )
        cfg.groups[group].cipher = HibeGroupCipher.load(Path(cfg.keystore), group)


def _hibe_admission_generation_path(store: Any, group: str) -> Path:
    component = hashlib.sha256(group.encode("utf-8")).hexdigest()
    return store.state_root / "hibe-admission-generations" / f"{component}.json"


def _hibe_challenge_generation_path(store: Any, challenge_id: str) -> Path:
    component = hashlib.sha256(challenge_id.encode("utf-8")).hexdigest()
    return store.state_root / "hibe-challenges" / f"{component}.json"


def _load_hibe_admission_generation_locked(store: Any, group: str) -> int:
    path = _hibe_admission_generation_path(store, group)
    if not path.exists():
        return 0
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE admission generation is unreadable",
        ) from exc
    expected = {
        "version": 1,
        "authority_did": store.cfg.device.device_identity,
        "ceremony_id": store.cfg.ceremony_id,
        "group": group,
    }
    if (
        not isinstance(record, dict)
        or set(record) != {*expected, "generation"}
        or any(record.get(key) != value for key, value in expected.items())
        or type(record.get("generation")) is not int
        or record["generation"] < 0
    ):
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE admission generation has an invalid scope or shape",
        )
    return int(record["generation"])


def _advance_hibe_admission_generation(store: Any, group: str) -> int:
    from .._keystore_backend import atomic_write_bytes

    with store._lock():
        generation = _load_hibe_admission_generation_locked(store, group) + 1
        record = {
            "version": 1,
            "authority_did": store.cfg.device.device_identity,
            "ceremony_id": store.cfg.ceremony_id,
            "group": group,
            "generation": generation,
        }
        atomic_write_bytes(
            _hibe_admission_generation_path(store, group),
            json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )
        return generation


def _current_hibe_admission_generation(store: Any, group: str) -> int:
    with store._lock():
        return _load_hibe_admission_generation_locked(store, group)


def _record_hibe_challenge_generation(store: Any, challenge: EnrollmentChallengeV1) -> None:
    from .._keystore_backend import atomic_write_bytes

    challenge_doc = challenge._wire_value(include_signature=True)
    challenge_digest = "sha256:" + hashlib.sha256(_canonical_bytes(challenge_doc)).hexdigest()
    with store._lock():
        generation = _load_hibe_admission_generation_locked(store, challenge.group)
        record = {
            "version": 1,
            "authority_did": store.cfg.device.device_identity,
            "ceremony_id": store.cfg.ceremony_id,
            "group": challenge.group,
            "reader_did": challenge.expected_reader_did,
            "challenge_id": challenge.challenge_id,
            "challenge_digest": challenge_digest,
            "generation": generation,
        }
        atomic_write_bytes(
            _hibe_challenge_generation_path(store, challenge.challenge_id),
            json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )


def _assert_hibe_challenge_generation_locked(
    store: Any,
    challenge: EnrollmentChallengeV1,
) -> None:
    path = _hibe_challenge_generation_path(store, challenge.challenge_id)
    if not path.exists():
        raise TrustError(
            TrustReason.CHALLENGE_MISSING,
            "HIBE reader challenge lacks retained admission-generation state",
        )
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE challenge generation record is unreadable",
        ) from exc
    challenge_digest = "sha256:" + hashlib.sha256(
        _canonical_bytes(challenge._wire_value(include_signature=True))
    ).hexdigest()
    expected = {
        "version": 1,
        "authority_did": store.cfg.device.device_identity,
        "ceremony_id": store.cfg.ceremony_id,
        "group": challenge.group,
        "reader_did": challenge.expected_reader_did,
        "challenge_id": challenge.challenge_id,
        "challenge_digest": challenge_digest,
    }
    if (
        not isinstance(record, dict)
        or set(record) != {*expected, "generation"}
        or any(record.get(key) != value for key, value in expected.items())
        or type(record.get("generation")) is not int
        or record["generation"] < 0
    ):
        raise TrustError(
            TrustReason.REPLAY_CONFLICT,
            "HIBE challenge generation record conflicts with the signed challenge",
        )
    current = _load_hibe_admission_generation_locked(store, challenge.group)
    if record["generation"] != current:
        raise TrustError(
            TrustReason.CHALLENGE_REPLAYED,
            "HIBE challenge predates the authority's reader-admission cutoff",
        )


def _assert_hibe_challenge_generation(store: Any, challenge: EnrollmentChallengeV1) -> None:
    with store._lock():
        _assert_hibe_challenge_generation_locked(store, challenge)


def issue_hibe_reader_challenge(
    group: str,
    reader_did: str,
    *,
    ttl: timedelta = timedelta(minutes=10),
    cfg: LoadedConfig | None = None,
) -> EnrollmentChallengeV1:
    """Issue and retain an authority-scoped challenge for one HIBE reader."""
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    _require_hibe_cipher(group, cfg, require_authority=True)
    parse_ed25519_did_key(reader_did)
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise TrustError(TrustReason.STATEMENT_INVALID, "challenge ttl must be positive")
    from .._keystore_backend import AdvisoryFileLock
    from ..enrollment import EnrollmentStore

    with AdvisoryFileLock(_hibe_lifecycle_lock_path(cfg, group)):
        _require_hibe_cipher(group, cfg, require_authority=True)
        if _hibe_revocation_active_path(cfg, group).exists():
            raise TrustError(
                TrustReason.EPOCH_CONFLICT,
                "HIBE reader lifecycle has an incomplete revocation; retry it before "
                "issuing another reader challenge",
            )
        store = EnrollmentStore(cfg, cfg.device)
        challenge = store.issue_challenge(reader_did, group, ttl)
        _record_hibe_challenge_generation(store, challenge)
        return challenge


def create_hibe_reader_proof(
    challenge: EnrollmentChallengeV1,
    *,
    expected_authority_did: str,
    cfg: LoadedConfig,
    now: datetime | None = None,
) -> KeyBindingProofV1:
    """Prove control of the reader DID named by an authority challenge."""
    if not isinstance(challenge, EnrollmentChallengeV1):
        raise TrustError(TrustReason.STATEMENT_INVALID, "HIBE reader challenge has the wrong type")
    parse_ed25519_did_key(expected_authority_did)
    if challenge.publisher_did != expected_authority_did:
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "HIBE challenge signer does not match the expected authority DID",
        )
    issued_at = _now_utc(now)
    verify_enrollment_challenge(
        challenge,
        expected_publisher_did=expected_authority_did,
        expected_reader_did=cfg.device.device_identity,
        expected_ceremony_id=challenge.ceremony_id,
        expected_group=challenge.group,
        now=issued_at,
    )
    challenge_digest = "sha256:" + hashlib.sha256(
        _canonical_bytes(challenge._wire_value(include_signature=True))
    ).hexdigest()
    return KeyBindingProofV1(
        version=1,
        purpose="hibe-reader",
        subject_did=cfg.device.device_identity,
        audience_did=challenge.publisher_did,
        ceremony_id=challenge.ceremony_id,
        group=challenge.group,
        issued_at=issued_at,
        expires_at=challenge.expires_at,
        nonce_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        binding={
            "algorithm": "Ed25519-did-key",
            "delivery": "recipient-seal-v1",
            "challenge_digest": challenge_digest,
        },
        signature_b64="",
    ).sign(cfg.device)


@dataclass(frozen=True)
class HibeAuthorityUpdateResult:
    group: str
    id_path: str
    path_epoch: int
    assertion: KeyBindingProofV1


def rotate_hibe_path(
    group: str,
    new_path: str,
    *,
    audience_did: str | None = None,
    ttl: timedelta = timedelta(minutes=10),
    cfg: LoadedConfig | None = None,
    now: datetime | None = None,
) -> HibeAuthorityUpdateResult:
    """Rotate one HIBE path while excluding grants and durable revocations."""
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    _require_hibe_cipher(group, cfg, require_authority=True)
    from .._keystore_backend import AdvisoryFileLock

    with AdvisoryFileLock(_hibe_lifecycle_lock_path(cfg, group)):
        _require_hibe_cipher(group, cfg, require_authority=True)
        if _hibe_revocation_active_path(cfg, group).exists():
            raise TrustError(
                TrustReason.EPOCH_CONFLICT,
                "HIBE reader lifecycle has an incomplete revocation; retry that exact "
                "revoke_reader operation before rotating the authority path",
            )
        return _rotate_hibe_path_locked(
            group,
            new_path,
            audience_did=audience_did,
            ttl=ttl,
            cfg=cfg,
            now=now,
        )


def _rotate_hibe_path_locked(
    group: str,
    new_path: str,
    *,
    audience_did: str | None = None,
    ttl: timedelta = timedelta(minutes=10),
    cfg: LoadedConfig | None = None,
    now: datetime | None = None,
) -> HibeAuthorityUpdateResult:
    """Rotate the authority path and return its writer-scoped signed update."""
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
    resolved_audience = audience_did or cfg.device.device_identity
    parse_ed25519_did_key(resolved_audience)
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise TrustError(TrustReason.STATEMENT_INVALID, "authority assertion ttl must be positive")
    issued_at = _now_utc(now)
    cipher_inst.rotate_id_path(new_path)
    _reload_native_group_cipher(group)
    assertion = issue_authority_assertion(
        group,
        audience_did=resolved_audience,
        ttl=ttl,
        cfg=cfg,
        now=issued_at,
    )
    return HibeAuthorityUpdateResult(
        group=group,
        id_path=cipher_inst.id_path(),
        path_epoch=cipher_inst.path_epoch(),
        assertion=assertion,
    )


def _hibe_grant_digests(
    proof: KeyBindingProofV1,
    *,
    reader_did: str,
    group: str,
    id_path: str,
) -> tuple[str, str]:
    proof_digest = _proof_digest(proof)
    grant_digest = _hibe_grant_digest_from_fields(
        proof_digest=proof_digest,
        reader_did=reader_did,
        ceremony_id=proof.ceremony_id,
        group=group,
        id_path=id_path,
    )
    return proof_digest, grant_digest


def _hibe_grant_digest_from_fields(
    *,
    proof_digest: str,
    reader_did: str,
    ceremony_id: str,
    group: str,
    id_path: str,
) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical_bytes(
            {
                "version": 1,
                "purpose": "hibe-reader-grant",
                "proof_digest": proof_digest,
                "reader_did": reader_did,
                "ceremony_id": ceremony_id,
                "group": group,
                "id_path": id_path,
            }
        )
    ).hexdigest()


def _retained_hibe_grant_path(store: Any, grant_digest: str) -> Path:
    return store.state_root / "hibe-grants" / f"{grant_digest.removeprefix('sha256:')}.tnpkg"


def _recover_committed_hibe_grant(
    store: Any,
    challenge: EnrollmentChallengeV1,
    proof: KeyBindingProofV1,
    *,
    reader_did: str,
    group: str,
    id_path: str,
) -> Path | None:
    proof_digest, grant_digest = _hibe_grant_digests(
        proof,
        reader_did=reader_did,
        group=group,
        id_path=id_path,
    )
    with store._lock():
        _assert_hibe_challenge_generation_locked(store, challenge)
        current = store._load_consumed(challenge.challenge_id)
        if current is None:
            return None
        if current.get("kind") != "hibe-reader-grant":
            raise TrustError(
                TrustReason.CHALLENGE_REPLAYED,
                "HIBE reader challenge has already been consumed",
            )
        if (
            current.get("proof_digest") != proof_digest
            or current.get("grant_digest") != grant_digest
        ):
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "HIBE reader challenge was consumed by a different signed proof or grant",
            )
        artifact_digest = current.get("artifact_digest")
        retained_path = _retained_hibe_grant_path(store, grant_digest)
        if not isinstance(artifact_digest, str) or not retained_path.exists():
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "committed HIBE grant is missing its retained delivery artifact",
            )
        retained_bytes = retained_path.read_bytes()
        actual_digest = "sha256:" + hashlib.sha256(retained_bytes).hexdigest()
        if actual_digest != artifact_digest:
            raise TrustError(
                TrustReason.BODY_DIGEST_MISMATCH,
                "retained HIBE grant artifact does not match committed digest",
            )
        registry = [
            item
            for item in _hibe_grants_load(store.cfg, group)
            if item.get("reader_did") == reader_did
        ]
        if len(registry) != 1 or any(
            registry[0].get(key) != expected
            for key, expected in (
                ("proof_digest", proof_digest),
                ("grant_digest", grant_digest),
                ("artifact_digest", artifact_digest),
            )
        ):
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "committed HIBE grant does not match retained verified-reader state",
            )
        return retained_path


def _commit_hibe_grant(
    store: Any,
    challenge: EnrollmentChallengeV1,
    proof: KeyBindingProofV1,
    *,
    reader_did: str,
    group: str,
    id_path: str,
    package_bytes: bytes,
    principal: VerifiedPrincipal,
    delegated_subauthority: bool,
) -> Path:
    proof_digest, grant_digest = _hibe_grant_digests(
        proof,
        reader_did=reader_did,
        group=group,
        id_path=id_path,
    )
    artifact_digest = "sha256:" + hashlib.sha256(package_bytes).hexdigest()
    retained_path = _retained_hibe_grant_path(store, grant_digest)
    from .._keystore_backend import atomic_write_bytes

    with store._lock():
        _assert_hibe_challenge_generation_locked(store, challenge)
        current = store._load_consumed(challenge.challenge_id)
        if current is not None:
            # Release/reacquire through the recovery helper would deadlock, so
            # classify the concurrent winner directly here.
            if (
                current.get("kind") == "hibe-reader-grant"
                and current.get("proof_digest") == proof_digest
                and current.get("grant_digest") == grant_digest
            ):
                return retained_path
            raise TrustError(
                TrustReason.REPLAY_CONFLICT,
                "HIBE reader challenge was concurrently consumed by another grant",
            )
        atomic_write_bytes(retained_path, package_bytes)
        _hibe_grants_update(
            store.cfg,
            group,
            reader_did,
            id_path,
            principal=principal,
            unsafe=False,
            delegated_subauthority=delegated_subauthority,
            grant_digest=grant_digest,
            artifact_digest=artifact_digest,
        )
        record = {
            "version": 1,
            "kind": "hibe-reader-grant",
            "challenge_id": challenge.challenge_id,
            "proof_digest": proof_digest,
            "grant_digest": grant_digest,
            "artifact_digest": artifact_digest,
        }
        atomic_write_bytes(
            store._consumed_path(challenge.challenge_id),
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        )
    return retained_path


def _deliver_hibe_grant(source: Path, destination: Path) -> None:
    from .._keystore_backend import atomic_write_bytes

    atomic_write_bytes(destination, source.read_bytes())


def _hibe_lifecycle_lock_path(cfg: Any, group: str) -> Path:
    lock_root = (Path(cfg.keystore).resolve() / ".hibe-lifecycle").resolve()
    component = hashlib.sha256(group.encode("utf-8")).hexdigest()
    candidate = (lock_root / f"{component}.lock").resolve()
    if not candidate.is_relative_to(lock_root):
        raise TrustError(
            TrustReason.SCOPE_MISMATCH,
            "HIBE lifecycle lock escaped the keystore lock root",
        )
    return candidate


def _hibe_revocation_active_path(cfg: Any, group: str) -> Path:
    return Path(cfg.keystore) / f"{group}.hibe.revocation.active.json"


def grant_reader(
    group: str,
    *,
    reader_did: str | None = None,
    id_path: str | None = None,
    out_path: Path | str | None = None,
    cfg: Any | None = None,
    proof: KeyBindingProofV1 | VerifiedPrincipal | None = None,
    allow_subauthority: bool = False,
    unsafe_plaintext: bool = False,
) -> AddRecipientResult:
    """Mint and deliver one HIBE reader capability under the lifecycle lock."""
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    _require_hibe_cipher(group, cfg, require_authority=True)
    from .._keystore_backend import AdvisoryFileLock

    with AdvisoryFileLock(_hibe_lifecycle_lock_path(cfg, group)):
        _require_hibe_cipher(group, cfg, require_authority=True)
        if _hibe_revocation_active_path(cfg, group).exists():
            raise TrustError(
                TrustReason.EPOCH_CONFLICT,
                "HIBE reader lifecycle has an incomplete revocation; retry that exact "
                "revoke_reader operation before granting another reader",
            )
        return _grant_reader_locked(
            group,
            reader_did=reader_did,
            id_path=id_path,
            out_path=out_path,
            cfg=cfg,
            proof=proof,
            allow_subauthority=allow_subauthority,
            unsafe_plaintext=unsafe_plaintext,
        )


def _grant_reader_locked(
    group: str,
    *,
    reader_did: str | None = None,
    id_path: str | None = None,
    out_path: Path | str | None = None,
    cfg: Any | None = None,
    proof: KeyBindingProofV1 | VerifiedPrincipal | None = None,
    allow_subauthority: bool = False,
    unsafe_plaintext: bool = False,
) -> AddRecipientResult:
    """Mint and recipient-seal one HIBE bearer capability.

    Normal delivery requires a real Ed25519 ``did:key`` and an unexpired,
    exact-scope ``hibe-reader`` proof (or its retained verified record).
    Plaintext bearer delivery exists only behind ``unsafe_plaintext=True``.
    An ancestor grant is a delegated subauthority and additionally requires
    ``allow_subauthority=True``.
    """
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)

    target_path = id_path or cipher_inst.id_path()
    # Let the cipher boundary perform the complete canonical-path validation
    # before any package or registry write.
    from ..cipher import _normalize_hibe_path

    target_path = _normalize_hibe_path(target_path, what="id_path")
    active_parts = cipher_inst.id_path().split("/")
    target_parts = target_path.split("/")
    delegated_subauthority = (
        len(target_parts) < len(active_parts)
        and target_parts == active_parts[: len(target_parts)]
    )
    if target_path != cipher_inst.id_path() and not delegated_subauthority:
        raise ValueError(
            "tn.admin.grant_reader: id_path must be the active exact path or one of its ancestors"
        )
    if delegated_subauthority and not allow_subauthority:
        raise ValueError(
            "tn.admin.grant_reader: ancestor grants create a delegated subauthority; "
            "pass allow_subauthority=True explicitly"
        )

    verified: VerifiedPrincipal | None = None
    challenge_store: Any | None = None
    verified_challenge: EnrollmentChallengeV1 | None = None
    signed_proof: KeyBindingProofV1 | None = None
    recovery_path: Path | None = None
    verified_at = _now_utc(None)
    if reader_did is None:
        raise TrustError(TrustReason.DID_INVALID, "HIBE reader_did is required")
    parse_ed25519_did_key(reader_did)
    if unsafe_plaintext:
        from ..security_audit import (
            UnsafeOperation,
            UnsafeOperationNotice,
            UnsafeRelaxation,
            record_unsafe_operation,
        )

        class _AuditContext:
            writable = True

            @staticmethod
            def emit_admin(event_type: str, fields: dict[str, object]) -> None:
                from .. import info

                info(event_type, **fields)

        record_unsafe_operation(
            UnsafeOperationNotice(
                operation=UnsafeOperation.HIBE_GRANT,
                relaxations=(UnsafeRelaxation.PLAINTEXT_BEARER_DELIVERY,),
                group=group,
                subject_did=reader_did,
                artifact_digest=None,
            ),
            _AuditContext(),
        )
    else:
        if isinstance(proof, KeyBindingProofV1):
            challenge_digest = proof.binding.get("challenge_digest")
            if not isinstance(challenge_digest, str):
                raise TrustError(
                    TrustReason.CHALLENGE_MISSING,
                    "HIBE reader proof must bind an authority-issued challenge",
                )
            from ..enrollment import EnrollmentStore

            store = EnrollmentStore(cfg, cfg.device)
            challenge = store._load_challenge_for_digest(challenge_digest)
            _assert_hibe_challenge_generation(store, challenge)
            freshness_error: TrustError | None = None
            try:
                verified = verify_key_binding_proof(
                    proof,
                    expected_purpose="hibe-reader",
                    expected_audience_did=cfg.device.device_identity,
                    expected_ceremony_id=cfg.ceremony_id,
                    expected_group=group,
                    now=verified_at,
                    challenge=challenge,
                )
            except TrustError as exc:
                if exc.reason not in {
                    TrustReason.STATEMENT_EXPIRED,
                    TrustReason.CHALLENGE_EXPIRED,
                }:
                    raise
                freshness_error = exc
                # Authenticate the historical statement at its signed issue
                # time solely so an already committed exact artifact can be
                # recovered after a crash. This never authorizes a new grant.
                verified = verify_key_binding_proof(
                    proof,
                    expected_purpose="hibe-reader",
                    expected_audience_did=cfg.device.device_identity,
                    expected_ceremony_id=cfg.ceremony_id,
                    expected_group=group,
                    now=proof.issued_at,
                    challenge=challenge,
                )
            challenge_store = store
            verified_challenge = challenge
            signed_proof = proof
            recovery_path = _recover_committed_hibe_grant(
                store,
                challenge,
                proof,
                reader_did=reader_did,
                group=group,
                id_path=target_path,
            )
            if recovery_path is None and freshness_error is not None:
                raise freshness_error
        elif isinstance(proof, VerifiedPrincipal):
            retained = _retained_hibe_principal(
                cfg,
                group,
                reader_did,
                now=verified_at,
            )
            if retained != proof:
                raise TrustError(
                    TrustReason.UNTRUSTED_PRINCIPAL,
                    "caller-supplied VerifiedPrincipal does not match retained verified state",
                )
            verified = retained
        elif proof is None:
            verified = _retained_hibe_principal(
                cfg,
                group,
                reader_did,
                now=verified_at,
            )
        else:
            raise TrustError(TrustReason.STATEMENT_INVALID, "unsupported HIBE reader proof type")
        if verified.did != reader_did:
            raise TrustError(
                TrustReason.DID_SIGNER_MISMATCH,
                "HIBE reader proof signer does not match reader_did",
            )

    import re as _re

    if out_path is None:
        safe_stem = _re.sub(
            r"[^A-Za-z0-9._-]", "_",
            (reader_did or "reader").split(":")[-1],
        )
        out_path = Path.cwd() / f"{safe_stem}.tnpkg"
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if recovery_path is not None:
        _deliver_hibe_grant(recovery_path, out_path)
        return AddRecipientResult(
            leaf_index=None,
            kit_path=out_path,
            updated_cfg=None,
            unsafe=False,
            delegated_subauthority=delegated_subauthority,
        )
    sk = cipher_inst.mint_reader_key(target_path)

    import tempfile as _tempfile

    from .._pkg_impl import _export_impl

    with _tempfile.TemporaryDirectory(prefix="tn-grant-reader-") as td:
        td_path = Path(td)
        temp_package = td_path / "grant.tnpkg"
        key_dir = td_path / "keys"
        key_dir.mkdir()
        (key_dir / f"{group}.hibe.mpk").write_bytes(cipher_inst.mpk())
        (key_dir / f"{group}.hibe.idpath").write_text(
            target_path, encoding="utf-8"
        )
        (key_dir / f"{group}.hibe.sk").write_bytes(sk)
        _export_impl(
            temp_package,
            kind="kit_bundle",
            cfg=cfg,
            to_did=reader_did,
            keystore=key_dir,
            groups=[group],
            seal_for_recipient=not unsafe_plaintext,
            _manifest_state={
                "hibe_grant": {
                    "delivery": (
                        "unsafe-plaintext-bearer"
                        if unsafe_plaintext
                        else "recipient-seal-v1"
                    ),
                    "delegated_subauthority": delegated_subauthority,
                    "id_path": target_path,
                    "unsafe": unsafe_plaintext,
                }
            },
        )
        package_bytes = temp_package.read_bytes()
        if (
            challenge_store is not None
            and verified_challenge is not None
            and signed_proof is not None
            and reader_did is not None
            and verified is not None
        ):
            retained_path = _commit_hibe_grant(
                challenge_store,
                verified_challenge,
                signed_proof,
                reader_did=reader_did,
                group=group,
                id_path=target_path,
                package_bytes=package_bytes,
                principal=verified,
                delegated_subauthority=delegated_subauthority,
            )
            _deliver_hibe_grant(retained_path, out_path)
        else:
            if reader_did:
                _hibe_grants_update(
                    cfg,
                    group,
                    reader_did,
                    target_path,
                    principal=verified,
                    unsafe=unsafe_plaintext,
                    delegated_subauthority=delegated_subauthority,
                )
            from .._keystore_backend import atomic_write_bytes

            atomic_write_bytes(out_path, package_bytes)
    return AddRecipientResult(
        leaf_index=None,
        kit_path=out_path,
        updated_cfg=None,
        unsafe=unsafe_plaintext,
        delegated_subauthority=delegated_subauthority,
    )


def _hibe_grants_path(cfg: Any, group: str) -> Path:
    """The authority-side grant registry: who was granted which path.

    Lives next to the group's key files, never rides a kit (the export
    collector only matches ``.hibe.{mpk,idpath,sk}``), and is what
    ``revoke_reader`` uses to re-issue kits to the survivors."""
    return Path(cfg.keystore) / f"{group}.hibe.grants"


def _hibe_grants_load(cfg: Any, group: str) -> list[dict[str, Any]]:
    path = _hibe_grants_path(cfg, group)
    if not path.exists():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustError(TrustReason.STATEMENT_INVALID, "HIBE grant registry is unreadable") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TrustError(TrustReason.STATEMENT_INVALID, "HIBE grant registry must be a list")
    return value


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field_name} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field_name} is not RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TrustError(TrustReason.STATEMENT_INVALID, f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _validate_retained_hibe_principal(
    principal: VerifiedPrincipal,
    *,
    cfg: Any,
    group: str,
    reader_did: str,
    now: datetime | None,
) -> VerifiedPrincipal:
    parse_ed25519_did_key(principal.did)
    if principal.did != reader_did:
        raise TrustError(TrustReason.DID_SIGNER_MISMATCH, "retained HIBE principal DID differs")
    if principal.purpose != "hibe-reader":
        raise TrustError(TrustReason.BINDING_INVALID, "retained principal is not a HIBE reader")
    if principal.audience_did != cfg.device.device_identity:
        raise TrustError(TrustReason.WRONG_RECIPIENT, "retained HIBE principal names another authority")
    if principal.ceremony_id != cfg.ceremony_id or principal.group != group:
        raise TrustError(TrustReason.SCOPE_MISMATCH, "retained HIBE principal scope differs")
    if now is not None and (
        now < principal.issued_at.astimezone(timezone.utc)
        or now >= principal.expires_at.astimezone(timezone.utc)
    ):
        raise TrustError(TrustReason.STATEMENT_EXPIRED, "retained HIBE reader proof has expired")
    return principal


def _new_hibe_accepted_admission(
    cfg: Any,
    principal: VerifiedPrincipal,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "version": 1,
        "purpose": "hibe-reader-admission",
        "authority_did": cfg.device.device_identity,
        "reader_did": principal.did,
        "audience_did": principal.audience_did,
        "ceremony_id": principal.ceremony_id,
        "group": principal.group,
        "proof_digest": principal.proof_digest,
        "proof_issued_at": _format_utc(principal.issued_at),
        "proof_expires_at": _format_utc(principal.expires_at),
        "accepted_at": _format_utc(_now_utc(None)),
    }
    return {
        **unsigned,
        "signature_b64": base64.b64encode(
            cfg.device.sign(_canonical_bytes(unsigned))
        ).decode("ascii"),
    }


def _accepted_hibe_principal(
    cfg: Any,
    group: str,
    reader_did: str,
    record: dict[str, Any],
) -> VerifiedPrincipal:
    admission = record.get("accepted_admission")
    expected_fields = {
        "version",
        "purpose",
        "authority_did",
        "reader_did",
        "audience_did",
        "ceremony_id",
        "group",
        "proof_digest",
        "proof_issued_at",
        "proof_expires_at",
        "accepted_at",
        "signature_b64",
    }
    if not isinstance(admission, dict) or set(admission) != expected_fields:
        raise TrustError(
            TrustReason.UNTRUSTED_PRINCIPAL,
            "HIBE survivor lacks a durable accepted-admission statement",
        )
    if (
        record.get("verified") is not True
        or record.get("unsafe") is not False
        or admission.get("version") != 1
        or admission.get("purpose") != "hibe-reader-admission"
    ):
        raise TrustError(
            TrustReason.UNTRUSTED_PRINCIPAL,
            "HIBE survivor admission was not accepted through the verified ceremony",
        )
    if admission.get("authority_did") != cfg.device.device_identity:
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "HIBE accepted admission is not signed by this authority",
        )
    if admission.get("reader_did") != reader_did:
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "HIBE accepted admission names another reader",
        )
    if admission.get("audience_did") != cfg.device.device_identity:
        raise TrustError(
            TrustReason.WRONG_RECIPIENT,
            "HIBE accepted admission names another authority audience",
        )
    if admission.get("ceremony_id") != cfg.ceremony_id or admission.get("group") != group:
        raise TrustError(
            TrustReason.SCOPE_MISMATCH,
            "HIBE accepted admission ceremony or group differs",
        )
    for record_field in (
        "reader_did",
        "audience_did",
        "ceremony_id",
        "group",
        "proof_digest",
        "proof_issued_at",
        "proof_expires_at",
    ):
        if record.get(record_field) != admission.get(record_field):
            raise TrustError(
                TrustReason.BINDING_INVALID,
                f"HIBE accepted admission differs from registry field {record_field}",
            )
    accepted_at = _parse_utc(admission["accepted_at"], "accepted_at")
    proof_issued_at = _parse_utc(admission["proof_issued_at"], "proof_issued_at")
    proof_expires_at = _parse_utc(admission["proof_expires_at"], "proof_expires_at")
    if proof_expires_at <= proof_issued_at or accepted_at < proof_issued_at:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE accepted admission timestamps are inconsistent",
        )
    signature_b64 = admission["signature_b64"]
    if not isinstance(signature_b64, str):
        raise TrustError(TrustReason.SIGNATURE_INVALID, "HIBE admission signature is missing")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (TypeError, ValueError) as exc:
        raise TrustError(
            TrustReason.SIGNATURE_INVALID,
            "HIBE admission signature is malformed",
        ) from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_b64:
        raise TrustError(
            TrustReason.SIGNATURE_INVALID,
            "HIBE admission signature is not canonical Ed25519",
        )
    unsigned = {key: value for key, value in admission.items() if key != "signature_b64"}
    verify_ed25519_did_signature(
        str(admission["authority_did"]),
        _canonical_bytes(unsigned),
        signature,
    )
    principal = VerifiedPrincipal(
        did=reader_did,
        purpose="hibe-reader",
        audience_did=str(admission["audience_did"]),
        ceremony_id=str(admission["ceremony_id"]),
        group=str(admission["group"]),
        proof_digest=str(admission["proof_digest"]),
        issued_at=proof_issued_at,
        expires_at=proof_expires_at,
    )
    return _validate_retained_hibe_principal(
        principal,
        cfg=cfg,
        group=group,
        reader_did=reader_did,
        now=None,
    )


def _retained_hibe_principal(
    cfg: Any,
    group: str,
    reader_did: str,
    *,
    now: datetime,
) -> VerifiedPrincipal:
    matches = [
        item
        for item in _hibe_grants_load(cfg, group)
        if item.get("reader_did") == reader_did
    ]
    if len(matches) != 1 or matches[0].get("verified") is not True:
        raise TrustError(
            TrustReason.UNTRUSTED_PRINCIPAL,
            "HIBE reader requires a valid scoped proof or retained verified-reader record",
        )
    record = matches[0]
    try:
        principal = VerifiedPrincipal(
            did=str(record["reader_did"]),
            purpose="hibe-reader",
            audience_did=str(record["audience_did"]),
            ceremony_id=str(record["ceremony_id"]),
            group=str(record["group"]),
            proof_digest=str(record["proof_digest"]),
            issued_at=_parse_utc(record["proof_issued_at"], "proof_issued_at"),
            expires_at=_parse_utc(record["proof_expires_at"], "proof_expires_at"),
        )
    except KeyError as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "verified HIBE grant registry record is incomplete",
        ) from exc
    return _validate_retained_hibe_principal(
        principal,
        cfg=cfg,
        group=group,
        reader_did=reader_did,
        now=now,
    )


def _hibe_grants_update(
    cfg: Any,
    group: str,
    reader_did: str,
    id_path: str,
    *,
    principal: VerifiedPrincipal | None,
    unsafe: bool,
    delegated_subauthority: bool,
    grant_digest: str | None = None,
    artifact_digest: str | None = None,
) -> None:
    from .._keystore_backend import AdvisoryFileLock, atomic_write_bytes

    path = _hibe_grants_path(cfg, group)
    with AdvisoryFileLock(path.with_suffix(path.suffix + ".lock")):
        grants = [
            item
            for item in _hibe_grants_load(cfg, group)
            if item.get("reader_did") != reader_did
        ]
        record: dict[str, Any] = {
            "reader_did": reader_did,
            "id_path": id_path,
            "verified": principal is not None,
            "unsafe": unsafe,
            "delegated_subauthority": delegated_subauthority,
            "audience_did": principal.audience_did if principal is not None else None,
            "ceremony_id": principal.ceremony_id if principal is not None else cfg.ceremony_id,
            "group": group,
            "proof_digest": principal.proof_digest if principal is not None else None,
            "grant_digest": grant_digest,
            "artifact_digest": artifact_digest,
            "proof_issued_at": _format_utc(principal.issued_at) if principal is not None else None,
            "proof_expires_at": _format_utc(principal.expires_at) if principal is not None else None,
            "accepted_admission": (
                _new_hibe_accepted_admission(cfg, principal)
                if principal is not None
                else None
            ),
        }
        grants.append(record)
        atomic_write_bytes(
            path,
            json.dumps(grants, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            ),
        )


def _hibe_grants_replace(cfg: Any, group: str, grants: list[dict[str, Any]]) -> None:
    from .._keystore_backend import AdvisoryFileLock, atomic_write_bytes

    path = _hibe_grants_path(cfg, group)
    with AdvisoryFileLock(path.with_suffix(path.suffix + ".lock")):
        atomic_write_bytes(
            path,
            json.dumps(grants, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            ),
        )


def _hibe_registry_digest(grants: list[dict[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(grants)).hexdigest()


def _hibe_revocation_completed_path(cfg: Any, group: str, reader_did: str) -> Path:
    reader_hash = hashlib.sha256(reader_did.encode("utf-8")).hexdigest()
    return Path(cfg.keystore) / f"{group}.hibe.revocation.completed.{reader_hash}.json"


def _hibe_revocation_root(cfg: Any, operation_id: str) -> Path:
    return Path(cfg.keystore) / ".hibe-revocations" / operation_id.removeprefix("sha256:")


def _load_hibe_revocation_record(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            f"HIBE revocation record {path.name} is unreadable",
        ) from exc
    required = {
        "version",
        "operation_id",
        "group",
        "reader_did",
        "authority_did",
        "audience_did",
        "ceremony_id",
        "start_path",
        "start_epoch",
        "target_path",
        "target_epoch",
        "start_registry_digest",
        "target_registry_digest",
        "admission_generation",
        "assertion",
        "survivors",
        "rotation",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("version") != 1:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            f"HIBE revocation record {path.name} has an invalid shape",
        )
    return value


def _write_hibe_revocation_record(path: Path, value: dict[str, Any]) -> None:
    from .._keystore_backend import atomic_write_bytes

    atomic_write_bytes(
        path,
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        ),
    )


def _validate_hibe_revocation_record(
    intent: dict[str, Any],
    *,
    group: str,
    reader_did: str,
    requested_path: str | None,
    audience_did: str,
    cfg: LoadedConfig,
) -> KeyBindingProofV1:
    scalar_matches = (
        intent["group"] == group
        and intent["reader_did"] == reader_did
        and intent["authority_did"] == cfg.device.device_identity
        and intent["audience_did"] == audience_did
        and intent["ceremony_id"] == cfg.ceremony_id
    )
    if not scalar_matches or (
        requested_path is not None and intent["target_path"] != requested_path
    ):
        raise TrustError(
            TrustReason.EPOCH_CONFLICT,
            "HIBE revocation retry does not match the retained lifecycle operation",
        )
    if (
        type(intent["start_epoch"]) is not int
        or type(intent["target_epoch"]) is not int
        or intent["target_epoch"] != intent["start_epoch"] + 1
        or type(intent["admission_generation"]) is not int
        or intent["admission_generation"] < 1
        or not isinstance(intent["start_path"], str)
        or not isinstance(intent["target_path"], str)
        or not isinstance(intent["survivors"], list)
        or not isinstance(intent["rotation"], dict)
    ):
        raise TrustError(TrustReason.STATEMENT_INVALID, "HIBE revocation record is invalid")
    operation_key = {
        "version": 1,
        "group": group,
        "reader_did": reader_did,
        "ceremony_id": cfg.ceremony_id,
        "authority_did": cfg.device.device_identity,
        "audience_did": audience_did,
        "start_epoch": intent["start_epoch"],
        "target_path": intent["target_path"],
    }
    expected_operation_id = "sha256:" + hashlib.sha256(
        _canonical_bytes(operation_key)
    ).hexdigest()
    if intent["operation_id"] != expected_operation_id:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE revocation operation identifier does not match its scope",
        )
    try:
        assertion = KeyBindingProofV1.from_dict(intent["assertion"])
    except (TypeError, TrustError) as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE revocation retained authority assertion is invalid",
        ) from exc
    if (
        assertion.subject_did != cfg.device.device_identity
        or assertion.subject_did != intent["authority_did"]
    ):
        raise TrustError(
            TrustReason.DID_SIGNER_MISMATCH,
            "HIBE revocation assertion signer is not the retained authority",
        )
    verify_key_binding_proof(
        assertion,
        expected_purpose="hibe-authority",
        expected_audience_did=audience_did,
        expected_ceremony_id=cfg.ceremony_id,
        expected_group=group,
        now=assertion.issued_at,
        challenge=None,
    )
    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
    expected_binding = {
        "algorithm": "TN-BBG-HIBE-BLS12-381",
        "mpk_sha256": "sha256:" + hashlib.sha256(cipher_inst.mpk()).hexdigest(),
        "max_depth": cipher_inst.max_depth(),
        "id_path": intent["target_path"],
        "path_epoch": intent["target_epoch"],
    }
    if dict(assertion.binding) != expected_binding:
        raise TrustError(
            TrustReason.BINDING_INVALID,
            "HIBE revocation assertion does not bind the retained target state",
        )
    return assertion


def _renew_hibe_revocation_assertion_if_needed(
    intent: dict[str, Any],
    assertion: KeyBindingProofV1,
    *,
    record_path: Path,
    ttl: timedelta,
    cfg: LoadedConfig,
    checked_at: datetime,
) -> KeyBindingProofV1:
    if checked_at < assertion.expires_at.astimezone(timezone.utc):
        return assertion
    renewed = _build_hibe_authority_assertion(
        str(intent["group"]),
        audience_did=str(intent["audience_did"]),
        id_path=str(intent["target_path"]),
        path_epoch=int(intent["target_epoch"]),
        ttl=ttl,
        cfg=cfg,
        issued_at=checked_at,
    )
    intent["assertion"] = renewed._wire_value(include_signature=True)
    _write_hibe_revocation_record(record_path, intent)
    return renewed


def _build_hibe_revocation_package(
    *,
    cfg: LoadedConfig,
    group: str,
    reader_did: str,
    id_path: str,
    sk: bytes,
    delegated_subauthority: bool,
) -> bytes:
    import tempfile as _tempfile

    from .._pkg_impl import _export_impl

    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
    with _tempfile.TemporaryDirectory(prefix="tn-hibe-revoke-stage-") as td:
        td_path = Path(td)
        package = td_path / "survivor.tnpkg"
        key_dir = td_path / "keys"
        key_dir.mkdir()
        (key_dir / f"{group}.hibe.mpk").write_bytes(cipher_inst.mpk())
        (key_dir / f"{group}.hibe.idpath").write_text(id_path, encoding="utf-8")
        (key_dir / f"{group}.hibe.sk").write_bytes(sk)
        _export_impl(
            package,
            kind="kit_bundle",
            cfg=cfg,
            to_did=reader_did,
            keystore=key_dir,
            groups=[group],
            seal_for_recipient=True,
            _manifest_state={
                "hibe_grant": {
                    "delivery": "recipient-seal-v1",
                    "delegated_subauthority": delegated_subauthority,
                    "id_path": id_path,
                    "unsafe": False,
                }
            },
        )
        return package.read_bytes()


def _prepare_hibe_revocation(
    *,
    cfg: LoadedConfig,
    group: str,
    reader_did: str,
    grants: list[dict[str, Any]],
    remaining: list[dict[str, Any]],
    principals: dict[str, VerifiedPrincipal],
    admission_generation: int,
    target_path: str,
    audience_did: str,
    ttl: timedelta,
    issued_at: datetime,
) -> dict[str, Any]:
    from .._keystore_backend import atomic_write_bytes
    from ..cipher import _encode_hibe_history_path

    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
    start_path = cipher_inst.id_path()
    start_epoch = cipher_inst.path_epoch()
    target_epoch = start_epoch + 1
    operation_key = {
        "version": 1,
        "group": group,
        "reader_did": reader_did,
        "ceremony_id": cfg.ceremony_id,
        "authority_did": cfg.device.device_identity,
        "audience_did": audience_did,
        "start_epoch": start_epoch,
        "target_path": target_path,
    }
    operation_id = "sha256:" + hashlib.sha256(_canonical_bytes(operation_key)).hexdigest()
    root = _hibe_revocation_root(cfg, operation_id)

    current_sk_path = Path(cfg.keystore) / f"{group}.hibe.sk"
    if not current_sk_path.exists():
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE authority is missing its current identity key",
        )
    prior_sk = current_sk_path.read_bytes()
    target_sk = cipher_inst.mint_reader_key(target_path)
    history_path = Path(cfg.keystore) / f"{group}.hibe.idpath.history"
    old_history = history_path.read_bytes() if history_path.exists() else b""
    staged_history = _encode_hibe_history_path(start_path).encode("utf-8") + b"\n" + old_history
    rotation_files = {
        "target_sk": "target.sk",
        "prior_sk": "prior.sk",
        "start_history": "start-history.txt",
        "history": "history.txt",
    }
    rotation_bytes = {
        "target_sk": target_sk,
        "prior_sk": prior_sk,
        "start_history": old_history,
        "history": staged_history,
    }
    rotation: dict[str, Any] = {}
    for key, filename in rotation_files.items():
        data = rotation_bytes[key]
        atomic_write_bytes(root / filename, data)
        rotation[key] = {
            "file": filename,
            "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        }

    survivors: list[dict[str, Any]] = []
    target_grants: list[dict[str, Any]] = []
    import re as _re

    for record in remaining:
        did = str(record["reader_did"])
        delegated = bool(record.get("delegated_subauthority", False))
        survivor_path = str(record["id_path"]) if delegated else target_path
        survivor_sk = cipher_inst.mint_reader_key(survivor_path)
        package_bytes = _build_hibe_revocation_package(
            cfg=cfg,
            group=group,
            reader_did=did,
            id_path=survivor_path,
            sk=survivor_sk,
            delegated_subauthority=delegated,
        )
        reader_hash = hashlib.sha256(did.encode("utf-8")).hexdigest()
        artifact_file = f"reader-{reader_hash}.tnpkg"
        atomic_write_bytes(root / artifact_file, package_bytes)
        artifact_digest = "sha256:" + hashlib.sha256(package_bytes).hexdigest()
        updated_record = dict(record)
        updated_record.update(
            id_path=survivor_path,
            verified=True,
            unsafe=False,
            artifact_digest=artifact_digest,
            audience_did=principals[did].audience_did,
            ceremony_id=principals[did].ceremony_id,
            group=group,
            proof_digest=principals[did].proof_digest,
            proof_issued_at=_format_utc(principals[did].issued_at),
            proof_expires_at=_format_utc(principals[did].expires_at),
        )
        updated_record["grant_digest"] = _hibe_grant_digest_from_fields(
            proof_digest=principals[did].proof_digest,
            reader_did=did,
            ceremony_id=principals[did].ceremony_id,
            group=group,
            id_path=survivor_path,
        )
        target_grants.append(updated_record)
        safe_stem = _re.sub(r"[^A-Za-z0-9._-]", "_", did.split(":")[-1])
        survivors.append(
            {
                "reader_did": did,
                "artifact_file": artifact_file,
                "artifact_digest": artifact_digest,
                "output_name": f"{safe_stem}.tnpkg",
                "registry_record": updated_record,
            }
        )

    assertion = _build_hibe_authority_assertion(
        group,
        audience_did=audience_did,
        id_path=target_path,
        path_epoch=target_epoch,
        ttl=ttl,
        cfg=cfg,
        issued_at=issued_at,
    )
    intent = {
        "version": 1,
        "operation_id": operation_id,
        "group": group,
        "reader_did": reader_did,
        "authority_did": cfg.device.device_identity,
        "audience_did": audience_did,
        "ceremony_id": cfg.ceremony_id,
        "start_path": start_path,
        "start_epoch": start_epoch,
        "target_path": target_path,
        "target_epoch": target_epoch,
        "start_registry_digest": _hibe_registry_digest(grants),
        "target_registry_digest": _hibe_registry_digest(target_grants),
        "admission_generation": admission_generation,
        "assertion": assertion._wire_value(include_signature=True),
        "survivors": survivors,
        "rotation": rotation,
    }
    _write_hibe_revocation_record(_hibe_revocation_active_path(cfg, group), intent)
    return intent


def _read_retained_hibe_revocation_bytes(
    *,
    cfg: LoadedConfig,
    intent: dict[str, Any],
    filename: str,
    expected_digest: str,
) -> bytes:
    if (
        not isinstance(filename, str)
        or Path(filename).name != filename
        or not isinstance(expected_digest, str)
    ):
        raise TrustError(TrustReason.STATEMENT_INVALID, "HIBE revocation artifact is invalid")
    path = _hibe_revocation_root(cfg, str(intent["operation_id"])) / filename
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise TrustError(
            TrustReason.STATEMENT_INVALID,
            "HIBE revocation retained artifact is missing",
        ) from exc
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    if actual != expected_digest:
        raise TrustError(
            TrustReason.BODY_DIGEST_MISMATCH,
            "HIBE revocation retained artifact digest differs",
        )
    return data


def _commit_hibe_revocation(
    *,
    cfg: LoadedConfig,
    group: str,
    intent: dict[str, Any],
) -> None:
    from .._keystore_backend import atomic_write_bytes
    from ..cipher import HibeGroupCipher, _hibe_path_epoch_path, _hibe_root_marker_path
    from ..enrollment import EnrollmentStore

    store = EnrollmentStore(cfg, cfg.device)
    if _current_hibe_admission_generation(store, group) != intent["admission_generation"]:
        raise TrustError(
            TrustReason.EPOCH_CONFLICT,
            "HIBE admission generation moved outside the retained revocation transaction",
        )

    current_grants = _hibe_grants_load(cfg, group)
    current_digest = _hibe_registry_digest(current_grants)
    allowed_registry_digests = {
        str(intent["start_registry_digest"]),
        str(intent["target_registry_digest"]),
    }
    if current_digest not in allowed_registry_digests:
        raise TrustError(
            TrustReason.EPOCH_CONFLICT,
            "HIBE grant registry changed outside the retained revocation transaction",
        )
    rotation = intent["rotation"]
    if not isinstance(rotation, dict) or set(rotation) != {
        "target_sk",
        "prior_sk",
        "start_history",
        "history",
    }:
        raise TrustError(TrustReason.STATEMENT_INVALID, "HIBE revocation rotation state is invalid")
    retained: dict[str, bytes] = {}
    for key in ("target_sk", "prior_sk", "start_history", "history"):
        descriptor = rotation[key]
        if not isinstance(descriptor, dict) or set(descriptor) != {"file", "sha256"}:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "HIBE revocation rotation artifact is invalid",
            )
        retained[key] = _read_retained_hibe_revocation_bytes(
            cfg=cfg,
            intent=intent,
            filename=str(descriptor["file"]),
            expected_digest=str(descriptor["sha256"]),
        )

    operation_hex = str(intent["operation_id"]).removeprefix("sha256:")
    keystore = Path(cfg.keystore)
    prior_archive_path = keystore / f"{group}.hibe.sk.previous.revocation.{operation_hex}"
    current_sk_path = keystore / f"{group}.hibe.sk"
    history_path = keystore / f"{group}.hibe.idpath.history"
    id_path_path = keystore / f"{group}.hibe.idpath"
    epoch_path = _hibe_path_epoch_path(keystore, group)

    def reject_foreign(
        path: Path,
        actual: bytes | None,
        allowed: set[bytes | None],
    ) -> None:
        if actual not in allowed:
            raise TrustError(
                TrustReason.EPOCH_CONFLICT,
                f"HIBE revocation found foreign bytes in {path.name}",
            )

    archive_bytes = prior_archive_path.read_bytes() if prior_archive_path.exists() else None
    reject_foreign(prior_archive_path, archive_bytes, {None, retained["prior_sk"]})
    try:
        current_sk_bytes = current_sk_path.read_bytes()
        id_path_bytes = id_path_path.read_bytes()
        epoch_bytes = epoch_path.read_bytes()
    except OSError as exc:
        raise TrustError(
            TrustReason.EPOCH_CONFLICT,
            "HIBE revocation live authority state is incomplete",
        ) from exc
    reject_foreign(
        current_sk_path,
        current_sk_bytes,
        {retained["prior_sk"], retained["target_sk"]},
    )
    reject_foreign(
        id_path_path,
        id_path_bytes,
        {
            str(intent["start_path"]).encode("utf-8"),
            str(intent["target_path"]).encode("utf-8"),
        },
    )
    reject_foreign(
        epoch_path,
        epoch_bytes,
        {
            f"{int(intent['start_epoch'])}\n".encode("ascii"),
            f"{int(intent['target_epoch'])}\n".encode("ascii"),
        },
    )
    history_bytes = history_path.read_bytes() if history_path.exists() else None
    allowed_history: set[bytes | None] = {retained["start_history"], retained["history"]}
    if retained["start_history"] == b"":
        allowed_history.add(None)
    reject_foreign(history_path, history_bytes, allowed_history)

    cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
    if cipher_inst.path_epoch() not in {
        int(intent["start_epoch"]),
        int(intent["target_epoch"]),
    } or cipher_inst.id_path() not in {
        str(intent["start_path"]),
        str(intent["target_path"]),
    }:
        raise TrustError(
            TrustReason.EPOCH_CONFLICT,
            "HIBE authority state moved outside the retained revocation transaction",
        )

    atomic_write_bytes(
        prior_archive_path,
        retained["prior_sk"],
    )
    atomic_write_bytes(history_path, retained["history"])
    atomic_write_bytes(current_sk_path, retained["target_sk"])
    atomic_write_bytes(
        id_path_path,
        str(intent["target_path"]).encode("utf-8"),
    )
    atomic_write_bytes(
        epoch_path,
        f"{int(intent['target_epoch'])}\n".encode("ascii"),
    )
    _hibe_root_marker_path(keystore, group).unlink(missing_ok=True)
    cfg.groups[group].cipher = HibeGroupCipher.load(keystore, group)
    _reload_native_group_cipher(group)

    if current_digest == intent["start_registry_digest"]:
        target_grants = []
        for survivor in intent["survivors"]:
            if not isinstance(survivor, dict) or not isinstance(
                survivor.get("registry_record"), dict
            ):
                raise TrustError(
                    TrustReason.STATEMENT_INVALID,
                    "HIBE revocation survivor record is invalid",
                )
            target_grants.append(dict(survivor["registry_record"]))
        if _hibe_registry_digest(target_grants) != intent["target_registry_digest"]:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "HIBE revocation target registry digest differs",
            )
        _hibe_grants_replace(cfg, group, target_grants)


def _deliver_hibe_revocation(
    *,
    cfg: LoadedConfig,
    intent: dict[str, Any],
    out_dir: Path,
) -> list[Path]:
    from .._keystore_backend import atomic_write_bytes

    delivered: list[Path] = []
    for survivor in intent["survivors"]:
        if not isinstance(survivor, dict):
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "HIBE revocation survivor artifact is invalid",
            )
        data = _read_retained_hibe_revocation_bytes(
            cfg=cfg,
            intent=intent,
            filename=str(survivor.get("artifact_file")),
            expected_digest=str(survivor.get("artifact_digest")),
        )
        output_name = survivor.get("output_name")
        if not isinstance(output_name, str) or Path(output_name).name != output_name:
            raise TrustError(
                TrustReason.STATEMENT_INVALID,
                "HIBE revocation survivor output name is invalid",
            )
        destination = out_dir / output_name
        atomic_write_bytes(destination, data)
        delivered.append(destination)
    return delivered


def _finish_hibe_revocation(
    *,
    cfg: LoadedConfig,
    group: str,
    reader_did: str,
    intent: dict[str, Any],
) -> None:
    completed_path = _hibe_revocation_completed_path(cfg, group, reader_did)
    _write_hibe_revocation_record(completed_path, intent)
    _hibe_revocation_active_path(cfg, group).unlink(missing_ok=True)


@dataclass
class RevokeReaderResult:
    """Structured return from ``tn.admin.revoke_reader`` (hibe groups).

    ``kit_paths`` are the re-issued ``.tnpkg`` kits for the surviving
    grantees — distribute them and have each survivor ``tn.absorb`` theirs.
    ``new_path`` is the identity path future seals use. External writers must
    remain quiesced until each has installed and durably acknowledged
    ``assertion`` at ``path_epoch``."""

    revoked: bool
    new_path: str
    kit_paths: list[Path]
    remaining: list[str]
    path_epoch: int
    assertion: KeyBindingProofV1 | None


def _bump_path(path: str) -> str:
    """Sibling successor of ``path``: bump a ``~r<n>`` counter on the last
    label (``policy-a`` → ``policy-a~r1`` → ``policy-a~r2``)."""
    import re as _re

    labels = path.split("/") if path else [""]
    m = _re.match(r"^(.*?)~r(\d+)$", labels[-1])
    if m:
        labels[-1] = f"{m.group(1)}~r{int(m.group(2)) + 1}"
    else:
        labels[-1] = f"{labels[-1]}~r1"
    return "/".join(labels)


def revoke_reader(
    group: str,
    reader_did: str,
    *,
    new_path: str | None = None,
    out_dir: Path | str | None = None,
    cfg: Any | None = None,
    audience_did: str | None = None,
    ttl: timedelta = timedelta(minutes=10),
    now: datetime | None = None,
) -> RevokeReaderResult:
    """Remove a hibe reader going FORWARD: rotate the group's identity path
    and re-issue kits to every other granted reader.

    Honest semantics (the cipher's, not this verb's): the revoked reader
    keeps everything sealed before the revocation — delegated keys are
    permanent, nothing can claw history back. This verb rotates THIS
    authority ceremony to ``new_path`` (default: a bumped sibling of the
    current path) and reissues survivor kits. It does not update external
    writers, which retain their own idpath and must authenticate/adopt the
    sibling before sealing again. Until every writer does so, an old
    exact-path key can still open stale-writer output. A reader holding an
    ancestor of the new path remains able to delegate down and is not
    revoked by this operation. Distribute the returned survivor kits and
    writer path update; use btn when routine per-reader cutoff is required.

    Operational cutoff invariant: quiesce every external writer before this
    call and do not resume fleet writes until every writer has successfully
    returned from ``install_authority_assertion`` for the returned exact epoch.
    The local writer fence enforces its persisted ACK; this process cannot
    remotely stop an offline/stale writer, so fleet coordination is mandatory.
    """
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    _require_hibe_cipher(group, cfg, require_authority=True)
    parse_ed25519_did_key(reader_did)
    resolved_audience = audience_did or cfg.device.device_identity
    parse_ed25519_did_key(resolved_audience)
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise TrustError(TrustReason.STATEMENT_INVALID, "authority assertion ttl must be positive")
    checked_at = _now_utc(now)
    from ..cipher import _normalize_hibe_path

    requested_path = (
        None if new_path is None else _normalize_hibe_path(new_path, what="new_path")
    )
    from .._keystore_backend import AdvisoryFileLock

    with AdvisoryFileLock(_hibe_lifecycle_lock_path(cfg, group)):
        cipher_inst = _require_hibe_cipher(group, cfg, require_authority=True)
        active_path = _hibe_revocation_active_path(cfg, group)
        intent = _load_hibe_revocation_record(active_path)
        record_path = active_path
        completed_retry = False

        if intent is None:
            grants = _hibe_grants_load(cfg, group)
            matching = [item for item in grants if item.get("reader_did") == reader_did]
            if len(matching) != 1:
                completed_path = _hibe_revocation_completed_path(cfg, group, reader_did)
                intent = _load_hibe_revocation_record(completed_path)
                if intent is None:
                    raise ValueError(
                        f"tn.admin.revoke_reader: {reader_did!r} has no recorded grant on "
                        f"group {group!r}. Grants made through tn.admin.grant_reader are "
                        f"recorded in {_hibe_grants_path(cfg, group).name}."
                    )
                record_path = completed_path
                completed_retry = True
            else:
                remaining = [g for g in grants if g.get("reader_did") != reader_did]
                target = requested_path or _bump_path(cipher_inst.id_path())
                target = _normalize_hibe_path(target, what="new_path")
                granted_path = _normalize_hibe_path(
                    str(matching[0].get("id_path")),
                    what="grant path",
                )
                grant_parts = granted_path.split("/")
                target_parts = target.split("/")
                if grant_parts == target_parts[: len(grant_parts)]:
                    # An ancestor capability derives into the target namespace;
                    # report the honest no-op without creating an intent.
                    return RevokeReaderResult(
                        revoked=False,
                        new_path=cipher_inst.id_path(),
                        kit_paths=[],
                        remaining=[str(item["reader_did"]) for item in grants],
                        path_epoch=cipher_inst.path_epoch(),
                        assertion=None,
                    )

                verified_survivors: dict[str, VerifiedPrincipal] = {}
                for item in remaining:
                    did = str(item.get("reader_did"))
                    verified_survivors[did] = _accepted_hibe_principal(
                        cfg,
                        group,
                        did,
                        item,
                    )
                from ..enrollment import EnrollmentStore

                admission_generation = _advance_hibe_admission_generation(
                    EnrollmentStore(cfg, cfg.device),
                    group,
                )
                intent = _prepare_hibe_revocation(
                    cfg=cfg,
                    group=group,
                    reader_did=reader_did,
                    grants=grants,
                    remaining=remaining,
                    principals=verified_survivors,
                    admission_generation=admission_generation,
                    target_path=target,
                    audience_did=resolved_audience,
                    ttl=ttl,
                    issued_at=checked_at,
                )

        assertion = _validate_hibe_revocation_record(
            intent,
            group=group,
            reader_did=reader_did,
            requested_path=requested_path,
            audience_did=resolved_audience,
            cfg=cfg,
        )
        assertion = _renew_hibe_revocation_assertion_if_needed(
            intent,
            assertion,
            record_path=record_path,
            ttl=ttl,
            cfg=cfg,
            checked_at=checked_at,
        )

        if completed_retry:
            if (
                cipher_inst.path_epoch() != intent["target_epoch"]
                or cipher_inst.id_path() != intent["target_path"]
            ):
                raise TrustError(
                    TrustReason.EPOCH_CONFLICT,
                    "completed HIBE revocation is no longer the active authority epoch",
                )
        else:
            _commit_hibe_revocation(cfg=cfg, group=group, intent=intent)

        if out_dir is None:
            ts = checked_at.strftime("%Y%m%dT%H%M%SZ")
            resolved_out_dir = Path.cwd() / f"hibe_regrant_{ts}"
        else:
            resolved_out_dir = Path(out_dir)
        kit_paths = _deliver_hibe_revocation(
            cfg=cfg,
            intent=intent,
            out_dir=resolved_out_dir,
        )
        if not completed_retry:
            _finish_hibe_revocation(
                cfg=cfg,
                group=group,
                reader_did=reader_did,
                intent=intent,
            )
        return RevokeReaderResult(
            revoked=True,
            new_path=str(intent["target_path"]),
            kit_paths=kit_paths,
            remaining=[str(item["reader_did"]) for item in intent["survivors"]],
            path_epoch=int(intent["target_epoch"]),
            assertion=assertion,
        )


def rotate_reader_path(group: str, new_path: str, *, cfg: Any | None = None) -> str:
    """Rotate a hibe group's identity path so FUTURE seals use ``new_path``.

    This is the hibe cipher's admission rotation, not btn-grade revocation:

    - Pre-rotation entries stay open forever for prior grantees (delegated
      keys are permanent).
    - A grantee holding a key for the exact old path loses access only to
      seals made by this updated ceremony (and external writers after they
      authenticate/adopt the new sibling path); one holding a key for an
      ANCESTOR of the new path keeps access.
    - Pick a sibling path (typically: bump the policy-hash leaf) — rotating
      to a DESCENDANT of the old path cuts off nobody, because old keys
      delegate down.

    Groups that need real forward revocation of an admitted reader should
    use btn (the default cipher). Returns the new path.
    """
    if cfg is None:
        from .. import current_config

        cfg = current_config()
    return rotate_hibe_path(group, new_path, cfg=cfg).id_path


def _reload_native_group_cipher(group: str) -> None:
    """After a rotation/revocation admin verb rewrote a group's keystore
    files, tell any bound native (Rust) runtime to rebuild that group's
    cipher so the next emit/read picks up the new identity path / epoch.
    No-op when the ceremony runs on the pure pipeline (no native runtime
    bound — the pure pipeline seals with the same in-memory cipher instance
    the verb just mutated, so it is never stale).

    A bound native runtime that FAILS to rebuild is a security failure,
    not a DX nit: it would keep sealing under the pre-rotation state, so
    the audience the caller just rotated away from could still open every
    subsequent entry. The callers are all explicit admin verbs the user
    awaits, so raise instead of continuing on the stale runtime."""
    import tn

    rt = getattr(tn, "_dispatch_rt", None)
    native = getattr(rt, "_rt", None) if rt is not None else None
    if native is None:
        return
    reload_fn = getattr(native, "reload_group_cipher", None)
    try:
        if reload_fn is None:
            raise AttributeError(
                "bound native runtime has no reload_group_cipher hook"
            )
        reload_fn(group)
    except Exception as exc:
        raise RuntimeError(
            f"rotation of group {group!r} is on disk, but the live runtime "
            f"failed to rebuild the group cipher and would keep sealing "
            f"under the PRE-rotation state. Do not emit until you rebind: "
            f"run tn.flush_and_close(); tn.init(...) to reload from disk."
        ) from exc


@dataclass
class RevokeRecipientResult:
    """Structured return from `tn.admin.revoke_recipient`.

    `revoked` is True on a successful cutoff. HIBE can return False when the
    recorded capability is an ancestor and therefore still derives into the
    proposed sibling path.
    `cipher` is the group's cipher. JWE revocations return the mutated
    `updated_cfg`; btn revocations don't. hibe revocations rotate the
    identity path and re-issue survivor kits — `new_path` and `kit_paths`
    carry that outcome; `path_epoch` and `authority_assertion` let external
    writers authenticate and pin the update (see ``revoke_reader`` for the
    honest semantics).
    """

    revoked: bool
    cipher: str
    updated_cfg: LoadedConfig | None = None
    new_path: str | None = None
    kit_paths: list[Path] | None = None
    path_epoch: int | None = None
    authority_assertion: KeyBindingProofV1 | None = None


def revoke_recipient(
    group: str,
    *,
    recipient: Any | None = None,
    leaf_index: int | None = None,
    recipient_did: str | None = None,
    audience_did: str | None = None,
    cfg: Any | None = None,
) -> RevokeRecipientResult:
    """Revoke a recipient.

    btn: pass ``leaf_index`` *or* ``recipient_did`` (the did is resolved
    to its active leaf via the admin log).
    JWE: pass ``recipient_did``.
    HIBE: pass ``recipient_did``. This routes to ``revoke_reader`` and only
    rotates the authority ceremony's local path. Pass an external writer's
    complete ``audience_did`` to make the returned authority assertion
    installable by that writer. External writers must authenticate/adopt the
    new sibling path before sealing, and an ancestor capability remains
    effective below its path.

    ``recipient=`` is the polymorphic shortcut — accepts a DID str, an
    int leaf, an ``AddRecipientResult`` from the matching add call, a
    contacts.yaml row dict, or any object with
    ``recipient_did`` / ``leaf_index`` attrs. Explicit ``leaf_index=`` /
    ``recipient_did=`` kwargs override the resolved fields.
    """
    if recipient is not None:
        resolved = _resolve_recipient(recipient)
        if leaf_index is None:
            leaf_index = resolved.leaf_index
        if recipient_did is None:
            recipient_did = resolved.recipient_did

    if cfg is None:
        from .. import current_config

        cfg = current_config()

    group_spec = cfg.groups.get(group)
    if group_spec is None:
        raise KeyError(f"unknown group: {group!r}")
    cipher = group_spec.cipher.name

    if cipher == "btn":
        if audience_did is not None:
            raise ValueError(
                "tn.admin.revoke_recipient: audience_did is hibe-only."
            )
        if leaf_index is None and recipient_did is None:
            raise ValueError(
                "tn.admin.revoke_recipient: btn group requires leaf_index "
                "or recipient_did."
            )
        if leaf_index is None:
            # recipient_did is not None here by the check above; narrow for
            # the type checker without a bare assert (stripped under -O).
            if recipient_did is None:  # pragma: no cover - guarded above
                raise ValueError(
                    "tn.admin.revoke_recipient: btn group requires leaf_index "
                    "or recipient_did."
                )
            leaf_index = _resolve_btn_did_to_leaf(group, recipient_did)
        # Inline the btn-runtime revoke flow (the old flat
        # tn.admin_revoke_recipient alias is gone in 0.2.0).
        from .. import _maybe_autoinit_load_only, _refresh_admin_cache_if_present, _require_dispatch
        _maybe_autoinit_load_only()
        _require_dispatch().revoke_recipient_btn(group, leaf_index)
        _refresh_admin_cache_if_present()
        return RevokeRecipientResult(revoked=True, cipher="btn", updated_cfg=None)

    elif cipher == "jwe":
        if audience_did is not None:
            raise ValueError(
                "tn.admin.revoke_recipient: audience_did is hibe-only."
            )
        if recipient_did is None:
            raise ValueError(
                "tn.admin.revoke_recipient: recipient_did required for JWE group."
            )
        if leaf_index is not None:
            raise ValueError(
                "tn.admin.revoke_recipient: leaf_index is btn-only; "
                "for JWE use recipient_did."
            )
        updated_cfg = _revoke_recipient_jwe_impl(cfg, group, recipient_did)
        return RevokeRecipientResult(revoked=True, cipher="jwe", updated_cfg=updated_cfg)

    elif cipher == "hibe":
        if recipient_did is None:
            raise ValueError(
                "tn.admin.revoke_recipient: recipient_did required for hibe group."
            )
        if leaf_index is not None:
            raise ValueError(
                "tn.admin.revoke_recipient: leaf_index is btn-only; "
                "for hibe use recipient_did."
            )
        res = revoke_reader(
            group,
            recipient_did,
            cfg=cfg,
            audience_did=audience_did,
        )
        return RevokeRecipientResult(
            revoked=res.revoked,
            cipher="hibe",
            updated_cfg=None,
            new_path=res.new_path,
            kit_paths=res.kit_paths,
            path_epoch=res.path_epoch,
            authority_assertion=res.assertion,
        )

    else:
        raise NotImplementedError(
            f"tn.admin.revoke_recipient: cipher {cipher!r} not yet supported."
        )


@dataclass
class RotateGroupResult:
    """Structured return from `tn.admin.rotate`.

    `cipher` is the group's cipher ("btn" or "jwe"). JWE rotations
    return `updated_cfg` (the mutated config); btn rotations don't
    expose a generation counter at this level (the runtime tracks it
    internally via the `tn.rotation.completed` admin event), so
    `generation` may be None.

    `cipher_actually_rotated` is the honest flag. Both ciphers rotate key
    material, so this is True for jwe and btn alike: jwe archives the active
    files and recreates the group with only the publisher self-recipient;
    btn mints a fresh master_seed + publisher_id and bumps the cipher epoch.
    """

    cipher: str
    generation: int | None = None
    updated_cfg: LoadedConfig | None = None
    cipher_actually_rotated: bool = False
    # Truth-telling fields. Populated for btn rotations; jwe
    # leaves them None for now (its own pubkey rename is a separate
    # piece of work).
    prior_publisher_id: bytes | None = None
    new_publisher_id: bytes | None = None
    prior_epoch: int | None = None
    new_epoch: int | None = None
    # Recipient identities whose kits were re-minted under the new
    # active state during this rotation. Empty if no enrolled recipients
    # other than the publisher.
    renewed_recipients: list[str] = field(default_factory=list)
    # Filesystem path where per-recipient .tnpkg bundles for the renewed
    # recipients were written. None if no recipients were renewed.
    renewal_output_dir: Path | None = None


def _renew_btn_recipients(
    cfg: LoadedConfig,
    group: str,
    *,
    new_epoch: int,
) -> tuple[list[str], Path | None]:
    """Mint a fresh kit for every active recipient in this group's
    yaml under the new (post-rotation) active state, and write a
    signed `.tnpkg` kit_bundle for each.

    Called immediately after the cipher has rotated. Reads the
    recipient list from yaml (the cipher class doesn't see it). Skips
    recipients whose `revoked_at` is set. Skips the publisher's own
    self-entry (their self-kit is already updated by the cipher's
    rotate()).

    Returns `(renewed_recipient_identities, output_dir_or_None)`. The
    output dir is `<keystore_parent>/rotations/<group>/<new_epoch>/`.
    Bundle filenames encode each recipient identity with `:` replaced
    by `_` for cross-platform filesystem safety. Operators distribute
    the bundles out-of-band; recipients absorb via `tn.absorb(<path>)`.

    Does NOT emit `tn.recipient.added` events — these recipients are
    already enrolled; we're renewing their cryptographic material
    under a new tree, not registering new readers. The
    `tn.rotation.completed` event lists them in its `renewed_recipients`
    field.
    """
    from .. import _pkg_impl

    publisher_id = cfg.device.device_identity

    # Canonical recipient registry is the admin event log, not yaml.
    # The raw-kit `add_recipient_btn` path mints kits + emits
    # tn.recipient.added events but doesn't always update yaml's
    # recipients[]. Read from the reducer-derived state so both the
    # tnpkg path (which updates yaml) and the raw-kit path (which
    # doesn't) flow through the same renewal loop.
    try:
        live_state = state(group=group)
    except Exception:  # noqa: BLE001
        live_state = {"recipients": []}
    recipients = live_state.get("recipients") or []

    targets: list[str] = []
    seen_targets: set[str] = set()
    for r in recipients:
        if not isinstance(r, dict):
            continue
        if r.get("active_status") in ("revoked", "retired"):
            continue
        rid = r.get("recipient_did") or r.get("recipient_identity")
        if not rid or rid == publisher_id:
            continue
        if rid in seen_targets:
            continue
        seen_targets.add(rid)
        targets.append(rid)

    if not targets:
        return ([], None)

    # Output dir: <keystore_parent>/rotations/<group>/<new_epoch>/
    # Epoch-indexed so multiple rotations don't collide and the
    # operator can tell which generation each bundle belongs to.
    out_dir = cfg.keystore.parent / "rotations" / group / str(new_epoch)
    out_dir.mkdir(parents=True, exist_ok=True)

    cipher_obj = cfg.groups[group].cipher  # BtnGroupCipher post-rotation
    renewed: list[str] = []

    import re as _re
    import tempfile as _tempfile

    for rid in targets:
        safe_stem = _re.sub(r"[^A-Za-z0-9._-]", "_", rid.split(":")[-1])
        bundle_path = out_dir / f"{safe_stem}.tnpkg"

        # Mint a fresh kit on the new active state. cipher_obj._state
        # was refreshed by BtnGroupCipher.rotate() to point at the new
        # active PublisherState.
        new_kit_bytes = cipher_obj._state.mint()
        cipher_obj._persist_state()

        # Wrap the raw kit bytes as a signed kit_bundle .tnpkg via the
        # existing export pipeline. The kit_bundle exporter discovers
        # `<group>.btn.mykit` files in the supplied keystore dir, so
        # we stage the new kit under that canonical filename in a temp
        # dir scoped to this recipient.
        with _tempfile.TemporaryDirectory(prefix="tn-renew-") as td:
            td_path = Path(td)
            (td_path / f"{group}.btn.mykit").write_bytes(new_kit_bytes)
            _pkg_impl._export_impl(
                bundle_path,
                kind="kit_bundle",
                cfg=cfg,
                to_did=rid,
                keystore=td_path,
                groups=[group],
            )
        renewed.append(rid)

    return (renewed, out_dir)


def _read_yaml_doc(yaml_path: Path) -> dict[str, Any]:
    """Read + parse yaml at `yaml_path`. Returns empty dict on missing
    file or non-mapping top-level. Used by recipient renewal which
    walks the recipients[] list."""
    import yaml as _yaml

    try:
        doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, _yaml.YAMLError):
        return {}
    return doc if isinstance(doc, dict) else {}


def rotate(
    group: str,
    *,
    revoke_did: str | None = None,
    pool_size: int | None = None,
    cfg: Any | None = None,
) -> RotateGroupResult:
    """Rotate group keys.

    Both ciphers rotate their active key material:

      - **JWE**: archives sender/mykey/recipients and recreates the group
        with only the publisher self-recipient. Every external reader must
        be re-enrolled before it receives post-rotation entries. Reusing an
        old reader public key also reuses that old private-key capability.

      - **btn**: drives `BtnGroupCipher.rotate()` which mints a fresh
        master_seed, derives a new publisher_id, bumps the cipher
        epoch, archives the prior state under
        `<group>.btn.state.retired.<epoch>`, and atomically promotes
        the new state into place. Pre-rotation recipient kits fail
        to decrypt post-rotation ciphertexts (publisher_id mismatch).

    `revoke_did` + `pool_size` are JWE-only.
    """
    if cfg is None:
        from .. import current_config

        cfg = current_config()

    group_spec = cfg.groups.get(group)
    if group_spec is None:
        raise KeyError(f"unknown group: {group!r}")
    cipher = group_spec.cipher.name

    if cipher == "btn":
        if revoke_did is not None or pool_size is not None:
            raise ValueError(
                "tn.admin.rotate: revoke_did and pool_size are JWE-only. "
                "For btn, call tn.admin.revoke_recipient(group, "
                "recipient_did=...) first, then tn.admin.rotate(group)."
            )
        cipher_result = group_spec.cipher.rotate()

        # Renew every active recipient: mint a fresh kit on the new
        # active state and write a signed .tnpkg bundle per recipient.
        # The cipher's rotate() already updated cfg.groups[group].cipher
        # in place, so this walks the new state. Skips the publisher's
        # self-entry (their self-kit is updated by the cipher's rotate).
        renewed_recipients, renewal_output_dir = _renew_btn_recipients(
            cfg, group, new_epoch=cipher_result.new_epoch,
        )

        # _rotate_impl now just runs the yaml-side index_epoch bump +
        # the truth-telling event emit. btn_cipher_result + the renewal
        # info flow into the emitted tn.rotation.completed fields.
        _rotate_impl(
            group,
            cfg=cfg,
            btn_cipher_result=cipher_result,
            renewed_recipients=renewed_recipients,
            renewal_output_dir=renewal_output_dir,
        )
        # rotate() wrote a fresh publisher state to disk, but a bound native
        # runtime still holds the pre-rotation cipher in memory — without this
        # the next in-process emit would seal at the OLD epoch (readable by the
        # audience we just rotated away from) until the process restarts. The
        # hibe reader-path verbs already do this; btn rotate must too.
        _reload_native_group_cipher(group)
        return RotateGroupResult(
            cipher="btn",
            generation=cipher_result.new_epoch,
            updated_cfg=None,
            cipher_actually_rotated=True,
            prior_publisher_id=cipher_result.prior_publisher_id,
            new_publisher_id=cipher_result.new_publisher_id,
            prior_epoch=cipher_result.prior_epoch,
            new_epoch=cipher_result.new_epoch,
            renewed_recipients=renewed_recipients,
            renewal_output_dir=renewal_output_dir,
        )

    elif cipher == "jwe":
        updated_cfg = _rotate_impl(
            group, revoke_did=revoke_did, pool_size=pool_size, cfg=cfg,
        )
        return RotateGroupResult(
            cipher="jwe",
            generation=None,
            updated_cfg=updated_cfg,
            cipher_actually_rotated=True,
        )

    elif cipher == "hibe":
        raise ValueError(
            f"tn.admin.rotate: group {group!r} uses cipher 'hibe'; this rotation "
            f"is btn/jwe-only. hibe groups rotate their identity path via "
            f"tn.admin.rotate_reader_path(group, new_path) (or revoke_reader(...) "
            f"to cut off a reader)."
        )

    else:
        raise NotImplementedError(
            f"tn.admin.rotate: cipher {cipher!r} not supported."
        )


# ====================================================================
# Runtime-singleton admin verbs. These dispatch through the active
# dispatch runtime established by tn.init() and read from the active
# log via the admin-aware reader. They live here so the admin namespace
# is self-contained.
# ====================================================================


def recipients(group: str, *, include_revoked: bool = False) -> list[dict[str, Any]]:
    """Return the current recipient map for `group` by replaying the log.

    Each entry is a dict with keys:
        leaf_index:     int
        recipient_did:  str | None    (None if the mint didn't name one)
        minted_at:      str (ISO-8601 UTC)
        kit_sha256:     str
        revoked:        bool          (True if a revocation event was seen)
        revoked_at:     str | None

    By default, only active (not-revoked) recipients are returned. Pass
    `include_revoked=True` to get all historical recipients including ones
    that have been revoked.

    Source of truth is the attested log — `tn.recipient.added` and
    `tn.recipient.revoked` events. Implementation delegates to
    :func:`state` (group-filtered) and reshapes the result to this
    function's narrower contract.
    """
    from .. import _surface

    _surface.info("tn.recipients(group=%r, include_revoked=%s)", group, include_revoked)
    full = state(group=group)
    out: list[dict[str, Any]] = []
    revoked_rows: list[dict[str, Any]] = []
    for r in full["recipients"]:
        is_revoked = r.get("active_status") in ("revoked", "retired")
        row = {
            "leaf_index": r["leaf_index"],
            "recipient_identity": r.get("recipient_identity"),
            "minted_at": r.get("minted_at"),
            "kit_sha256": r.get("kit_sha256"),
            "revoked": is_revoked,
            "revoked_at": r.get("revoked_at") or r.get("retired_at"),
        }
        if is_revoked:
            revoked_rows.append(row)
        else:
            out.append(row)
    out.sort(key=lambda r: r["leaf_index"])
    if include_revoked:
        revoked_rows.sort(key=lambda r: r["leaf_index"])
        out.extend(revoked_rows)
    return out


_ADMIN_EVENT_PREFIXES = (
    "tn.ceremony.",
    "tn.group.",
    "tn.recipient.",
    "tn.rotation.",
    "tn.coupon.",
    "tn.enrolment.",
    "tn.vault.",
)


def _is_admin_event(event_type: str) -> bool:
    return any(event_type.startswith(p) for p in _ADMIN_EVENT_PREFIXES)


def _merge_envelope_for_reducer(
    env: dict[str, Any], plaintext: dict[str, Any] | None
) -> dict[str, Any]:
    """Flatten the encrypted-payload fields onto the envelope so the
    reducer sees one dict.
    """
    merged: dict[str, Any] = dict(env)
    if plaintext:
        for group_fields in plaintext.values():
            if isinstance(group_fields, dict):
                merged.update(group_fields)
    return merged


def _fill_reducer_schema_defaults(
    event_type: str, merged: dict[str, Any]
) -> None:
    """Supply the schema defaults the Rust emitter omits.

    The catalog schema requires ``cipher`` on ``tn.recipient.added``
    and ``recipient_did`` on ``tn.recipient.revoked``, but the Rust
    emitter stores them as optional/implicit. Patch them here so the
    reducer's schema check passes without altering semantics.
    """
    if event_type == "tn.recipient.added":
        merged.setdefault("cipher", "btn")
    elif event_type == "tn.recipient.revoked":
        merged.setdefault("recipient_identity", None)


class _AdminStateBuilder:
    """Accumulates per-event reducer deltas into the
    ``tn.admin.state(...)`` return shape.

    One handler per reducer ``kind``. Each handler mutates the
    builder's state in place. The dispatch table avoids the long
    if/elif chain that drove the original ``state()`` complexity.
    """

    def __init__(self) -> None:
        self.state: dict[str, Any] = {
            "ceremony": None,
            "groups": [],
            "recipients": [],
            "rotations": [],
            "coupons": [],
            "enrolments": [],
            "vault_links": [],
        }
        self.by_leaf: dict[tuple[str, int], dict] = {}
        self.enrolments_by_peer: dict[tuple[str, str], dict] = {}
        self.vault_links_by_did: dict[str, dict] = {}

    def apply(self, delta: dict[str, Any], ts: Any) -> None:
        handler = self._HANDLERS.get(delta.get("kind"))
        if handler is not None:
            handler(self, delta, ts)

    def finalize(self) -> dict[str, Any]:
        self.state["recipients"] = list(self.by_leaf.values())
        self.state["enrolments"] = list(self.enrolments_by_peer.values())
        self.state["vault_links"] = list(self.vault_links_by_did.values())
        return self.state

    # ── per-kind handlers ───────────────────────────────────────

    def _on_ceremony_init(self, d: dict, ts: Any) -> None:
        self.state["ceremony"] = {
            "ceremony_id": d["ceremony_id"],
            "cipher": d["cipher"],
            "device_identity": d["device_identity"],
            "created_at": d["created_at"],
        }

    def _on_group_added(self, d: dict, ts: Any) -> None:
        self.state["groups"].append({
            "group": d["group"],
            "cipher": d["cipher"],
            "publisher_identity": d["publisher_identity"],
            "added_at": d["added_at"],
        })

    def _on_recipient_added(self, d: dict, ts: Any) -> None:
        leaf = d.get("leaf_index")
        if leaf is None:
            return
        self.by_leaf[(d["group"], leaf)] = {
            "group": d["group"],
            "leaf_index": leaf,
            "recipient_identity": d.get("recipient_identity"),
            "kit_sha256": d["kit_sha256"],
            "minted_at": ts,
            "active_status": "active",
            "revoked_at": None,
            "retired_at": None,
        }

    def _on_recipient_revoked(self, d: dict, ts: Any) -> None:
        leaf = d.get("leaf_index")
        if leaf is None:
            return
        rec = self.by_leaf.get((d["group"], leaf))
        if rec is not None:
            rec["active_status"] = "revoked"
            rec["revoked_at"] = ts

    def _on_rotation_completed(self, d: dict, ts: Any) -> None:
        self.state["rotations"].append({
            "group": d["group"],
            "cipher": d["cipher"],
            "generation": d["generation"],
            "previous_kit_sha256": d["previous_kit_sha256"],
            "rotated_at": d["rotated_at"],
        })
        # Retire any currently-active recipients in this group.
        for leaf_key, rec in self.by_leaf.items():
            if leaf_key[0] == d["group"] and rec["active_status"] == "active":
                rec["active_status"] = "retired"
                rec["retired_at"] = ts

    def _on_coupon_issued(self, d: dict, ts: Any) -> None:
        self.state["coupons"].append({
            "group": d["group"],
            "slot": d["slot"],
            "recipient_identity": d["recipient_identity"],
            "issued_to": d["issued_to"],
            "issued_at": ts,
        })

    def _on_enrolment_compiled(self, d: dict, ts: Any) -> None:
        self.enrolments_by_peer[(d["group"], d["peer_identity"])] = {
            "group": d["group"],
            "peer_identity": d["peer_identity"],
            "package_sha256": d["package_sha256"],
            "status": "offered",
            "compiled_at": d["compiled_at"],
            "absorbed_at": None,
        }

    def _on_enrolment_absorbed(self, d: dict, ts: Any) -> None:
        peer_key = (d["group"], d["publisher_identity"])
        existing = self.enrolments_by_peer.get(peer_key)
        if existing is not None:
            existing["status"] = "absorbed"
            existing["absorbed_at"] = d["absorbed_at"]
        else:
            self.enrolments_by_peer[peer_key] = {
                "group": d["group"],
                "peer_identity": d["publisher_identity"],
                "package_sha256": d["package_sha256"],
                "status": "absorbed",
                "compiled_at": None,
                "absorbed_at": d["absorbed_at"],
            }

    def _on_vault_linked(self, d: dict, ts: Any) -> None:
        self.vault_links_by_did[d["vault_identity"]] = {
            "vault_identity": d["vault_identity"],
            "project_id": d["project_id"],
            "linked_at": d["linked_at"],
            "unlinked_at": None,
        }

    def _on_vault_unlinked(self, d: dict, ts: Any) -> None:
        link = self.vault_links_by_did.get(d["vault_identity"])
        if link is not None:
            link["unlinked_at"] = d["unlinked_at"]

    _HANDLERS = {
        "ceremony_init":      _on_ceremony_init,
        "group_added":        _on_group_added,
        "recipient_added":    _on_recipient_added,
        "recipient_revoked":  _on_recipient_revoked,
        "rotation_completed": _on_rotation_completed,
        "coupon_issued":      _on_coupon_issued,
        "enrolment_compiled": _on_enrolment_compiled,
        "enrolment_absorbed": _on_enrolment_absorbed,
        "vault_linked":       _on_vault_linked,
        "vault_unlinked":     _on_vault_unlinked,
    }


def state(group: str | None = None) -> dict:
    """Return the full local admin state, derived by replaying the log
    through the Rust reducer.

    Shape matches the vault's GET /api/v1/projects/{id}/state endpoint:

        {
          "ceremony":    {...} | None,
          "groups":      [...],
          "recipients":  [...],
          "rotations":   [...],
          "coupons":     [...],
          "enrolments":  [...],
          "vault_links": [...],
        }

    If `group` is given, lists are filtered to that group; the ceremony
    dict is unchanged.
    """
    from .. import _maybe_autoinit_load_only, _read_raw_admin_aware, _surface, current_config

    _surface.info("tn.admin.state(group=%r)", group)
    _maybe_autoinit_load_only()
    import warnings

    try:
        from tn._native import core as tn_core
        have_rust_reducer = True
    except ImportError:
        have_rust_reducer = False

    builder = _AdminStateBuilder()

    if have_rust_reducer:
        from tn._native import core as tn_core
        for raw in _read_raw_admin_aware():
            env = raw["envelope"]
            event_type = env.get("event_type", "")
            if not _is_admin_event(event_type):
                continue
            merged = _merge_envelope_for_reducer(env, raw.get("plaintext"))
            _fill_reducer_schema_defaults(event_type, merged)
            ts = merged.get("timestamp")
            try:
                delta = tn_core.admin.reduce(merged)
            except ValueError as exc:
                warnings.warn(
                    f"tn.admin_state: admin event failed reduce: {event_type!r}: {exc}",
                    stacklevel=2,
                )
                continue
            builder.apply(delta, ts)

    state_dict = builder.finalize()

    # If no ceremony_init event was found in the log (common for btn ceremonies
    # where the Rust runtime writes ceremony info to the yaml, not the main log),
    # derive ceremony state from the current config as a fallback.
    if state_dict["ceremony"] is None:
        try:
            cfg = current_config()
            state_dict["ceremony"] = {
                "ceremony_id": cfg.ceremony_id,
                "cipher": cfg.cipher_name,
                "device_identity": cfg.device.device_identity,
                "created_at": None,
            }
        except RuntimeError:
            # current_config() raises RuntimeError when no init has happened.
            # That's the only fallback case worth swallowing here.
            pass

    if group is not None:
        # Filter lists to the given group. Ceremony is not filtered.
        # Use a distinct name from the tuple `key` used earlier in this
        # function so mypy's flow-typing doesn't conflate the two.
        for state_key in ("groups", "recipients", "rotations", "coupons", "enrolments"):
            state_dict[state_key] = [
                x for x in state_dict[state_key] if x.get("group") == group
            ]

    return state_dict


def add_agent_runtime(
    runtime_did: str,
    *,
    groups: list[str],
    out_path: str | Path,
    label: str | None = None,
) -> Path:
    """Mint kits for an LLM-runtime DID across all named groups + tn.agents.

    Equivalent to:

        for group in groups + ["tn.agents"]:
            tn.admin.add_recipient(
                group, recipient_did=runtime_did, out_path=kit_path_for(group)
            )
        tn.pkg.export(out_path, kind="kit_bundle", keystore=tempdir)

    The ``tn.agents`` group is always implicitly included (and de-duplicated
    if the caller passed it). Returns the absolute ``.tnpkg`` path.

    The runtime imports the bundle once via ``tn.pkg.absorb()``; from then on
    every ``tn.secure_read()`` call surfaces decrypted data + instructions.
    """
    from .. import _export_impl as export
    from .. import _logger, _maybe_autoinit_load_only, current_config

    _maybe_autoinit_load_only()

    import tempfile

    # Dedup: tn.agents is always added; if the caller passes it, don't
    # double-mint (tn.agents is always implicitly included).
    requested = [g for g in groups if g != "tn.agents"]
    requested = list(dict.fromkeys(requested))  # preserve order, drop dupes
    requested.append("tn.agents")

    cfg = current_config()

    # Mint kits into the publisher's own keystore (where ``add_recipient``
    # writes them). Then assemble a kit_bundle export, filtered to only
    # the groups we care about, by pointing ``export()`` at a temp dir
    # containing just those mykit files.
    with tempfile.TemporaryDirectory(prefix="tn-agent-bundle-") as td:
        td_path = Path(td)
        for gname in requested:
            if gname not in cfg.groups:
                raise ValueError(
                    f"tn.admin.add_agent_runtime: group {gname!r} is not "
                    f"declared in this ceremony's yaml (known: {sorted(cfg.groups)})"
                )
            # Mint into the temp dir using the canonical filename so
            # export(kind='kit_bundle') picks it up.
            kit_path = td_path / f"{gname}.btn.mykit"
            add_recipient(
                gname, recipient_did=runtime_did, out_path=kit_path,
            )

        # Build the bundle from the temp dir. Use kit_bundle kind so the
        # export carries readers-only material (no publisher private keys).
        out = export(
            out_path,
            kind="kit_bundle",
            cfg=cfg,
            to_did=runtime_did,
            keystore=td_path,
            groups=requested,
        )

        # Loud label: write a tiny sidecar so the bundle is identifiable
        # downstream. Best-effort; never fails the call.
        if label:
            try:
                sidecar = Path(out).with_suffix(Path(out).suffix + ".label")
                sidecar.write_text(label, encoding="utf-8")
            except OSError:
                _logger.exception(
                    "tn.admin_add_agent_runtime: failed to write label sidecar; continuing"
                )

    return Path(out)


def revoked_count(group: str) -> int:
    """Return the number of revoked recipients in `group`'s btn state.

    Requires a btn ceremony with the Rust runtime active (tn.using_rust() == True).
    """
    from .. import _maybe_autoinit_load_only, _require_dispatch

    _maybe_autoinit_load_only()
    return _require_dispatch().revoked_count_btn(group)
