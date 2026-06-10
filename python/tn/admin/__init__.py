"""Ceremony admin: group + recipient + rotation management.

These are the code-level equivalents of the admin CLI commands. Exposing
them as functions means library users can drive ceremony changes from
their own scripts / admin tools without shelling out.

Ciphers: `jwe` (static-ECDH + AES-KW + AES-GCM, pure Python) and `btn`
(NNL subset-difference broadcast, via the Rust `tn_core` extension). The
legacy `bgw` cipher was removed in Workstream G.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..config import (
    DEFAULT_POOL_SIZE,
    LoadedConfig,
    _create_group,
)

_log = logging.getLogger("tn.admin")


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

    Hot-reload behaviour (DX review #8): when the in-process logger
    runtime is bound, ``ensure_group`` reloads its view of the yaml
    after the write so subsequent ``tn.info(...)`` calls in the same
    process see the new group's routing. Prior to 0.4.2a2 callers
    had to ``tn.flush_and_close()`` + ``tn.init()`` to pick up the
    change.
    """
    internal_cipher = cipher if cipher is not None else cfg.cipher_name
    if internal_cipher not in ("jwe", "btn"):
        raise ValueError(f"ensure_group: unknown cipher {cipher!r}; expected 'jwe' or 'btn'")

    # Presence check differs per cipher.
    if internal_cipher == "btn":
        key_exists = (cfg.keystore / f"{group}.btn.state").exists()
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

    # DX review #8: rebind the live runtime's view of the yaml so the
    # next emit routes through the new group without forcing a full
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
# rotate (§7.5, §9)
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
           sender/mykey/recipients files renamed `.revoked.<ts>`.
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
    # Auto-emit enrolment package to outbox so the recipient has
    # something to absorb. Non-fatal: yaml mutation has already
    # succeeded; compile failure is logged and execution continues.
    try:
        from ..compile import compile_enrolment, emit_to_outbox

        emit_to_outbox(cfg, compile_enrolment(cfg, group, did))
    except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
        import logging

        logging.getLogger("tn.admin").warning(
            "add_recipient: compile_enrolment failed for %s in %s: %s. "
            "Recipient state was wired into the cipher successfully; only "
            "the enrolment package emission failed. Retry by calling "
            "tn.compile.compile_enrolment(cfg, %r, %r) directly, or let "
            "the next tn.init() _reconcile retry.",
            did,
            group,
            e,
            group,
            did,
        )
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
    """If the ceremony is linked AND TN_WALLET_AUTOSYNC=1, sync now.

    Never raises. Best-effort background hook. State-change operation
    has already succeeded locally before we're called; sync failures
    don't cascade. But unlike V1's silent-swallow, we now WRITE
    failures to a queue file at
      $XDG_STATE_HOME/tn/sync_queue/<ceremony_id>.jsonl
    so the user can inspect failed syncs via `tn wallet status` and
    drain them via `tn wallet sync --drain-queue`.
    """
    import os

    if os.environ.get("TN_WALLET_AUTOSYNC") != "1":
        return
    if not cfg.is_linked() and not getattr(cfg, "vault_enabled", False):
        return

    err_msg: str | None = None
    try:
        from .. import wallet as _wallet
        from ..identity import Identity, _default_identity_path
        from ..vault_client import VaultClient

        identity = Identity.load(_default_identity_path())
        link = _wallet.vault_link_info(cfg)
        if not link.enabled or not link.url:
            raise RuntimeError("ceremony has no vault.url; cannot sync")
        client = VaultClient.for_identity(identity, link.url)
        try:
            result = _wallet.sync_ceremony(cfg, client)
            if result.errors:
                err_msg = f"{len(result.errors)} per-file errors: {result.errors[:3]}"
        finally:
            client.close()
    except Exception as e:  # noqa: BLE001 — preserve broad swallow; see body of handler
        err_msg = f"{type(e).__name__}: {e}"

    if err_msg is not None:
        _append_sync_queue(cfg.ceremony_id, err_msg)


def _sync_queue_path(ceremony_id: str) -> Path:
    """$XDG_STATE_HOME/tn/sync_queue/<ceremony_id>.jsonl"""
    import os as _os
    from pathlib import Path as _Path

    override = _os.environ.get("TN_STATE_DIR")
    if override:
        base = _Path(override)
    else:
        xdg = _os.environ.get("XDG_STATE_HOME")
        if xdg:
            base = _Path(xdg) / "tn"
        elif _os.name == "nt":
            appdata = _os.environ.get("APPDATA") or str(_Path.home() / "AppData" / "Roaming")
            base = _Path(appdata) / "tn"
        else:
            base = _Path.home() / ".local" / "state" / "tn"
    return base / "sync_queue" / f"{ceremony_id}.jsonl"


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
# Wallet link state — §7 of the identity+wallet spec
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

    # YAML recipient entry shape (bgw cipher was removed in Workstream G).
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


def add_recipient(
    group: str,
    *,
    recipient: Any | None = None,
    recipient_did: str | None = None,
    out_path: Path | str | None = None,
    public_key: bytes | None = None,
    raw: bool = False,
    cfg: Any | None = None,
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
        Pass `public_key` (32-byte X25519 public key) and `cfg` (the
        LoadedConfig to mutate). Returns
        `AddRecipientResult(updated_cfg=cfg')`. `raw` is btn-only
        and ignored on JWE.

    For re-distributing kit material to an already-known recipient
    WITHOUT a new attestation event, use
    `tn.pkg.bundle_for_recipient` instead.

    `recipient_did` is optional in both cases (provided for the
    `tn.recipient.added` admin event's metadata).

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
            _export_impl(
                out_path,
                kind="kit_bundle",
                cfg=cfg,
                to_did=recipient_did,
                keystore=td_path,
                groups=[group],
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

    else:
        raise NotImplementedError(
            f"tn.admin.add_recipient: cipher {cipher!r} not yet supported."
        )


@dataclass
class RevokeRecipientResult:
    """Structured return from `tn.admin.revoke_recipient`.

    `revoked` is always True on a successful return (failures raise).
    `cipher` is the group's cipher ("btn" or "jwe"). JWE revocations
    return the mutated `updated_cfg`; btn revocations don't.
    """

    revoked: bool
    cipher: str
    updated_cfg: LoadedConfig | None = None


def revoke_recipient(
    group: str,
    *,
    recipient: Any | None = None,
    leaf_index: int | None = None,
    recipient_did: str | None = None,
    cfg: Any | None = None,
) -> RevokeRecipientResult:
    """Revoke a recipient.

    btn: pass ``leaf_index`` *or* ``recipient_did`` (the did is resolved
    to its active leaf via the admin log).
    JWE: pass ``recipient_did``.

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
        # Inline the btn-runtime revoke flow (was tn.admin_revoke_recipient
        # in pre-Stage-C; that flat alias is gone in 0.2.0).
        from .. import _maybe_autoinit_load_only, _refresh_admin_cache_if_present, _require_dispatch
        _maybe_autoinit_load_only()
        _require_dispatch().revoke_recipient_btn(group, leaf_index)
        _refresh_admin_cache_if_present()
        return RevokeRecipientResult(revoked=True, cipher="btn", updated_cfg=None)

    elif cipher == "jwe":
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

    0.4.2a10: `cipher_actually_rotated` is the honest flag. JWE
    rotation re-keys the cover set (forward-secret); the field is
    True. btn rotation today is metadata-only (epoch bump + self-kit
    refresh; the cipher's master_seed is unchanged); the field is
    False. The real btn cipher rotation lands in 0.4.3 — see
    `docs/superpowers/specs/2026-05-20-btn-cipher-rotation.md`.
    """

    cipher: str
    generation: int | None = None
    updated_cfg: LoadedConfig | None = None
    cipher_actually_rotated: bool = False
    # 0.4.3a1 truth-telling fields. Populated for btn rotations; jwe
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

    Both ciphers run a real forward-secret rotation as of 0.4.3a1:

      - **JWE**: the cover set is re-wrapped under fresh keys; old
        recipient kits no longer decrypt post-rotation entries.

      - **btn**: drives `BtnGroupCipher.rotate()` which mints a fresh
        master_seed, derives a new publisher_id, bumps the cipher
        epoch, archives the prior state under
        `<group>.btn.state.retired.<epoch>`, and atomically promotes
        the new state into place. Pre-rotation recipient kits fail
        to decrypt post-rotation ciphertexts (publisher_id mismatch).
        See `docs/superpowers/specs/2026-05-20-btn-cipher-rotation.md`.

    `revoke_did` + `pool_size` are JWE-only.

    Removed in 0.4.3a1: the `LooseRotationWarning` and the
    `acknowledge_loose=True` parameter from 0.4.2a10 — that warning
    was the stopgap for the metadata-only window before the cipher
    rotation actually landed. Both gone now; btn rotation is
    forward-secret.
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

    else:
        raise NotImplementedError(
            f"tn.admin.rotate: cipher {cipher!r} not yet supported."
        )


# ====================================================================
# Runtime-singleton admin verbs (moved from tn/__init__.py per spec
# section 6.4). These dispatch through the active dispatch runtime
# established by tn.init() and read from the active log via the
# admin-aware reader. They live here so the admin namespace is
# self-contained.
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
        import tn_core
        have_rust_reducer = True
    except ImportError:
        have_rust_reducer = False

    builder = _AdminStateBuilder()

    if have_rust_reducer:
        import tn_core
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

    Per the 2026-04-25 read-ergonomics spec section 2.8. Equivalent to:

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
    # double-mint (spec section 2.8: "always implicit-adds tn.agents").
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
