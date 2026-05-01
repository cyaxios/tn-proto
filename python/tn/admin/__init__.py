"""Ceremony admin: group + recipient + rotation management.

These are the code-level equivalents of the admin CLI commands. Exposing
them as functions means library users can drive ceremony changes from
their own scripts / admin tools without shelling out.

Ciphers: `jwe` (static-ECDH + AES-KW + AES-GCM, pure Python) and `btn`
(NNL subset-difference broadcast, via the Rust `tn_core` extension). The
legacy `bgw` cipher was removed in Workstream G.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..config import (
    DEFAULT_POOL_SIZE,
    LoadedConfig,
    _create_group,
)


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

    After calling this, the caller should `tn.flush_and_close()` + reopen
    with `tn.init()` so the logger picks up the new group.
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
            _update_yaml(cfg, lambda doc: _yaml_add_fields(doc, group, fields))
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

    _update_yaml(
        cfg,
        lambda doc: _yaml_add_group(
            doc,
            group,
            pool_size,
            cfg.device.did,
            fields,
            cipher_name=internal_cipher,
        ),
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
                    "publisher_did": cfg.device.did,
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
            "recipients": [{"did": me_did}],
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
) -> LoadedConfig:
    """Rotate a group's cipher: regenerate keys + bump index_epoch.

    Behavior differs per cipher:
      jwe: regenerates the sender X25519 key + recipient list. Old
           sender/mykey/recipients files renamed `.revoked.<ts>`.
      btn: regenerates the publisher state + self-kit. Old state/mykit
           files renamed `.revoked.<ts>` so pre-rotation entries stay
           readable by holders of the old kit (via the runtime's
           multi-kit read path).

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
    # renaming. Per-cipher priority:
    #   btn  -> <group>.btn.mykit   (reader kit, most stable cross-cipher proxy)
    #   jwe  -> <group>.jwe.mykey
    _prev_candidates: list[Path] = []
    if cfg.cipher_name == "btn":
        _prev_candidates = [cfg.keystore / f"{group}.btn.mykit"]
    else:  # jwe
        _prev_candidates = [cfg.keystore / f"{group}.jwe.mykey"]

    prev_kit_sha = "sha256:unknown"
    for _candidate in _prev_candidates:
        if _candidate.exists():
            try:
                prev_kit_sha = "sha256:" + _hashlib.sha256(_candidate.read_bytes()).hexdigest()
            except OSError:
                # File raced with rename or read permission denied; keep "unknown".
                pass
            break

    if cfg.cipher_name == "btn":
        # Preserve the old publisher state + self-kit so pre-rotation entries
        # stay readable by anyone who still holds the old kit (including the
        # publisher themselves, through the runtime's multi-kit read path).
        for suffix in ("btn.state", "btn.mykit"):
            src = cfg.keystore / f"{group}.{suffix}"
            if src.exists():
                _rename_revoked(src, ts)
    else:  # jwe
        for suffix in ("jwe.sender", "jwe.recipients", "jwe.mykey"):
            src = cfg.keystore / f"{group}.{suffix}"
            if src.exists():
                _rename_revoked(src, ts)

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

    _update_yaml(
        cfg,
        lambda doc: _yaml_rotate_group(
            doc,
            group,
            pool,
            cfg.device.did,
            revoke_did,
            new_epoch=new_group.index_epoch,
        ),
    )

    # Attested rotation event. Catalog-validated by the runtime before signing.
    if _lg._runtime is not None:
        # pool_size is not meaningful for jwe/btn; keep the field for schema
        # compat but omit actual values.
        _old_pool: int | None = None
        _new_pool: int | None = None
        _lg._require_init().emit(
            "info",
            "tn.rotation.completed",
            {
                "group": group,
                "cipher": cfg.cipher_name,
                "generation": new_group.index_epoch,
                "previous_kit_sha256": prev_kit_sha,
                "old_pool_size": _old_pool,
                "new_pool_size": _new_pool,
                "rotated_at": datetime.now(_tz.utc).isoformat(),
            },
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
            if not any(r.get("did") == did for r in recipients if isinstance(r, dict)):
                recipients.append({"did": did})

        _update_yaml(cfg, _mutate_pending)
        if _lg._runtime is not None:
            _lg._require_init().emit(
                "",
                "tn.recipient.intent_declared",
                {"group": group, "did": did},
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
        recipients = [r for r in recipients if r.get("did") != did]
        recipients.append(
            {
                "did": did,
                "pub_b64": base64.b64encode(pub_bytes).decode("ascii"),
            }
        )
        g["recipients"] = recipients

    _update_yaml(cfg, _mutate)

    if _lg._runtime is not None:
        _lg._require_init().emit(
            "",
            "tn.recipient.added",
            {"group": group, "added_did": did},
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
        g["recipients"] = [r for r in (g.get("recipients") or []) if r.get("did") != did]

    _update_yaml(cfg, _mutate)

    if _lg._runtime is not None:
        _lg._require_init().emit(
            "",
            "tn.recipient.revoked",
            {"group": group, "revoked_did": did},
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
    if not cfg.is_linked():
        return

    err_msg: str | None = None
    try:
        from .. import wallet as _wallet
        from ..identity import Identity, _default_identity_path
        from ..vault_client import VaultClient

        identity = Identity.load(_default_identity_path())
        if cfg.linked_vault is None:
            raise RuntimeError("ceremony has no linked_vault; cannot sync")
        client = VaultClient.for_identity(identity, cfg.linked_vault)
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
        pass  # last-resort swallow — telemetry isn't critical


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def _update_yaml(cfg: LoadedConfig, mutator) -> None:
    with open(cfg.yaml_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    mutator(doc)
    with open(cfg.yaml_path, "w", encoding="utf-8") as f:
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
        ceremony_block["mode"] = mode
        if mode == "linked":
            ceremony_block["linked_vault"] = linked_vault
            if linked_project_id:
                ceremony_block["linked_project_id"] = linked_project_id
        else:
            ceremony_block.pop("linked_vault", None)
            ceremony_block.pop("linked_project_id", None)

    _update_yaml(cfg, _mutate)

    cfg.mode = mode
    if mode == "linked":
        cfg.linked_vault = linked_vault
        if linked_project_id:
            cfg.linked_project_id = linked_project_id
    else:
        cfg.linked_vault = None
        cfg.linked_project_id = None
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
    me_entry: dict[str, Any] = {"did": me_did}
    recipients: list[dict[str, Any]] = [me_entry]
    if revoke_did is not None:
        old_recipients = g.get("recipients") or []
        for r in old_recipients:
            if r.get("did") and r["did"] != revoke_did and r["did"] != me_did:
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
    recipient_did: str | None = None,
    out_path: Path | str | None = None,
    public_key: bytes | None = None,
    cfg: Any | None = None,
) -> AddRecipientResult:
    """Add a recipient to a group. Branches on the group's cipher type.

    btn ceremonies: pass `out_path` (where to write the kit). Returns
    `AddRecipientResult(leaf_index=N, kit_path=Path)`.

    JWE ceremonies: pass `public_key` (32-byte X25519 public key) and
    `cfg` (the LoadedConfig to mutate). Returns
    `AddRecipientResult(updated_cfg=cfg')`.

    `recipient_did` is optional in both cases (provided for the
    `tn.recipient.added` admin event's metadata).

    `cfg` defaults to the runtime singleton's cfg.
    """
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
        if out_path is None:
            raise ValueError(
                "tn.admin.add_recipient: out_path is required for btn "
                f"group {group!r}."
            )
        # Inline the btn-runtime kit-mint flow (was tn.admin_add_recipient
        # in pre-Stage-C; that flat alias is gone in 0.2.0).
        from .. import _maybe_autoinit_load_only, _refresh_admin_cache_if_present, _require_dispatch
        _maybe_autoinit_load_only()
        out_path_p = Path(out_path)
        name = out_path_p.name
        if not name.endswith(".btn.mykit") or name == ".btn.mykit":
            raise ValueError(
                f"tn.admin.add_recipient: out_path basename must end with "
                f"'.btn.mykit' (e.g. {group!r}.btn.mykit), got {name!r}. The "
                f"kit_bundle exporter regex requires the .btn.mykit suffix; "
                f"non-matching files get silently skipped and the publisher's "
                f"own self-kit ships in their place."
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
    leaf_index: int | None = None,
    recipient_did: str | None = None,
    cfg: Any | None = None,
) -> RevokeRecipientResult:
    """Revoke a recipient. btn: leaf_index; JWE: recipient_did."""
    if cfg is None:
        from .. import current_config

        cfg = current_config()

    group_spec = cfg.groups.get(group)
    if group_spec is None:
        raise KeyError(f"unknown group: {group!r}")
    cipher = group_spec.cipher.name

    if cipher == "btn":
        if leaf_index is None:
            raise ValueError(
                "tn.admin.revoke_recipient: leaf_index required for btn group."
            )
        if recipient_did is not None:
            raise ValueError(
                "tn.admin.revoke_recipient: recipient_did is JWE-only; "
                "for btn use leaf_index."
            )
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
    """

    cipher: str
    generation: int | None = None
    updated_cfg: LoadedConfig | None = None


def rotate(
    group: str,
    *,
    revoke_did: str | None = None,
    pool_size: int | None = None,
    cfg: Any | None = None,
) -> RotateGroupResult:
    """Rotate group keys. revoke_did + pool_size are JWE-only.

    Both ciphers route through the same `_rotate_impl` body (which
    branches internally on `cfg.cipher_name`), so this verb's job is
    parameter validation + result wrapping. btn rotations ignore
    `revoke_did` / `pool_size` (the runtime doesn't take them).
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
                "tn.admin.rotate: revoke_did and pool_size are JWE-only."
            )
        # _rotate_impl handles btn internally — no separate runtime rotate.
        # btn rotations bump index_epoch and rename old state/mykit but
        # don't expose a "generation" counter at this layer; we report
        # the new index_epoch as the generation for symmetry.
        updated = _rotate_impl(group, cfg=cfg)
        new_epoch = updated.groups[group].index_epoch
        return RotateGroupResult(cipher="btn", generation=new_epoch, updated_cfg=None)

    elif cipher == "jwe":
        updated_cfg = _rotate_impl(
            group, revoke_did=revoke_did, pool_size=pool_size, cfg=cfg,
        )
        return RotateGroupResult(cipher="jwe", generation=None, updated_cfg=updated_cfg)

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
    `tn.recipient.revoked` events. Uses the Rust reducer
    (tn_core.admin.reduce) to derive per-event state changes; reducer
    errors on admin events are warned and skipped rather than aborting
    the whole replay.
    """
    from .. import _maybe_autoinit_load_only, _read_raw_admin_aware, _surface

    _surface.info("tn.recipients(group=%r, include_revoked=%s)", group, include_revoked)
    _maybe_autoinit_load_only()
    import warnings

    try:
        import tn_core  # PyO3 extension

        _have_rust_reducer = True
    except ImportError:
        _have_rust_reducer = False

    active: dict[int, dict[str, Any]] = {}
    revoked_map: dict[int, dict[str, Any]] = {}

    for raw in _read_raw_admin_aware():
        # _read_raw_admin_aware yields {"envelope": {...}, "plaintext": {...}, "valid": {...}}
        # from BOTH the main log and the admin log (the dedicated
        # `.tn/admin/admin.ndjson` file the new default routes admin
        # events to). Pre-2026-04-24 this used read_raw() which only sees
        # the main log; the admin-log default flip required this widening.
        env = raw["envelope"]
        valid = raw.get("valid", {})
        plaintext = raw.get("plaintext") or {}

        event_type = env.get("event_type", "")

        # Only process recipient-lifecycle events.
        if not event_type.startswith("tn.recipient."):
            continue

        # Admin events must be cryptographically sound. The valid dict has
        # per-check booleans; all three must pass.
        all_valid = (
            valid.get("signature", False)
            and valid.get("row_hash", False)
            and valid.get("chain", False)
        )
        if not all_valid:
            warnings.warn(
                f"tn.recipients: skipping tampered admin event event={event_type!r}",
                stacklevel=2,
            )
            continue

        # Build a flattened envelope suitable for the reducer.
        # The Rust runtime stores all per-event fields in the encrypted group
        # payload; after read_raw() decrypts them, they appear in
        # plaintext[<group_name>]. Merge all group plaintext fields into a
        # copy of the envelope so the reducer sees a flat dict.
        merged: dict[str, Any] = dict(env)
        for group_fields in plaintext.values():
            if isinstance(group_fields, dict):
                merged.update(group_fields)

        ts = env.get("timestamp")

        if _have_rust_reducer:
            # The catalog schema requires 'cipher' on tn.recipient.added and
            # 'recipient_did' on tn.recipient.revoked, but the Rust emitter
            # stores these as optional/implicit. Supply safe defaults so the
            # reducer's schema check passes without altering semantics.
            if event_type == "tn.recipient.added" and "cipher" not in merged:
                # btn ceremonies are the only ones that route through this
                # path (Rust runtime). Fall back to "btn" as the implicit default.
                merged.setdefault("cipher", "btn")
            if event_type == "tn.recipient.revoked" and "recipient_did" not in merged:
                merged.setdefault("recipient_did", None)

            try:
                delta = tn_core.admin.reduce(merged)
            except ValueError as exc:
                warnings.warn(
                    f"tn.recipients: admin event failed reduce: {event_type!r}: {exc}",
                    stacklevel=2,
                )
                continue

            kind = delta.get("kind")

            if kind == "recipient_added" and delta.get("group") == group:
                leaf = delta.get("leaf_index")
                if leaf is None:
                    continue
                active[leaf] = {
                    "leaf_index": leaf,
                    "recipient_did": delta.get("recipient_did"),
                    "minted_at": ts,
                    "kit_sha256": delta.get("kit_sha256"),
                    "revoked": False,
                    "revoked_at": None,
                }
            elif kind == "recipient_revoked" and delta.get("group") == group:
                leaf = delta.get("leaf_index")
                if leaf is None:
                    continue
                rec = active.pop(leaf, None)
                if rec is None:
                    rec = {
                        "leaf_index": leaf,
                        "recipient_did": None,
                        "minted_at": None,
                        "kit_sha256": None,
                    }
                rec["revoked"] = True
                rec["revoked_at"] = ts
                revoked_map[leaf] = rec
        else:
            # Fallback: inline switch when tn_core is not available.
            if event_type == "tn.recipient.added" and merged.get("group") == group:
                leaf_raw = merged.get("leaf_index")
                if leaf_raw is None:
                    continue
                leaf = int(leaf_raw)
                active[leaf] = {
                    "leaf_index": leaf,
                    "recipient_did": merged.get("recipient_did"),
                    "minted_at": ts,
                    "kit_sha256": merged.get("kit_sha256"),
                    "revoked": False,
                    "revoked_at": None,
                }
            elif event_type == "tn.recipient.revoked" and merged.get("group") == group:
                leaf_raw = merged.get("leaf_index")
                if leaf_raw is None:
                    continue
                leaf = int(leaf_raw)
                rec = active.pop(leaf, None)
                if rec is None:
                    rec = {
                        "leaf_index": leaf,
                        "recipient_did": None,
                        "minted_at": None,
                        "kit_sha256": None,
                    }
                rec["revoked"] = True
                rec["revoked_at"] = ts
                revoked_map[leaf] = rec

    out = sorted(active.values(), key=lambda r: r["leaf_index"])
    if include_revoked:
        out.extend(sorted(revoked_map.values(), key=lambda r: r["leaf_index"]))
    return out


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
    from .. import _maybe_autoinit_load_only, _read_raw_admin_aware, _surface
    from .. import current_config

    _surface.info("tn.admin.state(group=%r)", group)
    _maybe_autoinit_load_only()
    import warnings

    try:
        import tn_core

        _have_rust_reducer = True
    except ImportError:
        _have_rust_reducer = False

    state_dict: dict = {
        "ceremony": None,
        "groups": [],
        "recipients": [],
        "rotations": [],
        "coupons": [],
        "enrolments": [],
        "vault_links": [],
    }

    # Active recipients keyed by (group, leaf_index).
    by_leaf: dict[tuple[str, int], dict] = {}
    enrolments_by_peer: dict[tuple[str, str], dict] = {}
    vault_links_by_did: dict[str, dict] = {}

    for raw in _read_raw_admin_aware():
        env = raw["envelope"]
        raw.get("valid", {})
        plaintext = raw.get("plaintext") or {}

        event_type = env.get("event_type", "")

        # Only process admin events.
        if not (
            event_type.startswith("tn.ceremony.")
            or event_type.startswith("tn.group.")
            or event_type.startswith("tn.recipient.")
            or event_type.startswith("tn.rotation.")
            or event_type.startswith("tn.coupon.")
            or event_type.startswith("tn.enrolment.")
            or event_type.startswith("tn.vault.")
        ):
            continue

        # Build a flattened envelope suitable for the reducer.
        merged: dict[str, Any] = dict(env)
        for group_fields in plaintext.values():
            if isinstance(group_fields, dict):
                merged.update(group_fields)

        ts = merged.get("timestamp")

        if _have_rust_reducer:
            # Supply schema defaults the Rust emitter omits (matches recipients() fix).
            if event_type == "tn.recipient.added" and "cipher" not in merged:
                merged.setdefault("cipher", "btn")
            if event_type == "tn.recipient.revoked" and "recipient_did" not in merged:
                merged.setdefault("recipient_did", None)

            try:
                d = tn_core.admin.reduce(merged)
            except ValueError as exc:
                warnings.warn(
                    f"tn.admin_state: admin event failed reduce: {event_type!r}: {exc}",
                    stacklevel=2,
                )
                continue

            kind = d.get("kind")

            if kind == "ceremony_init":
                state_dict["ceremony"] = {
                    "ceremony_id": d["ceremony_id"],
                    "cipher": d["cipher"],
                    "device_did": d["device_did"],
                    "created_at": d["created_at"],
                }
            elif kind == "group_added":
                state_dict["groups"].append(
                    {
                        "group": d["group"],
                        "cipher": d["cipher"],
                        "publisher_did": d["publisher_did"],
                        "added_at": d["added_at"],
                    }
                )
            elif kind == "recipient_added":
                leaf = d.get("leaf_index")
                if leaf is None:
                    continue
                key = (d["group"], leaf)
                by_leaf[key] = {
                    "group": d["group"],
                    "leaf_index": leaf,
                    "recipient_did": d.get("recipient_did"),
                    "kit_sha256": d["kit_sha256"],
                    "minted_at": ts,
                    "active_status": "active",
                    "revoked_at": None,
                    "retired_at": None,
                }
            elif kind == "recipient_revoked":
                leaf = d.get("leaf_index")
                if leaf is None:
                    continue
                key = (d["group"], leaf)
                if key in by_leaf:
                    by_leaf[key]["active_status"] = "revoked"
                    by_leaf[key]["revoked_at"] = ts
            elif kind == "rotation_completed":
                state_dict["rotations"].append(
                    {
                        "group": d["group"],
                        "cipher": d["cipher"],
                        "generation": d["generation"],
                        "previous_kit_sha256": d["previous_kit_sha256"],
                        "rotated_at": d["rotated_at"],
                    }
                )
                # Retire any currently-active recipients in this group.
                for leaf_key, rec in by_leaf.items():
                    if leaf_key[0] == d["group"] and rec["active_status"] == "active":
                        rec["active_status"] = "retired"
                        rec["retired_at"] = ts
            elif kind == "coupon_issued":
                state_dict["coupons"].append(
                    {
                        "group": d["group"],
                        "slot": d["slot"],
                        "to_did": d["to_did"],
                        "issued_to": d["issued_to"],
                        "issued_at": ts,
                    }
                )
            elif kind == "enrolment_compiled":
                enrolments_by_peer[(d["group"], d["peer_did"])] = {
                    "group": d["group"],
                    "peer_did": d["peer_did"],
                    "package_sha256": d["package_sha256"],
                    "status": "offered",
                    "compiled_at": d["compiled_at"],
                    "absorbed_at": None,
                }
            elif kind == "enrolment_absorbed":
                peer_key: tuple[str, str] = (d["group"], d["from_did"])
                if peer_key in enrolments_by_peer:
                    enrolments_by_peer[peer_key]["status"] = "absorbed"
                    enrolments_by_peer[peer_key]["absorbed_at"] = d["absorbed_at"]
                else:
                    enrolments_by_peer[peer_key] = {
                        "group": d["group"],
                        "peer_did": d["from_did"],
                        "package_sha256": d["package_sha256"],
                        "status": "absorbed",
                        "compiled_at": None,
                        "absorbed_at": d["absorbed_at"],
                    }
            elif kind == "vault_linked":
                vault_links_by_did[d["vault_did"]] = {
                    "vault_did": d["vault_did"],
                    "project_id": d["project_id"],
                    "linked_at": d["linked_at"],
                    "unlinked_at": None,
                }
            elif kind == "vault_unlinked":
                if d["vault_did"] in vault_links_by_did:
                    vault_links_by_did[d["vault_did"]]["unlinked_at"] = d["unlinked_at"]

    state_dict["recipients"] = list(by_leaf.values())
    state_dict["enrolments"] = list(enrolments_by_peer.values())
    state_dict["vault_links"] = list(vault_links_by_did.values())

    # If no ceremony_init event was found in the log (common for btn ceremonies
    # where the Rust runtime writes ceremony info to the yaml, not the main log),
    # derive ceremony state from the current config as a fallback.
    if state_dict["ceremony"] is None:
        try:
            cfg = current_config()
            state_dict["ceremony"] = {
                "ceremony_id": cfg.ceremony_id,
                "cipher": cfg.cipher_name,
                "device_did": cfg.device.did,
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
    from .. import _logger, _maybe_autoinit_load_only, current_config
    from .. import _export_impl as export

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
