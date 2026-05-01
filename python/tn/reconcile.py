"""yaml <-> cipher-state reconciliation.

Runs on every tn.init(). Diffs yaml against on-disk cipher state and
applies corrections per-group based on cipher kind. Idempotent:
a fully-reconciled state produces an empty diff.

Plan 1 scope:
  - JWE groups: promote pending recipients when a matching offer is in
    pending_offers/.
  - Bearer groups: auto-issue a coupon for any recipient with no slot
    (equivalent to calling admin.issue_coupon).

Later plans:
  - Rotation detection, cipher-only revocations, self-recipient
    invariant enforcement.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

import yaml as _yaml

from .cipher import JWEGroupCipher
from .config import LoadedConfig
from .conventions import pending_offers_dir

_DID_SAFE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class Promotion:
    group: str
    peer_did: str


@dataclass
class CouponIssued:
    group: str
    peer_did: str
    slot: int


@dataclass
class ReconcileResult:
    promotions: list[Promotion] = field(default_factory=list)
    coupons_issued: list[CouponIssued] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)


def _reconcile(cfg: LoadedConfig) -> ReconcileResult:
    """Make cipher state match yaml. Idempotent."""
    from . import admin as _admin  # local import to avoid cycle

    result = ReconcileResult()

    yaml_dir = cfg.yaml_path.parent
    pending_dir = pending_offers_dir(yaml_dir)
    doc = _yaml.safe_load(cfg.yaml_path.read_text(encoding="utf-8")) or {}
    groups = doc.get("groups") or {}

    for group_name, group_doc in groups.items():
        gcfg = cfg.groups.get(group_name)
        if gcfg is None:
            continue
        recipients = group_doc.get("recipients") or []

        if isinstance(gcfg.cipher, JWEGroupCipher):
            for r in list(recipients):
                did = r.get("did")
                if not did or r.get("pub_b64"):
                    continue
                safe = _DID_SAFE.sub("_", did)
                offer_path = pending_dir / f"{safe}.json"
                if not offer_path.exists():
                    continue
                try:
                    offer_doc = json.loads(offer_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as e:
                    result.conflicts.append(
                        f"_reconcile: offer file {offer_path} for {did!r} in "
                        f"group {group_name!r} is malformed JSON: {e}. "
                        f"Skipped; delete it and ask the peer to re-send."
                    )
                    continue
                pub_b64 = offer_doc.get("x25519_pub_b64")
                if not pub_b64:
                    result.conflicts.append(
                        f"_reconcile: offer file {offer_path} for {did!r} in "
                        f"group {group_name!r} is missing x25519_pub_b64. "
                        f"Skipped."
                    )
                    continue
                try:
                    pub_bytes = base64.b64decode(pub_b64)
                except (ValueError, binascii.Error) as e:
                    result.conflicts.append(
                        f"_reconcile: offer file {offer_path} has invalid "
                        f"base64 in x25519_pub_b64: {e}. Skipped."
                    )
                    continue
                res = _admin.add_recipient(
                    group_name,
                    recipient_did=did,
                    public_key=pub_bytes,
                    cfg=cfg,
                )
                if res.updated_cfg is not None:
                    cfg = res.updated_cfg
                offer_path.unlink(missing_ok=True)
                result.promotions.append(Promotion(group=group_name, peer_did=did))

        # btn groups: yaml-declared DIDs are NOT auto-minted at init.
        # Use tn.admin_add_recipient(group, out_path, did) explicitly. The
        # previous orphan auto-mint path (_emit_missing_recipients) was
        # removed because no consumer read its output. No coupon flow —
        # that was BGW-only and has been removed.
    return result
