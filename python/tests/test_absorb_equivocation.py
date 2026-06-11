"""Absorb-time equivocation classification (Design A).

A `tn.recipient.added` that reuses a revoked (group, leaf) is ALWAYS
excluded from derived state (revocation is terminal — the reducer
already guarantees that). What this module adds is the causal
DISTINCTION, computed at absorb time from the incoming snapshot's
vector clock:

  * CONCURRENT reuse — the publisher had NOT seen the revoke when they
    shipped the snapshot (their clock doesn't cover it). Benign race;
    flagged as a plain LeafReuseAttempt (informed=False).
  * INFORMED reuse (equivocation) — the publisher's clock DID cover the
    revoke, so they knew the leaf was dead and re-added it anyway.
    Flagged informed=True.

The envelope is appended either way (append-only invariant: signed
events are facts), so the derived vector clock advances naturally and
no new admin event type is needed.

This file tests the pure classifier `_reuse_is_informed` directly —
no signatures, no ceremony — so the causal rule is mutation-checkable
in isolation.
"""
from __future__ import annotations

from tn.absorb import _reuse_is_informed

_REVOKED = "tn.recipient.revoked"


def test_informed_when_clock_covers_revoke_exactly():
    # Publisher's clock shows they had seen revoked-seq 5 from zPub; the
    # revoke we're checking is zPub@5 -> they knew. Informed.
    clock = {"did:key:zPub": {_REVOKED: 5}}
    assert _reuse_is_informed("did:key:zPub", 5, clock) is True


def test_informed_when_clock_exceeds_revoke_seq():
    clock = {"did:key:zPub": {_REVOKED: 9}}
    assert _reuse_is_informed("did:key:zPub", 5, clock) is True


def test_concurrent_when_clock_below_revoke_seq():
    # They'd only seen up to seq 4; the revoke is seq 5 -> hadn't seen it.
    clock = {"did:key:zPub": {_REVOKED: 4}}
    assert _reuse_is_informed("did:key:zPub", 5, clock) is False


def test_concurrent_when_did_absent_from_clock():
    # The revoke was authored by a DID the publisher never absorbed.
    clock = {"did:key:zSomeoneElse": {_REVOKED: 99}}
    assert _reuse_is_informed("did:key:zPub", 5, clock) is False


def test_concurrent_when_event_type_absent():
    # Publisher saw OTHER events from zPub but no revoked coordinate.
    clock = {"did:key:zPub": {"tn.recipient.added": 12}}
    assert _reuse_is_informed("did:key:zPub", 5, clock) is False


def test_concurrent_when_clock_empty():
    assert _reuse_is_informed("did:key:zPub", 5, {}) is False


def test_concurrent_when_revoke_seq_unknown():
    # A revoke whose sequence we couldn't determine can never be proven
    # "known" -> default to concurrent (never falsely accuse).
    clock = {"did:key:zPub": {_REVOKED: 5}}
    assert _reuse_is_informed("did:key:zPub", None, clock) is False


# ---------------------------------------------------------------------------
# Integration: drive a forged reused-leaf snapshot through real absorb and
# prove the `informed` flag is actually set from the snapshot clock (not
# just the pure helper in isolation).
# ---------------------------------------------------------------------------


def _setup_revoked_leaf(tmp_path):
    """init btn ceremony, add+revoke a recipient. Return
    (cfg, leaf_index, revoke_did, revoke_seq, last_add_row)."""
    import json as _json

    import tn
    from tn.admin.log import resolve_admin_log_path

    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    add = tn.admin.add_recipient(
        "default", recipient_did="did:key:zVictim",
        out_path=str(tmp_path / "victim.btn.mykit"),
    )
    leaf_index = add.leaf_index
    tn.admin.revoke_recipient("default", leaf_index=leaf_index)
    cfg = tn.current_config()

    admin_log = resolve_admin_log_path(cfg)
    if not admin_log.exists():
        admin_log = cfg.resolve_log_path()

    revoke_did = revoke_seq = last_add_row = None
    for line in admin_log.read_text(encoding="utf-8").splitlines():
        try:
            env = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        et = env.get("event_type")
        if et == "tn.recipient.added":
            last_add_row = env.get("row_hash")
        if et == _REVOKED and env.get("leaf_index") == leaf_index:
            revoke_did = env.get("device_identity")
            revoke_seq = env.get("sequence")
    assert isinstance(revoke_seq, int), "revoke event must carry a sequence"
    return cfg, leaf_index, revoke_did, revoke_seq, last_add_row


def _forge_readd_snapshot(cfg, leaf_index, last_add_row, clock):
    """Build (manifest, body) for an admin_log_snapshot whose body re-adds
    a revoked leaf, with a caller-controlled vector clock."""
    import json as _json
    from datetime import datetime, timezone

    from tn.chain import _compute_row_hash
    from tn.signing import _signature_b64
    from tn.tnpkg import TnpkgManifest

    ts = datetime.now(timezone.utc).isoformat()
    event_id = "forged-" + ts.replace(":", "-")
    public_fields = {
        "ceremony_id": cfg.ceremony_id,
        "group": "default",
        "leaf_index": leaf_index,
        "recipient_identity": "did:key:zReadded",
        "kit_sha256": "sha256:" + ("0" * 64),
        "cipher": "btn",
        "added_at": ts,
        "publisher_identity": cfg.device.device_identity,
    }
    row_hash = _compute_row_hash(
        device_identity=cfg.device.device_identity,
        timestamp=ts, event_id=event_id, event_type="tn.recipient.added",
        level="info", prev_hash=last_add_row, public_fields=public_fields,
        groups={},
    )
    sig = cfg.device.sign(row_hash.encode("ascii"))
    forged = {
        "device_identity": cfg.device.device_identity,
        "timestamp": ts, "event_id": event_id,
        "event_type": "tn.recipient.added", "level": "info",
        "sequence": 999_999, "prev_hash": last_add_row,
        "row_hash": row_hash, "signature": _signature_b64(sig),
        **public_fields,
    }
    body = {"body/admin.ndjson": (_json.dumps(forged, separators=(",", ":")) + "\n").encode()}
    manifest = TnpkgManifest(
        kind="admin_log_snapshot",
        publisher_identity=cfg.device.device_identity,
        ceremony_id=cfg.ceremony_id,
        as_of=ts,
        clock=clock,
    )
    return manifest, body, row_hash


def test_absorb_flags_informed_reuse_when_clock_covers_revoke(tmp_path):
    import tn
    from tn.absorb import _absorb_admin_log_snapshot, LeafReuseAttempt

    try:
        cfg, leaf, rdid, rseq, last_add = _setup_revoked_leaf(tmp_path)
        # Snapshot clock COVERS the revoke (publisher knew) -> informed.
        clock = {rdid: {"tn.recipient.added": 999_999, _REVOKED: rseq}}
        manifest, body, row_hash = _forge_readd_snapshot(cfg, leaf, last_add, clock)

        receipt = _absorb_admin_log_snapshot(cfg, manifest, body)
        reuses = [c for c in receipt.conflicts if isinstance(c, LeafReuseAttempt)]
        assert len(reuses) == 1
        assert reuses[0].leaf_index == leaf
        assert reuses[0].attempted_row_hash == row_hash
        assert reuses[0].informed is True, "publisher's clock covered the revoke"
    finally:
        tn.flush_and_close()


def test_absorb_flags_concurrent_reuse_when_clock_misses_revoke(tmp_path):
    import tn
    from tn.absorb import _absorb_admin_log_snapshot, LeafReuseAttempt

    try:
        cfg, leaf, rdid, _rseq, last_add = _setup_revoked_leaf(tmp_path)
        # Snapshot clock does NOT cover the revoke (publisher hadn't seen it).
        clock = {rdid: {"tn.recipient.added": 999_999}}
        manifest, body, _row_hash = _forge_readd_snapshot(cfg, leaf, last_add, clock)

        receipt = _absorb_admin_log_snapshot(cfg, manifest, body)
        reuses = [c for c in receipt.conflicts if isinstance(c, LeafReuseAttempt)]
        assert len(reuses) == 1
        assert reuses[0].informed is False, "publisher had not seen the revoke"
    finally:
        tn.flush_and_close()
