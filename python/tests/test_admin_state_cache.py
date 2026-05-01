"""Tests for the materialized AdminState LKV cache (Section 4 of the
2026-04-24 admin log architecture plan).

Covers:

* Cold path: an empty cache replays the admin log and matches
  ``tn.admin.state()`` shape.
* Hot path: emitting a single admin event advances ``at_offset`` by 1
  rather than triggering a full re-replay.
* Persistence across an init -> flush_and_close -> re-init cycle.
* Atomic write: a stranded ``admin.lkv.json.tmp`` is ignored on next
  startup; the cache rebuilds cleanly from the log.
* Revocation-is-terminal: an ``add(L) -> revoke(L) -> add(L)`` sequence
  produces one ``LeafReuseAttempt`` in ``head_conflicts`` and the
  materialized state shows L revoked.
* Same-coordinate fork detection.
* Idempotent refresh.
* Singleton lifecycle.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml as _yaml

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn.admin.cache import (
    AdminStateCache,
    LeafReuseAttempt,
    SameCoordinateFork,
    lkv_path_for,
)
from tn.admin.log import resolve_admin_log_path
from tn.config import load_or_create


def _force_admin_log_yaml(yaml_path: Path) -> None:
    """Route admin events to the dedicated ``.tn/tn/admin/admin.ndjson`` log."""
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["admin_log_location"] = "./.tn/admin/admin.ndjson"
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


@pytest.fixture(autouse=True)
def fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _init_btn(yaml_path: Path) -> None:
    """Init a btn ceremony with admin events routed to the dedicated log.
    Skip the test if the Rust runtime isn't available."""
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")
    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("admin cache tests require the Rust runtime (btn ceremonies)")


# ---------------------------------------------------------------------------
# 1. Cold path
# ---------------------------------------------------------------------------


def test_cold_path_matches_admin_state(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))
    tn.admin.add_recipient("default", recipient_did="did:key:zBob", out_path=str(tmp_path / "bob.btn.mykit"))
    expected = tn.admin.state()

    # First cached call: cold cache, replays the whole log.
    cached = tn.admin.cache.cached_admin_state()
    # Same recipient set + ceremony — order may differ slightly so compare
    # by (group, leaf_index).
    cached_recs = sorted(
        (r["group"], r["leaf_index"], r["active_status"])
        for r in cached["recipients"]
    )
    expected_recs = sorted(
        (r["group"], r["leaf_index"], r["active_status"])
        for r in expected["recipients"]
    )
    assert cached_recs == expected_recs
    assert cached["ceremony"]["device_did"] == expected["ceremony"]["device_did"]


# ---------------------------------------------------------------------------
# 2. Hot path: incremental advance
# ---------------------------------------------------------------------------


def test_hot_path_incremental_advance(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))

    # Prime the cache.
    s1 = tn.admin.cache.cached_admin_state()
    offset1 = tn._cached_admin_state.at_offset
    n_recs1 = len(s1["recipients"])

    # Add one more recipient.
    tn.admin.add_recipient("default", recipient_did="did:key:zBob", out_path=str(tmp_path / "bob.btn.mykit"))

    s2 = tn.admin.cache.cached_admin_state()
    offset2 = tn._cached_admin_state.at_offset

    assert len(s2["recipients"]) == n_recs1 + 1
    # Offset advanced by exactly one admin event.
    assert offset2 == offset1 + 1


# ---------------------------------------------------------------------------
# 3. Persistence across init/flush_and_close/re-init
# ---------------------------------------------------------------------------


def test_persistence_across_reinit(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))
    s_pre = tn.admin.cache.cached_admin_state()
    cfg = tn.current_config()
    lkv = lkv_path_for(cfg)
    assert lkv.exists(), "cache should have written admin.lkv.json"

    pre_offset = tn._cached_admin_state.at_offset
    tn.flush_and_close()

    # Re-instantiate via re-init. The new singleton should load from disk.
    tn.init(yaml_path)
    s_post = tn.admin.cache.cached_admin_state()
    post_offset = tn._cached_admin_state.at_offset
    assert post_offset == pre_offset
    pre_recs = sorted(
        (r["group"], r["leaf_index"]) for r in s_pre["recipients"]
    )
    post_recs = sorted(
        (r["group"], r["leaf_index"]) for r in s_post["recipients"]
    )
    assert pre_recs == post_recs


# ---------------------------------------------------------------------------
# 4. Atomicity under crash: orphan .tmp is ignored
# ---------------------------------------------------------------------------


def test_orphan_tmp_file_is_ignored(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))
    tn.admin.cache.cached_admin_state()
    cfg = tn.current_config()
    lkv = lkv_path_for(cfg)

    # Simulate a crash mid-write: drop a junk .tmp next to the real LKV.
    orphan = lkv.with_name(lkv.name + ".tmp")
    orphan.write_text("{not valid json", encoding="utf-8")
    tn.flush_and_close()

    # Re-init and access the cache. Must not raise; must produce correct
    # state. The orphan .tmp is simply ignored — we never read it.
    tn.init(yaml_path)
    s = tn.admin.cache.cached_admin_state()
    assert any(
        r.get("recipient_did") == "did:key:zAlice" for r in s["recipients"]
    )


# ---------------------------------------------------------------------------
# 5. Revocation-is-terminal: leaf-reuse attempt
# ---------------------------------------------------------------------------


def test_revocation_is_terminal_leaf_reuse(tmp_path):
    """Hand-craft an add(L) -> revoke(L) -> add(L) sequence in the admin
    log directly. The third add must surface as a LeafReuseAttempt; the
    state must show L revoked (no fresh active row).
    """
    from datetime import datetime, timezone

    from tn.chain import _compute_row_hash
    from tn.signing import _signature_b64

    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))
    cfg = tn.current_config()
    # Find leaf index just minted.
    recs = tn.admin.cache.cached_recipients("default")
    assert len(recs) == 1
    leaf_index = recs[0]["leaf_index"]

    tn.admin.revoke_recipient("default", leaf_index=leaf_index)
    # State now shows leaf revoked.
    s_revoked = tn.admin.cache.cached_admin_state()
    rev_rec = next(
        r
        for r in s_revoked["recipients"]
        if r["leaf_index"] == leaf_index and r["group"] == "default"
    )
    assert rev_rec["active_status"] == "revoked"

    # Now forge a third "add" envelope for the same (group, leaf_index)
    # and append it directly to the admin log. The cache must flag it as
    # a LeafReuseAttempt and NOT promote the leaf back to active.
    admin_log = resolve_admin_log_path(cfg)
    if not admin_log.exists():
        # Rust runtime may still be writing to the main log. Fall back.
        admin_log = cfg.resolve_log_path()
    lines = admin_log.read_text(encoding="utf-8").splitlines()
    last_add_row = None
    for line in lines:
        try:
            env = json.loads(line)
        except json.JSONDecodeError:
            continue
        if env.get("event_type") == "tn.recipient.added":
            last_add_row = env.get("row_hash")

    forged_ts = datetime.now(timezone.utc).isoformat()
    forged_event_id = "forged-" + forged_ts.replace(":", "-")
    public_fields = {
        "ceremony_id": cfg.ceremony_id,
        "group": "default",
        "leaf_index": leaf_index,
        "recipient_did": "did:key:zForged",
        "kit_sha256": "sha256:" + ("0" * 64),
        "cipher": "btn",
        "added_at": forged_ts,
        "publisher_did": cfg.device.did,
    }
    forged_row_hash = _compute_row_hash(
        did=cfg.device.did,
        timestamp=forged_ts,
        event_id=forged_event_id,
        event_type="tn.recipient.added",
        level="info",
        prev_hash=last_add_row,
        public_fields=public_fields,
        groups={},
    )
    sig = cfg.device.sign(forged_row_hash.encode("ascii"))
    forged_env = {
        "did": cfg.device.did,
        "timestamp": forged_ts,
        "event_id": forged_event_id,
        "event_type": "tn.recipient.added",
        "level": "info",
        "sequence": 999_999,
        "prev_hash": last_add_row,
        "row_hash": forged_row_hash,
        "signature": _signature_b64(sig),
        **public_fields,
    }
    with admin_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(forged_env, separators=(",", ":")) + "\n")

    # Force a refresh. The forged add lands in the log but should be
    # rejected by the reducer.
    tn._cached_admin_state.refresh()

    s_after = tn.admin.cache.cached_admin_state()
    # Still revoked, no fresh "active" entry for this leaf.
    matching = [
        r
        for r in s_after["recipients"]
        if r["leaf_index"] == leaf_index and r["group"] == "default"
    ]
    assert len(matching) == 1
    assert matching[0]["active_status"] == "revoked"

    # Conflict surfaces.
    conflicts = tn._cached_admin_state.head_conflicts
    leaf_reuses = [c for c in conflicts if isinstance(c, LeafReuseAttempt)]
    assert len(leaf_reuses) == 1
    assert leaf_reuses[0].group == "default"
    assert leaf_reuses[0].leaf_index == leaf_index
    assert leaf_reuses[0].attempted_row_hash == forged_row_hash


# ---------------------------------------------------------------------------
# 6. Same-coordinate fork detection
# ---------------------------------------------------------------------------


def test_same_coordinate_fork_detection(tmp_path):
    """Build a cache by feeding it two envelopes with identical
    ``(did, event_type, sequence)`` but different bodies / row_hashes.
    The cache flags the divergence."""
    from datetime import datetime, timezone

    from tn.chain import _compute_row_hash
    from tn.signing import _signature_b64

    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))
    cfg = tn.current_config()
    admin_log = resolve_admin_log_path(cfg)
    if not admin_log.exists():
        admin_log = cfg.resolve_log_path()

    # Find an existing add and forge a sibling at the same sequence with
    # different fields.
    target = None
    for line in admin_log.read_text(encoding="utf-8").splitlines():
        try:
            env = json.loads(line)
        except json.JSONDecodeError:
            continue
        if env.get("event_type") == "tn.recipient.added":
            target = env
            break
    assert target is not None
    seq = target["sequence"]

    # Prime the cache singleton so the explicit refresh() below has
    # something to act on.
    tn.admin.cache.cached_admin_state()

    forged_ts = datetime.now(timezone.utc).isoformat()
    public_fields = {
        "ceremony_id": cfg.ceremony_id,
        "group": "default",
        "leaf_index": 42,
        "recipient_did": "did:key:zEvilTwin",
        "kit_sha256": "sha256:" + ("9" * 64),
        "cipher": "btn",
        "added_at": forged_ts,
        "publisher_did": cfg.device.did,
    }
    forged_row_hash = _compute_row_hash(
        did=cfg.device.did,
        timestamp=forged_ts,
        event_id="forged-coord-fork",
        event_type="tn.recipient.added",
        level="info",
        prev_hash=target.get("row_hash"),
        public_fields=public_fields,
        groups={},
    )
    sig = cfg.device.sign(forged_row_hash.encode("ascii"))
    forged_env = {
        "did": cfg.device.did,
        "timestamp": forged_ts,
        "event_id": "forged-coord-fork",
        "event_type": "tn.recipient.added",
        "level": "info",
        "sequence": seq,  # SAME as target.sequence
        "prev_hash": target.get("row_hash"),
        "row_hash": forged_row_hash,
        "signature": _signature_b64(sig),
        **public_fields,
    }
    with admin_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(forged_env, separators=(",", ":")) + "\n")

    tn._cached_admin_state.refresh()

    assert tn.admin.cache.diverged() is True
    forks = [
        c
        for c in tn._cached_admin_state.head_conflicts
        if isinstance(c, SameCoordinateFork)
    ]
    assert len(forks) == 1
    assert forks[0].did == cfg.device.did
    assert forks[0].sequence == seq


# ---------------------------------------------------------------------------
# 7. Idempotent refresh
# ---------------------------------------------------------------------------


def test_idempotent_refresh(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))
    cache = tn._get_or_create_cache()
    # First refresh ingests whatever is on disk.
    n1 = cache.refresh()
    # Second refresh is a no-op.
    n2 = cache.refresh()
    assert n2 == 0, f"second refresh should be 0 new envelopes; got {n2}"
    # n1 may be 0 if the cache was already current via the auto-refresh.
    assert n1 >= 0


# ---------------------------------------------------------------------------
# 8. Singleton lifecycle
# ---------------------------------------------------------------------------


def test_singleton_lifecycle(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    a = tn._get_or_create_cache()
    b = tn._get_or_create_cache()
    assert a is b, "same singleton across calls within one init"

    tn.flush_and_close()
    # After flush_and_close the singleton is reset.
    assert tn._cached_admin_state is None

    tn.init(yaml_path)
    c = tn._get_or_create_cache()
    assert c is not a, "fresh singleton after re-init"


# ---------------------------------------------------------------------------
# Bonus: instantiating AdminStateCache directly works (multi-ceremony shape)
# ---------------------------------------------------------------------------


def test_direct_instantiation_per_cfg(tmp_path):
    yaml_path = tmp_path / "tn.yaml"
    _init_btn(yaml_path)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=str(tmp_path / "alice.btn.mykit"))
    cfg = load_or_create(yaml_path)
    cache = AdminStateCache(cfg)
    s = cache.state()
    assert any(
        r.get("recipient_did") == "did:key:zAlice" for r in s["recipients"]
    )
