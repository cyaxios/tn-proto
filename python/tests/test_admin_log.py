"""Tests for the admin-log snapshot pipeline (`.tnpkg` kind=admin_log_snapshot).

Covers:
* Round-trip: producer's admin log -> snapshot zip -> consumer's admin log.
* Manifest signature verifies; tampered manifest is rejected on absorb.
* Idempotent absorb: replaying the same snapshot is a noop.
* Equivocation: an `add(L) -> revoke(L) -> add(L)` sequence surfaces a
  `LeafReuseAttempt` in the receipt's conflicts list.
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import yaml as _yaml

import tn
from tn.absorb import AbsorbReceipt, LeafReuseAttempt, absorb
from tn.admin.log import resolve_admin_log_path
from tn.config import load_or_create
from tn.export import export
from tn.tnpkg import _read_manifest, _verify_manifest_signature


def _force_admin_log_yaml(yaml_path: Path) -> None:
    """Set ceremony.admin_log_location so admin events route to .tn/tn/admin/."""
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc.setdefault("ceremony", {})["admin_log_location"] = "./.tn/admin/admin.ndjson"
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


@pytest.fixture(autouse=True)
def fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


def _make_admin_log(yaml_dir: Path) -> Path:
    """Create a btn ceremony with a non-empty admin log and return the
    yaml path. Adds two recipients so we have ``tn.recipient.added``
    events to ship in the snapshot.
    """
    yaml_path = yaml_dir / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(yaml_path)
    tn.init(yaml_path, cipher="btn")

    if not tn.using_rust():
        tn.flush_and_close()
        pytest.skip("admin log snapshot tests require the Rust runtime (btn)")

    out_dir = yaml_dir / "_kits"
    out_dir.mkdir(exist_ok=True)
    tn.admin.add_recipient("default", recipient_did="did:key:zAlice", out_path=out_dir / "alice.btn.mykit")
    tn.admin.add_recipient("default", recipient_did="did:key:zBob", out_path=out_dir / "bob.btn.mykit")
    tn.flush_and_close()
    return yaml_path


def test_admin_log_snapshot_zip_shape_and_signature(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    yaml_path = _make_admin_log(src)
    cfg = load_or_create(yaml_path)

    out = tmp_path / "snap.tnpkg"
    export(out, kind="admin_log_snapshot", cfg=cfg)
    assert out.exists()

    manifest, body = _read_manifest(out)
    assert manifest.kind == "admin_log_snapshot"
    assert manifest.from_did == cfg.device.did
    assert manifest.scope == "admin"
    assert "body/admin.ndjson" in body
    assert manifest.event_count > 0
    assert manifest.head_row_hash is not None
    assert _verify_manifest_signature(manifest)


def test_admin_log_snapshot_round_trip_to_fresh_consumer(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    yaml_path = _make_admin_log(src)
    cfg = load_or_create(yaml_path)

    snap = tmp_path / "snap.tnpkg"
    export(snap, kind="admin_log_snapshot", cfg=cfg)

    # Fresh receiver in a separate dir.
    dst = tmp_path / "dst"
    dst.mkdir()
    dst_yaml = dst / "tn.yaml"
    tn.init(dst_yaml, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(dst_yaml)
    dst_cfg = load_or_create(dst_yaml)

    receipt = absorb(dst_cfg, snap)
    assert isinstance(receipt, AbsorbReceipt) is False  # legacy form (cfg, source)
    # legacy 2-arg returns AbsorbResult; the dispatcher still applied.
    assert receipt.status in {"enrolment_applied", "no_op"}

    # New 1-arg form returns AbsorbReceipt directly.
    tn.init(dst_yaml)
    receipt2 = tn.pkg.absorb(snap)
    tn.flush_and_close()
    assert isinstance(receipt2, AbsorbReceipt)
    # Idempotent: by the second call we already have everything.
    assert receipt2.noop or receipt2.deduped_count >= 1


def test_admin_log_snapshot_idempotent_absorb(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    yaml_path = _make_admin_log(src)
    cfg = load_or_create(yaml_path)

    snap = tmp_path / "snap.tnpkg"
    export(snap, kind="admin_log_snapshot", cfg=cfg)

    dst = tmp_path / "dst"
    dst.mkdir()
    dst_yaml = dst / "tn.yaml"
    tn.init(dst_yaml, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(dst_yaml)
    dst_cfg = load_or_create(dst_yaml)

    first = absorb(dst_cfg, snap)
    # Loose check via the legacy result shape — accepted_count isn't on
    # AbsorbResult, so we just ensure the legacy status reflects success.
    assert first.status in {"enrolment_applied", "no_op"}

    # Second pass: the receiver's admin log already contains every
    # row_hash. The new 1-arg form returns a receipt with noop=True.
    tn.init(dst_yaml)
    receipt = tn.pkg.absorb(snap)
    tn.flush_and_close()
    assert receipt.kind == "admin_log_snapshot"
    assert receipt.noop or receipt.accepted_count == 0


def test_admin_log_snapshot_rejects_tampered_manifest(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    yaml_path = _make_admin_log(src)
    cfg = load_or_create(yaml_path)

    snap = tmp_path / "snap.tnpkg"
    export(snap, kind="admin_log_snapshot", cfg=cfg)

    # Mutate one byte in the manifest after signing — flip a single
    # character of the ``as_of`` field. The signature must fail.
    with zipfile.ZipFile(snap, "r") as zf:
        manifest_doc = json.loads(zf.read("manifest.json").decode("utf-8"))
        body_files = {
            n: zf.read(n) for n in zf.namelist() if n != "manifest.json"
        }
    manifest_doc["event_count"] = int(manifest_doc.get("event_count", 0)) + 1
    with zipfile.ZipFile(snap, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest_doc, sort_keys=True, indent=2))
        for n, data in body_files.items():
            zf.writestr(n, data)

    # Receiver setup
    dst = tmp_path / "dst"
    dst.mkdir()
    dst_yaml = dst / "tn.yaml"
    tn.init(dst_yaml, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(dst_yaml)
    dst_cfg = load_or_create(dst_yaml)

    receipt = absorb(dst_cfg, snap)
    # Legacy AbsorbResult: tampered manifest should be rejected.
    assert receipt.status == "rejected"
    assert "signature" in receipt.reason.lower()


def test_admin_log_snapshot_equivocation_leaf_reuse(tmp_path: Path):
    """Hand-craft a snapshot whose body has add(L) -> revoke(L) -> add(L)
    with three distinct row_hashes (and valid signatures by the producer's
    device key). The third add is a leaf-reuse attempt and must surface
    in ``AbsorbReceipt.conflicts``.

    We forge the third add by signing a freshly-built envelope with the
    producer's real Ed25519 key; this models a malicious / buggy clone of
    the writer's identity that re-emits a previously-revoked leaf.
    """
    from datetime import datetime, timezone

    from tn.chain import _compute_row_hash
    from tn.signing import _signature_b64
    from tn.tnpkg import TnpkgManifest, _write_tnpkg

    src = tmp_path / "src"
    src.mkdir()
    yaml_path = _make_admin_log(src)
    cfg = load_or_create(yaml_path)

    # The Rust runtime currently writes admin events to the main log,
    # not the dedicated `.tn/tn/admin/admin.ndjson`. Read whichever exists
    # so the test works regardless of which path is in use.
    candidate_paths = [resolve_admin_log_path(cfg), cfg.resolve_log_path()]
    source_log = next((p for p in candidate_paths if p.exists() and p.stat().st_size > 0), None)
    if source_log is None:
        pytest.skip("no admin events in either main log or admin log")
    lines = source_log.read_text(encoding="utf-8").splitlines()
    add_events = [
        json.loads(line)
        for line in lines
        if line.strip() and json.loads(line).get("event_type") == "tn.recipient.added"
    ]
    if len(add_events) < 1:
        pytest.skip("need at least one add event in the source admin log")
    target = add_events[0]
    group = target["group"]
    leaf_index = target["leaf_index"]

    # Drive a real revoke through the runtime so the body has a properly
    # signed revoked envelope for (group, leaf_index).
    tn.init(yaml_path, cipher="btn")
    tn.admin.revoke_recipient(group, leaf_index=leaf_index)
    tn.flush_and_close()

    cfg = load_or_create(yaml_path)
    source_log = next((p for p in candidate_paths if p.exists() and p.stat().st_size > 0), None)
    assert source_log is not None
    lines = source_log.read_text(encoding="utf-8").splitlines()
    # Filter to admin events only; the main log mixes business events too.
    from tn.admin.log import is_admin_event_type as _is_admin

    envelopes = [
        json.loads(line)
        for line in lines
        if line.strip() and _is_admin(json.loads(line).get("event_type", ""))
    ]

    # Build a forged add(L) for the same (group, leaf_index) with a fresh
    # row_hash. The chain is single-event-type per the chain.py design;
    # we hang it off the latest add row_hash so the chain link stays
    # locally well-formed (the receiver does not enforce chain ordering
    # in the equivocation path — it only checks dedupe by row_hash).
    last_add_row = next(
        (e["row_hash"] for e in reversed(envelopes) if e["event_type"] == "tn.recipient.added"),
        target["row_hash"],
    )
    forged_ts = datetime.now(timezone.utc).isoformat()
    forged_event_id = "forged-" + forged_ts.replace(":", "-")
    public_fields = {
        "ceremony_id": cfg.ceremony_id,
        "group": group,
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

    # Build a snapshot body that is: real envelopes + forged add.
    body_ndjson = "\n".join(
        json.dumps(e, separators=(",", ":")) for e in [*envelopes, forged_env]
    ).encode("utf-8") + b"\n"

    manifest = TnpkgManifest(
        kind="admin_log_snapshot",
        from_did=cfg.device.did,
        ceremony_id=cfg.ceremony_id,
        as_of=forged_ts,
        scope="admin",
        clock={cfg.device.did: {"tn.recipient.added": 999_999}},
        event_count=len(envelopes) + 1,
        head_row_hash=forged_row_hash,
    )
    manifest.sign(cfg.device.signing_key())

    forged_snap = tmp_path / "forged.tnpkg"
    _write_tnpkg(forged_snap, manifest, {"body/admin.ndjson": body_ndjson})

    # Receiver setup — fresh, must absorb the forged snapshot.
    dst = tmp_path / "dst"
    dst.mkdir()
    dst_yaml = dst / "tn.yaml"
    tn.init(dst_yaml, cipher="btn")
    tn.flush_and_close()
    _force_admin_log_yaml(dst_yaml)

    tn.init(dst_yaml)
    receipt = tn.pkg.absorb(forged_snap)
    tn.flush_and_close()

    assert receipt.kind == "admin_log_snapshot"
    leaf_reuse = [c for c in receipt.conflicts if isinstance(c, LeafReuseAttempt)]
    assert len(leaf_reuse) >= 1, f"expected LeafReuseAttempt; got {receipt.conflicts!r}"
    flag = leaf_reuse[0]
    assert flag.group == group
    assert flag.leaf_index == leaf_index
    assert flag.attempted_row_hash == forged_row_hash
