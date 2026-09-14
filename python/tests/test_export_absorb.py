"""Tests for the unified `tn.pkg.export()` / `tn.pkg.absorb()` surface.

Round-trip every kind shipped in v1 and verify the manifest signature /
secret-protection invariants.
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import json
import os
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn import admin
from tn.absorb import absorb
from tn.compile import compile_enrolment
from tn.config import LoadedConfig, load_or_create
from tn.conventions import outbox_dir
from tn.enrollment import EnrollmentStore
from tn.export import _build_kit_bundle_body, export
from tn.offer import _ensure_mykey, offer
from tn.tnpkg import _read_manifest, _verify_manifest_signature
from tn.trust import AcceptedOffer


@pytest.mark.parametrize("kind", ["recipient_invite", "contact_update", "group_keys"])
def test_export_rejects_kinds_without_a_producer(tmp_path: Path, kind: str):
    destination = tmp_path / "output.tnpkg"
    with pytest.raises(ValueError, match="unknown kind"):
        export(destination, kind=kind)
    assert not destination.exists()


@pytest.fixture(autouse=True)
def fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


# Enrolment packages now require a durably reconciled AcceptedOffer obtained
# through the real trusted-offer ceremony (a hand-built one is rejected with
# TrustReason.UNTRUSTED_PRINCIPAL). This helper drives that ceremony end to end
# — publisher preauthorize + issue_challenge, reader offer, publisher absorb +
# reconcile — mirroring tests/test_jwe_trusted_enrollment_e2e.py.
def _only_outbox_artifact(cfg: LoadedConfig) -> Path:
    artifacts = list(outbox_dir(cfg.yaml_path).glob("*.tnpkg"))
    assert len(artifacts) == 1
    return artifacts[0]


def _accepted_flow(
    publisher: LoadedConfig, reader: LoadedConfig, group: str = "default"
) -> AcceptedOffer:
    store = EnrollmentStore(publisher, publisher.device)
    store.preauthorize(reader.device.did, group)
    challenge = store.issue_challenge(reader.device.did, group, timedelta(minutes=10))
    offer(reader, publisher.device.did, challenge=challenge, group=group)
    receipt = absorb(publisher, _only_outbox_artifact(reader))
    assert receipt.offer_digest is not None
    now = datetime.now(timezone.utc)
    return store.reconcile(store.pending_offer(receipt.offer_digest, now=now), now=now)


def test_export_offer_round_trip(tmp_path: Path):
    bob = tmp_path / "bob"
    bob.mkdir()
    bob_cfg = load_or_create(bob / "tn.yaml", cipher=_workflow_cipher("jwe"))
    # offer() parses publisher_did as a real ed25519 did:key, so the target
    # publisher must be a real DeviceKey-backed identity (a placeholder like
    # "did:key:z6MkAlice" fails base58 decoding). An unsolicited offer with no
    # challenge is fine here; it just needs the publisher's ceremony_id.
    alice_cfg = load_or_create(tmp_path / "alice" / "tn.yaml", cipher=_workflow_cipher("jwe"))
    alice_did = alice_cfg.device.device_identity
    pkg = offer(bob_cfg, publisher_did=alice_did, ceremony_id=alice_cfg.ceremony_id)
    out = tmp_path / "offer.tnpkg"
    export(out, kind="offer", cfg=bob_cfg, package=pkg, to_did=alice_did)
    assert out.exists()

    manifest, body = _read_manifest(out)
    assert manifest.kind == "offer"
    assert manifest.publisher_identity == bob_cfg.device.device_identity
    assert manifest.recipient_identity == alice_did
    assert "body/package.json" in body
    assert _verify_manifest_signature(manifest)


def test_export_enrolment_round_trip(tmp_path: Path):
    alice = tmp_path / "alice"
    alice.mkdir()
    alice_cfg = load_or_create(alice / "tn.yaml", cipher=_workflow_cipher("jwe"))
    # Bob is a real reader who enrolls through the trusted-offer ceremony so
    # compile_enrolment has a durably reconciled AcceptedOffer to bind.
    bob_cfg = load_or_create(tmp_path / "bob" / "tn.yaml", cipher=_workflow_cipher("jwe"))
    bob_did = bob_cfg.device.device_identity
    bob_pub = _ensure_mykey(bob_cfg, "default")
    accepted = _accepted_flow(alice_cfg, bob_cfg)
    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_did, bob_pub)
    pkg = compile_enrolment(alice_cfg, "default", bob_did, accepted_offer=accepted)

    out = tmp_path / "enrolment.tnpkg"
    export(out, kind="enrolment", cfg=alice_cfg, package=pkg, to_did=bob_did)

    manifest, body = _read_manifest(out)
    assert manifest.kind == "enrolment"
    assert manifest.recipient_identity == bob_did
    assert _verify_manifest_signature(manifest)
    body_pkg = json.loads(body["body/package.json"].decode("utf-8"))
    assert body_pkg["package_kind"] == "enrolment"


def test_export_kit_bundle_round_trip(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher=_workflow_cipher("btn"))
    cfg = tn.current_config()
    out = tmp_path / "bundle.tnpkg"
    export(out, kind="kit_bundle", cfg=cfg)
    tn.flush_and_close()

    manifest, body = _read_manifest(out)
    assert manifest.kind == "kit_bundle"
    assert _verify_manifest_signature(manifest)
    # At least one btn kit body file must be present.
    assert any(name.endswith(".btn.mykit") for name in body)
    # Marker should NOT be present for readers-only.
    assert "body/WARNING_CONTAINS_PRIVATE_KEYS" not in body


def _mk_keystore(tmp_path: Path, *names: str) -> Path:
    ks = tmp_path / "keys"
    ks.mkdir()
    for n in names:
        (ks / n).write_bytes(b"kitdata-" + n.encode())
    return ks


def test_build_kit_bundle_body_groups_filter(tmp_path: Path):
    """groups_filter restricts which group kits land in the body."""
    ks = _mk_keystore(tmp_path, "default.btn.mykit", "payments.btn.mykit")
    body, extras = _build_kit_bundle_body(
        None, ks, full=False, groups_filter=["payments"], confirm_includes_secrets=False
    )
    assert "body/payments.btn.mykit" in body
    assert "body/default.btn.mykit" not in body
    assert len(extras["state"]["kits"]) == 1
    assert extras["scope"] == "kit_bundle"


def test_build_kit_bundle_body_all_kits_when_no_filter(tmp_path: Path):
    ks = _mk_keystore(tmp_path, "default.btn.mykit", "payments.btn.mykit")
    body, extras = _build_kit_bundle_body(
        None, ks, full=False, groups_filter=None, confirm_includes_secrets=False
    )
    assert "body/default.btn.mykit" in body
    assert "body/payments.btn.mykit" in body
    assert len(extras["state"]["kits"]) == 2


def test_build_kit_bundle_body_no_kits_raises(tmp_path: Path):
    ks = tmp_path / "empty_keys"
    ks.mkdir()
    with pytest.raises(RuntimeError, match=r"no \*\.btn\.mykit"):
        _build_kit_bundle_body(
            None, ks, full=False, groups_filter=None, confirm_includes_secrets=False
        )


def test_export_full_keystore_requires_confirmation(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher=_workflow_cipher("btn"))
    cfg = tn.current_config()

    out = tmp_path / "full.tnpkg"
    with pytest.raises(ValueError, match="confirm_includes_secrets"):
        export(out, kind="full_keystore", cfg=cfg)
    assert not out.exists()

    # With confirmation, the export proceeds and the loud marker lives in body/.
    export(out, kind="full_keystore", cfg=cfg, confirm_includes_secrets=True)
    tn.flush_and_close()
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    assert "body/WARNING_CONTAINS_PRIVATE_KEYS" in names
    assert "body/local.private" in names
