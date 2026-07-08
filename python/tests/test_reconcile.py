
# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import base64
import json
import os
from pathlib import Path

import yaml as _yaml

from tn import admin
from tn.config import load_or_create
from tn.conventions import pending_offers_dir
from tn.reconcile import _reconcile


def test_reconcile_promotes_pending_jwe_recipient(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher=_workflow_cipher("jwe"))
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob")  # pending
    pending_offers_dir(tmp_path).mkdir(parents=True, exist_ok=True)
    bob_pub = os.urandom(32)
    (pending_offers_dir(tmp_path) / "did_key_z6MkBob.json").write_text(
        json.dumps(
            {
                "device_identity": "did:key:z6MkBob",
                "group": "default",
                "x25519_pub_b64": base64.b64encode(bob_pub).decode("ascii"),
                "compiled_at": "2026-04-21T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    result = _reconcile(cfg)
    # 0.4.3a1: Promotion.peer_did → Promotion.recipient_identity, yaml
    # recipient `did:` → `recipient_identity:`.
    assert any(p.recipient_identity == "did:key:z6MkBob" for p in result.promotions)
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    bob = next(
        r
        for r in doc["groups"]["default"]["recipients"]
        if r["recipient_identity"] == "did:key:z6MkBob"
    )
    assert base64.b64decode(bob["pub_b64"]) == bob_pub


# test_reconcile_auto_issues_bearer_coupon removed alongside the BGW cipher
# (Workstream G). btn recipient reconciliation lives in the btn admin
# test suite (test_recipient_tracking.py, test_admin_state.py); the orphan
# tn/__init__.py::_emit_missing_recipients helper was deleted.


def test_reconcile_idempotent(tmp_path: Path):
    """Running reconcile twice on a clean state should produce no further
    actions."""
    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result1 = _reconcile(cfg)
    assert result1.promotions == []
    assert result1.coupons_issued == []
    result2 = _reconcile(cfg)
    assert result2.promotions == []
    assert result2.coupons_issued == []
