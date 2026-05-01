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
    cfg = load_or_create(yaml_path, cipher="jwe")
    admin._add_recipient_jwe_impl(cfg, "default", "did:key:z6MkBob")  # pending
    pending_offers_dir(tmp_path).mkdir(parents=True, exist_ok=True)
    bob_pub = os.urandom(32)
    (pending_offers_dir(tmp_path) / "did_key_z6MkBob.json").write_text(
        json.dumps(
            {
                "signer_did": "did:key:z6MkBob",
                "group": "default",
                "x25519_pub_b64": base64.b64encode(bob_pub).decode("ascii"),
                "compiled_at": "2026-04-21T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    result = _reconcile(cfg)
    assert any(p.peer_did == "did:key:z6MkBob" for p in result.promotions)
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    bob = next(r for r in doc["groups"]["default"]["recipients"] if r["did"] == "did:key:z6MkBob")
    assert base64.b64decode(bob["pub_b64"]) == bob_pub


# test_reconcile_auto_issues_bearer_coupon removed alongside the BGW cipher
# (Workstream G). btn recipient reconciliation lives in the btn admin
# test suite (test_recipient_tracking.py, test_admin_state.py); the orphan
# tn/__init__.py::_emit_missing_recipients helper was deleted.


def test_reconcile_idempotent(tmp_path: Path):
    """Running reconcile twice on a clean state should produce no further
    actions."""
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    result1 = _reconcile(cfg)
    assert result1.promotions == []
    assert result1.coupons_issued == []
    result2 = _reconcile(cfg)
    assert result2.promotions == []
    assert result2.coupons_issued == []
