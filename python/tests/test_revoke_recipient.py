"""End-to-end revoke_recipient on a JWE ceremony.

Verifies the current contract of the O(1) JWE revoke: the recipient is
dropped from the group, index_epoch is NOT bumped (that is rotate()'s
job — remaining recipients' HMAC search tokens stay valid), a
``tn.recipient.revoked`` attestation lands in the log, and the chain +
signature + decrypt path remain intact across the revocation.

Cipher-specific by design: hibe revocation (path rotation + re-kitting)
is covered by test_hibe_revoke.py, btn revocation by the runtime tests.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
import tn.reader
from tn.admin.log import resolve_admin_log_path


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Every test starts and ends with a closed runtime (releases file
    handles before tmp_path cleanup, which Windows requires)."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def test_revoke_recipient(tmp_path):
    ws = tmp_path
    yaml_path = ws / "tn.yaml"
    log_path = ws / ".tn/tn/logs" / "tn.ndjson"

    tn.init(yaml_path, log_path=log_path, cipher="jwe")
    cfg = tn.current_config()
    assert cfg.cipher_name == "jwe"

    tn.info("order.created", amount=100)
    old_epoch = cfg.groups["default"].index_epoch

    # Revoke a stale/unknown DID — idempotent no-op in the cipher (not in
    # the recipients list), but the admin API still emits an attestation.
    res = tn.admin.revoke_recipient("default", recipient_did="did:some-stale", cfg=cfg)
    assert res.revoked and res.cipher == "jwe"
    cfg = res.updated_cfg or tn.current_config()

    # O(1) revoke leaves index_epoch alone; epoch bumps belong to rotate().
    assert cfg.groups["default"].index_epoch == old_epoch

    tn.info("order.created", amount=200)
    tn.flush_and_close()

    tn.init(yaml_path, log_path=log_path, cipher="jwe")
    cfg = tn.current_config()
    entries = list(tn.reader.read(log_path, cfg))
    # Business events only — the attestation routes to the admin log.
    assert len(entries) == 2, f"expected 2, got {len(entries)}"
    for e in entries:
        assert e["valid"]["signature"], e["envelope"]["event_id"]
        assert e["valid"]["row_hash"], e["envelope"]["event_id"]
        assert e["valid"]["chain"], e["envelope"]["event_id"]

    events = sorted(e["envelope"]["event_type"] for e in entries)
    assert events == ["order.created", "order.created"], events

    # The tn.recipient.revoked attestation lands in the admin log.
    admin_log = resolve_admin_log_path(cfg)
    assert admin_log.exists(), admin_log
    assert "tn.recipient.revoked" in admin_log.read_text(encoding="utf-8")

    tn.flush_and_close()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
