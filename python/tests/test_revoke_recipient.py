"""End-to-end revoke_recipient on a JWE ceremony.

Verifies: calling revoke_recipient bumps index_epoch, subsequent log
entries continue to verify, and the chain + signature + decrypt path
remain intact across the revocation.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="revoke_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"
        log_path = ws / ".tn/tn/logs" / "tn.ndjson"

        tn.init(yaml_path, log_path=log_path, cipher="jwe")
        cfg = tn.current_config()
        assert cfg.cipher_name == "jwe"

        tn.info("order.created", amount=100)
        old_epoch = cfg.groups["default"].index_epoch

        # Revoke a stale/unknown DID — idempotent no-op in the cipher
        # (not in recipients list), but the admin API still bumps the
        # epoch and emits an attestation. The epoch bump is the contract
        # callers rely on; whether the DID was actually present is
        # orthogonal.
        cfg = tn.revoke_recipient(cfg, "default", "did:some-stale")

        new_epoch = cfg.groups["default"].index_epoch
        assert new_epoch == old_epoch + 1, (old_epoch, new_epoch)

        tn.info("order.created", amount=200)
        tn.flush_and_close()

        tn.init(yaml_path, log_path=log_path, cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(log_path, cfg))
        # 2 business events + 1 tn.recipient.revoked attestation
        assert len(entries) == 3, f"expected 3, got {len(entries)}"
        for e in entries:
            assert e["valid"]["signature"], e["envelope"]["event_id"]
            assert e["valid"]["row_hash"], e["envelope"]["event_id"]
            assert e["valid"]["chain"], e["envelope"]["event_id"]

        events = sorted(e["envelope"]["event_type"] for e in entries)
        assert events == ["order.created", "order.created", "tn.recipient.revoked"], events

        print(
            f"revoke_recipient: epoch {old_epoch} -> {new_epoch}, "
            f"{len(entries)} chain entries verify"
        )
        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
