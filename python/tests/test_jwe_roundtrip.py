"""End-to-end tn.log round-trip under a JWE-configured ceremony.

Mirrors `test_tnlog_roundtrip.py` (which pins BGW) to prove the full
tn.init / tn.info / tn.read / signature / chain / decrypt pipeline
works identically under JWE as the group-sealing cipher.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jweroundtrip_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"
        log_path = ws / ".tn/tn/logs" / "tn.ndjson"

        tn.init(yaml_path, log_path=log_path, cipher="jwe")
        cfg = tn.current_config()
        assert cfg.cipher_name == "jwe", f"expected jwe, got {cfg.cipher_name}"
        print(f"DID:       {cfg.device.did}")
        print(f"cipher:    {cfg.cipher_name}")
        print(f"keystore:  {cfg.keystore}")

        # Request-scoped context — same shape as the BGW test.
        tn.set_context(
            server_did="did:key:z6Mk-service-stub",
            request_id="req-abc-123",
            method="POST",
            path="/orders",
            user_id=42,
        )

        tn.info("order.created", amount=999, currency="USD")
        tn.info("order.created", amount=250, currency="EUR")
        tn.warning("auth.retry", attempts=3)
        tn.info("order.created", amount=50, currency="GBP")

        tn.flush_and_close()

        # Reopen the ceremony to exercise the load() path under JWE.
        tn.init(yaml_path, log_path=log_path, cipher="jwe")
        cfg = tn.current_config()
        assert cfg.cipher_name == "jwe"

        # 2026-04-25 read-reshape: this script introspects entry["envelope"] /
        # ["plaintext"] / ["valid"], so it needs the audit-grade shape. The
        # default tn.read() now returns a flat decrypted dict.
        entries = list(tn.read(log_path, cfg, raw=True))
        print(f"\nread back {len(entries)} entries")
        assert len(entries) == 4, f"expected 4 entries, got {len(entries)}"

        per_event: dict[str, list] = {}
        for e in entries:
            env = e["envelope"]
            per_event.setdefault(env["event_type"], []).append(e)

        assert set(per_event) == {"order.created", "auth.retry"}, list(per_event)
        assert len(per_event["order.created"]) == 3
        assert len(per_event["auth.retry"]) == 1

        for e in entries:
            env = e["envelope"]
            assert e["valid"]["signature"], f"bad signature: {env['event_id']}"
            assert e["valid"]["row_hash"], f"bad row_hash:  {env['event_id']}"
            assert e["valid"]["chain"], f"broken chain:  {env['event_id']}"
            assert "default" in e["plaintext"], f"decrypt failed: {env['event_id']}"
            assert "user_id" in e["plaintext"]["default"]
            assert e["plaintext"]["default"]["user_id"] == 42

        # sequence check within order.created
        seqs = [e["envelope"]["sequence"] for e in per_event["order.created"]]
        assert seqs == [1, 2, 3], seqs
        assert per_event["auth.retry"][0]["envelope"]["sequence"] == 1

        # amount recovered correctly
        amounts = [e["plaintext"]["default"]["amount"] for e in per_event["order.created"]]
        assert amounts == [999, 250, 50], amounts

        print("all JWE roundtrip assertions passed")
        print(f"  signatures:  {sum(1 for e in entries if e['valid']['signature'])}/{len(entries)}")
        print(f"  row_hashes:  {sum(1 for e in entries if e['valid']['row_hash'])}/{len(entries)}")
        print(f"  chains:      {sum(1 for e in entries if e['valid']['chain'])}/{len(entries)}")
        print(
            f"  decrypted:   {sum(1 for e in entries if 'default' in e['plaintext'])}/{len(entries)}"
        )

        tn.flush_and_close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
