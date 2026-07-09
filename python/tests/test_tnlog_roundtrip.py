"""End-to-end tn.log round-trip: init -> log -> read -> verify, run under
every supported group-sealing cipher (btn, jwe, hibe).

Creates a fresh ceremony in a temp dir, writes a handful of entries
across two event types, then reads them back and asserts:
  - plaintext survives the encrypt / decrypt round trip
  - every entry's signature validates
  - every entry's row_hash recomputes
  - the chain per event_type is intact (prev_hash links match)
  - context fields propagate from contextvars into the envelope

This file absorbed the former ``test_jwe_roundtrip.py``; the cipher is now
a pytest parameter instead of one file per cipher.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
import tn.reader


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Every test starts and ends with a closed runtime (releases file
    handles before tmp_path cleanup, which Windows requires) and empty
    request context (set_context would otherwise leak into later tests
    in the same process)."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()


@pytest.mark.parametrize("cipher", ["btn", "jwe", "hibe"])
def test_tnlog_roundtrip(tmp_path, cipher):
    yaml_path = tmp_path / "tn.yaml"
    log_path = tmp_path / ".tn/tn/logs" / "tn.ndjson"

    tn.init(yaml_path, log_path=log_path, pool_size=4, cipher=cipher)
    cfg = tn.current_config()
    assert cfg.cipher_name == cipher

    # Request-scoped context (PRD §13).
    tn.set_context(
        server_did="did:key:z6Mk-service-stub",
        request_id="req-abc-123",
        method="POST",
        path="/orders",
        user_id=42,  # not in public_fields -> goes to default group
    )

    tn.info("order.created", amount=999, currency="USD")
    tn.info("order.created", amount=250, currency="EUR")
    tn.warning("auth.retry", attempts=3)
    tn.info("order.created", amount=50, currency="GBP")

    tn.flush_and_close()

    # Reopen the ceremony to exercise the load() path.
    tn.init(yaml_path, log_path=log_path, pool_size=4, cipher=cipher)
    cfg = tn.current_config()
    assert cfg.cipher_name == cipher

    # This test introspects entry["envelope"] / ["plaintext"] / ["valid"],
    # so it uses the audit-grade reader shape directly.
    entries = list(tn.reader.read(log_path, cfg))
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
        assert e["valid"]["row_hash"], f"bad row_hash: {env['event_id']}"
        assert e["valid"]["chain"], f"broken chain: {env['event_id']}"
        assert "default" in e["plaintext"], f"decrypt failed: {env['event_id']}"
        assert e["plaintext"]["default"]["user_id"] == 42

    # sequence check within order.created
    seqs = [e["envelope"]["sequence"] for e in per_event["order.created"]]
    assert seqs == [1, 2, 3], seqs
    assert per_event["auth.retry"][0]["envelope"]["sequence"] == 1

    # amount recovered correctly
    amounts = [e["plaintext"]["default"]["amount"] for e in per_event["order.created"]]
    assert amounts == [999, 250, 50], amounts

    tn.flush_and_close()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
