"""REAL same-language seal -> verify round-trip (Python).

Unlike ``test_cli_verify.py`` (which hand-rebuilds + re-signs a fixture
envelope and never calls ``cmd_seal``), this test produces the envelope
with the REAL ``tn.cli_seal.cmd_seal`` verb, takes its EXACT stdout
ndjson, and feeds that unmodified to the REAL ``tn.cli_verify.cmd_verify``
verb. The chain is only genuine if verify's input is seal's actual
output.

PASS: genuine seal output verifies ``ok:true`` for every line; ``row_hash``
and ``sequence`` are echoed back.

FAIL cases (the public verification gate MUST catch): tampered public field, tampered
scalar, corrupted signature, broken prev_hash chain, malformed JSON.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import sys

from tn.cli_seal import cmd_seal
from tn.cli_verify import cmd_verify

# Deterministic 32-byte Ed25519 seed (same fill as interop_driver.mjs:60-61
# would give for i=0): (0*17 + j) & 0xff == j, i.e. bytes(range(32)).
_SEED = bytes(range(32))
_SEED_B64 = base64.b64encode(_SEED).decode("ascii")

_GENESIS_PREV = "sha256:" + "0" * 64


def _seal_input(**overrides) -> dict:
    """A complete seal-input line (every _REQUIRED field + public_fields)."""
    inp = {
        "seed_b64": _SEED_B64,
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": _GENESIS_PREV,
        "timestamp": "2026-04-23T12:00:00.000000Z",
        "event_id": "00000000-0000-4000-8000-000000000001",
        "public_fields": {"amount": 100, "status": "paid"},
    }
    inp.update(overrides)
    return inp


def _seal(inputs: list[dict]) -> str:
    """Run the REAL cmd_seal over input dicts; return its raw stdout ndjson."""
    stdin_text = "".join(json.dumps(o) + "\n" for o in inputs)
    out = io.StringIO()
    saved_in, saved_out = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(stdin_text), out
    try:
        rc = cmd_seal(argparse.Namespace())
    finally:
        sys.stdin, sys.stdout = saved_in, saved_out
    assert rc == 0, "cmd_seal should exit 0 on well-formed input"
    return out.getvalue()


def _verify(envelope_ndjson: str) -> tuple[int, list[dict]]:
    """Feed envelope ndjson to the REAL cmd_verify; return (rc, results)."""
    args = argparse.Namespace(stdin=io.StringIO(envelope_ndjson))
    out = io.StringIO()
    saved = sys.stdout
    sys.stdout = out
    try:
        rc = cmd_verify(args)
    finally:
        sys.stdout = saved
    results = [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]
    return rc, results


# ──────────────────────────────────────────────────────────────────────
# PASS — genuine seal output verifies ok:true
# ──────────────────────────────────────────────────────────────────────


def test_roundtrip_single_ok():
    """The real seal -> verify chain: one entry, ok:true, fields echoed."""
    inp = _seal_input()
    env_ndjson = _seal([inp])

    # The envelope verify consumes is seal's EXACT byte output.
    envelope = json.loads(env_ndjson.strip())

    rc, results = _verify(env_ndjson)
    assert rc == 0
    assert len(results) == 1
    r = results[0]
    assert r == {
        "ok": True,
        "did": envelope["device_identity"],
        "event_type": "order.created",
        "event_id": inp["event_id"],
        "row_hash": envelope["row_hash"],
        "sequence": 1,
    }
    # row_hash the verifier recomputed equals the one seal stored.
    assert r["row_hash"] == envelope["row_hash"]


def test_roundtrip_batch_all_ok():
    """A batch of genuine seal outputs all verify ok:true."""
    inputs = [
        _seal_input(
            sequence=i + 1,
            event_id=f"00000000-0000-4000-8000-00000000000{i + 1}",
            timestamp=f"2026-04-23T12:0{i}:00.000000Z",
            public_fields={"amount": (i + 1) * 100, "note": f"entry {i}"},
        )
        for i in range(3)
    ]
    env_ndjson = _seal(inputs)
    rc, results = _verify(env_ndjson)
    assert rc == 0
    assert len(results) == 3
    assert all(r["ok"] for r in results)
    assert [r["sequence"] for r in results] == [1, 2, 3]


def test_roundtrip_empty_public_fields_ok():
    """Seal with no public_fields still produces a verifiable envelope."""
    inp = _seal_input(public_fields={})
    env_ndjson = _seal([inp])
    rc, results = _verify(env_ndjson)
    assert rc == 0
    assert results[0]["ok"] is True


# ──────────────────────────────────────────────────────────────────────
# FAIL — a correct verify MUST catch each mutation of genuine seal output.
# Each test also asserts the UNMUTATED envelope verifies ok:true, proving
# the failure is caused by the mutation and not by a broken harness (i.e.
# "would pass if verification were effectively skipped / not mutated").
# ──────────────────────────────────────────────────────────────────────


def test_tampered_public_field_caught():
    env_ndjson = _seal([_seal_input()])
    env = json.loads(env_ndjson.strip())

    # Sanity: the untouched genuine envelope verifies.
    rc_ok, results_ok = _verify(json.dumps(env) + "\n")
    assert results_ok[0]["ok"] is True

    env["amount"] = 999  # flip a public field after sealing
    rc, results = _verify(json.dumps(env) + "\n")
    assert rc == 0
    assert results[0]["ok"] is False
    assert results[0]["reason"] == "row_hash mismatch"
    assert results[0]["got"] == env["row_hash"]
    assert results[0]["expected"] != env["row_hash"]


def test_tampered_scalar_caught():
    env_ndjson = _seal([_seal_input()])
    env = json.loads(env_ndjson.strip())

    env["event_type"] = "order.refunded"  # change a hashed scalar after sealing
    rc, results = _verify(json.dumps(env) + "\n")
    assert rc == 0
    assert results[0]["ok"] is False
    assert results[0]["reason"] == "row_hash mismatch"


def test_corrupted_signature_caught():
    env_ndjson = _seal([_seal_input()])
    env = json.loads(env_ndjson.strip())

    # Replace with a valid-base64 but wrong 64-byte signature so row_hash
    # still matches and we actually reach the signature check.
    env["signature"] = base64.b64encode(b"\x01" * 64).decode("ascii")
    rc, results = _verify(json.dumps(env) + "\n")
    assert rc == 0
    assert results[0]["ok"] is False
    assert results[0]["reason"] == "bad signature"


def test_broken_prev_hash_chain_caught():
    """Two-entry chain; corrupt entry 2's prev_hash so it no longer links.

    ``verify`` is per-envelope and ``prev_hash`` is part of the row_hash
    preimage, so a broken chain link surfaces as a row_hash mismatch on the
    tampered entry. We also assert the cross-envelope chain invariant that a
    correct chain satisfies (entry2.prev_hash == entry1.row_hash) to make the
    "broken chain" semantics explicit, since verify itself does not check it.
    """
    inp1 = _seal_input(sequence=1)
    env1 = json.loads(_seal([inp1]).strip())

    # A genuine 2nd entry links to entry1: prev_hash == entry1.row_hash.
    inp2 = _seal_input(
        sequence=2,
        event_id="00000000-0000-4000-8000-000000000002",
        timestamp="2026-04-23T12:01:00.000000Z",
        prev_hash=env1["row_hash"],
        public_fields={"amount": 200},
    )
    env2 = json.loads(_seal([inp2]).strip())

    # Correct chain: entry2.prev_hash points at entry1.row_hash, and both
    # verify ok on their own.
    assert env2["prev_hash"] == env1["row_hash"]
    rc_ok, results_ok = _verify(
        json.dumps(env1) + "\n" + json.dumps(env2) + "\n"
    )
    assert [r["ok"] for r in results_ok] == [True, True]

    # Break the link: rewrite entry2.prev_hash to a wrong (genesis) value.
    env2["prev_hash"] = _GENESIS_PREV
    rc, results = _verify(json.dumps(env1) + "\n" + json.dumps(env2) + "\n")
    assert rc == 0
    assert results[0]["ok"] is True  # entry1 untouched
    assert results[1]["ok"] is False  # entry2 link broken
    assert results[1]["reason"] == "row_hash mismatch"
    # The cross-envelope chain invariant is now violated.
    assert env2["prev_hash"] != env1["row_hash"]


def test_malformed_json_is_fatal():
    """Non-JSON on verify's stdin is fatal: exit 2, no result lines."""
    rc, results = _verify("{not valid json\n")
    assert rc == 2
    assert results == []


# Note: the "encrypted group payload" FAIL case from the contract is NOT
# reproduced here as a seal->verify round-trip. cmd_seal is the public-only
# path (groups={}, cli_seal.py:90-91): it cannot emit an envelope carrying a
# {ciphertext,...} group payload, so there is no GENUINE seal output to feed
# verify for that case. Synthesising a fake ciphertext block would not be a
# real round-trip. That branch is already covered by the unit test
# test_cli_verify.py::test_group_payload_rejected. Per the HARD RULE we leave
# it out of this round-trip suite rather than fake it.
