"""Tests for ``tn.cli_verify`` — the Python mirror of ``tn-js verify``.

Exercises every branch of ``cmd_verify`` / ``_verify_envelope``: a
valid envelope, each rejection reason (missing field, group payload,
row_hash mismatch, bad signature), the per-envelope exception path, the
fatal malformed-JSON path, blank-line skipping, and the default-stdin
fallback.
"""

from __future__ import annotations

import argparse
import io
import json

from tn.chain import _compute_row_hash
from tn.cli_verify import cmd_verify
from tn.signing import DeviceKey, _signature_b64

_SEED = bytes(range(32))  # deterministic 32-byte Ed25519 seed


def _seal(**overrides):
    """Build a well-formed, signed public-only envelope dict.

    Any key in ``overrides`` replaces the default before signing, so a
    caller can produce an envelope whose row_hash/signature are still
    internally consistent.
    """
    dk = DeviceKey.from_private_bytes(_SEED)
    env = {
        "device_identity": dk.device_identity,
        "timestamp": "2026-04-23T12:00:00.000000Z",
        "event_id": "00000000-0000-4000-8000-000000000000",
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": "sha256:" + "0" * 64,
    }
    public_fields = overrides.pop("public_fields", {"amount": 100})
    env.update(overrides)
    env.update(public_fields)

    row_hash = _compute_row_hash(
        device_identity=env["device_identity"],
        timestamp=env["timestamp"],
        event_id=env["event_id"],
        event_type=env["event_type"],
        level=env["level"],
        prev_hash=env["prev_hash"],
        public_fields=public_fields,
        groups={},
    )
    env["row_hash"] = row_hash
    env["signature"] = _signature_b64(dk.sign(row_hash.encode("ascii")))
    return env


def _run(lines):
    """Feed ndjson ``lines`` through cmd_verify; return (rc, results)."""
    text = "".join(line + "\n" for line in lines)
    args = argparse.Namespace(stdin=io.StringIO(text))
    out = io.StringIO()
    import sys

    saved = sys.stdout
    sys.stdout = out
    try:
        rc = cmd_verify(args)
    finally:
        sys.stdout = saved
    results = [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]
    return rc, results


def test_valid_envelope_ok():
    env = _seal()
    rc, results = _run([json.dumps(env)])
    assert rc == 0
    assert results == [
        {
            "ok": True,
            "did": env["device_identity"],
            "event_type": "order.created",
            "event_id": env["event_id"],
            "row_hash": env["row_hash"],
            "sequence": 1,
        }
    ]


def test_missing_field():
    env = _seal()
    del env["signature"]
    rc, results = _run([json.dumps(env)])
    assert rc == 0
    assert results[0] == {
        "ok": False,
        "reason": "missing signature",
        "event_id": env["event_id"],
    }


def test_group_payload_rejected():
    env = _seal()
    env["secret"] = {"ciphertext": "deadbeef", "field_hashes": {}}
    rc, results = _run([json.dumps(env)])
    assert rc == 0
    assert results[0] == {
        "ok": False,
        "reason": "group payload secret present; public-only verify",
        "event_id": env["event_id"],
    }


def test_row_hash_mismatch():
    env = _seal()
    env["amount"] = 999  # tamper a public field after signing
    rc, results = _run([json.dumps(env)])
    assert rc == 0
    assert results[0]["ok"] is False
    assert results[0]["reason"] == "row_hash mismatch"
    assert results[0]["got"] == env["row_hash"]
    assert results[0]["expected"] != env["row_hash"]
    assert results[0]["event_id"] == env["event_id"]


def test_bad_signature():
    env = _seal()
    # Replace with a valid-base64 but wrong 64-byte signature so the
    # row_hash still matches and we reach the signature check.
    env["signature"] = _signature_b64(b"\x01" * 64)
    rc, results = _run([json.dumps(env)])
    assert rc == 0
    assert results[0] == {
        "ok": False,
        "reason": "bad signature",
        "event_id": env["event_id"],
    }


def test_per_envelope_exception():
    # row_hash as a non-string makes `.encode("ascii")` raise inside
    # _verify_envelope, after the presence + recompute checks pass... so
    # instead force the exception path via a signature that base64-decodes
    # but whose row_hash is an int (encode attribute error). Simplest: a
    # row_hash that is an int — recompute compares int != str so we'd hit
    # mismatch, not exception. Use an envelope where row_hash matches the
    # recompute but signature is non-string -> _signature_from_b64 raises.
    env = _seal()
    env["signature"] = 12345  # not a str -> _signature_from_b64 raises
    rc, results = _run([json.dumps(env)])
    assert rc == 0
    assert results[0]["ok"] is False
    assert results[0]["reason"].startswith("exception:")


def test_malformed_json_is_fatal():
    rc, results = _run(["{not json"])
    assert rc == 2
    assert results == []


def test_blank_lines_skipped():
    env = _seal()
    rc, results = _run(["", "   ", json.dumps(env)])
    assert rc == 0
    assert len(results) == 1
    assert results[0]["ok"] is True


def test_default_stdin_fallback(monkeypatch):
    env = _seal()
    text = json.dumps(env) + "\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    args = argparse.Namespace()  # no .stdin attribute -> falls back
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    rc = cmd_verify(args)
    assert rc == 0
    line = out.getvalue().strip()
    assert json.loads(line)["ok"] is True
