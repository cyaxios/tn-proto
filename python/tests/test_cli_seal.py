"""Tests for ``tn.cli_seal`` — the Python ``tn seal`` verb.

Mirrors the TS ``tn-js seal`` contract: one JSON object per stdin
line in, one attested envelope ndjson line out. Covers the happy
path (with and without ``public_fields``), blank-line skipping,
invalid-JSON and missing-field error branches (both exit 2), and
proves the envelope is byte-compatible with the SDK primitives
(:func:`tn.chain._compute_row_hash`, :class:`tn.signing.DeviceKey`).
"""

from __future__ import annotations

import argparse
import base64
import io
import json

import pytest

from tn import cli_seal
from tn.chain import ZERO_HASH, _compute_row_hash
from tn.signing import DeviceKey

# A deterministic 32-byte Ed25519 seed -> stable DID across runs.
_SEED = bytes(range(32))
_SEED_B64 = base64.b64encode(_SEED).decode("ascii")
_DK = DeviceKey.from_private_bytes(_SEED)


def _base_input(**overrides) -> dict:
    inp = {
        "seed_b64": _SEED_B64,
        "event_type": "order.created",
        "level": "info",
        "sequence": 1,
        "prev_hash": ZERO_HASH,
        "timestamp": "2026-04-23T12:00:00.000000Z",
        "event_id": "00000000-0000-4000-8000-000000000000",
    }
    inp.update(overrides)
    return inp


def _run(monkeypatch, stdin_text: str) -> tuple[str, int]:
    """Drive cmd_seal with a fake stdin; return (stdout, return_code).

    Swallows SystemExit so the exit-2 error branches are assertable.
    """
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    args = argparse.Namespace()
    try:
        rc = cli_seal.cmd_seal(args)
    except SystemExit as e:
        return out.getvalue(), int(e.code)
    return out.getvalue(), rc


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_seal_no_public_fields_byte_compatible(monkeypatch):
    inp = _base_input()
    out, rc = _run(monkeypatch, json.dumps(inp) + "\n")
    assert rc == 0

    line = out.rstrip("\n")
    env = json.loads(line)

    # Independent recomputation of the row_hash + signature.
    expected_rh = _compute_row_hash(
        device_identity=_DK.device_identity,
        timestamp=inp["timestamp"],
        event_id=inp["event_id"],
        event_type=inp["event_type"],
        level=inp["level"],
        prev_hash=inp["prev_hash"],
        public_fields={},
        groups={},
    )
    assert env["row_hash"] == expected_rh
    assert env["device_identity"] == _DK.device_identity
    assert DeviceKey.verify(
        _DK.device_identity, expected_rh.encode("utf-8"),
        _sig_bytes(env["signature"]),
    )

    # Exact mandatory key order + compact separators (byte-compatible wire).
    assert list(env.keys()) == [
        "device_identity", "timestamp", "event_id", "event_type",
        "level", "sequence", "prev_hash", "row_hash", "signature",
    ]
    assert ", " not in line and '": ' not in line  # compact, no spaces
    assert out.endswith("\n")


def test_seal_with_public_fields(monkeypatch):
    inp = _base_input(public_fields={"amount": 100, "currency": "USD"})
    out, rc = _run(monkeypatch, json.dumps(inp) + "\n")
    assert rc == 0
    env = json.loads(out)
    # Public fields appended after the mandatory scalars, in order.
    assert env["amount"] == 100
    assert env["currency"] == "USD"
    assert list(env.keys())[-2:] == ["amount", "currency"]

    expected_rh = _compute_row_hash(
        device_identity=_DK.device_identity,
        timestamp=inp["timestamp"],
        event_id=inp["event_id"],
        event_type=inp["event_type"],
        level=inp["level"],
        prev_hash=inp["prev_hash"],
        public_fields={"amount": 100, "currency": "USD"},
        groups={},
    )
    assert env["row_hash"] == expected_rh


def test_seal_public_fields_null_treated_as_empty(monkeypatch):
    # public_fields: null -> {} (mirrors TS `?? {}`).
    inp = _base_input(public_fields=None)
    out, rc = _run(monkeypatch, json.dumps(inp) + "\n")
    assert rc == 0
    env = json.loads(out)
    assert list(env.keys())[-1] == "signature"  # no extra fields


def test_seal_collision_public_field_skipped(monkeypatch):
    # A public field colliding with a mandatory key must NOT overwrite it.
    inp = _base_input(public_fields={"level": "SHOULD-NOT-WIN"})
    out, rc = _run(monkeypatch, json.dumps(inp) + "\n")
    assert rc == 0
    env = json.loads(out)
    assert env["level"] == "info"


def test_seal_multiple_lines(monkeypatch):
    a = json.dumps(_base_input(event_id="aaaa")) + "\n"
    b = json.dumps(_base_input(event_id="bbbb")) + "\n"
    out, rc = _run(monkeypatch, a + b)
    assert rc == 0
    lines = out.splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event_id"] == "aaaa"
    assert json.loads(lines[1])["event_id"] == "bbbb"


def test_seal_blank_lines_skipped(monkeypatch):
    body = json.dumps(_base_input()) + "\n"
    out, rc = _run(monkeypatch, "\n   \n" + body + "\n")
    assert rc == 0
    assert len(out.splitlines()) == 1


def test_seal_empty_stdin(monkeypatch):
    out, rc = _run(monkeypatch, "")
    assert rc == 0
    assert out == ""


# ---------------------------------------------------------------------
# Error branches (all exit 2)
# ---------------------------------------------------------------------


def test_seal_invalid_json_exits_2(monkeypatch, capsys):
    out, rc = _run(monkeypatch, "{not json}\n")
    assert rc == 2
    assert out == ""
    assert "invalid JSON on stdin" in capsys.readouterr().err


@pytest.mark.parametrize("missing", list(cli_seal._REQUIRED))
def test_seal_missing_required_field_exits_2(monkeypatch, capsys, missing):
    inp = _base_input()
    del inp[missing]
    out, rc = _run(monkeypatch, json.dumps(inp) + "\n")
    assert rc == 2
    assert f"missing field {missing}" in capsys.readouterr().err


def _sig_bytes(sig_b64: str) -> bytes:
    pad = "=" * (-len(sig_b64) % 4)
    return base64.urlsafe_b64decode(sig_b64 + pad)
