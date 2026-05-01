"""Entry object and VerifyError: shape, attributes, formatting, tamper handling.

After the 2026-04-25 ``tn.read()`` reshape, the default verb returns flat
dicts and no longer raises on tampered rows. This file exercises the
``Entry`` wrapper class directly: it reads via ``tn.read(raw=True)`` (the
``{envelope, plaintext, valid}`` shape) and constructs ``Entry`` objects
explicitly. The tamper tests use ``tn.read(verify=True)`` and assert the
``_valid`` block instead of catching ``VerifyError``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import Audit, Entry


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _setup(tmp_path: Path) -> Path:
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    return yaml


def _user_entries():
    """User-level Entry objects, wrapped from tn.read(raw=True)."""
    return [
        Entry(r)
        for r in tn.read(raw=True)
        if not r["envelope"]["event_type"].startswith("tn.")
    ]


def _user_raw():
    """tn.read(raw=True) filtered to user-level events."""
    return [e for e in tn.read(raw=True) if not e["envelope"]["event_type"].startswith("tn.")]


def test_entry_is_flat_and_no_groups_leak(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100, note="first", currency="USD")

    entries = _user_entries()
    assert len(entries) == 1
    e = entries[0]

    assert isinstance(e, Entry)
    # Envelope metadata surfaces as attributes, not nested dicts.
    assert isinstance(e.timestamp, datetime)
    assert e.timestamp.tzinfo is timezone.utc
    assert e.level == "INFO"
    assert e.event_type == "order.created"
    assert e.sequence == 1
    assert e.did.startswith("did:key:z")
    assert len(e.event_id) == 36  # uuid v4

    # Fields are merged and flat: no "default" or any other group name appears.
    assert e.fields == {"amount": 100, "note": "first", "currency": "USD"}
    assert "default" not in e.fields
    assert "pii" not in e.fields

    # Dict-style access delegates to fields.
    assert e["amount"] == 100
    assert "note" in e
    assert e.get("missing", 42) == 42

    # valid is a single bool, not a dict.
    assert e.valid is True


def test_entry_str_is_log_shaped(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100, note="first test")

    e = _user_entries()[0]
    line = str(e)

    # Expected shape: "2026-04-22 14:44:26.267 INFO    order.created  amount=100  note=\"first test\""
    assert " INFO " in line
    assert " order.created" in line
    assert "amount=100" in line
    # Strings with spaces get quoted for parseability.
    assert 'note="first test"' in line


def test_entry_to_logfmt_and_to_json(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100, currency="USD")

    e = _user_entries()[0]

    lf = e.to_logfmt()
    assert "event=order.created" in lf
    assert "level=INFO" in lf
    assert "amount=100" in lf
    assert "currency=USD" in lf

    js = e.to_json()
    parsed = json.loads(js)
    assert parsed["event_type"] == "order.created"
    assert parsed["level"] == "INFO"
    assert parsed["amount"] == 100
    assert parsed["currency"] == "USD"
    assert parsed["valid"] is True
    # JSON form is flat, no nested envelope/plaintext keys.
    assert "envelope" not in parsed
    assert "plaintext" not in parsed


def test_audit_exposes_crypto_details(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100)

    e = _user_entries()[0]
    a = e.audit
    assert isinstance(a, Audit)

    # Crypto details reachable through audit.
    assert a.signature  # base64url string
    assert a.row_hash.startswith("sha256:")
    assert a.prev_hash.startswith("sha256:")
    assert isinstance(a.validity, dict)
    assert set(a.validity.keys()) == {"signature", "row_hash", "chain"}

    # Per-group breakdown surfaces the group name for auditors who need it.
    assert "default" in a.per_group
    assert a.per_group["default"]["amount"] == 100

    # Field hashes per group.
    fh = a.field_hashes
    assert "default" in fh
    assert fh["default"]["amount"].startswith("hmac-sha256:v1:")

    # Ciphertext as raw bytes.
    ct = a.ciphertext
    assert isinstance(ct["default"], bytes)
    assert len(ct["default"]) > 0


def test_read_raw_returns_dict_form(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100)

    raw = _user_raw()
    assert len(raw) == 1
    r = raw[0]
    assert isinstance(r, dict)
    assert set(r.keys()) == {"envelope", "plaintext", "valid"}
    assert r["envelope"]["event_type"] == "order.created"
    assert r["plaintext"]["default"]["amount"] == 100
    assert r["valid"] == {"signature": True, "row_hash": True, "chain": True}


def test_multiple_entries_iterate_in_order(tmp_path):
    _setup(tmp_path)
    tn.info("a.test", n=1)
    tn.info("a.test", n=2)
    tn.info("b.test", n=10)

    entries = _user_entries()
    assert [(e.event_type, e.sequence) for e in entries] == [
        ("a.test", 1),
        ("a.test", 2),
        ("b.test", 1),  # b.test has its own sequence
    ]
    assert [e["n"] for e in entries] == [1, 2, 10]


def test_tampered_row_surfaces_via_valid_block(tmp_path):
    """``tn.read(verify=True)`` no longer raises on tamper — instead it
    surfaces the failed check via the ``_valid`` block. (The fail-closed
    behavior moves to the upcoming ``tn.secure_read()`` verb per the
    2026-04-25 read-ergonomics spec.)"""
    _setup(tmp_path)
    tn.info("order.created", amount=100)
    tn.info("order.paid", amount=100)
    tn.flush_and_close()

    log = tmp_path / ".tn/tn/logs" / "tn.ndjson"
    lines = log.read_text(encoding="utf-8").splitlines()
    # Log contains bootstrap events plus the two user events — tamper the
    # last line (order.paid).
    user_line_idx = len(lines) - 1
    target = json.loads(lines[user_line_idx])
    sig = target["signature"]
    target["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    lines[user_line_idx] = json.dumps(target, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tn.init(tmp_path / "tn.yaml")
    entries = [
        e for e in tn.read(verify=True) if not e["event_type"].startswith("tn.")
    ]
    # Both user events surface; the tampered one fails its signature check.
    bad = [e for e in entries if not all(e["_valid"].values())]
    assert len(bad) == 1
    assert bad[0]["_valid"]["signature"] is False


def test_raw_true_exposes_per_check_validity_on_tamper(tmp_path):
    """``tn.read(raw=True)`` keeps today's per-check validity dict so audit
    tooling can introspect tampered rows without losing structure."""
    _setup(tmp_path)
    tn.info("order.created", amount=100)
    tn.flush_and_close()

    log = tmp_path / ".tn/tn/logs" / "tn.ndjson"
    lines = log.read_text(encoding="utf-8").splitlines()
    user_idx = len(lines) - 1
    env = json.loads(lines[user_idx])
    sig = env["signature"]
    env["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    lines[user_idx] = json.dumps(env, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tn.init(tmp_path / "tn.yaml")
    raw_entries = [
        r for r in tn.read(raw=True) if not r["envelope"]["event_type"].startswith("tn.")
    ]
    assert len(raw_entries) == 1
    e = Entry(raw_entries[0])
    assert e.valid is False
    assert e.audit.validity["signature"] is False
