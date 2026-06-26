"""tn.log returns a record that str()s to valid JSON, so it's easy to "send".

The leveled verbs (info/warning/error/debug) are fire-and-forget; tn.log is
the one verb that returns the written record for forwarding. That record must
be sendable as a regular JSON body: `requests.post(url, data=str(tn.log(...)))`
should produce real JSON, not Python dict repr (single quotes). It also stays
dict-compatible so `requests.post(url, json=tn.log(...))` keeps working.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def fresh_ceremony(tmp_path: Path, monkeypatch):
    # monkeypatch auto-restores cwd + env after the test, so TN_NO_LINK does
    # not leak into the shared pytest process and break later link tests.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_NO_LINK", "1")
    import tn

    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.init()
    try:
        yield tn
    finally:
        tn.flush_and_close()


def test_log_record_str_is_valid_json(fresh_ceremony):
    tn = fresh_ceremony
    rec = tn.log("order.created", level="trace", order_id="A100", amount=4999)
    assert rec is not None

    # Backward compatible: still the envelope dict (json= and dict access work).
    assert isinstance(rec, dict)
    assert rec["event_type"] == "order.created"

    # str() must be VALID JSON (sendable), not Python repr with single quotes.
    text = str(rec)
    parsed = json.loads(text)  # raises if str() is not real JSON
    assert parsed["event_type"] == "order.created"
