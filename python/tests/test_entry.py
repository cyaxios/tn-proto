"""Entry pydantic model — shape, attributes, dunders, round-trip."""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn
from tn import Entry, VerifyError


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


# ---------------------------------------------------------------------
# Default tn.read() yields Entry instances with typed attribute access
# ---------------------------------------------------------------------


def test_read_yields_entry_instances(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100, note="first", currency="USD")

    entries = [e for e in tn.read() if e.event_type == "order.created"]
    assert len(entries) == 1
    e = entries[0]

    assert isinstance(e, Entry)
    assert e.event_type == "order.created"
    assert isinstance(e.timestamp, datetime)
    assert e.timestamp.tzinfo is not None
    assert e.level == "info"
    assert e.message is None
    assert e.sequence >= 1
    assert e.did.startswith("did:key:z")
    assert len(e.event_id) == 36
    assert e.run_id  # non-empty
    assert e.prev_hash.startswith("sha256:")
    assert e.row_hash.startswith("sha256:")
    assert e.signature  # non-empty


def test_user_kwargs_land_in_fields(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100, note="first", currency="USD")

    e = next(e for e in tn.read() if e.event_type == "order.created")
    assert e.fields == {"amount": 100, "note": "first", "currency": "USD"}
    # User kwargs do NOT collide with envelope attributes.
    assert "default" not in e.fields
    assert "signature" not in e.fields


def test_message_is_none_when_no_positional(tmp_path):
    _setup(tmp_path)
    tn.info("session.opened")
    e = next(e for e in tn.read() if e.event_type == "session.opened")
    assert e.message is None


def test_message_kwarg_hoists_to_typed_slot(tmp_path):
    """``message=`` kwarg on tn.info / tn.log / etc. must surface on
    ``entry.message`` (the typed envelope slot), not in ``entry.fields``.

    The writer encrypts the value into the plaintext payload under a
    ``"message"`` key for confidentiality; the reader hoists it out so
    callers read ``e.message`` instead of ``e.fields["message"]``.

    Note (DX review #3 — 0.4.2a2): positional messages were dropped
    in favour of the explicit ``message=`` kwarg. ``tn.info("evt",
    "free text")`` now raises ``TypeError`` instead of silently
    folding the positional into ``message``.
    """
    _setup(tmp_path)
    tn.info("auth.login", message="alice signed in from web", user_id="u123")
    e = next(e for e in tn.read() if e.event_type == "auth.login")
    assert e.message == "alice signed in from web"
    assert "message" not in e.fields
    assert e.fields == {"user_id": "u123"}


def test_extra_positionals_raise_typeerror(tmp_path):
    """DX review #3 — extra positionals after the event_type are
    rejected with a TypeError that tells the caller how to migrate
    (use kwargs for structured data, or ``message=`` for free text)."""
    import pytest
    _setup(tmp_path)
    with pytest.raises(TypeError, match=r"extra positional argument"):
        tn.info("debug.note", "short note", "second positional", tag="x")


# ---------------------------------------------------------------------
# Human-readable dunders
# ---------------------------------------------------------------------


def test_str_one_line_format(tmp_path):
    _setup(tmp_path)
    tn.info("order.created", amount=100)
    e = next(e for e in tn.read() if e.event_type == "order.created")
    s = str(e)
    # Format: "HH:MM:SS.mmm LEVEL  seq=N  event_type  k=v"
    assert "INFO" in s
    assert "order.created" in s
    assert "amount=100" in s
    # millisecond precision (one period in the timestamp segment)
    head = s.split(" ", 1)[0]
    assert head.count(":") == 2 and head.count(".") == 1


def test_repr_truncates_did(tmp_path):
    _setup(tmp_path)
    tn.info("x.y")
    e = next(iter(tn.read()))
    r = repr(e)
    assert r.startswith("Entry(")
    assert "event_type=" in r
    # DID should be truncated like z6Mk...8FAZ
    assert "..." in r


def test_repr_html_renders_table(tmp_path):
    _setup(tmp_path)
    tn.info("dash.event", click="ok")
    e = next(e for e in tn.read() if e.event_type == "dash.event")
    html = e._repr_html_()
    assert "<table" in html
    assert "dash.event" in html
    assert "click" in html


def test_repr_markdown_renders(tmp_path):
    _setup(tmp_path)
    tn.info("md.event", val=42)
    e = next(e for e in tn.read() if e.event_type == "md.event")
    md = e._repr_markdown_()
    assert "**md.event**" in md
    assert "`val`" in md or "val" in md


# ---------------------------------------------------------------------
# Pydantic model_dump round-trip
# ---------------------------------------------------------------------


def test_model_dump_json_round_trips(tmp_path):
    _setup(tmp_path)
    tn.info("rt.event", x=1, y="hi")
    e = next(e for e in tn.read() if e.event_type == "rt.event")
    raw = e.model_dump_json()
    parsed = json.loads(raw)
    assert parsed["event_type"] == "rt.event"
    assert parsed["fields"]["x"] == 1
    assert parsed["fields"]["y"] == "hi"
    assert "row_hash" in parsed
    assert "did" in parsed


# ---------------------------------------------------------------------
# raw=True returns the on-disk envelope dict (not Entry)
# ---------------------------------------------------------------------


def test_raw_true_yields_envelope_dict(tmp_path):
    _setup(tmp_path)
    tn.info("evt.x", k=1)
    envs = [
        env for env in tn.read(raw=True)
        if env.get("event_type") == "evt.x"
    ]
    assert len(envs) == 1
    env = envs[0]
    assert isinstance(env, dict)
    # Envelope has the group-keyed ciphertext block intact.
    assert "default" in env
    assert "ciphertext" in env["default"]


# ---------------------------------------------------------------------
# verify=True raises on tamper; verify="skip" handles validation
# failures (signature/row_hash/chain). Parse-level failures still raise
# under all verify modes since the iter terminates.
# ---------------------------------------------------------------------


def test_verify_true_passes_clean_log(tmp_path):
    _setup(tmp_path)
    tn.info("a.x"); tn.info("b.x")
    n = sum(1 for _ in tn.read(verify=True))
    assert n >= 2  # admin events + 2 user events


def test_verify_true_raises_on_tampered_ciphertext(tmp_path):
    yaml = _setup(tmp_path)
    tn.info("v.x", payload="orig")
    tn.flush_and_close()

    log = yaml.parent / ".tn/tn/logs/tn.ndjson"
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    victim_idx = next(i for i, ln in enumerate(lines) if "v.x" in ln)
    obj = json.loads(lines[victim_idx])
    ct = obj["default"]["ciphertext"]
    obj["default"]["ciphertext"] = ct[:-2] + ("Z" if ct[-2] != "Z" else "Y") + ct[-1]
    lines[victim_idx] = json.dumps(obj, separators=(",", ":")) + "\n"
    log.write_text("".join(lines), encoding="utf-8")

    tn.init(yaml)
    with pytest.raises(VerifyError):
        list(tn.read(verify=True))


# ---------------------------------------------------------------------
# Where filter receives Entry (not dict) by default; receives envelope
# dict when raw=True
# ---------------------------------------------------------------------


def test_where_receives_entry(tmp_path):
    _setup(tmp_path)
    tn.info("filter.match", n=1)
    tn.info("filter.skip", n=2)
    seen = list(tn.read(where=lambda e: e.event_type == "filter.match"))
    assert len(seen) == 1
    assert seen[0].event_type == "filter.match"


def test_where_receives_envelope_dict_when_raw(tmp_path):
    _setup(tmp_path)
    tn.info("raw.match", n=1)
    tn.info("raw.skip", n=2)
    seen = list(tn.read(raw=True, where=lambda env: env.get("event_type") == "raw.match"))
    assert len(seen) == 1
    assert seen[0]["event_type"] == "raw.match"


# ---------------------------------------------------------------------
# Entry.from_raw constructs from {envelope, plaintext, valid} triple
# ---------------------------------------------------------------------


def test_from_raw_constructor():
    raw = {
        "envelope": {
            "event_type": "x.y",
            "timestamp": "2026-05-08T03:30:20.184000Z",
            "level": "info",
            "device_identity": "did:key:zABC123",
            "event_id": "abc-123",
            "sequence": 1,
            "prev_hash": "sha256:000",
            "row_hash": "sha256:111",
            "signature": "sig",
            "default": {"ciphertext": "...", "field_hashes": {}},
        },
        "plaintext": {
            "default": {"amount": 100, "run_id": "rid-1"},
        },
        "valid": {"signature": True, "row_hash": True, "chain": True},
    }
    e = Entry.from_raw(raw)
    assert e.event_type == "x.y"
    assert e.fields == {"amount": 100}  # run_id hoisted to top
    assert e.run_id == "rid-1"
    assert e.did == "did:key:zABC123"
    assert e.row_hash == "sha256:111"
