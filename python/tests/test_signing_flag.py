"""tn.set_signing + _sign kwarg + yaml ceremony.sign flag.

Exercises the three layers of the Option-1 signing override (per the
RFC at docs/superpowers/specs/2026-04-22-tn-transaction-protocol.md):

    1. Ceremony yaml `ceremony.sign` (bool, default True)
    2. Session-level `tn.set_signing(True/False/None)`
    3. Per-call `tn.info("...", _sign=True/False)`

Precedence: per-call > session > yaml default.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import tn


@pytest.fixture(autouse=True)
def _clean_tn():  # pyright: ignore[reportUnusedFunction]
    tn.set_signing(None)  # reset between tests
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.set_signing(None)


def _btn_ceremony(tmp_path: Path) -> Path:
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher="btn")
    return yaml


def _user_entries(verify: bool = True):
    """tn.read(verify=True) filtered to user events (skips tn.* bootstrap)."""
    return [e for e in tn.read(verify=verify) if not e["event_type"].startswith("tn.")]


def _user_raw():
    """tn.read(raw=True) filtered to user events."""
    return [e for e in tn.read(raw=True) if not e["envelope"]["event_type"].startswith("tn.")]


def _set_yaml_sign(yaml_path: Path, value: bool) -> None:
    """Rewrite the ceremony.sign flag in the yaml and re-init.

    The yaml generator writes ``sign: true`` by default, so we replace
    that line in place rather than appending — appending would yield a
    duplicate ``sign:`` field that the Rust yaml parser rejects.
    """
    text = yaml_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    out = []
    replaced = False
    for ln in lines:
        stripped = ln.lstrip()
        if not replaced and stripped.startswith("sign:"):
            indent = ln[: len(ln) - len(stripped)]
            out.append(f"{indent}sign: {'true' if value else 'false'}")
            replaced = True
            continue
        out.append(ln)
    if not replaced:
        # Defensive: if the generator stops emitting sign:, append after cipher.
        for i, ln in enumerate(out):
            if "cipher: btn" in ln:
                indent = ln[: len(ln) - len(ln.lstrip())]
                out.insert(i + 1, f"{indent}sign: {'true' if value else 'false'}")
                break
    yaml_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def test_default_is_signed(tmp_path):
    _btn_ceremony(tmp_path)
    tn.info("test.default", k=1)
    entries = _user_entries()
    assert len(entries) == 1
    assert entries[0]["_valid"]["signature"] is True
    # Raw signature field is non-empty.
    raw = _user_raw()[0]
    assert raw["envelope"]["signature"] != ""


def test_set_signing_false_produces_unsigned_entry(tmp_path):
    _btn_ceremony(tmp_path)
    tn.set_signing(False)
    tn.info("test.unsigned", k=1)
    tn.flush_and_close()

    # Reopen and read with verify=True so the _valid block surfaces
    # (unsigned entries' signature check fails on the empty string).
    tn.init(tmp_path / "tn.yaml")
    entries = _user_entries(verify=True)
    assert len(entries) == 1
    e = entries[0]
    # Signature is absent — valid.signature is False (sig verify fails on empty).
    assert e["_valid"]["signature"] is False
    # Chain still verifies (row_hash was still computed).
    assert e["_valid"]["chain"] is True
    assert e["_valid"]["row_hash"] is True


def test_per_call_sign_false_overrides_default(tmp_path):
    _btn_ceremony(tmp_path)
    tn.info("signed.event", k=1)
    tn.info("unsigned.event", k=2, _sign=False)
    tn.info("signed.again", k=3)
    tn.flush_and_close()

    tn.init(tmp_path / "tn.yaml")
    raw = _user_raw()
    assert len(raw) == 3
    assert raw[0]["envelope"]["signature"] != ""  # signed
    assert raw[1]["envelope"]["signature"] == ""  # unsigned
    assert raw[2]["envelope"]["signature"] != ""  # signed again


def test_yaml_sign_false_default(tmp_path):
    """yaml ceremony.sign: false makes every emit unsigned unless overridden."""
    _btn_ceremony(tmp_path)
    tn.flush_and_close()

    yaml = tmp_path / "tn.yaml"
    _set_yaml_sign(yaml, False)

    tn.init(yaml)
    tn.info("default.unsigned", k=1)
    tn.info("force.signed", k=2, _sign=True)
    tn.flush_and_close()

    tn.init(yaml)
    raw = _user_raw()
    assert len(raw) == 2
    assert raw[0]["envelope"]["signature"] == ""  # yaml default = false
    assert raw[1]["envelope"]["signature"] != ""  # per-call override = true


def test_set_signing_none_reverts_to_yaml_default(tmp_path):
    _btn_ceremony(tmp_path)
    tn.set_signing(False)
    tn.info("a", k=1)
    tn.set_signing(None)  # revert
    tn.info("b", k=2)
    tn.flush_and_close()

    tn.init(tmp_path / "tn.yaml")
    raw = _user_raw()
    assert raw[0]["envelope"]["signature"] == ""
    assert raw[1]["envelope"]["signature"] != ""


def test_precedence_per_call_beats_session_and_yaml(tmp_path):
    """Per-call _sign=True wins even when session is False and yaml is False."""
    _btn_ceremony(tmp_path)
    tn.flush_and_close()
    _set_yaml_sign(tmp_path / "tn.yaml", False)

    tn.init(tmp_path / "tn.yaml")
    tn.set_signing(False)
    tn.info("force.signed", k=1, _sign=True)
    tn.flush_and_close()

    tn.init(tmp_path / "tn.yaml")
    raw = _user_raw()
    assert raw[0]["envelope"]["signature"] != ""
