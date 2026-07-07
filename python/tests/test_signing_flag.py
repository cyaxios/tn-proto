"""tn.set_signing + _sign kwarg + yaml ceremony.sign flag.

Exercises the three layers of the signing override:

    1. Ceremony yaml `ceremony.sign` (bool, default True)
    2. Session-level `tn.set_signing(True/False/None)`
    3. Per-call `tn.info("...", _sign=True/False)`

Precedence: per-call > session > yaml default.
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

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
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    return yaml


def _user_entries(verify: bool = False):
    """tn.read() filtered to user events (skips tn.* bootstrap).

    Note: with the 0.4.0a1 surface ``verify=True`` raises on integrity
    failure rather than annotating each entry — tests that need to inspect
    per-entry validity use ``_user_triples`` below.
    """
    return [e for e in tn.read(verify=verify) if not e.event_type.startswith("tn.")]


def _user_raw():
    """tn.read(raw=True) filtered to user events. Yields envelope dicts."""
    return [
        env for env in tn.read(raw=True)
        if not env.get("event_type", "").startswith("tn.")
    ]


def _user_triples():
    """Internal {envelope, plaintext, valid} triples for the current run,
    filtered to user events. Used to assert per-entry validity flags
    that the public ``tn.read`` no longer surfaces post-0.4.0a1.
    """
    from tn._read_impl import _read_raw_inner, _entry_in_current_run_raw
    cfg = tn.current_config()
    log = cfg.resolve_log_path()
    out = []
    for r in _read_raw_inner(log, cfg):
        if not _entry_in_current_run_raw(r):
            continue
        env = r.get("envelope") or {}
        if not str(env.get("event_type", "")).startswith("tn."):
            out.append(r)
    return out


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
    triples = _user_triples()
    assert len(triples) == 1
    assert triples[0]["valid"]["signature"] is True
    # Raw signature field is non-empty.
    raw = _user_raw()[0]
    assert raw["signature"] != ""


def test_set_signing_false_produces_unsigned_entry(tmp_path):
    _btn_ceremony(tmp_path)
    tn.set_signing(False)
    tn.info("test.unsigned", k=1)
    tn.flush_and_close()

    # Reopen and read the triples directly so we can inspect per-row
    # validity flags (the public ``tn.read`` no longer surfaces these).
    tn.init(tmp_path / "tn.yaml")
    triples = _user_triples()
    assert len(triples) == 1
    valid = triples[0]["valid"]
    # Signature is absent — valid.signature is False (sig verify fails on empty).
    assert valid["signature"] is False
    # Chain still verifies (row_hash was still computed).
    assert valid["chain"] is True
    assert valid["row_hash"] is True


def test_per_call_sign_false_overrides_default(tmp_path):
    _btn_ceremony(tmp_path)
    tn.info("signed.event", k=1)
    tn.info("unsigned.event", k=2, _sign=False)
    tn.info("signed.again", k=3)
    tn.flush_and_close()

    tn.init(tmp_path / "tn.yaml")
    raw = _user_raw()
    assert len(raw) == 3
    assert raw[0]["signature"] != ""  # signed
    assert raw[1]["signature"] == ""  # unsigned
    assert raw[2]["signature"] != ""  # signed again


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
    assert raw[0]["signature"] == ""  # yaml default = false
    assert raw[1]["signature"] != ""  # per-call override = true


def test_set_signing_none_reverts_to_yaml_default(tmp_path):
    _btn_ceremony(tmp_path)
    tn.set_signing(False)
    tn.info("a", k=1)
    tn.set_signing(None)  # revert
    tn.info("b", k=2)
    tn.flush_and_close()

    tn.init(tmp_path / "tn.yaml")
    raw = _user_raw()
    assert raw[0]["signature"] == ""
    assert raw[1]["signature"] != ""


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
    assert raw[0]["signature"] != ""
