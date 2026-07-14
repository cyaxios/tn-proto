"""Tamper / forgery coverage for Python ``secure_read`` (``tn.read(verify=…)``).

This closes a security hole: *every* existing tamper test mutates
``row_hash`` only. A regression that silently dropped the Ed25519 signature
check or the ``prev_hash`` chain check — while still recomputing ``row_hash`` —
would sail through green. The two negative tests below specifically exercise
the signature path and the chain path in isolation, so they bite the real
verifier and nothing else.

It also adds the missing Python ``secure_read`` happy path (genuine entries
verify clean), which had zero direct coverage.

Mechanism (see tn/_dispatch.py::_rust_entries_with_valid and tn/chain.py):
  * ``row_hash`` commits to device_identity/timestamp/event_id/event_type/
    level/prev_hash + sorted public fields + per-group ciphertext+field_hashes.
    It does NOT commit to ``sequence``, ``row_hash`` itself, or ``signature``.
  * The signature is Ed25519 over ``row_hash.encode("ascii")``.
  * The chain check is ``entry.prev_hash == previous-same-event_type.row_hash``.

So:
  * Replacing ``signature`` with a valid-length wrong value leaves ``row_hash``
    correct → only ``valid.signature`` flips False. (If verify only checked
    row_hash, this row would PASS — that's the regression we catch.)
  * Re-deriving entry #1's ``row_hash`` + ``signature`` after touching one of
    its public fields keeps entry #1 fully self-valid but makes entry #2's
    ``prev_hash`` stale → only ``valid.chain`` flips False on entry #2. (If
    verify only checked row_hash/signature, this row would PASS.)
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import base64
import json
from pathlib import Path

import pytest

import tn
from tn.chain import _compute_row_hash
from tn.read import VerifyError


@pytest.fixture(autouse=True)
def _isolated_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Fresh TN_HOME / cwd / ceremony per test, no vault contact, no stdout,
    and a guaranteed runtime teardown so the singleton never leaks."""
    monkeypatch.setenv("TN_HOME", str(tmp_path / "tn-home"))
    monkeypatch.delenv("TN_YAML", raising=False)
    monkeypatch.setenv("TN_NO_LINK", "1")
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.chdir(tmp_path)
    try:
        yield
    finally:
        tn.flush_and_close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _emit(tmp_path: Path, events: list[tuple[str, dict]]) -> tuple[str, Path]:
    """Mint a real btn ceremony, emit each (event_type, fields) through the
    REAL emit verb (``tn.info``), flush+close, and return (yaml_path, log_path).

    One ``tn`` flow per process: we close the writer before any reader re-binds.
    """
    yaml = tmp_path / "tn.yaml"
    tn.init(yaml, cipher=_workflow_cipher("btn"))
    cfg = tn.current_config()
    log_path = Path(cfg.resolve_log_path())
    for event_type, fields in events:
        tn.info(event_type, **fields)
    tn.flush_and_close()
    return str(yaml), log_path


def _read_lines(log_path: Path) -> list[dict]:
    text = log_path.read_text(encoding="utf-8")
    return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


def _write_lines(log_path: Path, envs: list[dict]) -> None:
    log_path.write_text(
        "\n".join(json.dumps(e) for e in envs) + "\n", encoding="utf-8"
    )


def _public_fields_and_groups(env: dict) -> tuple[dict, dict]:
    """Split an on-disk envelope into (public_fields, groups) exactly the way
    the verifier (_rust_entries_with_valid) does, so a recompute here matches
    the recompute there byte-for-byte."""
    reserved = {
        "device_identity",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "sequence",
        "prev_hash",
        "row_hash",
        "signature",
    }
    public_fields: dict = {}
    groups: dict = {}
    for k, v in env.items():
        if k in reserved:
            continue
        if isinstance(v, dict) and "ciphertext" in v and "field_hashes" in v:
            groups[k] = {
                "ciphertext": base64.standard_b64decode(v["ciphertext"]),
                "field_hashes": dict(v["field_hashes"]),
            }
        else:
            public_fields[k] = v
    return public_fields, groups


def _resign_in_place(env: dict, device) -> None:
    """Recompute ``env['row_hash']`` from its current fields and re-sign it
    with ``device`` (a ``DeviceKey``), so the envelope is internally valid
    (row_hash_ok AND signature_ok) for whatever its fields now say."""
    from tn.signing import _signature_b64

    public_fields, groups = _public_fields_and_groups(env)
    new_row_hash = _compute_row_hash(
        device_identity=env["device_identity"],
        timestamp=env["timestamp"],
        event_id=env["event_id"],
        event_type=env["event_type"],
        level=env.get("level", ""),
        prev_hash=env["prev_hash"],
        public_fields=public_fields,
        groups=groups,
    )
    env["row_hash"] = new_row_hash
    env["signature"] = _signature_b64(device.sign(new_row_hash.encode("ascii")))


# ---------------------------------------------------------------------------
# Happy path — genuine entries verify clean (audit §7.1: zero prior coverage)
# ---------------------------------------------------------------------------


def test_secure_read_happy_path_genuine_entries_verify_clean(tmp_path: Path) -> None:
    """A real emit → secure_read round-trip: every genuine row verifies and
    ``verify='raise'`` does NOT throw."""
    yaml_path, _ = _emit(
        tmp_path,
        [
            ("order.created", {"amount": 100, "order_id": "A100"}),
            ("order.created", {"amount": 200, "order_id": "A200"}),
        ],
    )

    tn.init(yaml_path)
    try:
        # verify="raise" must not raise on clean rows.
        entries = list(tn.read(verify="raise", all_runs=True))
        hits = [e for e in entries if e.event_type == "order.created"]
        assert len(hits) == 2, f"expected 2 order.created, got {len(hits)}"
        assert hits[0].fields["order_id"] == "A100"
        assert hits[1].fields["order_id"] == "A200"

        # verify='skip' returns the full set with no drops on clean rows.
        skipped = list(tn.read(verify="skip", all_runs=True))
        assert len([e for e in skipped if e.event_type == "order.created"]) == 2
    finally:
        tn.flush_and_close()

    # Every genuine row's per-check valid block is all-True.
    for t in _read_raw_after_init_triples(yaml_path):
        v = t["valid"]
        assert v["signature"] is True
        assert v["row_hash"] is True
        assert v["chain"] is True


# ---------------------------------------------------------------------------
# §5.2 — FORGED SIGNATURE (valid row_hash). This is THE key gap.
# ---------------------------------------------------------------------------


def test_forged_signature_with_valid_row_hash_is_rejected(tmp_path: Path) -> None:
    """Replace ``signature`` with a valid-length but WRONG Ed25519 signature,
    leaving ``row_hash`` untouched (and therefore still correct). secure_read
    MUST reject the row on the signature check alone.

    Proves the signature path bites: ``valid.row_hash`` stays True, so a
    verifier that only checked row_hash would (incorrectly) PASS this row.
    """
    yaml_path, log_path = _emit(
        tmp_path, [("order.created", {"amount": 100, "order_id": "A100"})]
    )

    envs = _read_lines(log_path)
    assert len(envs) == 1
    target = envs[0]
    good_row_hash = target["row_hash"]

    # Forge: a different valid-length (64-byte) Ed25519 signature. Use a sig
    # over a DIFFERENT message so it can't possibly verify against row_hash,
    # but is structurally a real signature (right length, real key).
    from tn.signing import DeviceKey, _signature_b64

    forger = DeviceKey.generate()
    bogus_sig = forger.sign(b"not the row hash")
    target["signature"] = _signature_b64(bogus_sig)
    assert target["row_hash"] == good_row_hash, "row_hash must stay valid"

    _write_lines(log_path, envs)

    # 1) The per-check valid block proves isolation: ONLY signature fails.
    triples = _read_raw_after_init_triples(yaml_path)
    assert len(triples) == 1
    valid = triples[0]["valid"]
    assert valid["row_hash"] is True, (
        "row_hash must stay valid — otherwise this test doesn't isolate the "
        "signature path (a row_hash-only verifier would already catch it)"
    )
    assert valid["chain"] is True
    assert valid["signature"] is False, "forged signature must fail the sig check"

    # 2) verify='raise' must throw on the forged row.
    tn.init(yaml_path)
    try:
        with pytest.raises(VerifyError) as ei:
            list(tn.read(verify="raise", all_runs=True))
        assert "signature_invalid" in ei.value.failed_checks
        assert "row_hash_invalid" not in ei.value.failed_checks
    finally:
        tn.flush_and_close()

    # 3) verify='skip' must DROP the forged row.
    tn.init(yaml_path)
    try:
        out = list(tn.read(verify="skip", all_runs=True))
        assert not [e for e in out if e.event_type == "order.created"], (
            "forged-signature row must be skipped under verify='skip'"
        )
    finally:
        tn.flush_and_close()

    # 4) Explicitly disabled verification must STILL surface it — proves it is
    #    the secure gate that catches it, not the parser.
    tn.init(yaml_path)
    try:
        out = list(tn.read(verify=False, all_runs=True))
        assert [e for e in out if e.event_type == "order.created"], (
            "verify=False must still surface the row"
        )
    finally:
        tn.flush_and_close()


# ---------------------------------------------------------------------------
# §5.3 — BROKEN prev_hash CHAIN (isolated from row_hash/signature).
# ---------------------------------------------------------------------------


def test_broken_prev_hash_chain_is_rejected(tmp_path: Path) -> None:
    """Two same-event_type rows form a chain (row2.prev_hash == row1.row_hash).
    We mutate a public field of row #1 and re-derive its row_hash + signature
    so row #1 stays FULLY self-valid, but its new row_hash no longer matches
    row #2's ``prev_hash`` → the chain link is broken at row #2 while row #2's
    own row_hash and signature remain valid.

    Proves the chain path bites in isolation: row #2's ``valid.row_hash`` and
    ``valid.signature`` stay True, so a verifier that skipped the chain check
    would (incorrectly) PASS row #2.
    """
    yaml_path, log_path = _emit(
        tmp_path,
        [
            ("order.created", {"amount": 100, "order_id": "A100"}),
            ("order.created", {"amount": 200, "order_id": "A200"}),
        ],
    )

    envs = _read_lines(log_path)
    rows = [e for e in envs if e.get("event_type") == "order.created"]
    assert len(rows) == 2
    row1, row2 = rows[0], rows[1]
    assert row2["prev_hash"] == row1["row_hash"], "precondition: chain is intact"

    # Load the ceremony's real device key so we can re-sign row #1.
    tn.init(yaml_path)
    device = tn.current_config().device
    tn.flush_and_close()

    # Tamper a PUBLIC field on row #1 (level is public + part of row_hash).
    # Then re-derive row1.row_hash + signature so row #1 is internally valid.
    original_row1_hash = row1["row_hash"]
    row1["level"] = "warning"  # was "info"
    _resign_in_place(row1, device)
    assert row1["row_hash"] != original_row1_hash, (
        "row #1's row_hash must change so row #2's prev_hash goes stale"
    )
    # row #2 is untouched: its prev_hash still points at row #1's OLD row_hash.
    assert row2["prev_hash"] == original_row1_hash
    assert row2["prev_hash"] != row1["row_hash"]

    _write_lines(log_path, envs)

    # Per-check isolation: row #1 fully valid; row #2 fails ONLY on chain.
    triples = _read_raw_after_init_triples(yaml_path)
    by_seq = {t["envelope"]["sequence"]: t for t in triples}
    v1 = by_seq[1]["valid"]
    v2 = by_seq[2]["valid"]
    assert v1["row_hash"] is True and v1["signature"] is True and v1["chain"] is True, (
        f"row #1 must stay fully self-valid after re-sign, got {v1}"
    )
    assert v2["row_hash"] is True, (
        "row #2's own row_hash must stay valid — otherwise this doesn't "
        "isolate the chain path"
    )
    assert v2["signature"] is True, "row #2's signature must stay valid"
    assert v2["chain"] is False, "the broken chain link must be flagged"

    # verify='raise' must throw, citing the chain check.
    tn.init(yaml_path)
    try:
        with pytest.raises(VerifyError) as ei:
            list(tn.read(verify="raise", all_runs=True))
        assert "chain_invalid" in ei.value.failed_checks
    finally:
        tn.flush_and_close()

    # verify='skip' drops the chain-broken row #2 but keeps the valid row #1.
    tn.init(yaml_path)
    try:
        out = list(tn.read(verify="skip", all_runs=True))
        amounts = sorted(
            e.fields.get("amount") for e in out if e.event_type == "order.created"
        )
        assert amounts == [100], (
            f"only the chain-broken row should be dropped, got amounts={amounts}"
        )
    finally:
        tn.flush_and_close()


# ---------------------------------------------------------------------------
# §5.1 — baseline: tampered row_hash is rejected (parity with TS suite).
# ---------------------------------------------------------------------------


def test_tampered_row_hash_is_rejected(tmp_path: Path) -> None:
    """Flip ``row_hash`` to a clearly-wrong value. secure_read MUST reject it;
    explicit verify=False MUST still surface it."""
    yaml_path, log_path = _emit(
        tmp_path, [("order.created", {"amount": 100, "order_id": "A100"})]
    )

    envs = _read_lines(log_path)
    envs[0]["row_hash"] = "sha256:" + "0" * 64
    _write_lines(log_path, envs)

    tn.init(yaml_path)
    try:
        with pytest.raises(VerifyError) as ei:
            list(tn.read(verify="raise", all_runs=True))
        assert "row_hash_invalid" in ei.value.failed_checks
    finally:
        tn.flush_and_close()

    tn.init(yaml_path)
    try:
        out = list(tn.read(verify="skip", all_runs=True))
        assert not [e for e in out if e.event_type == "order.created"]
    finally:
        tn.flush_and_close()

    tn.init(yaml_path)
    try:
        out = list(tn.read(verify=False, all_runs=True))
        assert [e for e in out if e.event_type == "order.created"], (
            "plain read must still surface the tampered row"
        )
    finally:
        tn.flush_and_close()


# ---------------------------------------------------------------------------
# Shared raw-triple reader (kept below the tests that use it for readability).
# ---------------------------------------------------------------------------


def _read_raw_after_init_triples(yaml_path: str) -> list[dict]:
    """Re-bind and return raw {envelope, plaintext, valid} triples via the
    read_raw path that carries the per-check ``valid`` block. ``verify=False``
    so nothing is dropped — we want to inspect every row's booleans."""
    import tn as _tn
    from tn._read_impl import _read_raw_inner

    _tn.init(yaml_path)
    try:
        return list(_read_raw_inner(None, None, all_runs=True))
    finally:
        _tn.flush_and_close()
