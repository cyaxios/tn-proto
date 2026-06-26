"""Cross-implementation conformance: the Python reference MUST reproduce
every golden vector in ``crypto/tn-core/tests/fixtures`` byte-for-byte.

The same vectors are exercised by the Rust core (``cargo test *_golden``)
and by the wasm/TS runner (``crypto/tn-wasm/test/conformance_golden.mjs``).
All three reading the identical vectors is the conformance gate: if any
implementation drifts, its run of the shared vectors goes red.

These assertions cover the wire-format primitives (canonical bytes,
row_hash, signing, index tokens) plus the envelope's cryptographic
components. The full envelope NDJSON line is asserted by the Rust and
wasm runners, which call a single envelope serializer; the Python
reference assembles the line inside its logger, so this file verifies the
components it can call directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tn.canonical import _canonical_bytes
from tn.chain import _compute_row_hash
from tn.indexing import _derive_group_index_key, _index_token
from tn.signing import DeviceKey, _signature_b64

FIXTURES = (
    Path(__file__).resolve().parents[2] / "crypto" / "tn-core" / "tests" / "fixtures"
)


def _load(name: str) -> list:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _load("canonical_vectors.json"), ids=lambda c: c["name"])
def test_canonical_bytes(case: dict) -> None:
    out = _canonical_bytes(case["input_json"])
    assert out.hex() == case["output_hex"]
    assert out.decode("utf-8", "replace") == case["output_str"]


@pytest.mark.parametrize("case", _load("row_hash_vectors.json"), ids=lambda c: c["name"])
def test_row_hash(case: dict) -> None:
    inp = case["inputs"]
    groups = {
        gn: {
            "ciphertext": bytes.fromhex(g["ciphertext_hex"]),
            "field_hashes": g["field_hashes"],
        }
        for gn, g in inp["groups"].items()
    }
    got = _compute_row_hash(
        device_identity=inp["did"],
        timestamp=inp["timestamp"],
        event_id=inp["event_id"],
        event_type=inp["event_type"],
        level=inp["level"],
        prev_hash=inp["prev_hash"],
        public_fields=inp["public_fields"],
        groups=groups,
    )
    assert got == case["expected_row_hash"]


@pytest.mark.parametrize("entry", _load("signing_vectors.json"), ids=lambda e: e["did"][:20])
def test_signing(entry: dict) -> None:
    dk = DeviceKey.from_private_bytes(bytes.fromhex(entry["seed_hex"]))
    # did encodes the public key (base58btc of 0xed01 || pub32), so a did
    # match is a public-key match.
    assert dk.did == entry["did"]
    for case in entry["cases"]:
        msg = bytes.fromhex(case["message_hex"])
        sig = dk.sign(msg)
        assert _signature_b64(sig) == case["signature_b64url_nopad"]
        assert DeviceKey.verify(entry["did"], msg, sig) is True


@pytest.mark.parametrize(
    "case", _load("index_token_vectors.json"), ids=lambda c: f"{c['group']}-{c['field']}"
)
def test_index_token(case: dict) -> None:
    master = bytes.fromhex(case["master_hex"])
    gk = _derive_group_index_key(master, case["ceremony"], case["group"], case["epoch"])
    assert gk.hex() == case["derived_key_hex"]
    assert _index_token(gk, case["field"], case["value"]) == case["expected_token"]


@pytest.mark.parametrize(
    "case", _load("envelope_vectors.json"), ids=lambda c: c["inputs"]["event_id"][-4:]
)
def test_envelope_components(case: dict) -> None:
    inp = case["inputs"]
    assert inp["cipher"] == "identity", "fixture only covers the identity cipher"

    dk = DeviceKey.from_private_bytes(bytes.fromhex(inp["seed_hex"]))
    gk = _derive_group_index_key(
        bytes.fromhex(inp["master_index_key_hex"]),
        inp["ceremony_id"],
        inp["group"],
        inp["epoch"],
    )
    field_hashes = {
        k: _index_token(gk, k, v) for k, v in sorted(inp["private_fields"].items())
    }
    assert field_hashes == case["expected_field_hashes"]

    ct = _canonical_bytes(inp["private_fields"])  # identity cipher
    assert ct.hex() == case["expected_ciphertext_hex"]

    row_hash = _compute_row_hash(
        device_identity=dk.did,
        timestamp=inp["timestamp"],
        event_id=inp["event_id"],
        event_type=inp["event_type"],
        level=inp["level"],
        prev_hash=inp["prev_hash"],
        public_fields=inp["public_fields"],
        groups={inp["group"]: {"ciphertext": ct, "field_hashes": field_hashes}},
    )
    assert row_hash == case["expected_row_hash"]

    sig = dk.sign(row_hash.encode("ascii"))
    assert _signature_b64(sig) == case["expected_signature_b64url"]
