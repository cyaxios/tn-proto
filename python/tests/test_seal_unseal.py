"""tn.seal / tn.unseal round-trip and verification tests."""

import base64
import json
import os

import pytest

import tn
from tn.chain import ZERO_HASH, _compute_row_hash
from tn.signing import DeviceKey, _signature_from_b64


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    tn.flush_and_close()


def _workflow_cipher(default: str) -> str:
    return os.environ.get("TN_TEST_CIPHER", default)


def test_seal_returns_sealed_object(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.invoice.v1", amount=9800, customer="acme")

    assert isinstance(sealed, dict)
    # str() renders compact wire JSON (the log's line format), not Python repr
    parsed = json.loads(str(sealed))
    assert parsed == dict(sealed)

    # standalone conventions
    assert sealed["sequence"] == 0
    assert sealed["prev_hash"] == ""
    assert sealed["tn_sealed"] == 1
    assert sealed["event_type"] == "obj.invoice.v1"

    # fields are encrypted, not in the clear
    assert "amount" not in sealed
    assert "customer" not in sealed
    assert "ciphertext" in sealed["default"]

    # always signed, and the signature verifies
    assert DeviceKey.verify(
        sealed["device_identity"],
        sealed["row_hash"].encode("ascii"),
        _signature_from_b64(sealed["signature"]),
    )

    # row_hash is honestly derived from the envelope contents: the
    # standalone preimage hashes prev_hash "" (not ZERO_HASH), excludes
    # sequence, and binds the tn_sealed marker as a public field
    groups = {
        "default": {
            "ciphertext": base64.b64decode(sealed["default"]["ciphertext"]),
            "field_hashes": sealed["default"]["field_hashes"],
        }
    }
    assert sealed["row_hash"] == _compute_row_hash(
        device_identity=sealed["device_identity"],
        timestamp=sealed["timestamp"],
        event_id=sealed["event_id"],
        event_type=sealed["event_type"],
        level=sealed["level"],
        prev_hash=sealed["prev_hash"],
        public_fields={"tn_sealed": sealed["tn_sealed"]},
        groups=groups,
    )
    # no aad passed -> no tn_aad echo; aad-free wire shape stays minimal
    assert "tn_aad" not in sealed


def test_seal_rejects_reserved_field(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    with pytest.raises(ValueError, match="tn_sealed"):
        tn.seal("obj.test.v1", tn_sealed=1)


def test_seal_does_not_disturb_chain(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    tn.seal("obj.test.v1", receipt=False, x=1)
    # chains are per-event_type: log the SAME type the seal used. If seal
    # had advanced that chain, this row would be sequence 2 with a real
    # prev_hash instead of the genesis link.
    row = tn.log("obj.test.v1", y=2)
    assert row["sequence"] == 1
    assert row["prev_hash"] == ZERO_HASH


def test_seal_writes_receipt_row_by_default(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.invoice.v1", amount=1)
    # tn.* events route to the admin/protocol-events log by default (a
    # dedicated file, not the main ceremony log), per logger.py's
    # `event_type.startswith("tn.")` routing — read that surface.
    receipts = list(tn.read("tn.object.sealed", log="admin"))
    assert len(receipts) == 1
    r = receipts[0]
    assert r.fields["object_id"] == sealed["row_hash"]
    assert r.fields["object_type"] == "obj.invoice.v1"
    assert r.fields["groups"] == ["default"]


def test_seal_receipt_false_writes_nothing(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    tn.seal("obj.invoice.v1", receipt=False, amount=1)
    assert list(tn.read("tn.object.sealed", log="admin")) == []


def test_unseal_roundtrip_own_ceremony(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.invoice.v1", receipt=False, amount=9800, customer="acme")
    entry = tn.unseal(sealed)
    assert entry.event_type == "obj.invoice.v1"
    assert entry.fields["amount"] == 9800
    assert entry.fields["customer"] == "acme"
    assert entry.sequence == 0
    assert entry.hidden_groups == []


def test_unseal_accepts_all_source_shapes(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    as_dict = tn.unseal(dict(sealed))
    as_str = tn.unseal(str(sealed))
    as_bytes = tn.unseal(str(sealed).encode("utf-8"))
    p = tmp_path / "obj.json"
    p.write_text(str(sealed), encoding="utf-8")
    as_path = tn.unseal(p)
    for e in (as_dict, as_str, as_bytes, as_path):
        assert e.fields["x"] == 1


def test_unseal_raw_returns_triple(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    sealed = tn.seal("obj.test.v1", receipt=False, x=1)
    triple = tn.unseal(sealed, raw=True)
    assert set(triple) == {"envelope", "plaintext", "valid"}
    assert triple["envelope"]["row_hash"] == sealed["row_hash"]
    assert triple["plaintext"]["default"] == {"x": 1}
    assert triple["valid"]["signature"] is True
    assert triple["valid"]["row_hash"] is True
