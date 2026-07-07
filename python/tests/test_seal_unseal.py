"""tn.seal / tn.unseal round-trip and verification tests."""

import json
import os

import pytest

import tn
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
    # str() renders canonical JSON, not Python repr
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


def test_seal_rejects_reserved_field(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    with pytest.raises(ValueError, match="tn_sealed"):
        tn.seal("obj.test.v1", tn_sealed=1)


def test_seal_does_not_disturb_chain(tmp_path):
    tn.init(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    tn.seal("obj.test.v1", receipt=False, x=1)
    row = tn.log("chain.probe.v1", y=2)
    # first log row for this event_type is sequence 1 — seal advanced nothing
    assert row["sequence"] == 1
