"""Unit tests for tn.sealing."""

from __future__ import annotations

import pytest

from tn.sealing import (
    AES_KEY_SIZE,
    NONCE_SIZE,
    SEAL_VERSION,
    SealedBlob,
    SealingError,
    _make_aad,
    _seal,
    _unseal,
)

KEY = b"k" * AES_KEY_SIZE
DID = "did:key:z6Mkabc"
CER = "local_36b02034"
FILE = "default.jwe.sender"


# --- AAD format ----------------------------------------------------------


def test_aad_format_is_did_slash_ceremony_slash_file():
    assert _make_aad(DID, CER, FILE) == f"{DID}/{CER}/{FILE}"


def test_aad_rejects_slashes_in_ids():
    with pytest.raises(ValueError):
        _make_aad(DID, "foo/bar", FILE)
    with pytest.raises(ValueError):
        _make_aad(DID, CER, "foo/bar")


# --- Seal/unseal round trip ---------------------------------------------


def test_seal_unseal_roundtrip():
    pt = b"hello world" * 10
    blob = _seal(pt, wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    assert blob.v == SEAL_VERSION
    assert len(blob.nonce) == NONCE_SIZE
    assert blob.ct != pt
    got = _unseal(blob, wrap_key=KEY)
    assert got == pt


def test_seal_produces_fresh_nonce_each_call():
    pt = b"same plaintext"
    a = _seal(pt, wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    b = _seal(pt, wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    assert a.nonce != b.nonce
    assert a.ct != b.ct


def test_seal_empty_payload_works():
    blob = _seal(b"", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    assert _unseal(blob, wrap_key=KEY) == b""


# --- Wire format --------------------------------------------------------


def test_to_bytes_from_bytes_roundtrip():
    blob = _seal(b"payload", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    wire = blob.to_bytes()
    restored = SealedBlob.from_bytes(wire)
    assert restored.v == blob.v
    assert restored.nonce == blob.nonce
    assert restored.ct == blob.ct
    assert restored.aad == blob.aad


def test_from_bytes_rejects_bad_json():
    with pytest.raises(SealingError):
        SealedBlob.from_bytes(b"{not json")


def test_from_bytes_rejects_wrong_version():
    import base64
    import json

    bad = json.dumps(
        {
            "v": 999,
            "nonce": base64.urlsafe_b64encode(b"n" * NONCE_SIZE).rstrip(b"=").decode(),
            "ct": "AA",
            "aad": "x/y/z",
        }
    ).encode()
    with pytest.raises(SealingError):
        SealedBlob.from_bytes(bad)


def test_from_bytes_rejects_wrong_nonce_length():
    import base64
    import json

    bad = json.dumps(
        {
            "v": SEAL_VERSION,
            "nonce": base64.urlsafe_b64encode(b"n" * 5).rstrip(b"=").decode(),
            "ct": "AA",
            "aad": "x/y/z",
        }
    ).encode()
    with pytest.raises(SealingError):
        SealedBlob.from_bytes(bad)


# --- Failure modes ------------------------------------------------------


def test_unseal_with_wrong_key_fails():
    blob = _seal(b"secret", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    wrong = b"x" * AES_KEY_SIZE
    with pytest.raises(SealingError):
        _unseal(blob, wrap_key=wrong)


def test_unseal_with_tampered_ciphertext_fails():
    blob = _seal(b"secret", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    tampered = SealedBlob(
        v=blob.v,
        nonce=blob.nonce,
        ct=bytes([blob.ct[0] ^ 0xFF]) + blob.ct[1:],
        aad=blob.aad,
    )
    with pytest.raises(SealingError):
        _unseal(tampered, wrap_key=KEY)


def test_unseal_with_tampered_aad_fails():
    blob = _seal(b"secret", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    blob.aad = "did:key:z6Mkother/local_other/default.jwe.sender"
    with pytest.raises(SealingError):
        _unseal(blob, wrap_key=KEY)


# --- Expected-AAD verification ------------------------------------------


def test_unseal_with_matching_expected_aad_passes():
    blob = _seal(b"x", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    got = _unseal(
        blob,
        wrap_key=KEY,
        expected_did=DID,
        expected_ceremony_id=CER,
        expected_file_name=FILE,
    )
    assert got == b"x"


def test_unseal_with_mismatched_expected_did_fails():
    blob = _seal(b"x", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    with pytest.raises(SealingError, match="AAD mismatch"):
        _unseal(
            blob,
            wrap_key=KEY,
            expected_did="did:key:z6Mkother",
            expected_ceremony_id=CER,
            expected_file_name=FILE,
        )


def test_unseal_with_mismatched_expected_ceremony_fails():
    blob = _seal(b"x", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    with pytest.raises(SealingError, match="AAD mismatch"):
        _unseal(
            blob,
            wrap_key=KEY,
            expected_did=DID,
            expected_ceremony_id="local_other",
            expected_file_name=FILE,
        )


def test_unseal_with_mismatched_expected_file_fails():
    blob = _seal(b"x", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    with pytest.raises(SealingError, match="AAD mismatch"):
        _unseal(
            blob,
            wrap_key=KEY,
            expected_did=DID,
            expected_ceremony_id=CER,
            expected_file_name="other.file",
        )


def test_expected_params_must_be_all_or_none():
    blob = _seal(b"x", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    with pytest.raises(ValueError, match="expected_"):
        _unseal(blob, wrap_key=KEY, expected_did=DID)  # missing the others


# --- Key size guards -----------------------------------------------------


def test_seal_rejects_wrong_key_size():
    with pytest.raises(ValueError, match="32 bytes"):
        _seal(b"x", wrap_key=b"short", did=DID, ceremony_id=CER, file_name=FILE)


def test_unseal_rejects_wrong_key_size():
    blob = _seal(b"x", wrap_key=KEY, did=DID, ceremony_id=CER, file_name=FILE)
    with pytest.raises(ValueError, match="32 bytes"):
        _unseal(blob, wrap_key=b"short")


# --- Integration with Identity.vault_wrap_key() --------------------------


def test_seal_unseal_with_identity_wrap_key():
    from tn.identity import Identity

    ident = Identity.create_new()
    wk = ident.vault_wrap_key()
    blob = _seal(
        b"my keystore bytes",
        wrap_key=wk,
        did=ident.did,
        ceremony_id="cer-abc",
        file_name="default.jwe.mykey",
    )
    wire = blob.to_bytes()
    restored = SealedBlob.from_bytes(wire)
    got = _unseal(restored, wrap_key=wk)
    assert got == b"my keystore bytes"


def test_different_mnemonics_cannot_unseal_each_other():
    from tn.identity import Identity

    a = Identity.create_new()
    b = Identity.create_new()
    blob = _seal(
        b"alice only",
        wrap_key=a.vault_wrap_key(),
        did=a.did,
        ceremony_id="cer",
        file_name="f",
    )
    with pytest.raises(SealingError):
        _unseal(blob, wrap_key=b.vault_wrap_key())
