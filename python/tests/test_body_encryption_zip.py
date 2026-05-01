"""Round-trip tests for ``tn.pkg.export._encrypt_body_in_place`` /
``decrypt_body_blob`` after the format moved from a custom binary
frame to a STORED zip plaintext.

See D-N "body plaintext is a STORED zip" in the vault decisions log.
"""

from __future__ import annotations

import os
import struct
import zipfile
from io import BytesIO

from tn.export import _encrypt_body_in_place, decrypt_body_blob


def _example_body() -> dict[str, bytes]:
    return {
        "body/local.private": b"\x01" * 32,
        "body/local.public": b"did:key:z6Mk_example_pubkey",
        "body/tn.yaml": b"ceremony_id: local_test\ncipher: btn\ngroups: {}\n",
        "body/default.btn.mykit": os.urandom(128),
        "body/default.btn.state": os.urandom(96),
        "body/WARNING_CONTAINS_PRIVATE_KEYS": b"",
    }


def test_encrypt_then_decrypt_round_trip_uses_stored_zip():
    """Headline assertion: encrypt → decrypt recovers the input dict, and
    the ciphertext plaintext is a real STORED zip readable by stdlib."""
    body = _example_body()
    key = os.urandom(32)

    new_body, extras = _encrypt_body_in_place(body, {}, key)
    assert set(new_body.keys()) == {"body/encrypted.bin"}
    blob = new_body["body/encrypted.bin"]
    assert len(blob) >= 12 + 16  # nonce + tag minimum

    # State extras name the new frame so future readers can dispatch.
    state = extras["state"]["body_encryption"]
    assert state["cipher_suite"] == "aes-256-gcm"
    assert state["frame"] == "tn-encrypted-body-v2-zip"
    assert state["ciphertext_sha256"].startswith("sha256:")

    # Round-trip via the public decrypt helper.
    recovered = decrypt_body_blob(blob, key)
    assert recovered == body


def test_decrypted_plaintext_is_readable_stored_zip():
    """An advanced user holding the BEK can `unzip` the decrypted
    plaintext directly with stock tools — no custom parser required."""
    body = _example_body()
    key = os.urandom(32)
    new_body, _ = _encrypt_body_in_place(body, {}, key)
    blob = new_body["body/encrypted.bin"]

    # Manually decrypt to inspect the plaintext.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ct = blob[:12], blob[12:]
    plaintext = AESGCM(key).decrypt(nonce, ct, None)

    # Magic bytes.
    assert plaintext[:4] == b"PK\x03\x04", "plaintext is not a real zip"

    with zipfile.ZipFile(BytesIO(plaintext)) as zf:
        # All members STORED, not deflated.
        for info in zf.infolist():
            assert info.compress_type == zipfile.ZIP_STORED, (
                f"{info.filename} is not STORED ({info.compress_type})"
            )
        names = set(zf.namelist())
    assert names == set(body.keys())


def _build_legacy_custom_frame_blob(body: dict[str, bytes], key: bytes) -> bytes:
    """Reproduce Session 4's custom-frame format so the legacy-compat
    fallback can be exercised without resurrecting old code paths."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    pt = bytearray()
    pt.extend(struct.pack(">I", len(body)))
    for name in sorted(body.keys()):
        nb = name.encode("utf-8")
        pt.extend(struct.pack(">I", len(nb)))
        pt.extend(nb)
        pt.extend(struct.pack(">I", len(body[name])))
        pt.extend(body[name])
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, bytes(pt), None)
    return nonce + ct


def test_decrypt_body_blob_legacy_compat_custom_frame():
    """LEGACY-COMPAT-2026-04-29 — the in-flight projects on the live vault
    were sealed under the old custom binary frame. Until those rows are
    re-claimed under the new format, ``decrypt_body_blob`` must still
    decode them."""
    body = _example_body()
    key = os.urandom(32)
    blob = _build_legacy_custom_frame_blob(body, key)

    recovered = decrypt_body_blob(blob, key)
    assert recovered == body


def test_decrypt_body_blob_too_short_raises():
    """Defensive: a clearly truncated blob fails fast with a
    deterministic error rather than blowing up inside AESGCM."""
    import pytest

    with pytest.raises(ValueError, match="too short"):
        decrypt_body_blob(b"\x00" * 8, b"\x00" * 32)
