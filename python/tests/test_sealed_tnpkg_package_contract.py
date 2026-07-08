from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import hashlib
import zipfile
from pathlib import Path

from tn.config import load_or_create
from tn.export import decrypt_body_blob, export
from tn.tnpkg import _read_manifest, _verify_manifest_signature


def test_byok_full_keystore_outer_package_exposes_only_encrypted_body(tmp_path: Path):
    cfg = load_or_create(tmp_path / "payroll" / "tn.yaml", cipher=_workflow_cipher("btn"))
    out = tmp_path / "payroll-sealed.tnpkg"
    bek = bytes(range(32))

    export(
        out,
        kind="full_keystore",
        cfg=cfg,
        confirm_includes_secrets=True,
        encrypt_body_with=bek,
    )

    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
    assert names == {"manifest.json", "body/encrypted.bin"}

    manifest, body = _read_manifest(out)
    assert manifest.kind == "full_keystore"
    assert _verify_manifest_signature(manifest)

    blob = body["body/encrypted.bin"]
    body_encryption = (manifest.state or {}).get("body_encryption") or {}
    assert body_encryption == {
        "cipher_suite": "aes-256-gcm",
        "nonce_bytes": 12,
        "frame": "tn-encrypted-body-v2-zip",
        "ciphertext_sha256": "sha256:" + hashlib.sha256(blob).hexdigest(),
    }

    plaintext = decrypt_body_blob(blob, bek)
    assert "body/local.private" in plaintext
    assert "body/tn.yaml" in plaintext
    assert "body/encrypted.bin" not in plaintext
