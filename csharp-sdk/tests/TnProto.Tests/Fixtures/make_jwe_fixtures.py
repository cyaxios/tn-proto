"""Regenerate the committed JWE fixtures for JweSealedGroupCipherTests.

Each fixture is a real RFC 7516 General JSON JWE produced by the repo's
normative sealer (python/tn/cipher.py::_jwe_seal via joserfc), so the C#
cipher decrypts actual Python wire bytes rather than a C# re-encoding.
Key material is minted fresh on every run; the committed fixtures only
need to stay internally consistent, not stable across regenerations.

Run from the repo root:

    PYTHONPATH=python python csharp-sdk/tests/TnProto.Tests/Fixtures/make_jwe_fixtures.py
"""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tn.cipher import _jwe_seal

HERE = Path(__file__).resolve().parent

# A JSON-object body, like every sealed-object group plaintext on the wire.
PLAINTEXT = b'{"body":"for the fixture reader"}'


def _keypair() -> tuple[bytes, bytes]:
    sk = X25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk.private_bytes_raw(), pub


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _write(name: str, doc: dict) -> None:
    path = HERE / name
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def main() -> None:
    sk, pub = _keypair()
    _write(
        "jwe_single_recipient.json",
        {
            "description": "one recipient, no aad member",
            "plaintext_b64": _b64(PLAINTEXT),
            "aad_b64": "",
            "reader_sk_b64": _b64(sk),
            "jwe": _jwe_seal([pub], PLAINTEXT, b"").decode("utf-8"),
        },
    )

    sk1, pub1 = _keypair()
    sk2, pub2 = _keypair()
    _write(
        "jwe_two_recipients.json",
        {
            "description": "two anonymous recipient blocks; each key opens its own",
            "plaintext_b64": _b64(PLAINTEXT),
            "aad_b64": "",
            "first_recipient_sk_b64": _b64(sk1),
            "second_recipient_sk_b64": _b64(sk2),
            "jwe": _jwe_seal([pub1, pub2], PLAINTEXT, b"").decode("utf-8"),
        },
    )

    aad = b'{"case":"A-17"}'
    sk, pub = _keypair()
    _write(
        "jwe_aad_bound.json",
        {
            "description": "one recipient with the marker bound as the JWE aad member",
            "plaintext_b64": _b64(PLAINTEXT),
            "aad_b64": _b64(aad),
            "reader_sk_b64": _b64(sk),
            "jwe": _jwe_seal([pub], PLAINTEXT, aad).decode("utf-8"),
        },
    )

    old_sk, old_pub = _keypair()
    new_sk, _new_pub = _keypair()
    _write(
        "jwe_rotation_walk.json",
        {
            "description": (
                "sealed to the OLD reader key only; a post-rotation keystore "
                "holds mykey=new and mykey.revoked.<ts>=old, so only the "
                "revoked-key walk opens this blob"
            ),
            "plaintext_b64": _b64(PLAINTEXT),
            "aad_b64": "",
            "current_sk_b64": _b64(new_sk),
            "revoked_sk_b64": _b64(old_sk),
            "jwe": _jwe_seal([old_pub], PLAINTEXT, b"").decode("utf-8"),
        },
    )


if __name__ == "__main__":
    main()
