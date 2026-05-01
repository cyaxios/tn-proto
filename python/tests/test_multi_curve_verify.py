"""DeviceKey.verify accepts secp256k1 DIDs in addition to Ed25519.

TN signs only Ed25519; the verify path accepts secp256k1 DIDs so readers
can validate entries whose publisher holds a secp256k1 identity (for
example, an ATProto-federated party) without a translation layer.
"""

from __future__ import annotations

import importlib.util as _il
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

# Side-step tn/__init__.py which eagerly loads libtncrypto.
sys.modules.setdefault("tn", type(sys)("tn"))
_spec = _il.spec_from_file_location("tn.signing", HERE.parent / "tn" / "signing.py")
assert _spec and _spec.loader
_mod = _il.module_from_spec(_spec)
sys.modules["tn.signing"] = _mod
_spec.loader.exec_module(_mod)
DeviceKey = _mod.DeviceKey
_b58encode = _mod._b58encode
_SECP256K1_MULTICODEC = _mod._SECP256K1_MULTICODEC


def _secp_pair():
    """Fabricate a secp256k1 did:key + matching signature over a message.

    Uses cryptography's primitives directly; does not rely on TN's
    DeviceKey.sign() (which is Ed25519-only).
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    priv = ec.generate_private_key(ec.SECP256K1())
    pub_comp = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    did = "did:key:z" + _b58encode(_SECP256K1_MULTICODEC + pub_comp)

    def sign(message: bytes) -> bytes:
        der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return did, sign


def test_ed25519_roundtrip() -> None:
    dk = DeviceKey.generate()
    msg = b"hello from tn"
    sig = dk.sign(msg)
    assert DeviceKey.verify(dk.did, msg, sig) is True


def test_ed25519_rejects_bad_sig() -> None:
    dk = DeviceKey.generate()
    bad = b"\x00" * 64
    assert DeviceKey.verify(dk.did, b"msg", bad) is False


def test_secp256k1_verify_accepts_valid_signature() -> None:
    did, sign = _secp_pair()
    msg = b"atproto-federated entry"
    sig = sign(msg)
    assert DeviceKey.verify(did, msg, sig) is True


def test_secp256k1_verify_rejects_bad_signature() -> None:
    did, _ = _secp_pair()
    assert DeviceKey.verify(did, b"msg", b"\x00" * 64) is False


def test_rejects_unknown_multicodec() -> None:
    unknown_prefix = b"\xff\x01"
    body = b"\x00" * 32
    bogus_did = "did:key:z" + _b58encode(unknown_prefix + body)
    assert DeviceKey.verify(bogus_did, b"msg", b"\x00" * 64) is False


def main() -> int:
    tests = [
        test_ed25519_roundtrip,
        test_ed25519_rejects_bad_sig,
        test_secp256k1_verify_accepts_valid_signature,
        test_secp256k1_verify_rejects_bad_signature,
        test_rejects_unknown_multicodec,
    ]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"all {len(tests)} multi-curve verify tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
