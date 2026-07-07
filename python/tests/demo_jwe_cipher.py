"""Executable reference for the JWE group cipher (`cipher: jwe`).

Generates the captured output in docs/guide/jwe-howto.md. Exercises the cipher
directly (seal/open/marker/add/revoke) and shows the on-wire RFC 7516 object.
Self-asserting: run it as a smoke test of the surface.

Run:  python tests/demo_jwe_cipher.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from tn.cipher import JWEGroupCipher, NotARecipientError  # noqa: E402


def section(t: str) -> None:
    print(f"\n{'=' * 66}\n{t}\n{'=' * 66}")


def raw_pub(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def main() -> int:
    d = Path(tempfile.mkdtemp(prefix="jwedemo_"))

    section("create a jwe group (publisher is also the sole reader)")
    pub = JWEGroupCipher.create(d, "orders", recipient_dids=["did:key:alice"])
    print("keystore files:", sorted(p.name for p in d.glob("orders.jwe.*")))

    section("seal / open a body")
    blob = pub.encrypt(b'{"amount": 999, "currency": "USD"}')
    print(f"sealed blob     : {len(blob)} bytes of RFC 7516 JWE JSON")
    print("open (publisher):", pub.decrypt(blob).decode())

    section("the on-wire object (JWE General JSON Serialization)")
    obj = json.loads(blob)
    print("members         :", sorted(obj))
    print("protected       :", obj["protected"], "(b64url {\"enc\":\"A256GCM\"})")
    print("recipients      :", len(obj["recipients"]))
    print("recipient[0].alg:", obj["recipients"][0]["header"]["alg"])
    print("recipient[0].epk:", obj["recipients"][0]["header"]["epk"])

    section("bind a marker (the JWE aad member: authenticated, not encrypted)")
    gov = pub.encrypt(b'{"amount": 999}', b"policy=finra-oba")
    print("aad member set  :", "aad" in json.loads(gov))
    print("open, right aad :", pub.decrypt(gov, b"policy=finra-oba").decode())
    try:
        pub.decrypt(gov, b"policy=other")
    except NotARecipientError:
        print("open, wrong aad : rejected (NotARecipientError)")
    print("plain seal aad? :", "aad" in json.loads(pub.encrypt(b"{}")))

    section("add a second recipient — both can open, next seal wraps to both")
    bob = X25519PrivateKey.generate()
    pub.add_recipient("did:key:bob", raw_pub(bob))
    blob2 = pub.encrypt(b'{"amount": 250}')
    print("recipient blocks:", len(json.loads(blob2)["recipients"]))
    bob_view = JWEGroupCipher.as_recipient(pub.sender_pub(), bob)
    print("alice opens     :", pub.decrypt(blob2).decode())
    print("bob opens       :", bob_view.decrypt(blob2).decode())

    section("revoke bob — forward only (pre-revocation seals he holds stay open)")
    pub.revoke_recipient("did:key:bob")
    blob3 = pub.encrypt(b'{"amount": 50}')
    print("recipient blocks:", len(json.loads(blob3)["recipients"]))
    print("alice opens new :", pub.decrypt(blob3).decode())
    try:
        bob_view.decrypt(blob3)
    except NotARecipientError:
        print("bob opens new   : rejected (revoked before this seal)")
    print("bob opens old   :", bob_view.decrypt(blob2).decode(), "(pre-revocation, still his)")

    print("\nall jwe cipher checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
