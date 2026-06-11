"""Round-trip + revocation tests for the JWE group cipher class.

No native-crypto dependency: this test runs on Windows via the bundled
.venv without libtncrypto.
"""

from __future__ import annotations

import importlib.util as _il
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# Side-step tn/__init__.py — it eagerly imports _native which loads
# libtncrypto. Load just the modules we need directly by file path so
# the JWE test stays runnable without the compiled .dll/.so.
def _load_module(name: str, relpath: str):
    path = HERE.parent / relpath
    spec = _il.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = _il.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sys.modules.setdefault("tn", type(sys)("tn"))
_load_module("tn.canonical", "tn/canonical.py")
_load_module("tn.indexing", "tn/indexing.py")
_load_module("tn.signing", "tn/signing.py")
cipher_mod = _load_module("tn.cipher_standalone", "tn/cipher.py")
JWEGroupCipher = cipher_mod.JWEGroupCipher
NotAPublisherError = cipher_mod.NotAPublisherError
NotARecipientError = cipher_mod.NotARecipientError


def test_jwe_roundtrip_publisher_can_decrypt_own() -> None:
    with tempfile.TemporaryDirectory(prefix="jwe_") as td:
        ks = Path(td)
        cipher = JWEGroupCipher.create(ks, "default", recipient_dids=["did:self"])
        ct = cipher.encrypt(b"hello jwe world")
        pt = cipher.decrypt(ct)
        assert pt == b"hello jwe world"


def test_jwe_multi_recipient_all_decrypt() -> None:
    with tempfile.TemporaryDirectory(prefix="jwe_") as td:
        ks = Path(td)
        import cryptography.hazmat.primitives.asymmetric.x25519 as _x
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        recipients = []
        for i in range(3):
            sk = _x.X25519PrivateKey.generate()
            pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            recipients.append({"did": f"did:r{i}", "pub": pub, "sk": sk})

        cipher = JWEGroupCipher.create(
            ks,
            "default",
            recipient_dids=[r["did"] for r in recipients],
            recipient_pubs={r["did"]: r["pub"] for r in recipients},
        )
        ct = cipher.encrypt(b"shared payload")

        for r in recipients:
            recv_cipher = JWEGroupCipher.as_recipient(
                sender_pub=cipher.sender_pub(),
                my_sk=r["sk"],
            )
            assert recv_cipher.decrypt(ct) == b"shared payload"


def test_jwe_revoked_recipient_cannot_decrypt_new_entries() -> None:
    """After revoke, next encrypt must not include the revoked recipient's
    wrapped CEK. Attempting to decrypt the new envelope raises."""
    with tempfile.TemporaryDirectory(prefix="jwe_") as td:
        ks = Path(td)
        import cryptography.hazmat.primitives.asymmetric.x25519 as _x
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        evicted_sk = _x.X25519PrivateKey.generate()
        evicted_pub = evicted_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        kept_sk = _x.X25519PrivateKey.generate()
        kept_pub = kept_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        cipher = JWEGroupCipher.create(
            ks,
            "default",
            recipient_dids=["did:evict", "did:keep"],
            recipient_pubs={"did:evict": evicted_pub, "did:keep": kept_pub},
        )

        # Before revocation: evicted can decrypt.
        ct_before = cipher.encrypt(b"before")
        evicted_view = JWEGroupCipher.as_recipient(sender_pub=cipher.sender_pub(), my_sk=evicted_sk)
        assert evicted_view.decrypt(ct_before) == b"before"

        # Revoke.
        cipher.revoke_recipient("did:evict")

        # After: new envelope excludes them. Decrypt raises NotARecipientError.
        ct_after = cipher.encrypt(b"after")
        try:
            evicted_view.decrypt(ct_after)
        except NotARecipientError:
            pass
        else:
            raise AssertionError("evicted recipient should not decrypt post-revocation")

        # Kept recipient still works.
        kept_view = JWEGroupCipher.as_recipient(sender_pub=cipher.sender_pub(), my_sk=kept_sk)
        assert kept_view.decrypt(ct_after) == b"after"


def main() -> int:
    tests = [
        test_jwe_roundtrip_publisher_can_decrypt_own,
        test_jwe_multi_recipient_all_decrypt,
        test_jwe_revoked_recipient_cannot_decrypt_new_entries,
    ]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"all {len(tests)} jwe cipher tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
