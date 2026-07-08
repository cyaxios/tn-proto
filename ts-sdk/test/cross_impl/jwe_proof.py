"""Python side of the jwe add_recipient cross-language proof.
modes: genkey <dir> | pub <yaml> <keydir> <secret> | read <pubLog> <bKeystore> <secret>
Driven by run_proof.sh. Requires the tn Python package importable.
"""
import sys

mode = sys.argv[1]

if mode == "genkey":
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    d = sys.argv[2]
    sk = X25519PrivateKey.generate()
    open(d + "/b_priv.bin", "wb").write(sk.private_bytes_raw())
    open(d + "/b_pub.bin", "wb").write(
        sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )

elif mode == "pub":
    import tn

    yaml, keydir, secret = sys.argv[2], sys.argv[3], sys.argv[4]
    tn.init(yaml, cipher="jwe")
    bpub = open(keydir + "/b_pub.bin", "rb").read()
    tn.admin.add_recipient("default", recipient_did="did:key:z6MkBproofjwe", public_key=bpub)
    tn.set_context(request_id="proof")
    tn.info("proof.rec", secret=secret, n=42)
    tn.flush_and_close()

elif mode == "read":
    from tn.reader import read_as_recipient

    pub_log, b_keystore, expect = sys.argv[2], sys.argv[3], sys.argv[4]
    ok = False
    for e in read_as_recipient(pub_log, b_keystore, group="default"):
        pt = (e.get("plaintext") or {}).get("default") or {}
        valid = e.get("valid") or {}
        if pt.get("secret") == expect and valid.get("signature"):
            ok = True
    print("PY-READ", "OK" if ok else "FAIL")
    sys.exit(0 if ok else 1)
