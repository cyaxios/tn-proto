"""Python side of the hibe grant_reader (add_recipient) cross-language proof.

Secure flow (the grant kit is sealed to the reader's device key, so the reader
must exist and share its real DID before the authority grants):
  readerinit <readerYaml>                    -- reader: mint own ceremony, print DID
  auth   <yaml> <kitPath> <secret> <readerDid> -- authority: grant reader, emit
  absorb <readerYaml> <kitPath>               -- reader: absorb (unseal) the kit
  read   <authLog> <readerKeystore> <secret>
"""
import contextlib
import sys

mode = sys.argv[1]

if mode == "readerinit":
    import tn

    yaml = sys.argv[2]
    # Init writes nothing to stdout as a library call, but redirect anyway so
    # the ONLY thing on stdout is the DID the harness captures.
    with contextlib.redirect_stdout(sys.stderr):
        tn.init(yaml)  # reader's own btn default ceremony
        did = tn.current_config().device.device_identity
        tn.flush_and_close()
    print(did)

elif mode == "auth":
    import tn

    yaml, kit_path, secret, reader_did = (
        sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
    )
    tn.init(yaml, cipher="hibe")
    tn.admin.grant_reader("default", reader_did=reader_did, out_path=kit_path)
    tn.set_context(request_id="proof")
    tn.info("proof.rec", secret=secret, n=42)
    tn.flush_and_close()

elif mode == "absorb":
    import tn

    yaml, kit_path = sys.argv[2], sys.argv[3]
    tn.init(yaml)  # attach to the reader ceremony minted in readerinit
    tn.absorb(kit_path)
    tn.flush_and_close()

elif mode == "read":
    from tn.reader import read_as_recipient

    auth_log, keystore, expect = sys.argv[2], sys.argv[3], sys.argv[4]
    ok = False
    for e in read_as_recipient(auth_log, keystore, group="default"):
        pt = (e.get("plaintext") or {}).get("default") or {}
        if pt.get("secret") == expect and (e.get("valid") or {}).get("signature"):
            ok = True
    print("PY-READ", "OK" if ok else "FAIL")
    sys.exit(0 if ok else 1)
