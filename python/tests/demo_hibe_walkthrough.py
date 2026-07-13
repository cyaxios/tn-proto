"""Executable walkthrough of the hibe cipher, used to generate the how-to
doc (docs/guide/hibe-howto.md). Every code block and every line of output
in that doc is produced by running this file, so the doc cannot drift from
the implementation.

Run:  python tests/demo_hibe_walkthrough.py

It is also a test: the asserts fail loudly if any documented behavior
changes, which is the signal to regenerate the doc.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
import tn.reader
from tn import _hibe
from tn.recipient_seal import recipient_key_is_resolvable


def h(b: bytes) -> str:
    """Short, stable hex preview of a key/blob."""
    return b[:8].hex() + f"... ({len(b)} bytes)"


def section(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


# ---------------------------------------------------------------------------
def part1_key_model() -> None:
    """The four pieces of key material, at the primitive layer (tn._hibe)."""
    section("PART 1 - the key material")

    # An authority runs Setup once. It produces a keypair for the WHOLE
    # system: one public master key (mpk) and one master secret (msk).
    mpk, msk = _hibe.setup(2)  # max_depth=2: paths up to 2 labels deep
    print(f"mpk (master public key, SHAREABLE) : {h(mpk)}")
    print(f"msk (master secret, AUTHORITY ONLY): {h(msk)}")
    print(
        "mpk fingerprint (byte identifier only): "
        f"{_hibe.mpk_fingerprint(mpk).hex()}"
    )

    # From the msk the authority mints a reader key (sk) for an IDENTITY
    # PATH. The path is just a string; there is no per-reader key exchange.
    alice_sk = _hibe.keygen(mpk, msk, "alice")
    print(f"\nalice's reader key for path 'alice': {h(alice_sk)}")
    print(f"  the key knows its own path: {_hibe.key_id_path(alice_sk)!r}")

    # Anyone with the mpk can seal to a path WITHOUT holding a key for it.
    blob = _hibe.seal(mpk, "alice", b"hello alice")
    print(f"\nsealed to 'alice' with only the mpk: {h(blob)}")

    # Only a key on that path opens it.
    opened = _hibe.open(mpk, alice_sk, blob)
    print(f"alice opens it: {opened!r}")
    assert opened == b"hello alice"

    # A key for a DIFFERENT path cannot.
    bob_sk = _hibe.keygen(mpk, msk, "bob")
    try:
        _hibe.open(mpk, bob_sk, blob)
        raise AssertionError("bob must not open alice's blob")
    except _hibe.HibeCryptoError:
        print("bob's key refuses alice's blob (HibeCryptoError)")


# ---------------------------------------------------------------------------
def part2_hierarchy() -> None:
    """Why they are 'hierarchical': a parent key makes child keys itself."""
    section("PART 2 - the hierarchy (delegation without the master secret)")

    mpk, msk = _hibe.setup(3)
    # The authority hands a DEPARTMENT key one level down.
    dept_sk = _hibe.keygen(mpk, msk, "engineering")
    print(f"authority minted 'engineering' key: {h(dept_sk)}")

    # The department, holding only that key and the mpk (NO msk), derives a
    # key for a child path locally.
    alice_sk = _hibe.delegate(mpk, dept_sk, "alice")
    print(f"department delegated -> 'engineering/alice': {_hibe.key_id_path(alice_sk)!r}")
    print("  (no master secret was used or needed)")

    blob = _hibe.seal(mpk, "engineering/alice", b"design review notes")
    assert _hibe.open(mpk, alice_sk, blob) == b"design review notes"
    print("alice's delegated key opens a blob sealed to her full path: ok")

    # The parent (department) key also opens the child's path, by deriving
    # down on the fly.
    alice_again = _hibe.delegate(mpk, dept_sk, "alice")
    assert _hibe.open(mpk, alice_again, blob) == b"design review notes"
    print("the department key spans everything beneath it: ok")


# ---------------------------------------------------------------------------
def part3_product_workflow() -> None:
    """The everyday surface: init, log, grant, absorb, read."""
    section("PART 3 - the product workflow (tn.init / grant_reader / absorb)")

    ws = Path(tempfile.mkdtemp(prefix="hibe_howto_"))
    authority_yaml = ws / "authority" / "tn.yaml"
    authority_log = ws / "authority" / "log.ndjson"
    reader_yaml = ws / "alice" / "tn.yaml"
    reader_log = ws / "alice" / "log.ndjson"

    # Alice creates her device identity first and authenticates this complete
    # Ed25519 did:key to the authority out of band.
    tn.init(reader_yaml, log_path=reader_log)
    alice_did = tn.current_config().device.device_identity
    assert recipient_key_is_resolvable(alice_did)
    tn.flush_and_close()

    # 1. The authority starts a hibe ceremony. It becomes its OWN authority:
    #    Setup runs, the msk stays in this keystore, nothing tn-hosted holds
    #    a decryption root.
    tn.init(authority_yaml, log_path=authority_log, cipher="hibe")
    cfg = tn.current_config()
    print(f"authority ceremony cipher: {cfg.cipher_name}")
    keyfiles = sorted(p.name for p in cfg.keystore.glob("default.hibe.*"))
    print(f"key files written: {keyfiles}")

    # 2. Log some governed entries.
    tn.info("decision.recorded", subject="loan-4821", outcome="approved")
    tn.info("decision.recorded", subject="loan-4822", outcome="declined")
    print("logged 2 entries under the 'default' hibe group")

    # 3. Grant a reader. This mints their key and packages it as a .tnpkg
    #    recipient-sealed kit. The HIBE sk inside remains a bearer capability.
    kit = ws / "alice.tnpkg"
    tn.admin.grant_reader("default", reader_did=alice_did, out_path=kit)
    print(f"granted reader; kit written to: {kit.name}")

    import zipfile

    with zipfile.ZipFile(kit) as zf:
        body_names = sorted(n for n in zf.namelist() if n.startswith("body/"))
    assert body_names == ["body/encrypted.bin"]
    print("kit body is recipient-sealed: ['encrypted.bin']")
    print("  (note: NO .hibe.msk — the master secret never leaves the authority)")
    tn.flush_and_close()

    # 4. The reader is a separate person with their own ceremony. They
    #    absorb the kit, and can now read the authority's log.
    tn.init(reader_yaml, log_path=reader_log)
    reader_cfg = tn.current_config()
    receipt = tn.absorb(kit)
    print(f"\nreader absorbed the kit: accepted={receipt.accepted_count}")

    entries = list(
        tn.reader.read_as_recipient(authority_log, reader_cfg.keystore, group="default")
    )
    for e in entries:
        body = e["plaintext"]["default"]
        print(f"  read: {body['subject']} -> {body['outcome']}")
    assert [e["plaintext"]["default"]["outcome"] for e in entries] == ["approved", "declined"]
    tn.flush_and_close()


# ---------------------------------------------------------------------------
def part4_remove_reader() -> None:
    """Adding a second reader, then removing the first."""
    section("PART 4 - removing a reader (revoke = rotate + re-issue)")

    ws = Path(tempfile.mkdtemp(prefix="hibe_revoke_"))
    a_yaml = ws / "authority" / "tn.yaml"
    a_log = ws / "authority" / "log.ndjson"

    alice_yaml = ws / "alice" / "tn.yaml"
    alice_log = ws / "alice" / "log.ndjson"
    tn.init(alice_yaml, log_path=alice_log)
    alice_did = tn.current_config().device.device_identity
    assert recipient_key_is_resolvable(alice_did)
    tn.flush_and_close()

    bob_yaml = ws / "bob" / "tn.yaml"
    bob_log = ws / "bob" / "log.ndjson"
    tn.init(bob_yaml, log_path=bob_log)
    bob_did = tn.current_config().device.device_identity
    assert recipient_key_is_resolvable(bob_did)
    tn.flush_and_close()

    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    tn.info("memo", text="visible to both readers")
    alice_kit, bob_kit = ws / "alice.tnpkg", ws / "bob.tnpkg"
    tn.admin.grant_reader("default", reader_did=alice_did, out_path=alice_kit)
    tn.admin.grant_reader("default", reader_did=bob_did, out_path=bob_kit)
    print("granted alice and bob")

    # Remove bob. The path rotates and every SURVIVOR gets a re-issued kit.
    res = tn.admin.revoke_reader("default", bob_did, out_dir=ws / "regrant")
    print(f"revoked bob; new sealing path = {res.new_path!r}")
    print(f"survivors re-kitted: {len(res.remaining)}")
    tn.info("memo", text="sealed AFTER bob was removed")
    tn.flush_and_close()

    # Bob keeps what he could already read, loses everything after.
    tn.init(bob_yaml, log_path=bob_log)
    bob_ks = tn.current_config().keystore
    tn.absorb(bob_kit)
    tn.flush_and_close()
    bob_sees = {
        e["envelope"]["sequence"]: e["plaintext"]["default"]
        for e in tn.reader.read_as_recipient(a_log, bob_ks, group="default")
    }
    print("\nbob's view after removal:")
    for seq, body in sorted(bob_sees.items()):
        shown = body.get("text", body)
        print(f"  seq {seq}: {shown}")
    assert bob_sees[2] == {"$no_read_key": True}
    print("  (bob keeps the pre-removal memo, is locked out of the new one)")


def part5_aad_binding() -> None:
    """Binding a policy marker to a governed body with an AAD dict."""
    section("PART 5 - welding a policy marker (the AAD dict)")

    ws = Path(tempfile.mkdtemp(prefix="hibe_aad_"))
    a_yaml = ws / "authority" / "tn.yaml"
    a_log = ws / "authority" / "log.ndjson"

    # Pass an aad dict at emit. The marker is authenticated into the body and
    # echoed (authenticated) into the record's public section.
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    tn.info("oba.filed", note="quarterly OBA", aad={"policy": "finra-oba", "v": "1"})
    tn.flush_and_close()

    line = [ln for ln in a_log.read_text(encoding="utf-8").splitlines() if ln][0]
    env = json.loads(line)
    print(f"public tn_aad echo (a canonical JSON string): {env['tn_aad']!r}")

    # A legitimate read reconstructs the marker and opens the body.
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    cfg = tn.current_config()
    rec = next(e for e in tn.reader.read(a_log, cfg))
    print(f"row_hash valid: {rec['valid']['row_hash']}, decrypts: {rec['plaintext']['default']}")
    tn.flush_and_close()

    # Tamper the marker on disk: decryption fails AND row_hash breaks.
    tampered = env.copy()
    tampered["tn_aad"] = env["tn_aad"].replace("finra-oba", "swapped-policy")
    a_log.write_text(json.dumps(tampered, separators=(",", ":")) + "\n", encoding="utf-8")
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    cfg = tn.current_config()
    rec = next(e for e in tn.reader.read(a_log, cfg))
    print(f"after swapping the marker -> row_hash valid: {rec['valid']['row_hash']}, "
          f"body: {rec['plaintext']['default']}")
    assert not rec["valid"]["row_hash"]
    tn.flush_and_close()


def main() -> int:
    part1_key_model()
    part2_hierarchy()
    part3_product_workflow()
    part4_remove_reader()
    part5_aad_binding()
    print(f"\n{'=' * 70}\nall walkthrough sections passed\n{'=' * 70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
