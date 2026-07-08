"""HIBE reader add/remove lifecycle: grant two readers, revoke one, and
verify the forward/backward semantics the docs promise.

  - revoke = rotate the identity path + re-issue kits to the survivors
  - the revoked reader keeps pre-revocation entries (permanent-key limit,
    stated, not hidden) and loses everything after
  - a survivor absorbs their re-issued kit and reads seamlessly across the
    rotation (the superseded key is retained for old entries)
  - grants are recorded in the authority-side registry; the registry and
    the msk never ride a kit
"""

from __future__ import annotations

import json
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn  # noqa: E402
import tn.reader  # noqa: E402

ALICE = "did:key:z6Mk-alice"
BOB = "did:key:z6Mk-bob"


def _by_type(log_path: Path, keystore: Path) -> dict[str, dict]:
    return {
        e["envelope"]["event_type"]: e["plaintext"]["default"]
        for e in tn.reader.read_as_recipient(log_path, keystore, group="default")
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hiberevoke_") as td:
        ws = Path(td)
        a_yaml = ws / "authority" / "tn.yaml"
        a_log = ws / "authority" / "log.ndjson"

        # --- Add two readers, seal epoch 1.
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        a_keystore = tn.current_config().keystore
        tn.info("e1", note="both readers admitted")
        alice_kit = ws / "alice.tnpkg"
        bob_kit = ws / "bob.tnpkg"
        tn.admin.grant_reader("default", reader_did=ALICE, out_path=alice_kit)
        tn.admin.grant_reader("default", reader_did=BOB, out_path=bob_kit)
        grants = json.loads((a_keystore / "default.hibe.grants").read_text())
        assert {g["reader_did"] for g in grants} == {ALICE, BOB}

        # --- Remove bob: rotate + re-issue alice's kit.
        res = tn.admin.revoke_reader(
            "default", BOB, out_dir=ws / "regrant"
        )
        assert res.revoked and res.new_path == "self~r1"
        assert res.remaining == [ALICE]
        assert len(res.kit_paths) == 1 and res.kit_paths[0].exists()
        grants = json.loads((a_keystore / "default.hibe.grants").read_text())
        assert {g["reader_did"] for g in grants} == {ALICE}
        tn.info("e2", note="after bob was removed")
        tn.flush_and_close()
        print("revoke: bob removed, path rotated, alice re-kitted")

        # Neither the registry nor any master secret rides a kit.
        for kit in (alice_kit, bob_kit, res.kit_paths[0]):
            with zipfile.ZipFile(kit) as zf:
                names = zf.namelist()
            assert not any(n.endswith((".hibe.msk", ".hibe.grants")) for n in names), names

        # --- Bob: keeps e1 (honest limit), locked out of e2.
        tn.init(ws / "bob" / "tn.yaml", log_path=ws / "bob" / "log.ndjson")
        bob_ks = tn.current_config().keystore
        tn.absorb(bob_kit)
        tn.flush_and_close()
        got = _by_type(a_log, bob_ks)
        assert got["e1"]["note"] == "both readers admitted"
        assert got["e2"] == {"$no_read_key": True}, got["e2"]
        print("revoke: bob keeps e1, cannot open e2")

        # --- Alice: absorbs original + re-issued kit, reads across the
        # rotation without any special handling.
        tn.init(ws / "alice" / "tn.yaml", log_path=ws / "alice" / "log.ndjson")
        alice_ks = tn.current_config().keystore
        tn.absorb(alice_kit)
        tn.absorb(res.kit_paths[0])
        tn.flush_and_close()
        got = _by_type(a_log, alice_ks)
        assert got["e1"]["note"] == "both readers admitted"
        assert got["e2"]["note"] == "after bob was removed"
        print("revoke: alice reads seamlessly across the rotation")

        # --- Guardrails + the generic verb.
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        try:
            tn.admin.revoke_reader("default", "did:key:z6Mk-nobody")
            raise AssertionError("revoking an unknown did must raise")
        except ValueError:
            pass
        # revoke_recipient routes hibe groups to the same flow.
        import os

        cwd = os.getcwd()
        os.chdir(ws)  # default out_dir lands under cwd; keep it in the tmp ws
        try:
            r2 = tn.admin.revoke_recipient("default", recipient_did=ALICE)
        finally:
            os.chdir(cwd)
        assert r2.revoked and r2.cipher == "hibe"
        assert r2.new_path == "self~r2"  # counter bumps, not stacks
        assert r2.kit_paths == []  # nobody left to re-kit
        tn.flush_and_close()
        print("revoke: guardrails + generic revoke_recipient verb ok")

    return 0


if __name__ == "__main__":
    sys.exit(main())
