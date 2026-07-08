"""Full hibe lifecycle at the Python layer, as one story through the
public product surface (no cipher internals):

  Act 1  authority mints a hibe ceremony, logs epoch-a, grants reader 1
  Act 2  reader 1 absorbs the kit and reads epoch-a from the foreign log
  Act 3  authority rotates the policy path, logs epoch-b, grants reader 2
  Act 4  reader 1 keeps epoch-a, loses epoch-b (permanent-key semantics)
  Act 5  reader 2 opens epoch-b but not epoch-a (granted post-rotation)
  Act 6  the authority reads across both epochs with signature, row_hash,
         and chain all verifying

Every ceremony is closed and reopened between acts, so the whole keystore
persistence path is exercised, not just in-memory state.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn  # noqa: E402
import tn.reader  # noqa: E402


def _by_type(log_path: Path, keystore: Path) -> dict[str, dict]:
    return {
        e["envelope"]["event_type"]: e["plaintext"]["default"]
        for e in tn.reader.read_as_recipient(log_path, keystore, group="default")
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hibelifecycle_") as td:
        ws = Path(td)
        a_yaml = ws / "authority" / "tn.yaml"
        a_log = ws / "authority" / "log.ndjson"
        kit1 = ws / "reader1.tnpkg"
        kit2 = ws / "reader2.tnpkg"

        # --- Act 1: authority bootstraps, seals epoch-a, grants reader 1.
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        assert tn.current_config().cipher_name == "hibe"
        tn.info("epoch.a.first", note="before rotation, entry 1")
        tn.info("epoch.a.second", note="before rotation, entry 2")
        tn.admin.grant_reader("default", reader_did="did:key:z6Mk-r1", out_path=kit1)
        tn.flush_and_close()
        print("act 1: authority sealed epoch-a and granted reader 1")

        # --- Act 2: reader 1 absorbs and reads the foreign log.
        tn.init(ws / "reader1" / "tn.yaml", log_path=ws / "reader1" / "log.ndjson")
        r1_keystore = tn.current_config().keystore
        tn.absorb(kit1)
        tn.flush_and_close()
        got = _by_type(a_log, r1_keystore)
        assert got["epoch.a.first"]["note"] == "before rotation, entry 1"
        assert got["epoch.a.second"]["note"] == "before rotation, entry 2"
        print("act 2: reader 1 opened epoch-a")

        # --- Act 3: rotation, epoch-b, a post-rotation grant.
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        tn.admin.rotate_reader_path("default", "policy-b")
        tn.info("epoch.b.first", note="after rotation")
        tn.admin.grant_reader("default", reader_did="did:key:z6Mk-r2", out_path=kit2)
        tn.flush_and_close()
        print("act 3: authority rotated, sealed epoch-b, granted reader 2")

        # --- Act 4: reader 1 keeps history, loses the new epoch.
        got = _by_type(a_log, r1_keystore)
        assert got["epoch.a.first"]["note"] == "before rotation, entry 1"
        assert got["epoch.b.first"] == {"$no_read_key": True}, got["epoch.b.first"]
        print("act 4: reader 1 keeps epoch-a, cannot open epoch-b")

        # --- Act 5: reader 2 sees exactly the inverse.
        tn.init(ws / "reader2" / "tn.yaml", log_path=ws / "reader2" / "log.ndjson")
        r2_keystore = tn.current_config().keystore
        tn.absorb(kit2)
        tn.flush_and_close()
        got = _by_type(a_log, r2_keystore)
        assert got["epoch.b.first"]["note"] == "after rotation"
        assert got["epoch.a.first"] == {"$no_read_key": True}, got["epoch.a.first"]
        print("act 5: reader 2 opens epoch-b, cannot open epoch-a")

        # --- Act 6: the authority spans both epochs and everything verifies.
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        a_cfg = tn.current_config()
        entries = list(tn.reader.read(a_log, a_cfg))
        assert len(entries) == 3
        for e in entries:
            ev = e["envelope"]["event_type"]
            assert e["valid"]["signature"], f"bad signature: {ev}"
            assert e["valid"]["row_hash"], f"bad row_hash: {ev}"
            assert e["valid"]["chain"], f"broken chain: {ev}"
            assert "note" in e["plaintext"]["default"], f"authority decrypt failed: {ev}"
        tn.flush_and_close()
        print("act 6: authority reads all epochs; signature/row_hash/chain verify")

    return 0


if __name__ == "__main__":
    sys.exit(main())
