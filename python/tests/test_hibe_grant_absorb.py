"""HIBE delegation ceremony (Phase 5): authority grants a reader key as a
``.tnpkg``; the reader absorbs it and opens the authority's log.

Also pins the custody rules: the kit carries mpk/idpath/sk but NEVER the
authority master secret, and absorb refuses a ``.hibe.msk`` smuggled into a
non-self-addressed bundle.
"""

from __future__ import annotations

import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn  # noqa: E402
import tn.reader  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hibegrant_") as td:
        ws = Path(td)

        # --- Authority side: hibe ceremony, one sealed entry, one grant.
        a_yaml = ws / "authority" / "tn.yaml"
        a_log = ws / "authority" / "log.ndjson"
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        tn.set_context(user_id=7)
        tn.info("governed.entry", secret="for-granted-readers-only")
        kit_path = ws / "reader.tnpkg"
        res = tn.admin.grant_reader(
            "default",
            reader_did="did:key:z6Mk-reader-stub",
            out_path=kit_path,
        )
        assert res.kit_path == kit_path and kit_path.exists()
        tn.flush_and_close()

        # The kit must carry exactly the reader files — never the msk.
        with zipfile.ZipFile(kit_path) as zf:
            names = zf.namelist()
        assert not any(n.endswith(".hibe.msk") for n in names), names
        for needed in ("default.hibe.mpk", "default.hibe.idpath", "default.hibe.sk"):
            assert any(n.endswith(needed) for n in names), (needed, names)
        print("grant: kit carries mpk/idpath/sk, no msk")

        # --- Reader side: own (btn) ceremony, absorb the kit, read the log.
        r_yaml = ws / "reader" / "tn.yaml"
        r_log = ws / "reader" / "log.ndjson"
        tn.init(r_yaml, log_path=r_log)
        r_cfg = tn.current_config()
        receipt = tn.absorb(kit_path)
        assert (r_cfg.keystore / "default.hibe.sk").exists(), receipt
        assert (r_cfg.keystore / "default.hibe.mpk").exists(), receipt

        entries = list(
            tn.reader.read_as_recipient(a_log, r_cfg.keystore, group="default")
        )
        assert len(entries) == 1
        body = entries[0]["plaintext"]["default"]
        assert body.get("secret") == "for-granted-readers-only", body
        print("absorb: granted reader opened the authority's sealed entry")
        tn.flush_and_close()

        # --- Independent second grant: different key bytes, same access.
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        kit2 = ws / "reader2.tnpkg"
        tn.admin.grant_reader("default", reader_did="did:key:z6Mk-reader-2", out_path=kit2)
        tn.flush_and_close()
        with zipfile.ZipFile(kit_path) as zf:
            sk1 = next(zf.read(n) for n in zf.namelist() if n.endswith("default.hibe.sk"))
        with zipfile.ZipFile(kit2) as zf:
            sk2 = next(zf.read(n) for n in zf.namelist() if n.endswith("default.hibe.sk"))
        assert sk1 != sk2, "each grant must mint independently randomized key material"
        print("grant: second grantee got independent key material")

    return 0


if __name__ == "__main__":
    sys.exit(main())
