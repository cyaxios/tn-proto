"""Exercise the code-level CLI equivalents: tn.log, issue_key, rotate."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="tnadm_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"
        log_path = ws / ".tn/tn/logs" / "tn.ndjson"

        tn.init(yaml_path, log_path=log_path, pool_size=4, cipher="bgw")
        cfg = tn.current_config()

        # ---- severity-less tn.log() ----------------------------------------
        tn.log("system.boot", node="alpha", version="0.1.0")
        # tn.log returns None; verify the entry by reading back the envelope.
        envs = [r["envelope"] for r in tn.read_raw()
                if r["envelope"].get("event_type") == "system.boot"]
        assert envs and envs[-1].get("level") == "", (
            f"expected empty level on tn.log() entry, got envs={envs!r}"
        )
        print("tn.log() (no severity): ok")

        # ---- issue_key handed to a recipient DID ---------------------------
        recipient_did = "did:key:zQ3shFriendDidStub1234567890abcdef"
        key_path = tn.issue_key(cfg, "default", recipient_did)
        assert key_path.exists()
        assert key_path.stat().st_size > 0
        print(f"issue_key: wrote {key_path.name} ({key_path.stat().st_size} bytes)")

        # unissued pool shrunk
        assert len(cfg.groups["default"].unissued_slots) == 2

        # ---- import_key (recipient side) -----------------------------------
        # Simulate a separate party importing the file we just issued.
        with tempfile.TemporaryDirectory(prefix="tnrcpt_") as td2:
            rcpt_ws = Path(td2)
            rcpt_yaml = rcpt_ws / "tn.yaml"
            tn.flush_and_close()
            tn.init(rcpt_yaml, log_path=rcpt_ws / ".tn/tn/logs" / "tn.ndjson")
            rcpt_cfg = tn.current_config()

            # recipient should NOT have the publisher's keys yet — import one
            imported = tn.import_key(rcpt_cfg, "default", key_path)
            assert imported.exists()
            assert imported.name == "default.read"
            print(f"import_key: landed at {imported.relative_to(rcpt_ws)}")
            tn.flush_and_close()  # release lock before tempdir rmtree on Windows

        # ---- rotate (revoke the recipient we just issued to) ---------------
        tn.flush_and_close()
        tn.init(yaml_path, log_path=log_path, pool_size=4, cipher="bgw")
        cfg = tn.current_config()

        before_group = cfg.groups["default"]
        cfg = tn.admin.rotate("default", revoke_did=recipient_did)
        after_group = cfg.groups["default"]
        assert after_group.cipher._write_ctx is not before_group.cipher._write_ctx
        print("rotate: new BGW context in place")

        # Old slot key should NOT decrypt a newly-encrypted ciphertext
        # after rotation.
        new_ct = after_group.cipher._write_ctx.encrypt(b"post-rotation secret")
        try:
            before_group.cipher._my_slot_key.decrypt(new_ct)
        except tn.TNCryptoError:
            print("rotate: old slot key correctly fails to decrypt post-rotation data")
        else:
            raise AssertionError("old slot key unexpectedly decrypted new ciphertext")

        # Revoked key file renamed with .revoked.<ts> suffix
        revoked = list(ws.glob(".tn/tn/keys/default.*.revoked.*"))
        assert revoked, "expected .revoked.<ts> files after rotation"
        print(f"rotate: {len(revoked)} key files renamed .revoked.*")

        # Rotation chain entry should exist in the log
        entries = list(tn.read(log_path, cfg))
        rotation_entries = [
            e for e in entries if e["envelope"]["event_type"] == "tn.rotation.completed"
        ]
        assert rotation_entries, "no tn.rotation.completed entry in the log"
        print(
            f"rotate: chain entry written and verifies "
            f"(sig={rotation_entries[0]['valid']['signature']})"
        )

        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
