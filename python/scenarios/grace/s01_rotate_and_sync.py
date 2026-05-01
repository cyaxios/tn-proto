"""Grace s01 — rotate + sync round-trip.

Flow:
1. Set up a linked ceremony on laptop A. Write 50 log entries.
2. Sync. Note which sealed blobs the vault is holding (by sha256).
3. Rotate the default group. New keys, new epoch.
4. Write 50 more entries under the rotated keys.
5. Sync again. Vault should now hold NEW sealed blobs for the
   rotated key files (different sha256 than before).
6. Wipe laptop A. Restore on laptop B via mnemonic.
7. On B, verify the post-rotation log entries decrypt correctly
   (the rotated keystore is the one the vault now holds).
"""

from __future__ import annotations

import hashlib
import shutil

import tn
from scenarios._harness import Scenario, ScenarioContext
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class GraceRotateAndSync(Scenario):
    persona = "grace"
    name = "s01_rotate_and_sync"
    tags = {"vault", "jwe", "rotate", "sync"}
    needs_vault = True

    PRE_COUNT = 50
    POST_COUNT = 50

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None

        # --- Laptop A: init, log, sync ------------------------------
        laptop_a = ctx.workspace.root / "laptop_a"
        laptop_a.mkdir(exist_ok=True)
        a_yaml = laptop_a / "tn.yaml"
        a_log = laptop_a / ".tn/tn/logs" / "tn.ndjson"
        a_log.parent.mkdir(exist_ok=True)

        ident = Identity.create_new()
        mnemonic = ident._mnemonic
        assert mnemonic is not None
        ctx.record("did", ident.did)

        tn.init(a_yaml, log_path=a_log, cipher="jwe", identity=ident)
        cfg = tn.current_config()
        ceremony_id = cfg.ceremony_id

        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        client.reset_account()

        _wallet.link_ceremony(cfg, client, project_name=ceremony_id)
        project_id = cfg.linked_project_id
        ctx.record("project_id", project_id)

        # --- Write first batch ---------------------------------------
        for i in range(self.PRE_COUNT):
            tn.info("pre.rotate", seq=i, payload=f"p{i}")

        # Sync initial state
        with ctx.timer("pre_sync_ms"):
            r1 = _wallet.sync_ceremony(cfg, client)
        ctx.assert_invariant("pre_sync_no_errors", not r1.errors)
        pre_sender_hash = hashlib.sha256(
            (cfg.keystore / "default.jwe.sender").read_bytes(),
        ).hexdigest()
        ctx.record("pre_sender_hash", pre_sender_hash[:16])

        # --- Rotate -------------------------------------------------
        with ctx.timer("rotate_ms"):
            tn.rotate("default")

        # sender file should have changed on disk
        post_sender_hash = hashlib.sha256(
            (cfg.keystore / "default.jwe.sender").read_bytes(),
        ).hexdigest()
        ctx.record("post_sender_hash", post_sender_hash[:16])
        ctx.assert_invariant(
            "sender_key_changed_on_rotate",
            pre_sender_hash != post_sender_hash,
        )

        # --- Write second batch (under rotated keys) ----------------
        for i in range(self.POST_COUNT):
            tn.info("post.rotate", seq=i, payload=f"q{i}")

        # Sync again — the vault should now hold the NEW sender blob.
        with ctx.timer("post_sync_ms"):
            r2 = _wallet.sync_ceremony(cfg, client)
        ctx.assert_invariant("post_sync_no_errors", not r2.errors)
        ctx.record("post_sync_uploaded_count", len(r2.uploaded))

        # Verify the vault returns a blob whose contents (after unseal)
        # match the LOCAL rotated sender file byte-for-byte.
        local_rotated_sender = (cfg.keystore / "default.jwe.sender").read_bytes()
        from_vault = client.download_file(
            project_id,
            "default.jwe.sender",
            ceremony_id=ceremony_id,
        )
        ctx.assert_invariant(
            "vault_has_rotated_sender_key",
            from_vault == local_rotated_sender,
        )

        # Preserve log file
        transferred_log = ctx.workspace.root / "transferred.ndjson"
        shutil.copy(a_log, transferred_log)

        tn.flush_and_close()
        client.close()

        # --- Wipe laptop A, restore on B ----------------------------
        shutil.rmtree(laptop_a)

        laptop_b = ctx.workspace.root / "laptop_b"
        laptop_b.mkdir(exist_ok=True)

        ident_b = Identity.from_mnemonic(mnemonic)
        client_b = VaultClient.for_identity(ident_b, ctx.vault.base_url)

        restore_res = _wallet.restore_ceremony(
            client_b,
            project_id,
            target_dir=laptop_b,
        )
        ctx.assert_invariant("restore_no_errors", not restore_res.errors)

        # Copy the log over
        b_log = laptop_b / ".tn/tn/logs" / "tn.ndjson"
        b_log.parent.mkdir(exist_ok=True)
        shutil.copy(transferred_log, b_log)

        # --- On B: read + decrypt ----------------------------------
        tn.init(laptop_b / "tn.yaml", log_path=b_log, cipher="jwe", identity=ident_b)
        cfg_b = tn.current_config()
        entries = list(tn.read(b_log, cfg_b, raw=True))
        pre = [e for e in entries if e["envelope"]["event_type"] == "pre.rotate"]
        post = [e for e in entries if e["envelope"]["event_type"] == "post.rotate"]
        ctx.record("total_entries_read", len(entries))
        ctx.record("pre_entries", len(pre))
        ctx.record("post_entries", len(post))

        # Post-rotation entries must decrypt correctly (the rotated
        # keys that were synced to vault and pulled to B can read them).
        post_decrypted = 0
        post_ok = True
        for idx, e in enumerate(post):
            pt = e["plaintext"].get("default", {})
            expected_seq = idx
            expected_payload = f"q{idx}"
            if pt.get("seq") == expected_seq and pt.get("payload") == expected_payload:
                post_decrypted += 1
            else:
                post_ok = False
        ctx.record("post_decrypted_count", post_decrypted)
        ctx.assert_invariant(
            "post_rotation_decryption_on_b",
            post_ok and post_decrypted == self.POST_COUNT,
        )

        # Pre-rotation entries: per the s02 finding, publisher loses
        # access to pre-rotate entries after a rotation. On B (which
        # restored the post-rotation state), we expect the same
        # behavior. Record it but don't gate on it.
        pre_readable = sum(
            1
            for e in pre
            if e["plaintext"].get("default", {}).get("$no_read_key") is not True
            and "seq" in e["plaintext"].get("default", {})
        )
        ctx.record("pre_rotation_readable_on_b", pre_readable)

        client_b.close()
        tn.flush_and_close()
