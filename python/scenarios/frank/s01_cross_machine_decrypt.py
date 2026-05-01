"""Frank s01 — cross-machine decrypt.

THE central property check the user asked for:
"If I have the read file, I can read my log on another machine."

Flow:
1. Laptop A: fresh identity, fresh ceremony, link to vault, log 100 entries.
2. Laptop A: sync keystore + yaml to vault. Keep the log file locally.
3. Laptop A: "dies." We wipe its workspace entirely.
4. Laptop B: fresh workspace, but SAME identity (same mnemonic).
5. Laptop B: auth to vault, pull ceremony state down via restore.
6. Transfer the log file from A → B (simulating: user copied ndjson).
7. Laptop B: tn.read the transferred log → every entry decrypts to the
   correct plaintext written on A.

Invariants:
- restore_pulled_all_files: the restore manifest + file list match
  what A uploaded
- laptop_b_decrypts_a_log: every entry's plaintext['default']
  matches what we wrote on A
"""

from __future__ import annotations

import shutil

import tn
from scenarios._harness import Scenario, ScenarioContext
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class FrankCrossMachineDecrypt(Scenario):
    persona = "frank"
    name = "s01_cross_machine_decrypt"
    tags = {"vault", "jwe", "restore", "cross-machine"}
    needs_vault = True

    LOG_COUNT = 100

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None, "frank requires vault fixture"

        # ------------- Laptop A --------------------------------------
        laptop_a_dir = ctx.workspace.root / "laptop_a"
        laptop_a_dir.mkdir(exist_ok=True)
        a_yaml = laptop_a_dir / "tn.yaml"
        a_log = laptop_a_dir / ".tn/tn/logs" / "tn.ndjson"
        a_log.parent.mkdir(exist_ok=True)

        # Unified identity on laptop A: one mnemonic drives device_priv
        # and vault_wrap_key. Record the mnemonic so we can regenerate
        # the SAME identity on laptop B later.
        ident_a = Identity.create_new()
        a_mnemonic = ident_a._mnemonic
        ctx.record("did", ident_a.did)

        with ctx.timer("laptop_a_init_ms"):
            tn.init(a_yaml, log_path=a_log, cipher="jwe", identity=ident_a)
        cfg_a = tn.current_config()
        ceremony_id = cfg_a.ceremony_id
        assert cfg_a.device.did == ident_a.did
        ctx.record("ceremony_id", ceremony_id)

        # Inputs we'll verify round-trip decryption for on laptop B.
        inputs: list[dict] = []
        for i in range(self.LOG_COUNT):
            event = {
                "order_id": f"O{i:06d}",
                "amount": 2000 + i,
                "email": f"u{i}@frank.ex",
            }
            inputs.append(event)
            tn.info("order.created", **event)

        client = VaultClient.for_identity(ident_a, ctx.vault.base_url)
        client.reset_account()

        _wallet.link_ceremony(cfg_a, client, project_name=ceremony_id)
        project_id = cfg_a.linked_project_id
        ctx.record("project_id", project_id)

        with ctx.timer("laptop_a_sync_ms"):
            sync_res = _wallet.sync_ceremony(cfg_a, client)
        ctx.record("a_uploaded_count", len(sync_res.uploaded))
        ctx.assert_invariant(
            "a_sync_no_errors",
            len(sync_res.errors) == 0,
        )

        tn.flush_and_close()

        # Preserve laptop A's log file before "destroying" A.
        transferred_log = ctx.workspace.root / "transferred_from_a.ndjson"
        shutil.copy(a_log, transferred_log)

        # ------------- Disaster: wipe laptop A -----------------------
        shutil.rmtree(laptop_a_dir)

        # ------------- Laptop B: fresh machine, same identity --------
        laptop_b_dir = ctx.workspace.root / "laptop_b"
        laptop_b_dir.mkdir(exist_ok=True)

        # On B, the user types their mnemonic (real wallet flow:
        # `tn wallet restore --mnemonic <words>`). Identity.from_mnemonic
        # deterministically regenerates device_priv + vault_wrap_key.
        # Same words → same DID → authenticates as laptop A → same
        # wrap_key → can unseal blobs that A sealed.
        ident_b = Identity.from_mnemonic(a_mnemonic)
        assert ident_b.did == ident_a.did, "mnemonic must deterministically regenerate the same DID"

        client_b = VaultClient.for_identity(ident_b, ctx.vault.base_url)

        # Restore the project into laptop B's workspace.
        with ctx.timer("vault_restore_ms"):
            restore_res = _wallet.restore_ceremony(
                client_b,
                project_id,
                target_dir=laptop_b_dir,
            )
        ctx.record("restored_files", restore_res.files_restored)
        ctx.assert_invariant(
            "restore_no_errors",
            len(restore_res.errors) == 0,
        )
        ctx.assert_invariant(
            "restore_pulled_yaml",
            (laptop_b_dir / "tn.yaml").exists(),
        )
        ctx.assert_invariant(
            "restore_pulled_keystore",
            (laptop_b_dir / ".tn/tn/keys" / "default.jwe.mykey").exists(),
        )

        # Transfer laptop A's log file to B (simulating user copying it).
        b_log = laptop_b_dir / ".tn/tn/logs" / "tn.ndjson"
        b_log.parent.mkdir(exist_ok=True)
        shutil.copy(transferred_log, b_log)

        # ------------- Laptop B: read and decrypt --------------------
        tn.flush_and_close()
        tn.init(laptop_b_dir / "tn.yaml", log_path=b_log, cipher="jwe")
        cfg_b = tn.current_config()

        entries = list(tn.read(b_log, cfg_b, raw=True))
        ctx.record("entries_read_on_b", len(entries))
        ctx.assert_invariant(
            "entry_count_matches",
            len(entries) == self.LOG_COUNT,
        )

        # Round-trip: every entry's plaintext matches what A wrote.
        decryption_ok = True
        decrypted = 0
        for e in entries:
            seq = e["envelope"].get("sequence")
            pt = e["plaintext"].get("default", {})
            if seq is None or not (1 <= seq <= len(inputs)):
                decryption_ok = False
                continue
            expected = inputs[seq - 1]
            if (
                pt.get("order_id") == expected["order_id"]
                and pt.get("amount") == expected["amount"]
                and pt.get("email") == expected["email"]
            ):
                decrypted += 1
            else:
                decryption_ok = False

        ctx.record("decrypted_count", decrypted)
        ctx.assert_invariant(
            "laptop_b_decrypts_a_log",
            decryption_ok and decrypted == self.LOG_COUNT,
        )

        client.close()
        client_b.close()
        tn.flush_and_close()
