"""Dana s01 — multi-ceremony under a single identity.

Spec §2 non-goal clarification: "the expected pattern is one ceremony
per writer-machine under a shared identity." Dana is the persona that
audits across those ceremonies.

Flow:
1. One DID (one mnemonic), two separate ceremonies in two workspace dirs.
2. Link BOTH to the same vault account.
3. Write distinct log entries to each.
4. Sync both.
5. Verify: `client.list_projects()` shows 2 projects under this DID.
6. Restore both to a third workspace (the auditor's view) and confirm
   each ceremony's log decrypts cleanly using the matching restored keys.
7. Cross-ceremony independence: entries from ceremony A do NOT appear in
   ceremony B's log, and vice versa.
"""

from __future__ import annotations

import shutil

import tn
from scenarios._harness import Scenario, ScenarioContext
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class DanaMultiCeremonyOneIdentity(Scenario):
    persona = "dana"
    name = "s01_multi_ceremony_one_identity"
    tags = {"vault", "jwe", "multi-ceremony", "audit"}
    needs_vault = True

    PER_CEREMONY_COUNT = 30

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None

        ident = Identity.create_new()
        mnemonic = ident._mnemonic
        assert mnemonic is not None
        ctx.record("did", ident.did)

        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        client.reset_account()

        # Ceremony A
        ws_a = ctx.workspace.root / "cer_a"
        ws_a.mkdir(exist_ok=True)
        a_yaml = ws_a / "tn.yaml"
        a_log = ws_a / ".tn/tn/logs" / "tn.ndjson"
        a_log.parent.mkdir(exist_ok=True)
        tn.init(a_yaml, log_path=a_log, cipher="jwe", identity=ident)
        cfg_a = tn.current_config()
        cer_a_id = cfg_a.ceremony_id
        for i in range(self.PER_CEREMONY_COUNT):
            tn.info("ceremony_a.event", idx=i, tag=f"A{i}")
        _wallet.link_ceremony(cfg_a, client, project_name=f"cer_A_{cer_a_id}")
        _wallet.sync_ceremony(cfg_a, client)
        proj_a = cfg_a.linked_project_id
        tn.flush_and_close()

        # Ceremony B — different workspace, same identity
        ws_b = ctx.workspace.root / "cer_b"
        ws_b.mkdir(exist_ok=True)
        b_yaml = ws_b / "tn.yaml"
        b_log = ws_b / ".tn/tn/logs" / "tn.ndjson"
        b_log.parent.mkdir(exist_ok=True)
        tn.init(b_yaml, log_path=b_log, cipher="jwe", identity=ident)
        cfg_b = tn.current_config()
        cer_b_id = cfg_b.ceremony_id
        for i in range(self.PER_CEREMONY_COUNT):
            tn.info("ceremony_b.event", idx=i, tag=f"B{i}")
        _wallet.link_ceremony(cfg_b, client, project_name=f"cer_B_{cer_b_id}")
        _wallet.sync_ceremony(cfg_b, client)
        proj_b = cfg_b.linked_project_id
        tn.flush_and_close()

        # The two ceremonies should be distinct
        ctx.assert_invariant("distinct_ceremony_ids", cer_a_id != cer_b_id)
        ctx.assert_invariant("distinct_project_ids", proj_a != proj_b)

        # Both projects visible under the one account
        projects = client.list_projects()
        project_ids = {p.get("id") or p.get("_id") for p in projects}
        ctx.record("projects_on_vault", len(projects))
        ctx.assert_invariant(
            "both_projects_listed",
            proj_a in project_ids and proj_b in project_ids,
        )

        # Preserve both log files before "wiping" and restoring
        trans_a = ctx.workspace.root / "transferred_a.ndjson"
        trans_b = ctx.workspace.root / "transferred_b.ndjson"
        shutil.copy(a_log, trans_a)
        shutil.copy(b_log, trans_b)

        # --- Auditor view (same mnemonic, fresh workspace) ----------
        auditor_dir = ctx.workspace.root / "auditor"
        auditor_dir.mkdir(exist_ok=True)

        ident_d = Identity.from_mnemonic(mnemonic)
        client_d = VaultClient.for_identity(ident_d, ctx.vault.base_url)

        # Restore each ceremony into its own sub-dir
        restore_a_dir = auditor_dir / "cer_a"
        restore_b_dir = auditor_dir / "cer_b"
        ra = _wallet.restore_ceremony(client_d, proj_a, target_dir=restore_a_dir)
        rb = _wallet.restore_ceremony(client_d, proj_b, target_dir=restore_b_dir)
        ctx.assert_invariant("restore_a_no_errors", not ra.errors)
        ctx.assert_invariant("restore_b_no_errors", not rb.errors)

        # Copy the preserved logs into place
        (restore_a_dir / ".tn/tn/logs").mkdir(exist_ok=True)
        (restore_b_dir / ".tn/tn/logs").mkdir(exist_ok=True)
        shutil.copy(trans_a, restore_a_dir / ".tn/tn/logs" / "tn.ndjson")
        shutil.copy(trans_b, restore_b_dir / ".tn/tn/logs" / "tn.ndjson")

        # Read ceremony A with ceremony A's restored state
        tn.init(
            restore_a_dir / "tn.yaml",
            log_path=restore_a_dir / ".tn/tn/logs" / "tn.ndjson",
            cipher="jwe",
            identity=ident_d,
        )
        cfg_ra = tn.current_config()
        entries_a = list(tn.read(restore_a_dir / ".tn/tn/logs" / "tn.ndjson", cfg_ra, raw=True))
        a_event_types = {e["envelope"]["event_type"] for e in entries_a}
        a_correct = sum(
            1
            for e in entries_a
            if e["envelope"]["event_type"] == "ceremony_a.event"
            and e["plaintext"].get("default", {}).get("tag", "").startswith("A")
        )
        ctx.record("a_entries_decrypted", a_correct)
        ctx.assert_invariant("a_all_entries_decrypt", a_correct == self.PER_CEREMONY_COUNT)
        ctx.assert_invariant(
            "a_has_only_a_events",
            "ceremony_b.event" not in a_event_types,
        )
        tn.flush_and_close()

        # Read ceremony B with ceremony B's restored state
        tn.init(
            restore_b_dir / "tn.yaml",
            log_path=restore_b_dir / ".tn/tn/logs" / "tn.ndjson",
            cipher="jwe",
            identity=ident_d,
        )
        cfg_rb = tn.current_config()
        entries_b = list(tn.read(restore_b_dir / ".tn/tn/logs" / "tn.ndjson", cfg_rb, raw=True))
        b_event_types = {e["envelope"]["event_type"] for e in entries_b}
        b_correct = sum(
            1
            for e in entries_b
            if e["envelope"]["event_type"] == "ceremony_b.event"
            and e["plaintext"].get("default", {}).get("tag", "").startswith("B")
        )
        ctx.record("b_entries_decrypted", b_correct)
        ctx.assert_invariant("b_all_entries_decrypt", b_correct == self.PER_CEREMONY_COUNT)
        ctx.assert_invariant(
            "b_has_only_b_events",
            "ceremony_a.event" not in b_event_types,
        )
        tn.flush_and_close()

        client.close()
        client_d.close()
