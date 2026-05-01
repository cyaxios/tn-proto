"""Erin s04 — Link a pre-existing local ceremony after-the-fact.

Spec §12.2 row: erin/s04_link_existing_ceremony
  Property: Create local ceremony → tn wallet link <yaml> → yaml flips to
  mode=linked, initial upload.

Steps:
1.  Fresh mnemonic identity.
2.  tn.init() → local-only ceremony auto-created.
3.  Write 20 log entries so the keystore has real state.
4.  Authenticate to vault + reset (clean slate).
5.  Call wallet.link_ceremony(cfg, client) AFTER the fact.
6.  Assert cfg.is_linked() True, yaml reflects mode=linked.
7.  sync_ceremony: uploads all current keystore files + tn.yaml.
8.  Assert logs written PRE-link stay readable after link
    (keys must not have changed under us).
"""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext
from scenarios._harness.vault import vault_fixture  # noqa: F401
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class ErinLinkExistingCeremony(Scenario):
    persona = "erin"
    name = "s04_link_existing_ceremony"
    tags = {"vault", "jwe", "link", "post-hoc"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None, "erin s04 requires vault fixture"

        # 1. Fresh mnemonic identity
        ident = Identity.create_new()
        ctx.record("did", ident.did)

        # 2. tn.init — auto-creates a local ceremony (no vault contact)
        with ctx.timer("tn_init_ms"):
            tn.init(
                ctx.yaml_path,
                log_path=ctx.log_path,
                cipher="jwe",
                identity=ident,
            )
        cfg = tn.current_config()
        ctx.assert_invariant("initially_local", not cfg.is_linked())

        # 3. Write 20 log entries PRE-link
        for i in range(20):
            tn.info("pre_link_entry", value=i, phase="pre_link")
        tn.flush_and_close()

        # Capture the raw log bytes so we can verify them after link
        pre_link_log_bytes = ctx.log_path.read_bytes()
        pre_link_entry_count = pre_link_log_bytes.count(b"\n")
        ctx.record("pre_link_entries", pre_link_entry_count)

        # Re-open the ceremony for the vault operations
        tn.init(
            ctx.yaml_path,
            log_path=ctx.log_path,
            cipher="jwe",
            identity=ident,
        )
        cfg = tn.current_config()

        # 4. Authenticate to vault + reset
        with ctx.timer("vault_auth_ms"):
            client = VaultClient.for_identity(ident, ctx.vault.base_url)
        reset = client.reset_account()
        ctx.record("reset_result", reset)

        # 5. Link the ceremony AFTER the fact
        with ctx.timer("link_ms"):
            _wallet.link_ceremony(cfg, client, project_name=cfg.ceremony_id)

        # 6. Assert cfg.is_linked() True, yaml reflects mode=linked
        ctx.assert_invariant("ceremony_is_linked", cfg.is_linked())
        ctx.assert_invariant(
            "yaml_mode_is_linked",
            cfg.mode == "linked",
        )
        ctx.assert_invariant(
            "linked_vault_set",
            cfg.linked_vault == ctx.vault.base_url,
        )
        ctx.assert_invariant(
            "linked_project_id_set",
            bool(cfg.linked_project_id),
        )
        ctx.record("linked_project_id", cfg.linked_project_id)

        # Verify the yaml on disk also shows mode=linked
        import yaml as _yaml

        doc = _yaml.safe_load(ctx.yaml_path.read_text(encoding="utf-8")) or {}
        ceremony_block = doc.get("ceremony", {})
        ctx.assert_invariant(
            "yaml_on_disk_mode_linked",
            ceremony_block.get("mode") == "linked",
        )

        # 7. sync_ceremony: upload all keystore files + tn.yaml
        with ctx.timer("sync_ms"):
            sync_result = _wallet.sync_ceremony(cfg, client)

        ctx.record("uploaded_count", len(sync_result.uploaded))
        ctx.record("uploaded_names", sync_result.uploaded)
        ctx.record("sync_errors", [f"{n}: {m}" for n, m in sync_result.errors])
        ctx.assert_invariant("sync_no_errors", len(sync_result.errors) == 0)
        ctx.assert_invariant("sync_uploaded_positive", len(sync_result.uploaded) > 0)

        # tn.yaml must be among the uploaded files
        ctx.assert_invariant(
            "yaml_in_uploaded",
            "tn.yaml" in sync_result.uploaded,
        )

        # 8. PRE-link log entries stay readable after link (keys unchanged)
        # Re-read the log file and verify entry count is identical to
        # what we wrote before the link (log file is untouched).
        post_link_log_bytes = ctx.log_path.read_bytes()
        ctx.assert_invariant(
            "pre_link_logs_intact",
            post_link_log_bytes == pre_link_log_bytes,
        )

        # Decrypt entries using the current (unchanged) keys
        tn.flush_and_close()
        tn.init(
            ctx.yaml_path,
            log_path=ctx.log_path,
            cipher="jwe",
            identity=ident,
        )
        cfg2 = tn.current_config()
        decrypted_entries = list(tn.read(ctx.log_path, cfg2, raw=True))
        ctx.record("decrypted_entry_count", len(decrypted_entries))
        ctx.assert_invariant(
            "pre_link_entries_decryptable",
            len(decrypted_entries) >= 20,
        )

        client.close()
        tn.flush_and_close()
