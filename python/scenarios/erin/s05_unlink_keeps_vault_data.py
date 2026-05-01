"""Erin s05 — Unlink a ceremony; vault data is preserved.

Spec §12.2 row: erin/s05_unlink_keeps_vault
  Property: Linked ceremony → tn wallet unlink → yaml back to mode=local,
  vault data untouched. Then re-link: idempotent or creates new.

Steps:
1.  Fresh mnemonic identity.
2.  tn.init → local ceremony. Authenticate + reset vault.
3.  Link + sync.
4.  Capture linked_project_id.
5.  Call tn.admin.set_link_state(cfg, mode="local") — simulate unlink.
6.  Assert cfg.is_linked() False, yaml shows mode=local,
    linked_vault + linked_project_id removed from yaml.
7.  Vault still has the project (verify via client.get_project) —
    unlink must NOT delete vault-side data.
8.  Re-link to the same vault: should succeed, document whether
    project_id is same or new.
"""

from __future__ import annotations

import tn
import tn.admin
from scenarios._harness import Scenario, ScenarioContext
from scenarios._harness.vault import vault_fixture  # noqa: F401
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class ErinUnlinkKeepsVaultData(Scenario):
    persona = "erin"
    name = "s05_unlink_keeps_vault_data"
    tags = {"vault", "jwe", "link", "unlink"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None, "erin s05 requires vault fixture"

        # 1. Fresh mnemonic identity
        ident = Identity.create_new()
        ctx.record("did", ident.did)

        # 2. tn.init → local ceremony. Authenticate + reset vault.
        tn.init(
            ctx.yaml_path,
            log_path=ctx.log_path,
            cipher="jwe",
            identity=ident,
        )
        cfg = tn.current_config()
        ctx.assert_invariant("initially_local", not cfg.is_linked())

        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        client.reset_account()

        # 3. Link + sync
        with ctx.timer("link_ms"):
            _wallet.link_ceremony(cfg, client, project_name=cfg.ceremony_id)

        with ctx.timer("sync_ms"):
            sync_result = _wallet.sync_ceremony(cfg, client)

        ctx.record("sync_uploaded", len(sync_result.uploaded))
        ctx.assert_invariant("sync_ok", len(sync_result.errors) == 0)

        # 4. Capture linked_project_id before unlink
        project_id_before = cfg.linked_project_id
        ctx.record("project_id_before_unlink", project_id_before)
        ctx.assert_invariant("project_id_exists", bool(project_id_before))

        # 5. Unlink: flip mode back to local
        with ctx.timer("unlink_ms"):
            tn.admin.set_link_state(cfg, mode="local")

        # 6. Assert local state
        ctx.assert_invariant("cfg_is_unlinked", not cfg.is_linked())
        ctx.assert_invariant("cfg_mode_local", cfg.mode == "local")
        ctx.assert_invariant("cfg_linked_vault_cleared", cfg.linked_vault is None)
        ctx.assert_invariant("cfg_project_id_cleared", cfg.linked_project_id is None)

        # Verify the yaml on disk reflects the unlink
        import yaml as _yaml

        doc = _yaml.safe_load(ctx.yaml_path.read_text(encoding="utf-8")) or {}
        ceremony_block = doc.get("ceremony", {})
        ctx.assert_invariant(
            "yaml_on_disk_mode_local",
            ceremony_block.get("mode") == "local",
        )
        ctx.assert_invariant(
            "yaml_linked_vault_removed",
            "linked_vault" not in ceremony_block,
        )
        ctx.assert_invariant(
            "yaml_project_id_removed",
            "linked_project_id" not in ceremony_block,
        )

        # 7. Vault still has the project — unlink is client-only
        with ctx.timer("get_project_after_unlink_ms"):
            project = client.get_project(project_id_before)

        ctx.record("vault_project_still_exists", True)
        ctx.assert_invariant(
            "vault_project_intact",
            bool(project.get("id") or project.get("_id")),
        )

        # 8. Re-link to same vault
        with ctx.timer("relink_ms"):
            _wallet.link_ceremony(cfg, client, project_name=cfg.ceremony_id)

        ctx.assert_invariant("relinked_is_linked", cfg.is_linked())
        project_id_after = cfg.linked_project_id
        ctx.record("project_id_after_relink", project_id_after)

        # Document whether re-link reuses the same project or creates a new one.
        # V1 implementation creates a new project each time link_ceremony is called
        # (there is no "find by ceremony_id" lookup yet). Both outcomes are valid
        # for V1; we record the observation rather than assert either way.
        same_project = project_id_before == project_id_after
        ctx.record("relink_same_project_id", same_project)
        ctx.note(
            f"re-link same_project={same_project}: "
            f"before={project_id_before}, after={project_id_after}",
        )

        # Either way, the ceremony must be linked and have a valid project_id
        ctx.assert_invariant(
            "relink_project_id_valid",
            bool(project_id_after),
        )

        client.close()
        tn.flush_and_close()
