"""Erin s06 — Per-ceremony opt-in: link only ceremony #2 of three.

Spec §12.2 row: erin/s06_per_ceremony_opt_in
  Property: Three local ceremonies on one machine; link only ceremony B;
  A and C stay local, B uploads; vault has exactly 1 project under this DID.

Steps:
1.  Single mnemonic identity — one DID across all ceremonies.
2.  Create three local ceremonies in separate workspace dirs:
    ceremony_a, ceremony_b, ceremony_c.
3.  Authenticate to vault + reset (clean DID slate).
4.  Link ONLY ceremony_b.
5.  sync_ceremony for ceremony_b.
6.  Assert ceremony_a yaml: mode=local (untouched).
7.  Assert ceremony_b yaml: mode=linked, has project_id.
8.  Assert ceremony_c yaml: mode=local (untouched).
9.  Assert vault has exactly 1 project under this DID.
"""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext
from scenarios._harness.fixtures import make_workspace
from scenarios._harness.vault import vault_fixture  # noqa: F401
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class ErinPerCeremonyOptIn(Scenario):
    persona = "erin"
    name = "s06_per_ceremony_opt_in"
    tags = {"vault", "jwe", "link", "multi-ceremony"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None, "erin s06 requires vault fixture"

        # 1. Single mnemonic identity
        ident = Identity.create_new()
        ctx.record("did", ident.did)

        # 2. Create three local ceremonies in separate workspace dirs.
        #    We use sub-directories of the scenario's temp root.
        base = ctx.workspace.root.parent  # the TemporaryDirectory root

        ws_a = make_workspace(base, "ceremony_a")
        ws_b = make_workspace(base, "ceremony_b")
        ws_c = make_workspace(base, "ceremony_c")

        # Init ceremony A
        tn.init(ws_a.yaml_path, log_path=ws_a.logs / "tn.ndjson", cipher="jwe", identity=ident)
        cfg_a = tn.current_config()
        ctx.assert_invariant("ceremony_a_initially_local", not cfg_a.is_linked())
        cer_id_a = cfg_a.ceremony_id
        tn.flush_and_close()

        # Init ceremony B
        tn.init(ws_b.yaml_path, log_path=ws_b.logs / "tn.ndjson", cipher="jwe", identity=ident)
        cfg_b = tn.current_config()
        ctx.assert_invariant("ceremony_b_initially_local", not cfg_b.is_linked())
        cer_id_b = cfg_b.ceremony_id
        # Keep cfg_b live for the link step below; flush happens after.

        # We need to re-open C without flushing B yet — flush B first.
        tn.flush_and_close()

        tn.init(ws_c.yaml_path, log_path=ws_c.logs / "tn.ndjson", cipher="jwe", identity=ident)
        cfg_c = tn.current_config()
        ctx.assert_invariant("ceremony_c_initially_local", not cfg_c.is_linked())
        cer_id_c = cfg_c.ceremony_id
        tn.flush_and_close()

        ctx.record("ceremony_id_a", cer_id_a)
        ctx.record("ceremony_id_b", cer_id_b)
        ctx.record("ceremony_id_c", cer_id_c)

        # All three should have distinct ceremony IDs
        ctx.assert_invariant(
            "ceremony_ids_distinct",
            len({cer_id_a, cer_id_b, cer_id_c}) == 3,
        )

        # 3. Authenticate to vault + reset
        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        client.reset_account()

        # 4. Link ONLY ceremony B.  Re-open B to get a live cfg.
        tn.init(ws_b.yaml_path, log_path=ws_b.logs / "tn.ndjson", cipher="jwe", identity=ident)
        cfg_b = tn.current_config()

        with ctx.timer("link_b_ms"):
            _wallet.link_ceremony(cfg_b, client, project_name=cer_id_b)

        ctx.assert_invariant("ceremony_b_linked", cfg_b.is_linked())
        ctx.record("ceremony_b_project_id", cfg_b.linked_project_id)

        # 5. Sync ceremony B
        with ctx.timer("sync_b_ms"):
            sync_b = _wallet.sync_ceremony(cfg_b, client)
        ctx.record("sync_b_uploaded", len(sync_b.uploaded))
        ctx.assert_invariant("sync_b_no_errors", len(sync_b.errors) == 0)

        tn.flush_and_close()

        # 6 & 8. Verify ceremony A and C yamls are still mode=local (untouched).
        import yaml as _yaml

        doc_a = _yaml.safe_load(ws_a.yaml_path.read_text(encoding="utf-8")) or {}
        mode_a = (doc_a.get("ceremony") or {}).get("mode", "local")
        ctx.assert_invariant("yaml_a_still_local", mode_a == "local")
        ctx.assert_invariant(
            "yaml_a_no_linked_vault",
            "linked_vault" not in (doc_a.get("ceremony") or {}),
        )

        doc_c = _yaml.safe_load(ws_c.yaml_path.read_text(encoding="utf-8")) or {}
        mode_c = (doc_c.get("ceremony") or {}).get("mode", "local")
        ctx.assert_invariant("yaml_c_still_local", mode_c == "local")
        ctx.assert_invariant(
            "yaml_c_no_linked_vault",
            "linked_vault" not in (doc_c.get("ceremony") or {}),
        )

        # 7. Verify ceremony B yaml shows mode=linked + project_id
        doc_b = _yaml.safe_load(ws_b.yaml_path.read_text(encoding="utf-8")) or {}
        cer_b = doc_b.get("ceremony") or {}
        ctx.assert_invariant("yaml_b_mode_linked", cer_b.get("mode") == "linked")
        ctx.assert_invariant("yaml_b_has_project_id", bool(cer_b.get("linked_project_id")))

        # 9. Vault has exactly 1 project under this DID
        projects = client.list_projects()
        ctx.record("vault_project_count", len(projects))
        ctx.assert_invariant("vault_exactly_one_project", len(projects) == 1)

        client.close()
