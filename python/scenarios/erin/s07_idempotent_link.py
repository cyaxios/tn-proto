"""Erin s07 — Idempotent link: calling link_ceremony twice is a no-op.

Spec §12.2 row: erin/s07_idempotent_link
  Property: Linking an already-linked ceremony is a no-op; no duplicate
  uploads; vault still has exactly 1 project.

Steps:
1.  Fresh mnemonic identity.
2.  tn.init → local ceremony. Authenticate + reset vault.
3.  First link_ceremony call.
4.  Capture project_id from first link.
5.  Second link_ceremony call on the same cfg.
6.  Assert: no error raised.
7.  Assert: cfg.linked_project_id unchanged between calls.
8.  Assert: vault still has exactly 1 project (no duplicate created).
"""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext
from scenarios._harness.vault import vault_fixture  # noqa: F401
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class ErinIdempotentLink(Scenario):
    persona = "erin"
    name = "s07_idempotent_link"
    tags = {"vault", "jwe", "link", "idempotent"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None, "erin s07 requires vault fixture"

        # 1. Fresh mnemonic identity
        ident = Identity.create_new()
        ctx.record("did", ident.did)

        # 2. tn.init + vault reset
        tn.init(
            ctx.yaml_path,
            log_path=ctx.log_path,
            cipher="jwe",
            identity=ident,
        )
        cfg = tn.current_config()

        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        client.reset_account()

        # 3. First link
        with ctx.timer("first_link_ms"):
            _wallet.link_ceremony(cfg, client, project_name=cfg.ceremony_id)

        ctx.assert_invariant("linked_after_first_call", cfg.is_linked())
        project_id_first = cfg.linked_project_id
        ctx.record("project_id_first", project_id_first)
        ctx.assert_invariant("first_project_id_set", bool(project_id_first))

        # Verify vault state after first link
        projects_after_first = client.list_projects()
        ctx.record("projects_after_first_link", len(projects_after_first))
        ctx.assert_invariant(
            "one_project_after_first_link",
            len(projects_after_first) == 1,
        )

        # 4/5. Second link_ceremony call — must be idempotent (no error)
        second_link_error: str | None = None
        try:
            with ctx.timer("second_link_ms"):
                _wallet.link_ceremony(cfg, client, project_name=cfg.ceremony_id)
        except Exception as exc:
            second_link_error = f"{type(exc).__name__}: {exc}"

        ctx.record("second_link_error", second_link_error)
        ctx.assert_invariant("no_error_on_second_link", second_link_error is None)

        # 6. Still linked
        ctx.assert_invariant("still_linked_after_second_call", cfg.is_linked())

        # 7. project_id unchanged
        project_id_second = cfg.linked_project_id
        ctx.record("project_id_second", project_id_second)
        ctx.assert_invariant(
            "project_id_unchanged",
            project_id_first == project_id_second,
        )

        # 8. Vault still has exactly 1 project (no duplicate)
        projects_after_second = client.list_projects()
        ctx.record("projects_after_second_link", len(projects_after_second))
        ctx.assert_invariant(
            "one_project_after_second_link",
            len(projects_after_second) == 1,
        )

        client.close()
        tn.flush_and_close()
