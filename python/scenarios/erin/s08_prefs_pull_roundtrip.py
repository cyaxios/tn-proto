"""Erin s08 — Prefs pull round-trip: set → pull → cache → reload.

Spec §12.2 row: erin/s08_prefs_pull_roundtrip
  Property tested here: prefs round-trip (set → pull → cache → reload).
  The "auto-link new ceremonies based on preference" logic isn't wired
  in V1, so we only verify the preference was pulled and persisted as a
  scalar. A V1 new ceremony is still mode=local regardless of the cached
  pref — we note that too (spec §7.2 note).

Steps:
1.  Fresh mnemonic identity. Persist it to a temp identity.json.
    Record prefs_version_before (should be 0 for a new identity).
2.  Authenticate to vault + reset.
3.  Set account prefs via client.put_prefs("linked")
    (simulating the user setting it on the web console).
4.  Run `tn wallet pull-prefs` via cli.main([...]) with TN_IDENTITY_DIR
    overridden to point at our temp identity file.
5.  Reload Identity.load(path) → assert prefs.default_new_ceremony_mode == "linked".
    Record prefs_version_after. Assert prefs_version_after > prefs_version_before.
6.  Create a NEW ceremony with tn.init(new_yaml, identity=reloaded) →
    V1 still produces mode=local (auto-link is a V2 feature). Note only.
"""

from __future__ import annotations

import os

from scenarios._harness import Scenario, ScenarioContext
from scenarios._harness.vault import vault_fixture  # noqa: F401
from tn.cli import main as cli_main
from tn.identity import Identity
from tn.vault_client import VaultClient


class ErinPrefsPullRoundtrip(Scenario):
    persona = "erin"
    name = "s08_prefs_pull_roundtrip"
    tags = {"vault", "prefs", "pull-prefs", "identity"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None, "erin s08 requires vault fixture"

        # 1. Fresh mnemonic identity — persisted to a controlled path
        ident = Identity.create_new()
        ctx.record("did", ident.did)

        # Write identity.json under our temp workspace so TN_IDENTITY_DIR
        # can point at it without touching the user's real identity file.
        identity_dir = ctx.workspace.root / "identity_home"
        identity_dir.mkdir(parents=True, exist_ok=True)
        identity_path = identity_dir / "identity.json"
        ident.linked_vault = ctx.vault.base_url
        ident.ensure_written(identity_path)
        ctx.record("identity_path", str(identity_path))

        # Record prefs_version BEFORE the pull (new identity → 0)
        prefs_version_before = ident.prefs_version
        ctx.record("prefs_version_before", prefs_version_before)

        # 2. Authenticate to vault + reset
        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        reset = client.reset_account()
        ctx.record("reset_result", reset)

        # 3. Set account prefs to "linked" (as if the user did it on the
        #    web console or via client.put_prefs directly).
        with ctx.timer("put_prefs_ms"):
            put_result = client.put_prefs("linked")
        ctx.record("put_prefs_result", put_result)
        ctx.record("prefs_version_from_put", put_result.get("prefs_version"))

        # Confirm the vault now reports mode=linked
        server_prefs = client.get_prefs()
        ctx.assert_invariant(
            "server_prefs_is_linked",
            server_prefs.get("default_new_ceremony_mode") == "linked",
        )
        client.close()

        # 4. Run `tn wallet pull-prefs` via the CLI with TN_IDENTITY_DIR
        #    overridden so it reads/writes OUR identity.json (not the
        #    developer's real one).
        env_backup = os.environ.get("TN_IDENTITY_DIR")
        os.environ["TN_IDENTITY_DIR"] = str(identity_dir)
        try:
            with ctx.timer("pull_prefs_cli_ms"):
                exit_code = cli_main(
                    ["wallet", "pull-prefs", "--vault", ctx.vault.base_url],
                )
        finally:
            if env_backup is None:
                os.environ.pop("TN_IDENTITY_DIR", None)
            else:
                os.environ["TN_IDENTITY_DIR"] = env_backup

        ctx.record("pull_prefs_exit_code", exit_code)
        ctx.assert_invariant("pull_prefs_exit_ok", exit_code == 0)

        # 5. Reload Identity from disk → assert prefs updated
        reloaded = Identity.load(identity_path)
        ctx.record(
            "reloaded_default_mode",
            reloaded.prefs.default_new_ceremony_mode,
        )
        prefs_version_after = reloaded.prefs_version
        ctx.record("prefs_version_after", prefs_version_after)
        ctx.assert_invariant(
            "prefs_updated_to_linked",
            reloaded.prefs.default_new_ceremony_mode == "linked",
        )
        ctx.assert_invariant(
            "prefs_version_incremented",
            prefs_version_after > prefs_version_before,
        )

        # Note: V1 does NOT auto-link new ceremonies from prefs. That is a V2
        # feature. We do not assert it here per spec §7.2. The pull-and-cache
        # round-trip (steps 1–5) is the scope of this scenario.
        ctx.note(
            "prefs pull-and-cache round-trip complete. "
            f"prefs_version {prefs_version_before} → {prefs_version_after}"
        )
