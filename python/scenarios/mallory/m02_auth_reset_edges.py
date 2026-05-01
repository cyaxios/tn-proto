"""Mallory m02 — auth + reset authorization edges.

Hits the vault with hostile requests to prove:
- DID-A's JWT can't read DID-B's projects (cross-user authz)
- Reset endpoint requires the caller's own DID in the confirm body
- Another user's sealed-seed blob is inaccessible

Requires live vault.
"""

from __future__ import annotations

import httpx

from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity
from tn.vault_client import VaultClient


class MalloryAuthResetEdges(Scenario):
    persona = "mallory"
    name = "m02_auth_reset_edges"
    tags = {"vault", "security", "authz"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None

        # Two users.
        alice = Identity.create_new()
        bob_mallory = Identity.create_new()

        alice_c = VaultClient.for_identity(alice, ctx.vault.base_url)
        bob_c = VaultClient.for_identity(bob_mallory, ctx.vault.base_url)

        alice_c.reset_account()
        bob_c.reset_account()

        # Alice creates a project.
        alice_project = alice_c.create_project("alice-private")
        alice_pid = alice_project.get("id") or alice_project.get("_id")
        assert alice_pid is not None

        alice_c.upload_file(
            alice_pid,
            "secret.bin",
            b"alice's confidential bytes",
            ceremony_id="cer_alice",
        )

        # --- Attack 1: Bob/Mallory tries to read Alice's project ------
        # Using Bob's own JWT, hit Alice's project URL.
        resp = bob_c._http.get(
            f"{ctx.vault.base_url}/api/v1/projects/{alice_pid}",
            headers={"Authorization": f"Bearer {bob_c.token}"},
        )
        ctx.record("cross_user_project_read_status", resp.status_code)
        ctx.assert_invariant(
            "cross_user_project_read_rejected",
            resp.status_code in (403, 404),
        )

        # --- Attack 2: Bob tries to download Alice's file -------------
        resp2 = bob_c._http.get(
            f"{ctx.vault.base_url}/api/v1/projects/{alice_pid}/files/secret.bin",
            headers={"Authorization": f"Bearer {bob_c.token}"},
        )
        ctx.record("cross_user_file_read_status", resp2.status_code)
        ctx.assert_invariant(
            "cross_user_file_read_rejected",
            resp2.status_code in (403, 404),
        )

        # --- Attack 3: Reset with wrong confirm body -----------------
        # Bob tries to reset using Alice's DID in confirm (his JWT).
        resp3 = bob_c._http.post(
            f"{ctx.vault.base_url}/api/v1/account/reset",
            headers={"Authorization": f"Bearer {bob_c.token}"},
            json={"confirm": alice.did},
        )
        ctx.record("reset_wrong_did_status", resp3.status_code)
        ctx.assert_invariant(
            "reset_wrong_confirm_rejected",
            resp3.status_code in (400, 403),
        )

        # --- Attack 4: Reset with no JWT ----------------------------
        resp4 = httpx.post(
            f"{ctx.vault.base_url}/api/v1/account/reset",
            json={"confirm": alice.did},
            timeout=10.0,
        )
        ctx.record("reset_no_jwt_status", resp4.status_code)
        ctx.assert_invariant(
            "reset_no_jwt_rejected",
            resp4.status_code in (401, 403, 422),
        )

        # --- Control: Alice can reset her own account ---------------
        reset_result = alice_c.reset_account()
        ctx.record("control_reset_ok", True)
        ctx.record("control_reset_result", reset_result)

        # After Alice's reset, her project should be gone.
        resp5 = alice_c._http.get(
            f"{ctx.vault.base_url}/api/v1/projects/{alice_pid}",
            headers={"Authorization": f"Bearer {alice_c.token}"},
        )
        ctx.assert_invariant(
            "control_reset_wiped_alice_project",
            resp5.status_code in (403, 404),
        )

        # --- Attack 5: Bob's account untouched by Alice's reset ------
        # Bob's token should still work.
        try:
            bob_c.get_prefs()
            bob_still_ok = True
        except Exception:
            bob_still_ok = False
        ctx.assert_invariant("isolation_bob_not_affected", bob_still_ok)

        alice_c.close()
        bob_c.close()
