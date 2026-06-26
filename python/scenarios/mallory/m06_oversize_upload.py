"""Mallory m06 — oversize upload must be rejected.

Spec: vault enforces a max file size. Per tnproto-org/src/config.py
MAX_FILE_SIZE defaults to 65536 (64 KB). This scenario probes that
limit with payloads at, just above, and well above.

Legitimate sealed blobs are generally under 2 KB (JWE keys + metadata),
so a 64 KB cap is generous but finite. An attacker wanting to exhaust
the vault's disk / bandwidth shouldn't be able to upload arbitrarily
large "sealed blobs."
"""

from __future__ import annotations

from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity
from tn.vault_client import VaultClient


class MalloryOversizeUpload(Scenario):
    persona = "mallory"
    name = "m06_oversize_upload"
    tags = {"vault", "security", "upload"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None
        base = ctx.vault.base_url

        ident = Identity.create_new()
        client = VaultClient.for_identity(ident, base)
        client.reset_account()

        proj = client.create_project("m06-oversize")
        pid = proj.get("id") or proj.get("_id")
        ctx.record("project_id", pid)

        def put(name: str, size: int) -> int:
            resp = client._http.put(
                f"{base}/api/v1/projects/{pid}/files/{name}",
                headers={
                    "Authorization": f"Bearer {client.token}",
                    "Content-Type": "application/octet-stream",
                },
                content=b"A" * size,
            )
            return resp.status_code

        # Small — should succeed
        s_small = put("small.bin", 1024)
        ctx.record("small_1k_status", s_small)
        ctx.assert_invariant("small_upload_accepted", 200 <= s_small < 300)

        # Exactly at limit — should succeed (boundary check)
        s_at = put("at_limit.bin", 65536)
        ctx.record("at_limit_64k_status", s_at)
        ctx.assert_invariant(
            "at_limit_accepted_or_rejected_cleanly", s_at in (200, 201, 204, 413, 400, 422)
        )

        # Just over limit — must be rejected
        s_over = put("over_limit.bin", 65537)
        ctx.record("over_limit_64k_plus_1_status", s_over)
        ctx.assert_invariant("over_limit_rejected", s_over in (400, 413, 422))

        # Well over limit — must be rejected, must not OOM the vault
        s_huge = put("huge.bin", 1024 * 1024)  # 1 MB
        ctx.record("huge_1m_status", s_huge)
        ctx.assert_invariant("huge_rejected", s_huge in (400, 413, 422))

        # Vault is still responsive after the oversize attempts
        after_listing = client.list_files(pid)
        ctx.record("files_after_attempts", len(after_listing))
        ctx.assert_invariant("vault_still_responsive", isinstance(after_listing, list))

        # Verify the oversize payloads did NOT land
        landed_names = {f.get("name") for f in after_listing}
        ctx.assert_invariant(
            "oversize_not_in_listing",
            "over_limit.bin" not in landed_names and "huge.bin" not in landed_names,
        )

        client.close()
