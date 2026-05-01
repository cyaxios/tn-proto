"""Erin s01 — Full link + upload flow end-to-end.

This is the proving scenario for the wallet link story:

1. Fresh identity (mnemonic-derived device key)
2. Fresh local ceremony (tn.init auto-creates)
3. Authenticate to the vault (DID challenge-response, Ed25519)
4. Reset account state (clean slate for the test)
5. Link the ceremony (create vault project, flip yaml to mode=linked)
6. Sync (seal + upload every key file + tn.yaml)
7. Verify each uploaded file lands as sealed ciphertext
   (the vault cannot see plaintext keys)
8. Download one file back, unseal, verify AAD + content
"""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext
from scenarios._harness.vault import vault_fixture  # noqa: F401
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class ErinLinkAndUpload(Scenario):
    persona = "erin"
    name = "s01_link_and_upload"
    tags = {"vault", "jwe", "link", "upload"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None, "erin requires vault fixture"

        # 1. Unified identity: one mnemonic → device_priv + vault_wrap_key.
        ident = Identity.create_new()
        ctx.record("did", ident.did)
        with ctx.timer("tn_init_ms"):
            tn.init(
                ctx.yaml_path,
                log_path=ctx.log_path,
                cipher="jwe",
                identity=ident,
            )
        cfg = tn.current_config()
        assert cfg.device.did == ident.did, "DID should match unified identity"

        # 2. Authenticate to vault
        with ctx.timer("vault_auth_ms"):
            client = VaultClient.for_identity(ident, ctx.vault.base_url)

        # 3. Reset account (clean slate)
        reset = client.reset_account()
        ctx.record("reset_result", reset)

        # 4. Link the ceremony
        with ctx.timer("link_ms"):
            _wallet.link_ceremony(cfg, client, project_name=cfg.ceremony_id)

        ctx.assert_invariant("ceremony_is_linked", cfg.is_linked())
        ctx.record("linked_vault", cfg.linked_vault)
        ctx.record("linked_project_id", cfg.linked_project_id)

        # 5. Sync (seal + upload every key file + tn.yaml)
        with ctx.timer("vault_sync_ms"):
            result = _wallet.sync_ceremony(cfg, client)

        ctx.record("uploaded_count", len(result.uploaded))
        ctx.record("uploaded_names", result.uploaded)
        ctx.record("sync_errors", [f"{n}: {m}" for n, m in result.errors])
        ctx.assert_invariant("sync_no_errors", len(result.errors) == 0)
        ctx.assert_invariant("sync_uploaded_positive", len(result.uploaded) > 0)

        # 6. Verify vault stores only ciphertext. AAD is public metadata
        # (ceremony_id + did + file_name) — we check that actual *content*
        # bytes from tn.yaml don't leak. The yaml has "cipher: jwe" which
        # appears in the plaintext body but not in any AAD.
        raw_yaml_plaintext = ctx.yaml_path.read_bytes()
        sealed_yaml = client.download_sealed(cfg.linked_project_id, "tn.yaml")
        sealed_wire = sealed_yaml.to_bytes()
        ctx.record("sealed_yaml_bytes", len(sealed_wire))
        # "cipher: jwe" is content, not AAD. Must be ciphertext'd.
        content_probe = b"cipher: jwe"
        assert content_probe in raw_yaml_plaintext, "probe string missing from source yaml"
        no_content_in_sealed = content_probe not in sealed_wire
        ctx.assert_invariant("vault_returns_encrypted_only", no_content_in_sealed)

        # 7. Round-trip: download + unseal + compare
        unsealed = client.download_file(
            cfg.linked_project_id,
            "tn.yaml",
            ceremony_id=cfg.ceremony_id,
        )
        ctx.assert_invariant(
            "yaml_roundtrip_matches",
            unsealed == raw_yaml_plaintext,
        )

        client.close()
        tn.flush_and_close()
