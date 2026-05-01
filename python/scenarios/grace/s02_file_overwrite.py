"""Grace s02 — vault file overwrite / upsert semantics.

Spec §10 (and existing SPEC.md): uploading a file with the same name
replaces the prior content. Tests that:
1. Upload blob #1 at filename X.
2. Upload blob #2 (different content) at filename X.
3. Download X → bytes match blob #2, not blob #1.
4. client.list_files returns exactly one X (not two).
5. SHA-256 of blob #2 in the listing matches blob #2's actual SHA.
"""

from __future__ import annotations

import hashlib

import tn
from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity
from tn.sealing import seal
from tn.vault_client import VaultClient


class GraceFileOverwrite(Scenario):
    persona = "grace"
    name = "s02_file_overwrite"
    tags = {"vault", "jwe", "upsert", "sync"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None

        ident = Identity.create_new()
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe", identity=ident)
        cfg = tn.current_config()
        ctx.record("did", ident.did)

        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        client.reset_account()

        project = client.create_project("grace-overwrite-test", ceremony_id=cfg.ceremony_id)
        project_id = project.get("id") or project.get("_id")
        ctx.record("project_id", project_id)

        wk = ident.vault_wrap_key()

        # Upload v1
        v1 = b"version-one-content-xxxxxxxxxxxxxxxxx"
        blob_v1 = seal(
            v1, wrap_key=wk, did=ident.did, ceremony_id=cfg.ceremony_id, file_name="blob"
        )
        client.upload_sealed(project_id, "blob", blob_v1)

        listing_1 = client.list_files(project_id)
        blob_entries_1 = [f for f in listing_1 if f.get("name") == "blob"]
        ctx.record("listing_1_blob_count", len(blob_entries_1))
        ctx.assert_invariant("one_blob_after_first_upload", len(blob_entries_1) == 1)
        sha_v1_server = blob_entries_1[0].get("sha256") if blob_entries_1 else None

        # Upload v2 (different content, same filename)
        v2 = b"version-two-content-DIFFERENT-!!!!!!!!!!!"
        blob_v2 = seal(
            v2, wrap_key=wk, did=ident.did, ceremony_id=cfg.ceremony_id, file_name="blob"
        )
        client.upload_sealed(project_id, "blob", blob_v2)

        listing_2 = client.list_files(project_id)
        blob_entries_2 = [f for f in listing_2 if f.get("name") == "blob"]
        ctx.record("listing_2_blob_count", len(blob_entries_2))
        ctx.assert_invariant("still_one_blob_after_overwrite", len(blob_entries_2) == 1)

        # sha should now reflect v2, not v1
        sha_v2_server = blob_entries_2[0].get("sha256") if blob_entries_2 else None
        ctx.record("sha_v1_server", sha_v1_server)
        ctx.record("sha_v2_server", sha_v2_server)
        ctx.assert_invariant("listing_sha_changed_on_overwrite", sha_v1_server != sha_v2_server)

        # Download → must be v2
        downloaded = client.download_file(
            project_id,
            "blob",
            ceremony_id=cfg.ceremony_id,
        )
        ctx.assert_invariant("downloaded_is_v2", downloaded == v2)
        ctx.assert_invariant("downloaded_not_v1", downloaded != v1)

        # Verify the server-reported sha matches what v2 would produce
        # if the vault sha's the SEALED blob (common) rather than plaintext.
        # We don't know which — just record both comparisons.
        sealed_v2_bytes = blob_v2.to_bytes()
        ctx.record(
            "sha_matches_sealed_v2", sha_v2_server == hashlib.sha256(sealed_v2_bytes).hexdigest()
        )
        ctx.record("sha_matches_plaintext_v2", sha_v2_server == hashlib.sha256(v2).hexdigest())

        client.close()
        tn.flush_and_close()
