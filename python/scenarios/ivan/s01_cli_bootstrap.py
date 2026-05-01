"""Ivan s01 — full CLI bootstrap + roundtrip.

Drives the tn init + tn wallet * verbs end-to-end against a live
vault. Unique from Erin/Frank in that it goes through the CLI
argparse surface (the actual user experience), not the Python API.

Flow:
1. TN_IDENTITY_DIR points at a scratch dir.
2. tn.cli.main(['init', <project>, --mnemonic-file ...]) — scaffold
3. tn.cli.main(['wallet', 'status', ...]) — reports identity + local
4. tn.cli.main(['wallet', 'link', ...]) — creates vault project, uploads
5. tn.cli.main(['wallet', 'sync', ...]) — force-push works twice (idempotent)
6. Point TN_IDENTITY_DIR at a different dir, simulate fresh machine
7. tn.cli.main(['wallet', 'restore', '--mnemonic', ...]) — pulls identity
   + ceremonies into a restored dir
8. Verify the restored yaml + keystore match what the original wrote
9. tn.init() the restored ceremony and confirm it loads and logs work
"""

from __future__ import annotations

import hashlib
import os

from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity


class IvanCLIBootstrap(Scenario):
    persona = "ivan"
    name = "s01_cli_bootstrap"
    tags = {"cli", "jwe", "identity", "wallet"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None

        from tn import cli as _cli

        # --- 1. Fresh identity home (TN_IDENTITY_DIR override) ------
        xdg_a = ctx.workspace.root / "xdg_a"
        os.environ["TN_IDENTITY_DIR"] = str(xdg_a)

        # Pre-generate a mnemonic we control so we can drive
        # --mnemonic-file (non-interactive, bypasses TTY prompt).
        seed_ident = Identity.create_new()
        mnemonic = seed_ident._mnemonic
        assert mnemonic is not None
        mfile = ctx.workspace.root / "mnemonic.txt"
        mfile.write_text(mnemonic, encoding="utf-8")

        proj_dir = ctx.workspace.root / "my_app"

        # --- 2. tn init ----------------------------------------------
        with ctx.timer("cli_init_ms"):
            rc = _cli.main(
                [
                    "init",
                    str(proj_dir),
                    "--mnemonic-file",
                    str(mfile),
                    "--skip-confirm",
                ]
            )
        ctx.assert_invariant("init_rc_zero", rc == 0)
        ctx.assert_invariant(
            "identity_json_created",
            (xdg_a / "identity.json").exists(),
        )
        ctx.assert_invariant(
            "ceremony_yaml_created",
            (proj_dir / "tn.yaml").exists(),
        )
        ctx.assert_invariant(
            "keystore_populated",
            (proj_dir / ".tn/tn/keys" / "default.jwe.sender").exists(),
        )

        # --- 3. tn wallet status -------------------------------------
        rc = _cli.main(["wallet", "status", str(proj_dir / "tn.yaml")])
        ctx.assert_invariant("status_rc_zero", rc == 0)

        # --- 4. tn wallet link --------------------------------------
        with ctx.timer("cli_link_ms"):
            rc = _cli.main(
                [
                    "wallet",
                    "link",
                    str(proj_dir / "tn.yaml"),
                    "--vault",
                    ctx.vault.base_url,
                ]
            )
        ctx.assert_invariant("link_rc_zero", rc == 0)

        # identity.json should now carry the linked vault URL
        ident_after_link = Identity.load(xdg_a / "identity.json")
        ctx.assert_invariant(
            "identity_cached_vault_url",
            ident_after_link.linked_vault == ctx.vault.base_url,
        )

        # --- 5. tn wallet sync (idempotent — run twice) --------------
        rc1 = _cli.main(["wallet", "sync", str(proj_dir / "tn.yaml")])
        rc2 = _cli.main(["wallet", "sync", str(proj_dir / "tn.yaml")])
        ctx.assert_invariant("sync_both_rc_zero", rc1 == 0 and rc2 == 0)

        # --- 6. Simulate fresh machine: new TN_IDENTITY_DIR ---------
        xdg_b = ctx.workspace.root / "xdg_b"
        os.environ["TN_IDENTITY_DIR"] = str(xdg_b)
        restore_dir = ctx.workspace.root / "restored"

        # --- 7. tn wallet restore -----------------------------------
        with ctx.timer("cli_restore_ms"):
            rc = _cli.main(
                [
                    "wallet",
                    "restore",
                    "--mnemonic",
                    mnemonic,
                    "--vault",
                    ctx.vault.base_url,
                    "--all-projects",
                    "--out-dir",
                    str(restore_dir),
                    "--force",
                ]
            )
        ctx.assert_invariant("restore_rc_zero", rc == 0)
        ctx.assert_invariant(
            "restored_identity_written",
            (xdg_b / "identity.json").exists(),
        )

        # --- 8. Verify restored state matches original ---------------
        restored_yamls = list(restore_dir.rglob("tn.yaml"))
        ctx.assert_invariant(
            "restored_one_ceremony",
            len(restored_yamls) == 1,
        )
        if restored_yamls:
            restored_dir = restored_yamls[0].parent
            # Every key file that A wrote should be in B with matching content.
            missing = []
            mismatches = []
            for src in sorted((proj_dir / ".tn/tn/keys").iterdir()):
                if not src.is_file():
                    continue
                dst = restored_dir / ".tn/tn/keys" / src.name
                if not dst.exists():
                    missing.append(src.name)
                    continue
                if (
                    hashlib.sha256(src.read_bytes()).hexdigest()
                    != hashlib.sha256(dst.read_bytes()).hexdigest()
                ):
                    mismatches.append(src.name)
            ctx.record("restored_missing", missing)
            ctx.record("restored_mismatches", mismatches)
            ctx.assert_invariant("all_keys_restored", not missing)
            ctx.assert_invariant("all_keys_match_original", not mismatches)

            # Tn.yaml content identical too
            yaml_match = (
                hashlib.sha256((proj_dir / "tn.yaml").read_bytes()).hexdigest()
                == hashlib.sha256(restored_yamls[0].read_bytes()).hexdigest()
            )
            ctx.assert_invariant("yaml_content_match", yaml_match)

        # --- 9. tn.init the restored ceremony and confirm it works ---
        if restored_yamls:
            import tn

            tn.flush_and_close()
            restored_ident = Identity.load(xdg_b / "identity.json")
            tn.init(
                restored_yamls[0],
                log_path=restored_yamls[0].parent / ".tn/tn/logs" / "tn.ndjson",
                cipher="jwe",
                identity=restored_ident,
            )
            tn.info("post.restore", marker="ok")
            tn.flush_and_close()

            # Re-open and read
            tn.init(
                restored_yamls[0],
                log_path=restored_yamls[0].parent / ".tn/tn/logs" / "tn.ndjson",
                cipher="jwe",
                identity=restored_ident,
            )
            cfg_b = tn.current_config()
            log_path = restored_yamls[0].parent / ".tn/tn/logs" / "tn.ndjson"
            entries = list(tn.read(log_path, cfg_b, raw=True))
            ctx.record("post_restore_entries", len(entries))
            ctx.assert_invariant("post_restore_entries_read", len(entries) == 1)
            if entries:
                pt = entries[0]["plaintext"].get("default", {})
                ctx.assert_invariant(
                    "post_restore_plaintext_ok",
                    pt.get("marker") == "ok",
                )
            tn.flush_and_close()
