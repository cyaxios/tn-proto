"""Grace s03 — end-to-end log sync (ceremony.sync_logs = true).

Spec §9.4 option B: if the ceremony yaml sets `sync_logs: true`,
wallet.sync_ceremony uploads log files alongside keys + yaml. This
scenario verifies the flag actually wires through:

1. Alice inits linked ceremony.
2. Alice explicitly flips `ceremony.sync_logs: true` in the yaml
   (and re-loads cfg so the flag is live).
3. Alice writes 25 log entries.
4. sync_ceremony — uploaded file list must include `logs__tn.ndjson`.
5. Download the sealed log blob from the vault, unseal locally with
   the same wrap key, verify the bytes equal the local ndjson file.
6. Negative control: flip sync_logs=false on a SECOND ceremony,
   sync, verify NO logs__* files appear in the upload list.
"""

from __future__ import annotations

import yaml as yaml_mod

import tn
from scenarios._harness import Scenario, ScenarioContext
from tn import wallet as _wallet
from tn.identity import Identity
from tn.vault_client import VaultClient


class GraceLogSyncRoundtrip(Scenario):
    persona = "grace"
    name = "s03_log_sync_roundtrip"
    tags = {"vault", "jwe", "sync", "logs"}
    needs_vault = True

    LOG_COUNT = 25

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None

        # --- Ceremony A: sync_logs = true ---------------------------
        a_ws = ctx.workspace.root / "cer_a"
        a_ws.mkdir(exist_ok=True)
        a_yaml = a_ws / "tn.yaml"
        a_log = a_ws / ".tn/tn/logs" / "tn.ndjson"
        a_log.parent.mkdir(exist_ok=True)

        ident = Identity.create_new()
        tn.init(a_yaml, log_path=a_log, cipher="jwe", identity=ident)
        cfg_a = tn.current_config()

        # Toggle the sync_logs flag by editing the yaml and re-init'ing.
        tn.flush_and_close()
        doc = yaml_mod.safe_load(a_yaml.read_text(encoding="utf-8"))
        doc.setdefault("ceremony", {})["sync_logs"] = True
        a_yaml.write_text(yaml_mod.safe_dump(doc, sort_keys=False), encoding="utf-8")
        tn.init(a_yaml, log_path=a_log, cipher="jwe", identity=ident)
        cfg_a = tn.current_config()
        ctx.assert_invariant("flag_loaded", cfg_a.sync_logs is True)

        # Link + log + sync
        client = VaultClient.for_identity(ident, ctx.vault.base_url)
        client.reset_account()
        _wallet.link_ceremony(cfg_a, client, project_name=cfg_a.ceremony_id)

        for i in range(self.LOG_COUNT):
            tn.info("logged.evt", idx=i, payload=f"entry-{i}")
        tn.flush_and_close()

        result = _wallet.sync_ceremony(cfg_a, client)
        ctx.record("uploaded_names_a", result.uploaded)
        log_uploads = [n for n in result.uploaded if n.startswith("logs__")]
        ctx.record("log_uploads_count", len(log_uploads))
        ctx.assert_invariant(
            "log_file_was_uploaded",
            "logs__tn.ndjson" in result.uploaded,
        )
        ctx.assert_invariant(
            "no_sync_errors_a",
            not result.errors,
        )

        # Download + unseal + compare bytes
        local_log_bytes = a_log.read_bytes()
        downloaded = client.download_file(
            cfg_a.linked_project_id,
            "logs__tn.ndjson",
            ceremony_id=cfg_a.ceremony_id,
        )
        ctx.assert_invariant(
            "downloaded_log_matches_local",
            downloaded == local_log_bytes,
        )
        ctx.record("downloaded_log_bytes", len(downloaded))

        # --- Ceremony B: sync_logs = false (negative control) ------
        b_ws = ctx.workspace.root / "cer_b"
        b_ws.mkdir(exist_ok=True)
        b_yaml = b_ws / "tn.yaml"
        b_log = b_ws / ".tn/tn/logs" / "tn.ndjson"
        b_log.parent.mkdir(exist_ok=True)

        tn.init(b_yaml, log_path=b_log, cipher="jwe", identity=ident)
        cfg_b = tn.current_config()
        ctx.assert_invariant("b_flag_default_false", cfg_b.sync_logs is False)

        _wallet.link_ceremony(cfg_b, client, project_name=cfg_b.ceremony_id)
        for i in range(10):
            tn.info("skipped.evt", idx=i)
        tn.flush_and_close()

        result_b = _wallet.sync_ceremony(cfg_b, client)
        ctx.record("uploaded_names_b", result_b.uploaded)
        b_log_uploads = [n for n in result_b.uploaded if n.startswith("logs__")]
        ctx.assert_invariant(
            "b_no_logs_uploaded",
            not b_log_uploads,
        )

        client.close()
