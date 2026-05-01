"""Example 3: my customer's email shouldn't leak just because my logs did.

Story
-----
Jamie accidentally emails a log file to a partner company. In a regular
stack that leak would expose every customer email address and IP ever
logged. With TN, Jamie had put those fields in a `pii` group, so the
partner sees timestamps, event types, and order IDs but the email/IP
ciphertexts are opaque without the `pii` reader kit.

What this shows
---------------
  - `tn.ensure_group("pii", fields=[...])` adds a group after init.
  - Logging a field routed to a group encrypts it under that group's
    key. Unrouted fields go to `default`.
  - A partner who only holds the `default` reader kit sees the envelope
    and `default` plaintext but the `pii`/`internal` groups stay opaque.

Run it
------
    python ex03_groups.py
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import tn


def main() -> int:
    if not tn.using_rust():
        print("SKIP: this example needs the tn_core Rust extension. "
              "Run tools/rebuild_pyo3.sh tn-core, then retry.")
        return 0

    with tempfile.TemporaryDirectory(prefix="jamie3_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        # 1) Start fresh with btn cipher (kit-based recipients).
        tn.init(yaml_path, cipher="btn")
        cfg = tn.current_config()

        # 2) Declare two more groups with their field mappings. Idempotent:
        #    re-running does nothing if the group is already there.
        cfg = tn.ensure_group(cfg, "pii", fields=["email", "ip", "user_agent"])
        cfg = tn.ensure_group(cfg, "internal", fields=["request_id", "debug_trace"])
        print(f"groups now defined: {sorted(cfg.groups)}")

        # Reopen so the logger picks up the new groups.
        tn.flush_and_close()
        tn.init(yaml_path, cipher="btn")

        # 3) Log one event that spans all three groups.
        tn.info(
            "page.view",
            path="/checkout",  # -> default group
            email="alice@example.com",  # -> pii
            ip="10.0.0.17",  # -> pii
            user_agent="Mozilla/5.0",  # -> pii
            request_id="req_abc123",  # -> internal
            debug_trace="cache_miss",  # -> internal
            referrer="newsletter",  # -> default (unmapped)
        )

        log_path = ws / ".tn" / "logs" / "tn.ndjson"
        tn.flush_and_close()

        # 4) Read back as PUBLISHER (all groups decrypt).
        tn.init(yaml_path, cipher="btn")
        print("\n--- as publisher (hold every group's keys) ---")
        for raw in tn.read_raw():
            if raw["envelope"].get("event_type", "").startswith("tn."):
                continue
            for gname, pt in sorted(raw["plaintext"].items()):
                print(f"  {gname:8}: {pt}")
        tn.flush_and_close()

        # 5) Read back as a PARTNER who only holds the `default` kit.
        #    Simulate by copying the publisher's ceremony minus the pii +
        #    internal kit files.
        partner_ws = ws / "partner_view"
        partner_ws.mkdir()
        partner_keys = partner_ws / ".tn" / "keys"
        partner_keys.mkdir(parents=True)
        # Copy device key + only the default-group btn kit + state files.
        # (pii.btn.mykit and internal.btn.mykit are intentionally NOT copied.)
        src_keys = ws / ".tn" / "keys"
        for fname in src_keys.iterdir():
            if fname.name.startswith(("pii.btn", "internal.btn")):
                continue
            shutil.copy2(fname, partner_keys / fname.name)

        # Partner's tn.yaml has only the default group declared.
        partner_yaml = partner_ws / "tn.yaml"
        partner_yaml.write_text(
            "ceremony:\n"
            "  id: partner-view\n"
            "  mode: local\n"
            "keystore: { path: ./.tn/keys }\n"
            f"me: {{ did: {cfg.device.did} }}\n"
            "groups:\n"
            "  default:\n"
            "    cipher: btn\n",
            encoding="utf-8",
        )
        tn.init(partner_yaml, cipher="btn")

        print("\n--- as partner (only the `default` kit) ---")
        for raw in tn.read_raw(log_path):
            env = raw["envelope"]
            if env.get("event_type", "").startswith("tn."):
                continue
            print(f"  event_type: {env['event_type']}")
            default_plain = raw["plaintext"].get("default", {})
            print(f"  default (decrypted): {default_plain}")
            for g in ("pii", "internal"):
                if g in env:
                    ct_len = len(env[g]["ciphertext"])
                    print(
                        f"  {g:8} group: [encrypted, {ct_len}-byte ciphertext, "
                        "not decryptable without the kit]"
                    )

        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
