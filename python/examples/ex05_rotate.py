"""Example 5: analyst just quit — revoke their kit.

Story
-----
The analyst leaves the company. They might still have a copy of the
`analytics.btn.mykit` Jamie gave them. Jamie revokes the analyst's
leaf in the btn group. Entries written AFTER revocation are opaque to
the ex-analyst's kit. Entries written BEFORE are still decryptable —
that's data they legally saw while employed.

What this shows
---------------
  - `tn.admin.add_recipient(group, recipient_did=..., out_path=kit_path)` mints
    a kit with a numeric leaf index for that DID.
  - `tn.admin.revoke_recipient(group, leaf_index=leaf_index)` marks the leaf as
    revoked, writing a signed `tn.recipient.revoked` chain entry.
  - The revoked kit can still decrypt OLD ciphertexts (data the
    recipient legitimately saw while entitled).
  - The revoked kit CANNOT decrypt NEW ciphertexts written after the
    revoke event — the publisher state moves the privileged subset
    forward and the revoked leaf falls outside it.
  - `tn.admin.rotate(group)` is the heavier alternative — invalidates every
    kit, requires re-issuing to all current readers. Use only when the
    publisher root is suspected compromised.

Run it
------
    python ex05_rotate.py
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path

import tn


def main() -> int:
    if not tn.using_rust():
        print("SKIP: this example needs the tn_core Rust extension. "
              "Run tools/rebuild_pyo3.sh tn-core, then retry.")
        return 0

    # tn_btn ships alongside tn-core when the Rust path is built.
    try:
        import tn_btn
    except ImportError:
        print("SKIP: tn_btn extension not built. Run "
              "tools/rebuild_pyo3.sh tn-btn, then retry.")
        return 0

    with tempfile.TemporaryDirectory(prefix="jamie5_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        # Fresh ceremony with a `analytics` group on btn.
        tn.init(yaml_path, cipher="btn")
        cfg = tn.current_config()
        cfg = tn.ensure_group(cfg, "analytics", fields=["path"])
        tn.flush_and_close()
        tn.init(yaml_path, cipher="btn")

        # Mint a kit for the analyst and capture the kit bytes for
        # later (the analyst's saved copy).
        analyst_kit = ws / "analyst.analytics.mykit"
        analyst_did = "did:key:zFormerAnalyst"
        analyst_leaf = tn.admin.add_recipient("analytics", recipient_did=analyst_did, out_path=str(analyst_kit))
        analyst_kit_bytes = analyst_kit.read_bytes()
        print(f"minted leaf {analyst_leaf} for {analyst_did}")

        # Pre-revocation entries.
        tn.info("request.served", request_id="r-1", path="/dashboard")
        tn.info("request.served", request_id="r-2", path="/reports")
        tn.flush_and_close()
        tn.init(yaml_path, cipher="btn")

        # Capture pre-revocation `analytics` ciphertexts so we can later
        # prove the analyst's kit still decrypts them.
        pre_revocation_cts = []
        for raw in tn.read_raw():
            env = raw["envelope"]
            if env.get("event_type") == "request.served" and "analytics" in env:
                pre_revocation_cts.append(env["analytics"]["ciphertext"])
        assert pre_revocation_cts, "no pre-revocation ciphertexts captured"

        # ---- incident: analyst leaves. Revoke their leaf. -----------
        tn.admin.revoke_recipient("analytics", leaf_index=analyst_leaf)
        print(f"\nrevoked leaf {analyst_leaf} ({analyst_did})")

        # Post-revocation entries.
        tn.info("request.served", request_id="r-3", path="/admin")
        tn.flush_and_close()
        tn.init(yaml_path, cipher="btn")

        post_revocation_cts = []
        for raw in tn.read_raw():
            env = raw["envelope"]
            if env.get("event_type") == "request.served" and "analytics" in env:
                ct_b64 = env["analytics"]["ciphertext"]
                if ct_b64 not in pre_revocation_cts:
                    post_revocation_cts.append(ct_b64)
        assert post_revocation_cts, "no post-revocation ciphertexts captured"

        # ---- verification: analyst's kit can STILL decrypt pre-revoke -
        old_ct_bytes = base64.standard_b64decode(pre_revocation_cts[0])
        try:
            tn_btn.decrypt(analyst_kit_bytes, old_ct_bytes)
            print("[ok] analyst's old kit still decrypts data written BEFORE revocation")
        except Exception as e:
            print(f"[FAIL] expected old kit to decrypt pre-revocation entry: {e}")
            return 1

        # ---- verification: analyst's kit FAILS on post-revoke --------
        new_ct_bytes = base64.standard_b64decode(post_revocation_cts[0])
        try:
            tn_btn.decrypt(analyst_kit_bytes, new_ct_bytes)
            print("[FAIL] unexpected: analyst's kit decrypted POST-revocation data")
            return 1
        except (tn_btn.NotEntitled, tn_btn.BtnRuntimeError):
            print("[ok] analyst's kit cannot decrypt data written AFTER revocation")

        # ---- the revocation itself is an attested chain entry --------
        revoke_entries = [
            r for r in tn.read_raw()
            if r["envelope"].get("event_type") == "tn.recipient.revoked"
        ]
        print(f"\nrevocation chain entries in the log: {len(revoke_entries)}")
        for r in revoke_entries:
            valid = all(r["valid"].values())
            env = r["envelope"]
            print(f"  event_id={env.get('event_id')} valid={valid} "
                  f"sequence={env.get('sequence')}")

        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
