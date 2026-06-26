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
        from tn._native import btn as tn_btn
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
        # prove the analyst's kit still decrypts them. raw=True yields
        # the on-disk envelope dict; the analytics group ciphertext
        # block lives at env["analytics"]["ciphertext"].
        pre_revocation_cts = []
        for env in tn.read(raw=True):
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
        for env in tn.read(raw=True):
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
        # The revoke event is just another row in the log: signed,
        # chained, verifiable. We pull it back as a typed Entry, then
        # re-walk with verify=True to confirm the integrity sweep
        # passes across the whole log (including the revoke event).
        revoke_entries = [
            e for e in tn.read() if e.event_type == "tn.recipient.revoked"
        ]
        print(f"\nrevocation chain entries in the log: {len(revoke_entries)}")
        for e in revoke_entries:
            print(f"  event_id={e.event_id} sequence={e.sequence} "
                  f"row_hash={e.row_hash[:18]}...")

        # tn.read(verify=True) walks every row and re-checks
        # signature/row_hash/chain. Clean log → silent. Tampered → raises.
        try:
            checked = sum(1 for _ in tn.read(verify=True))
            print(f"  [ok] {checked} rows pass full integrity verify "
                  f"(signature, row_hash, chain)")
        except tn.VerifyError as exc:
            print(f"  [FAIL] verify error at seq={exc.sequence} "
                  f"event={exc.event_type!r} failed={exc.failed_checks}")
            return 1

        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
