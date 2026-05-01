"""Carol s01 — JWE O(1) revocation semantics.

Flow:
1. Alice inits JWE ceremony.
2. Carol mints X25519, shares pub with Alice.
3. Alice adds Carol via tn.add_recipient.
4. Alice writes 50 "pre-revoke" log entries.
5. Alice calls tn.revoke_recipient(cfg, "default", carol_did).
   - O(1) — no rotation, no coordination with other recipients.
   - Index epoch bumps so Carol's HMAC index tokens are invalidated.
6. Alice writes 50 "post-revoke" log entries.
7. Carol receives Alice's ndjson + her own mykey.
8. Carol attempts to decrypt EVERY entry with her X25519 private.
   - Pre-revoke: all 50 decrypt cleanly (she had a wrapped CEK at
     the time they were written).
   - Post-revoke: all 50 FAIL to decrypt (no wrapped CEK for her).

Invariants:
- revoked_reads_prerevoke_ok (Carol reads her own pre-revoke access)
- revoked_cant_read_post (Carol gets 0 plaintext from post-revoke)
- index_epoch_bumped (verify the epoch actually incremented)
"""

from __future__ import annotations

import shutil

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import tn
from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity


class CarolRevokeThenCannotRead(Scenario):
    persona = "carol"
    name = "s01_revoke_then_cannot_read"
    tags = {"jwe", "revocation", "multi-recipient"}
    needs_vault = False

    PRE_COUNT = 50
    POST_COUNT = 50

    def run(self, ctx: ScenarioContext) -> None:
        # --- Alice (publisher) ---------------------------------------
        alice_ws = ctx.workspace.root / "alice"
        alice_ws.mkdir(exist_ok=True)
        alice_yaml = alice_ws / "tn.yaml"
        alice_log = alice_ws / ".tn/tn/logs" / "tn.ndjson"
        alice_log.parent.mkdir(exist_ok=True)

        alice_ident = Identity.create_new()
        tn.init(alice_yaml, log_path=alice_log, cipher="jwe", identity=alice_ident)
        cfg = tn.current_config()

        # --- Carol mints X25519 + Alice adds her --------------------
        carol_sk = X25519PrivateKey.generate()
        carol_pub = carol_sk.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        carol_did = f"did:key:zCarol{carol_pub[:8].hex()}"
        tn.add_recipient(cfg, "default", carol_did, carol_pub)

        # --- Alice writes pre-revoke entries ------------------------
        for i in range(self.PRE_COUNT):
            tn.info("pre.revoke", idx=i, secret=f"PRE-{i}")

        # --- Record pre-revoke index epoch --------------------------
        epoch_before = cfg.groups["default"].index_epoch
        ctx.record("epoch_before_revoke", epoch_before)

        # --- Alice revokes Carol ------------------------------------
        with ctx.timer("revoke_ms"):
            tn.revoke_recipient(cfg, "default", carol_did)
        epoch_after = cfg.groups["default"].index_epoch
        ctx.record("epoch_after_revoke", epoch_after)
        ctx.assert_invariant(
            "index_epoch_bumped",
            epoch_after > epoch_before,
        )

        # --- Alice writes post-revoke entries -----------------------
        for i in range(self.POST_COUNT):
            tn.info("post.revoke", idx=i, secret=f"POST-{i}")
        tn.flush_and_close()

        # --- Carol's workspace: mykey only --------------------------
        carol_ws = ctx.workspace.root / "carol"
        carol_ks = carol_ws / ".tn/tn/keys"
        carol_ks.mkdir(parents=True, exist_ok=True)
        (carol_ks / "default.jwe.mykey").write_bytes(
            carol_sk.private_bytes_raw(),
        )

        carol_log = carol_ws / "received.ndjson"
        shutil.copy(alice_log, carol_log)

        # --- Carol reads via the recipient API --------------------
        pre_decrypted = 0
        post_decrypted = 0
        pre_total = 0
        post_total = 0
        for entry in tn.read_as_recipient(carol_log, carol_ks, group="default"):
            event = entry["envelope"].get("event_type")
            is_pre = event == "pre.revoke"
            is_post = event == "post.revoke"
            if is_pre:
                pre_total += 1
            if is_post:
                post_total += 1
            pt = entry["plaintext"].get("default", {})
            if "$no_read_key" in pt or "$decrypt_error" in pt or not pt:
                continue
            secret = pt.get("secret", "")
            if is_pre and secret.startswith("PRE-"):
                pre_decrypted += 1
            elif is_post and secret.startswith("POST-"):
                post_decrypted += 1

        ctx.record("pre_total", pre_total)
        ctx.record("post_total", post_total)
        ctx.record("pre_decrypted", pre_decrypted)
        ctx.record("post_decrypted", post_decrypted)

        ctx.assert_invariant(
            "carol_reads_prerevoke_ok",
            pre_decrypted == self.PRE_COUNT,
        )
        ctx.assert_invariant(
            "carol_cannot_read_postrevoke",
            post_decrypted == 0,
        )
        # Sanity: post-revoke entries DO still appear in the stream;
        # they just don't decrypt for Carol.
        ctx.assert_invariant(
            "postrevoke_entries_present_in_stream",
            post_total == self.POST_COUNT,
        )
