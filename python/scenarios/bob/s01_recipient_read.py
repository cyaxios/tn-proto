"""Bob s01 — multi-recipient JWE: Bob reads Alice's log.

Flow:
1. Alice inits a JWE ceremony (publisher).
2. Bob mints his own X25519 keypair, shares ONLY the public half with
   Alice over an out-of-band channel.
3. Alice calls `tn.add_recipient(cfg, "default", bob_did, bob_pub)`.
4. Alice writes 50 log entries (each includes a wrapped CEK for Bob).
5. Bob receives a copy of Alice's ndjson (any channel) plus nothing
   more. His workspace holds only his own `default.jwe.mykey`.
6. Bob decrypts every entry with his X25519 private — plaintext bytes
   match exactly what Alice wrote.
7. Bob cannot write (no sender key) — enforcement via NotAPublisherError.
"""

from __future__ import annotations

import shutil

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import tn
from scenarios._harness import Scenario, ScenarioContext
from tn.cipher import JWEGroupCipher, NotAPublisherError
from tn.identity import Identity


class BobRecipientRead(Scenario):
    persona = "bob"
    name = "s01_recipient_read"
    tags = {"jwe", "recipient", "multi-recipient"}
    needs_vault = False

    LOG_COUNT = 50

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
        ctx.record("alice_did", alice_ident.did)

        # --- Bob mints his own X25519, gives only pub to Alice -------
        bob_sk = X25519PrivateKey.generate()
        bob_pub_bytes = bob_sk.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        bob_did = f"did:key:zBob{bob_pub_bytes[:8].hex()}"
        ctx.record("bob_did", bob_did)

        # Alice adds Bob as a recipient to the default group
        with ctx.timer("add_recipient_ms"):
            tn.add_recipient(cfg, "default", bob_did, bob_pub_bytes)

        # --- Alice writes log entries --------------------------------
        inputs: list[dict] = []
        for i in range(self.LOG_COUNT):
            event = {"order_id": f"O{i:04d}", "amount": 500 + i, "note": f"bob-visible-{i}"}
            inputs.append(event)
            tn.info("order.created", **event)
        tn.flush_and_close()
        ctx.record("alice_logged", self.LOG_COUNT)

        # --- Bob's workspace: only his mykey file --------------------
        bob_ws = ctx.workspace.root / "bob"
        bob_keystore = bob_ws / ".tn/tn/keys"
        bob_keystore.mkdir(parents=True, exist_ok=True)
        (bob_keystore / "default.jwe.mykey").write_bytes(
            bob_sk.private_bytes_raw(),
        )

        # Bob also receives a copy of Alice's ndjson (any channel)
        bob_log = bob_ws / "received.ndjson"
        shutil.copy(alice_log, bob_log)

        # --- Bob reads + decrypts using the high-level recipient API ---
        decrypted_ok = 0
        decrypted_correct = 0
        bob_readable_events = 0
        sig_verified = 0
        chain_verified = 0
        for entry in tn.read_as_recipient(bob_log, bob_keystore, group="default"):
            if entry["envelope"].get("event_type") != "order.created":
                continue
            bob_readable_events += 1
            if entry["valid"]["signature"]:
                sig_verified += 1
            if entry["valid"]["chain"]:
                chain_verified += 1
            pt = entry["plaintext"].get("default", {})
            if "$no_read_key" in pt or "$decrypt_error" in pt or not pt:
                continue
            decrypted_ok += 1
            expected = next(
                (e for e in inputs if e["order_id"] == pt.get("order_id")),
                None,
            )
            if (
                expected
                and pt.get("amount") == expected["amount"]
                and pt.get("note") == expected["note"]
            ):
                decrypted_correct += 1

        ctx.record("bob_decrypted_ok", decrypted_ok)
        ctx.record("bob_decrypted_correct", decrypted_correct)
        ctx.record("bob_readable_events", bob_readable_events)
        ctx.record("sig_verified", sig_verified)
        ctx.record("chain_verified", chain_verified)
        ctx.assert_invariant(
            "bob_decrypted_all_entries",
            decrypted_correct == self.LOG_COUNT,
        )
        ctx.assert_invariant(
            "bob_sees_full_log",
            bob_readable_events == self.LOG_COUNT,
        )
        ctx.assert_invariant(
            "bob_signature_all_verified",
            sig_verified == self.LOG_COUNT,
        )

        # --- Bob CANNOT write (no sender key in his keystore) --------
        bob_cipher = JWEGroupCipher.load(bob_keystore, "default")
        try:
            bob_cipher.encrypt(b"bob would like to forge")
            ctx.assert_invariant("bob_cannot_publish", False)
        except NotAPublisherError:
            ctx.assert_invariant("bob_cannot_publish", True)
