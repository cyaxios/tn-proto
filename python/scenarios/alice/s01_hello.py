"""Alice s01 — first attested log, 1000 entries, read back, verify.

Mirrors examples/ex01_hello.py and tests/test_jwe_roundtrip.py but
under the harness so metrics, yaml snapshot, and invariants are
recorded.
"""

from __future__ import annotations

import json
import statistics

import tn
from scenarios._harness import Scenario, ScenarioContext


class AliceHello(Scenario):
    persona = "alice"
    name = "s01_hello"
    tags = {"baseline", "jwe", "local"}
    needs_vault = False
    needs_handlers = {"file"}

    LOG_COUNT = 1000

    def run(self, ctx: ScenarioContext) -> None:
        # tn.init auto-creates the ceremony on first call. Do NOT
        # pre-write a yaml — tn has its own schema.
        with ctx.timer("ceremony_ms"):
            with ctx.timer("tn_init_ms"):
                tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")

        cfg = tn.current_config()
        ctx.record("cipher", cfg.cipher_name)
        ctx.record("did", cfg.device.did)
        ctx.record("recipient_count", 1)
        ctx.record("group_count", 1)
        ctx.record("handler_count", 1)

        plaintext_bytes: list[int] = []
        inputs: list[dict] = []  # index i -> the event we wrote
        for i in range(self.LOG_COUNT):
            event = {
                "order_id": f"O{i:06d}",
                "amount": 1000 + i,
                "email": f"u{i}@ex.com",
            }
            inputs.append(event)
            plaintext_bytes.append(len(json.dumps(event, separators=(",", ":"))))
            with ctx.timer_us("log_us"):
                tn.info("order.created", **event)
        ctx.record("log_count", self.LOG_COUNT)

        tn.flush_and_close()

        # Reopen for reads.
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()

        envelope_bytes: list[int] = []
        all_valid_sig = True
        all_valid_chain = True
        no_plaintext_leak = True
        seen_plaintext_samples = [
            "u0@ex.com",
            "u500@ex.com",
            "O000000",
            "O000500",
        ]

        entries = list(tn.read(ctx.log_path, cfg, raw=True))

        # Pair each entry with its input by sequence number. `tn.info`
        # assigns sequence per-event-type starting at 1, so order.created[i]
        # corresponds to sequence i+1.
        decryption_verified = True
        decrypted_count = 0
        for e in entries:
            env = e["envelope"]
            envelope_bytes.append(len(json.dumps(env, separators=(",", ":"), default=str)))
            all_valid_sig &= bool(e["valid"]["signature"])
            all_valid_chain &= bool(e["valid"]["chain"])
            raw = json.dumps(env, default=str)
            for leak in seen_plaintext_samples:
                if leak in raw:
                    no_plaintext_leak = False
                    break

            seq = env.get("sequence")
            pt_default = e["plaintext"].get("default", {})
            if seq is not None and 1 <= seq <= len(inputs):
                expected = inputs[seq - 1]
                if (
                    pt_default.get("order_id") == expected["order_id"]
                    and pt_default.get("amount") == expected["amount"]
                    and pt_default.get("email") == expected["email"]
                ):
                    decrypted_count += 1
                else:
                    decryption_verified = False
            else:
                decryption_verified = False

        ctx.record_envelope_ratio(envelope_bytes, plaintext_bytes)
        if envelope_bytes:
            ctx.record(
                "envelope_bytes_p99",
                statistics.quantiles(envelope_bytes, n=100)[98]
                if len(envelope_bytes) >= 100
                else max(envelope_bytes),
            )

        ctx.assert_invariant("chain_verified", all_valid_chain)
        ctx.assert_invariant("signature_verified", all_valid_sig)
        ctx.assert_invariant("no_plaintext_in_envelope", no_plaintext_leak)
        ctx.assert_invariant(
            "decryption_verified",
            decryption_verified and decrypted_count == len(inputs),
        )

        ctx.record("entry_count_read", len(entries))
        ctx.record("decrypted_count", decrypted_count)

        tn.flush_and_close()
