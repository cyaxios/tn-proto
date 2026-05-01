"""Alice s08 — init, log 500, close, re-init same yaml, log 500,
verify a single coherent chain."""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext


class AliceResume(Scenario):
    persona = "alice"
    name = "s08_resume"
    tags = {"baseline", "jwe", "local", "resume"}

    def run(self, ctx: ScenarioContext) -> None:
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        for i in range(500):
            tn.info("before.restart", seq=i)
        tn.flush_and_close()

        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        for i in range(500):
            tn.info("after.restart", seq=i)
        tn.flush_and_close()

        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(ctx.log_path, cfg, raw=True))

        before = [e for e in entries if e["envelope"]["event_type"] == "before.restart"]
        after = [e for e in entries if e["envelope"]["event_type"] == "after.restart"]

        decryption_ok = True
        decrypted_count = 0
        for bucket in (before, after):
            for idx, e in enumerate(bucket):
                if e["plaintext"].get("default", {}).get("seq") == idx:
                    decrypted_count += 1
                else:
                    decryption_ok = False

        ctx.record("log_count", len(entries))
        ctx.record("before_count", len(before))
        ctx.record("after_count", len(after))
        ctx.record("decrypted_count", decrypted_count)
        ctx.assert_invariant(
            "chain_verified",
            all(e["valid"]["chain"] for e in entries),
        )
        ctx.assert_invariant(
            "signature_verified",
            all(e["valid"]["signature"] for e in entries),
        )
        ctx.assert_invariant(
            "decryption_verified",
            decryption_ok and decrypted_count == 1000,
        )
        tn.flush_and_close()
