"""Alice s06 — period rollover, reader spans both chain segments."""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext


class AliceRollover(Scenario):
    persona = "alice"
    name = "s06_rollover"
    tags = {"baseline", "jwe", "local", "rollover"}

    def run(self, ctx: ScenarioContext) -> None:
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        for i in range(100):
            tn.info("segment.one", seq=i)
        tn.flush_and_close()

        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        for i in range(100):
            tn.info("segment.two", seq=i)
        tn.flush_and_close()

        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(ctx.log_path, cfg, raw=True))

        seg1 = [e for e in entries if e["envelope"]["event_type"] == "segment.one"]
        seg2 = [e for e in entries if e["envelope"]["event_type"] == "segment.two"]

        decryption_ok = True
        decrypted_count = 0
        for n in (seg1, seg2):
            for idx, e in enumerate(n):
                if e["plaintext"].get("default", {}).get("seq") == idx:
                    decrypted_count += 1
                else:
                    decryption_ok = False

        ctx.record("log_count", len(entries))
        ctx.record("seg1_count", len(seg1))
        ctx.record("seg2_count", len(seg2))
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
            decryption_ok and decrypted_count == 200,
        )
        tn.flush_and_close()
