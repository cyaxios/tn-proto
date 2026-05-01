"""Alice s02 — rotate mid-stream, verify chain continues cleanly."""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext


class AliceRotate(Scenario):
    persona = "alice"
    name = "s02_rotate"
    tags = {"baseline", "jwe", "local", "rotation"}

    def run(self, ctx: ScenarioContext) -> None:
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()

        for i in range(200):
            tn.info("evt.pre", seq=i)

        with ctx.timer("rotation_ms"):
            tn.rotate("default")

        for i in range(200):
            tn.info("evt.post", seq=i)

        tn.flush_and_close()

        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(ctx.log_path, cfg, raw=True))

        chain_ok = all(e["valid"]["chain"] for e in entries)
        sig_ok = all(e["valid"]["signature"] for e in entries)
        pre = [e for e in entries if e["envelope"]["event_type"] == "evt.pre"]
        post = [e for e in entries if e["envelope"]["event_type"] == "evt.post"]

        # Round-trip: verify pre/post-rotation entries separately.
        # Finding: after tn.rotate(), the publisher's own pre-rotation
        # entries read back as plaintext={'$no_read_key': True} — the
        # old cipher state is gone. Post-rotation entries decrypt cleanly.
        # We record both so the behavior is explicit, and we only gate
        # "decryption_verified" on the post-rotation half (which is what
        # a well-behaved ceremony guarantees after rotation).
        def _decrypted_match(bucket, field_name="seq"):
            ok_flag = True
            count = 0
            for idx, e in enumerate(bucket):
                pt = e["plaintext"].get("default", {})
                if pt.get(field_name) == idx and "$no_read_key" not in pt:
                    count += 1
                else:
                    ok_flag = False
            return ok_flag, count

        pre_ok, pre_decrypted = _decrypted_match(pre)
        post_ok, post_decrypted = _decrypted_match(post)

        ctx.record("log_count", len(entries))
        ctx.record("pre_count", len(pre))
        ctx.record("post_count", len(post))
        ctx.record("pre_rotation_decrypted_count", pre_decrypted)
        ctx.record("post_rotation_decrypted_count", post_decrypted)
        ctx.record("recipient_count", 1)
        ctx.record("group_count", 1)
        ctx.assert_invariant("chain_verified", chain_ok)
        ctx.assert_invariant("signature_verified", sig_ok)
        ctx.assert_invariant(
            "post_rotation_decryption_verified",
            post_ok and post_decrypted == 200,
        )
        ctx.assert_invariant(
            "pre_rotation_decryption_verified",
            pre_ok and pre_decrypted == 200,
        )
        if not pre_ok:
            ctx.note(
                "pre-rotation entries unreadable by publisher after rotate "
                "(plaintext['default']['$no_read_key']=True); rotation is "
                "destructive to publisher's own history with current SDK",
            )

        tn.flush_and_close()
