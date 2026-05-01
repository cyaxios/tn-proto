"""Alice s07 — route fields into pii / ops / finance groups.

Creates three groups via tn.ensure_group with field lists. Logs events
that touch fields across all three groups. Reads back and records
which groups appear in plaintext.
"""

from __future__ import annotations

import tn
from scenarios._harness import Scenario, ScenarioContext


class AliceFieldRouting(Scenario):
    persona = "alice"
    name = "s07_field_routing"
    tags = {"baseline", "jwe", "local", "routing"}

    def run(self, ctx: ScenarioContext) -> None:
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()

        with ctx.timer("ensure_groups_ms"):
            tn.ensure_group(cfg, "pii", fields=["email", "ip"])
            tn.ensure_group(cfg, "ops", fields=["latency_ms", "country"])
            tn.ensure_group(cfg, "finance", fields=["amount"])

        # Re-open so the logger picks up the new groups (per ensure_group docstring).
        tn.flush_and_close()
        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")

        for i in range(100):
            tn.info(
                "user.signup",
                email=f"u{i}@ex.com",
                ip="10.0.0.1",
                amount=1000 + i,
                country="ES",
                latency_ms=42,
            )
        tn.flush_and_close()

        tn.init(ctx.yaml_path, log_path=ctx.log_path, cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(ctx.log_path, cfg, raw=True))

        groups_seen: set[str] = set()
        # Per-group round-trip: each routed field must decrypt from its
        # assigned group's plaintext bucket.
        per_group_ok = {"pii": True, "ops": True, "finance": True}
        per_group_count = {"pii": 0, "ops": 0, "finance": 0}
        for idx, e in enumerate(entries):
            pt = e.get("plaintext", {})
            groups_seen.update(pt.keys())

            pii = pt.get("pii", {})
            if pii.get("email") == f"u{idx}@ex.com" and pii.get("ip") == "10.0.0.1":
                per_group_count["pii"] += 1
            else:
                per_group_ok["pii"] = False

            ops = pt.get("ops", {})
            if ops.get("latency_ms") == 42 and ops.get("country") == "ES":
                per_group_count["ops"] += 1
            else:
                per_group_ok["ops"] = False

            fin = pt.get("finance", {})
            if fin.get("amount") == 1000 + idx:
                per_group_count["finance"] += 1
            else:
                per_group_ok["finance"] = False

        ctx.record("log_count", len(entries))
        ctx.record("group_count", 3)
        ctx.record("groups_seen", sorted(groups_seen))
        ctx.record("per_group_decrypted_count", per_group_count)
        ctx.assert_invariant(
            "chain_verified",
            all(e["valid"]["chain"] for e in entries),
        )
        ctx.assert_invariant(
            "signature_verified",
            all(e["valid"]["signature"] for e in entries),
        )
        ctx.assert_invariant(
            "decryption_verified_pii",
            per_group_ok["pii"] and per_group_count["pii"] == 100,
        )
        ctx.assert_invariant(
            "decryption_verified_ops",
            per_group_ok["ops"] and per_group_count["ops"] == 100,
        )
        ctx.assert_invariant(
            "decryption_verified_finance",
            per_group_ok["finance"] and per_group_count["finance"] == 100,
        )
        tn.flush_and_close()
