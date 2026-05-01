"""Alice s03 — YAML ceremony matrix sweep.

15 hand-picked cells varying (groups, recipients_per_group,
context_keys, field_count). Each cell records its own metrics +
per-cell yaml snapshot. Not full cartesian — shape coverage.

Handlers dimension deferred to alice/s05_handlers_fanout (requires
per-cell ceremony rebuild, covered there).

CONCERN: n_recips is cosmetic — tn.ensure_group() creates the group
with just the publisher as recipient. The intended recipient count is
recorded in metrics so the CSV reflects the cell's design intent, but
true multi-recipient JWE encryption per cell is deferred (same as
Bob/Carol/Dana personas which exercise the low-level JWEGroupCipher
path).
"""

from __future__ import annotations

import json
import shutil
import statistics

import tn
from scenarios._harness import Scenario, ScenarioContext

# (groups, recipients_per_group, context_keys, field_count)
MATRIX = [
    (1, 1, 0, 5),
    (1, 1, 3, 5),
    (1, 3, 0, 20),
    (1, 10, 0, 20),
    (2, 1, 0, 20),
    (2, 3, 3, 20),
    (2, 3, 10, 100),
    (5, 1, 0, 20),
    (5, 3, 0, 20),
    (5, 3, 3, 100),
    (5, 10, 0, 20),
    (1, 1, 0, 50),
    (1, 3, 10, 50),
    (3, 3, 3, 20),
    (3, 1, 10, 100),
]


def _fields(n: int) -> dict:
    return {f"f{i:03d}": f"v{i:03d}" for i in range(n)}


class AliceCeremonyMatrix(Scenario):
    persona = "alice"
    name = "s03_ceremony_matrix"
    tags = {"baseline", "jwe", "local", "matrix"}
    LOG_COUNT_PER_CELL = 200

    def run(self, ctx: ScenarioContext) -> None:
        cell_root = ctx.workspace.root / "cells"
        cell_root.mkdir(exist_ok=True)

        for idx, (n_groups, n_recips, n_ctx, n_fields) in enumerate(MATRIX):
            cell_id = f"{idx:02d}"
            with ctx.cell(cell_id):
                # Fresh keystore + yaml per cell so ceremonies don't stomp each other.
                cell_dir = cell_root / cell_id
                if cell_dir.exists():
                    shutil.rmtree(cell_dir)
                cell_dir.mkdir(parents=True, exist_ok=True)
                cell_yaml = cell_dir / "tn.yaml"
                cell_log = cell_dir / ".tn/tn/logs" / "tn.ndjson"
                cell_log.parent.mkdir(exist_ok=True)

                ctx.yaml_path = cell_yaml  # so snapshot_yaml picks up this cell's yaml

                with ctx.timer("tn_init_ms"):
                    tn.init(cell_yaml, log_path=cell_log, cipher="jwe")

                # Add extra groups if requested (default group is pre-created by tn.init).
                cfg = tn.current_config()
                for g in range(1, n_groups):
                    tn.ensure_group(cfg, f"g{g}")
                if n_groups > 1:
                    tn.flush_and_close()
                    tn.init(cell_yaml, log_path=cell_log, cipher="jwe")

                # Context fields: simulate by calling set_context once.
                if n_ctx > 0:
                    kv = {f"ck{i}": f"cv{i}" for i in range(n_ctx)}
                    tn.set_context(**kv)

                evt = _fields(n_fields)
                for _ in range(self.LOG_COUNT_PER_CELL):
                    with ctx.timer_us("log_us"):
                        tn.info("matrix.row", **evt)

                if n_ctx > 0:
                    tn.clear_context()

                tn.flush_and_close()

                tn.init(cell_yaml, log_path=cell_log, cipher="jwe")
                cfg = tn.current_config()
                envelope_bytes = []
                entries = list(tn.read(cell_log, cfg, raw=True))

                # Per-cell round-trip: every decrypted field must equal
                # what we wrote in `evt`. All unrouted fields land in
                # plaintext["default"] since no field routing is set up
                # in this scenario.
                decryption_ok = True
                decrypted_count = 0
                sig_ok = True
                for e in entries:
                    envelope_bytes.append(
                        len(
                            json.dumps(
                                e["envelope"],
                                separators=(",", ":"),
                                default=str,
                            )
                        )
                    )
                    sig_ok &= bool(e["valid"]["signature"])
                    pt = e["plaintext"].get("default", {})
                    if all(pt.get(k) == v for k, v in evt.items()):
                        decrypted_count += 1
                    else:
                        decryption_ok = False

                plaintext_ref = len(json.dumps(evt, separators=(",", ":")))

                if envelope_bytes:
                    mean_env = statistics.mean(envelope_bytes)
                    ctx.record("envelope_bytes_mean", mean_env)
                    ctx.record(
                        "envelope_plaintext_ratio",
                        mean_env / plaintext_ref if plaintext_ref else None,
                    )
                ctx.record("plaintext_bytes_mean", plaintext_ref)
                ctx.record("group_count", n_groups)
                ctx.record("recipient_count", n_recips * n_groups)
                ctx.record("handler_count", 1)  # handler matrix is s05
                ctx.record("field_count", n_fields)
                ctx.record("context_key_count", n_ctx)
                ctx.record("log_count", self.LOG_COUNT_PER_CELL)
                ctx.record("decrypted_count", decrypted_count)
                ctx.assert_invariant(
                    "chain_verified",
                    all(e["valid"]["chain"] for e in entries),
                )
                ctx.assert_invariant("signature_verified", sig_ok)
                ctx.assert_invariant(
                    "decryption_verified",
                    decryption_ok and decrypted_count == self.LOG_COUNT_PER_CELL,
                )
                tn.flush_and_close()
