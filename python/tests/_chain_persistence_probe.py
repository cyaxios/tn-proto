"""Probe: does chain state survive flush_and_close + reinit?"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        yaml = ws / "tn.yaml"
        log = ws / ".tn/tn/logs" / "tn.ndjson"

        tn.init(yaml, cipher="jwe")
        tn.info("order.created", amount=1)
        tn.flush_and_close()

        tn.init(yaml, cipher="jwe")
        tn.info("order.created", amount=2)
        tn.flush_and_close()

        tn.init(yaml, cipher="jwe")
        cfg = tn.current_config()
        entries = list(tn.read(log, cfg))
        print(f"entries in log: {len(entries)}")
        for i, e in enumerate(entries):
            env = e["envelope"]
            v = e["valid"]
            seq = env["sequence"]
            prev = env["prev_hash"]
            row = env["row_hash"]
            print(
                f"  #{i} seq={seq} prev_hash={prev[:22]}... "
                f"row_hash={row[:22]}... chain={v['chain']}"
            )
        tn.flush_and_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
