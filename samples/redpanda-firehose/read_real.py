"""Read real TN envelopes from the Kafka handler's source.

Uses KafkaHandler.reader() directly — the same method that tn.read() will
call automatically once base.py gains the reader() contract and tn.read()
is wired to prefer file-handler source when present, Kafka otherwise.

    python read_real.py
    python read_real.py --group-id my-consumer

Set before running:
    export RP_USERNAME=tn-firehose
    export RP_PASSWORD=PTkWReJpXJ10SA4O20M9oBNiwoMDL5
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-id", default="tn-real-reader-1")
    ap.add_argument("--since", choices=["earliest", "latest"], default="earliest")
    args = ap.parse_args()

    # Build the same handler that send_real.py uses so we get the right
    # connection config without hardcoding it here.
    from tn.handlers.kafka import KafkaHandler

    handler = KafkaHandler(
        "redpanda-cloud",
        outbox_path=Path("tn_cloud_demo/outbox/rp-reader"),
        bootstrap="d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com:9092",
        topic="tn.firehose.00000000-0000-0000-0000-000000000001",
        sasl={
            "mechanism": "SCRAM-SHA-256",
            "user": os.environ["RP_USERNAME"],
            "pass": os.environ["RP_PASSWORD"],
        },
    )

    print(f"source    : {handler.resolved_address()}")
    print(f"group     : {args.group_id}")
    print(f"since     : {args.since}")
    print()

    received = 0
    for raw in handler.reader(group_id=args.group_id, since=args.since):
        received += 1
        _handle(raw)

    print(f"\nIdle timeout — {received} messages received.")


def _handle(raw: bytes) -> None:
    try:
        env = json.loads(raw)
    except Exception:
        print(f"  [encrypted frame, {len(raw)} bytes — not from KafkaHandler]")
        return

    event_id   = env.get("event_id", "")
    event_type = env.get("event_type", "")
    ts         = env.get("timestamp", "")
    device     = env.get("device_identity", "")
    row_hash   = env.get("row_hash", "")
    seq        = env.get("sequence", "?")
    pf         = env.get("public_fields") or {}

    print(
        f"  off=?  id={event_id[:8]}…"
        f"  type={event_type:<28}"
        f"  seq={seq}"
        f"  ts={ts[11:19]}"
    )
    print(f"    did      : {device[:48]}…")
    print(f"    row_hash : {row_hash}")
    if pf:
        print(f"    public   : {pf}")
    print()


if __name__ == "__main__":
    main()
