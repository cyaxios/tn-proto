"""Redpanda firehose producer demo.

Produces synthetic TN envelopes to a local Redpanda instance and prints
the Kafka offset/partition each one lands on.

    python demo_produce.py
    python demo_produce.py --bootstrap tn-redpanda.fly.dev:9092
    python demo_produce.py --project-id YOUR-UUID --count 50

Requires Redpanda running first:
    docker compose up -d redpanda   (wait ~10 s for healthy)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# handler.py lives in the same directory
sys.path.insert(0, str(Path(__file__).parent))
from handler import TnRedpandaHandler, topic_for

_DEMO_PROJECT = "00000000-0000-0000-0000-000000000001"

_EVENT_TYPES = [
    "transaction.review",
    "transaction.approved",
    "transaction.flagged",
    "session.started",
    "portfolio.rebalanced",
]


def fake_envelope(project_id: str, seq: int) -> tuple[dict, bytes]:
    """Build a plausible (demo, unsigned) TN envelope."""
    now = datetime.now(timezone.utc).isoformat()
    event_type = _EVENT_TYPES[seq % len(_EVENT_TYPES)]
    # row_hash would be computed by the chain in a real TN flow;
    # use a uuid hex stand-in for the demo.
    row_hash = "sha256:" + uuid.uuid4().hex + uuid.uuid4().hex[:32]
    env: dict = {
        "device_identity": "did:key:z6Mk" + "d" * 40,
        "timestamp": now,
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "level": "info",
        "sequence": seq,
        "prev_hash": "sha256:" + "0" * 64,
        "row_hash": row_hash,
        "signature": "Ed25519:DEMO==",
        "public_fields": {
            "project_id": project_id,
            "agent": "wealth-advisor-demo",
            "seq": seq,
        },
    }
    return env, (json.dumps(env) + "\n").encode()


def main() -> None:
    ap = argparse.ArgumentParser(description="Produce TN envelopes to Redpanda")
    ap.add_argument("--bootstrap", default="localhost:9092", help="Kafka bootstrap servers")
    ap.add_argument("--project-id", default=_DEMO_PROJECT, help="TN project UUID")
    ap.add_argument("--count", type=int, default=10, help="Number of envelopes to produce")
    ap.add_argument("--delay-ms", type=float, default=100, help="ms between envelopes")
    args = ap.parse_args()

    outbox = Path("/tmp/tn-redpanda-demo-outbox")
    outbox.mkdir(parents=True, exist_ok=True)

    handler = TnRedpandaHandler(
        "demo-producer",
        outbox,
        bootstrap=args.bootstrap,
        project_id=args.project_id,
    )

    topic = topic_for(args.project_id)
    print(f"bootstrap : {args.bootstrap}")
    print(f"topic     : {topic}")
    print(f"envelopes : {args.count}")
    print()

    for i in range(args.count):
        env, raw = fake_envelope(args.project_id, i)
        handler.emit(env, raw)
        print(
            f"  [{i:02d}] queued  "
            f"event_id={env['event_id'][:8]}…  "
            f"type={env['event_type']}"
        )
        time.sleep(args.delay_ms / 1000)

    print("\nFlushing outbox to broker…")
    handler.close(timeout=30)
    print(f"\nDone — {args.count} envelopes sent.")
    print(f"\nNow run:  python demo_consume.py --project-id {args.project_id}")


if __name__ == "__main__":
    main()
