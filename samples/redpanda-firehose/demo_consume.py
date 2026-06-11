"""Redpanda firehose consumer demo.

Reads from the project firehose topic, decrypts each frame with the
Phase-A stub BEK, and prints the envelope fields.

    python demo_consume.py                          # local Redpanda, demo project
    python demo_consume.py --from-offset latest     # tail only new frames
    python demo_consume.py --bootstrap tn-redpanda.fly.dev:9092

Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from handler import _stub_bek, decrypt_frame, topic_for

_DEMO_PROJECT = "00000000-0000-0000-0000-000000000001"


def main() -> None:
    ap = argparse.ArgumentParser(description="Consume TN envelopes from Redpanda")
    ap.add_argument("--bootstrap", default="localhost:9092")
    ap.add_argument("--project-id", default=_DEMO_PROJECT)
    ap.add_argument("--key-id", default=None)
    ap.add_argument(
        "--from-offset",
        choices=["earliest", "latest"],
        default="earliest",
        help="earliest = full history; latest = tail only",
    )
    ap.add_argument("--group-id", default=None, help="Override consumer group ID")
    args = ap.parse_args()

    try:
        from kafka import KafkaConsumer
        from kafka.errors import NoBrokersAvailable
    except ImportError:
        raise SystemExit("pip install kafka-python")

    topic = topic_for(args.project_id)
    bek = _stub_bek(args.project_id, args.key_id)
    group_id = args.group_id or f"tn-demo-consumer.{args.project_id[:8]}"

    print(f"bootstrap  : {args.bootstrap}")
    print(f"topic      : {topic}")
    print(f"group      : {group_id}")
    print(f"offset     : {args.from_offset}")
    print("Ctrl+C to stop.\n")

    username = os.environ.get("RP_USERNAME")
    password = os.environ.get("RP_PASSWORD")

    kwargs: dict[str, Any] = dict(
        bootstrap_servers=args.bootstrap,
        group_id=group_id,
        auto_offset_reset=args.from_offset,
        enable_auto_commit=True,
        consumer_timeout_ms=15000,
    )
    if username:
        kwargs.update(
            security_protocol="SASL_SSL",
            sasl_mechanism="SCRAM-SHA-256",
            sasl_plain_username=username,
            sasl_plain_password=password,
        )

    try:
        consumer = KafkaConsumer(topic, **kwargs)
    except NoBrokersAvailable:
        raise SystemExit(
            f"Cannot reach Redpanda at {args.bootstrap}.\n"
            "  Local: docker compose up -d redpanda\n"
            "  Cloud: set RP_USERNAME and RP_PASSWORD env vars"
        )

    received = 0
    try:
        # Iterating over the consumer respects consumer_timeout_ms — it
        # raises StopIteration after the idle timeout, giving us a clean
        # exit after a quiet period as well as on Ctrl+C.
        for msg in consumer:
            received += 1
            _handle(msg, bek, args.project_id, args.key_id)
        print(f"\nIdle timeout — {received} messages received.")
    except KeyboardInterrupt:
        print(f"\nStopped — {received} messages received.")
    finally:
        consumer.close()


def _handle(msg: Any, bek: bytes, project_id: str, key_id: str | None) -> None:
    headers = {k: v.decode(errors="replace") for k, v in (msg.headers or [])}
    event_type = headers.get("tn-event-type", "")
    event_id   = headers.get("tn-event-id", "")
    ts         = headers.get("tn-ts", "")
    row_hash   = headers.get("tn-row-hash", "")  # included in print below

    try:
        plain = decrypt_frame(bek, project_id, key_id, event_type, msg.value)
        envelope = json.loads(plain)
        tag = "OK"
    except Exception as exc:
        envelope = {}
        tag = f"ERR({exc})"

    print(
        f"  p={msg.partition} off={msg.offset:6d}"
        f"  id={event_id[:8]}…"
        f"  type={event_type:<28}"
        f"  ts={ts[11:19]}"   # HH:MM:SS portion
        f"  rh={row_hash[7:15]}…"  # sha256: prefix stripped
        f"  [{tag}]"
    )
    pf = envelope.get("public_fields") or {}
    if "content" in pf:
        print(f"    >> {pf['content']!r}")
    elif pf:
        print(f"    public_fields: {pf}")


if __name__ == "__main__":
    main()
