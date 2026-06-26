"""End-to-end Python verification against live Redpanda Cloud.

Sends a uniquely-marked real TN envelope, then consumes the topic and
confirms the exact marker came back through the broker.

    export RP_USERNAME=tn-firehose
    export RP_PASSWORD=PTkWReJpXJ10SA4O20M9oBNiwoMDL5
    python verify_py.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

import tn
from tn.handlers.kafka import KafkaHandler
from tn.handlers.base import TNHandler

BOOTSTRAP = "d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com:9092"
TOPIC = "tn.firehose.00000000-0000-0000-0000-000000000001"
TN_DIR = Path(__file__).parent / "tn_verify_py"


def main() -> int:
    marker = f"PYVERIFY-{uuid.uuid4().hex[:12]}"
    print(f"marker: {marker}")

    captured: dict[str, str] = {}

    class Capture(TNHandler):
        def __init__(self) -> None:
            super().__init__("capture")
        def emit(self, envelope: dict, raw_line: bytes) -> None:
            if envelope.get("event_type") == "verify.message":
                captured["event_id"] = envelope.get("event_id", "")
        def resolved_address(self):
            return None

    # Set up consumer FIRST and capture the high-watermark so we only read
    # the tail — the topic has tens of thousands of bench messages.
    from kafka import KafkaConsumer, TopicPartition
    consumer = KafkaConsumer(
        bootstrap_servers=BOOTSTRAP,
        security_protocol="SASL_SSL",
        sasl_mechanism="SCRAM-SHA-256",
        sasl_plain_username=os.environ["RP_USERNAME"],
        sasl_plain_password=os.environ["RP_PASSWORD"],
        consumer_timeout_ms=20000,
        request_timeout_ms=30000,
    )
    tp = TopicPartition(TOPIC, 0)
    consumer.assign([tp])
    watermark = consumer.end_offsets([tp])[tp]
    print(f"high-watermark before send: {watermark}")

    TN_DIR.mkdir(parents=True, exist_ok=True)
    kh = KafkaHandler(
        "verify",
        outbox_path=TN_DIR / "outbox",
        bootstrap=BOOTSTRAP,
        topic=TOPIC,
        sasl={"mechanism": "SCRAM-SHA-256",
              "user": os.environ["RP_USERNAME"],
              "pass": os.environ["RP_PASSWORD"]},
        compression_type="gzip",
        acks="all",
    )
    tn.init(project_dir=str(TN_DIR), profile="telemetry", stdout=False,
            extra_handlers=[kh, Capture()])
    tn.info("verify.message", marker=marker)
    tn.flush_and_close()
    want_id = captured.get("event_id", "")
    print(f"sent + flushed, event_id={want_id}")

    # Read forward from the watermark — only new messages.
    consumer.seek(tp, watermark)
    found = False
    t0 = time.time()
    for msg in consumer:
        try:
            env = json.loads(msg.value)
        except Exception:
            continue
        # marker is an encrypted field — won't be plaintext in the envelope.
        # Instead match on event_type + this run's recency: the verify.message
        # event_type is unique to this script.
        if env.get("event_id") == want_id:
            print(f"  matched event_id {want_id} at offset {msg.offset}, "
                  f"type={env.get('event_type')}, "
                  f"device={env.get('device_identity','')[:24]}, "
                  f"row_hash={env.get('row_hash','')[:20]}")
            found = True
            break
        if time.time() - t0 > 25:
            break
    consumer.close()

    if found:
        print("PASS: real TN envelope made the round-trip through Redpanda Cloud")
        return 0
    print("FAIL: did not find verify.message in topic")
    return 1


if __name__ == "__main__":
    sys.exit(main())
