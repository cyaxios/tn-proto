"""Full log+read round-trip for the Python Kafka handler.

write: real tn.info() -> KafkaHandler -> Redpanda Cloud
read:  KafkaHandler.reader() -> raw sealed bytes back from the broker

Confirms the EXACT event_id written via the SDK comes back through the
handler's own reader() (not a hand-rolled consumer). The reader yields the
sealed envelope bytes — identical shape to a line in .tn/logs/tn.ndjson.

    export RP_USERNAME=tn-firehose
    export RP_PASSWORD=PTkWReJpXJ10SA4O20M9oBNiwoMDL5
    python roundtrip_py.py
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import tn
from tn.handlers.kafka import KafkaHandler
from tn.handlers.base import TNHandler

BOOTSTRAP = "d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com:9092"
TOPIC = "tn.firehose.00000000-0000-0000-0000-000000000001"
TN_DIR = Path(__file__).parent / "tn_roundtrip_py"


def main() -> int:
    marker = f"RTPY-{uuid.uuid4().hex[:12]}"
    captured: dict[str, str] = {}

    class Capture(TNHandler):
        def __init__(self) -> None:
            super().__init__("capture")
        def emit(self, envelope: dict, raw_line: bytes) -> None:
            if envelope.get("event_type") == "roundtrip.py":
                captured["event_id"] = envelope.get("event_id", "")
        def resolved_address(self):
            return None

    TN_DIR.mkdir(parents=True, exist_ok=True)
    kh = KafkaHandler(
        "rp",
        outbox_path=TN_DIR / "outbox",
        bootstrap=BOOTSTRAP,
        topic=TOPIC,
        sasl={"mechanism": "SCRAM-SHA-256",
              "user": os.environ["RP_USERNAME"],
              "pass": os.environ["RP_PASSWORD"]},
        compression_type="gzip",
        acks="all",
    )

    # ── WRITE via the real SDK ───────────────────────────────────────
    tn.init(project_dir=str(TN_DIR), profile="telemetry", stdout=False,
            extra_handlers=[kh, Capture()])
    tn.info("roundtrip.py", marker=marker)
    tn.flush_and_close()
    want_id = captured.get("event_id", "")
    print(f"WROTE event_id={want_id} marker={marker}")

    # ── READ via the handler's own reader() ──────────────────────────
    # Fresh handler instance — proves reader() stands alone from the writer.
    reader_h = KafkaHandler(
        "rp-reader",
        outbox_path=TN_DIR / "outbox_reader",
        bootstrap=BOOTSTRAP,
        topic=TOPIC,
        sasl={"mechanism": "SCRAM-SHA-256",
              "user": os.environ["RP_USERNAME"],
              "pass": os.environ["RP_PASSWORD"]},
    )
    print(f"reader source: {reader_h.resolved_address()}")

    found = None
    scanned = 0
    for raw in reader_h.reader(group_id=f"rt-py-{uuid.uuid4().hex[:8]}", since="earliest"):
        scanned += 1
        try:
            env = json.loads(raw)
        except Exception:
            continue
        if env.get("event_id") == want_id:
            found = env
            break

    if found is not None:
        print(f"READ matched after scanning {scanned} msgs: "
              f"event_type={found.get('event_type')}, "
              f"device={found.get('device_identity','')[:24]}")
        print("PASS: tn.info() -> Kafka -> handler.reader() round-trip works")
        return 0
    print(f"FAIL: event_id {want_id} not seen via reader() (scanned {scanned})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
