"""Send text using the real TN SDK.

First run mints the device identity and creates .tn-cloud/tn.yaml.
Subsequent runs reuse the same identity and chain.

    python send_real.py "Hello from real TN"
    python send_real.py --count 100 "bench message"
    python send_real.py --no-file "text"   # Redpanda-only, drop file handler

Set before running:
    export RP_USERNAME=tn-firehose
    export RP_PASSWORD=PTkWReJpXJ10SA4O20M9oBNiwoMDL5
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import tn
from tn.handlers.kafka import KafkaHandler

TN_DIR = Path(__file__).parent / "tn_cloud_demo"


def _redpanda_handler() -> KafkaHandler:
    return KafkaHandler(
        "redpanda-cloud",
        outbox_path=TN_DIR / "outbox" / "redpanda-cloud",
        bootstrap="d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com:9092",
        topic="tn.firehose.00000000-0000-0000-0000-000000000001",
        sasl={
            "mechanism": "SCRAM-SHA-256",
            "user": os.environ["RP_USERNAME"],
            "pass": os.environ["RP_PASSWORD"],
        },
        compression_type="gzip",
        acks="all",
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("text", nargs="?", default="Hello from real TN firehose")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--no-file", action="store_true",
                    help="Drop file handler — Redpanda-only throughput test")
    args = ap.parse_args()

    TN_DIR.mkdir(parents=True, exist_ok=True)

    # tn.init() mints the device on first run, loads it on subsequent runs.
    # extra_handlers adds Redpanda on top of the default file handler.
    tn.init(project_dir=str(TN_DIR), extra_handlers=[_redpanda_handler()])

    if args.no_file:
        # Access the live handler list and drop the file handler so only
        # Redpanda receives events — this is the "turn off file" benchmark.
        ctx = tn.get_context()
        handlers = ctx.get("handlers", [])
        before = len(handlers)
        handlers[:] = [h for h in handlers if "file" not in h.name.lower()]
        print(f"[no-file] dropped {before - len(handlers)} handler(s)")

    print(f"count={args.count}  text={args.text!r}")

    t0 = time.perf_counter()
    for i in range(args.count):
        tn.info("text.message", content=args.text, seq=i)
    emit_ms = (time.perf_counter() - t0) * 1000

    flush_t0 = time.perf_counter()
    tn.flush_and_close()
    flush_ms = (time.perf_counter() - flush_t0) * 1000

    print(f"emit   {emit_ms:.1f} ms  ({emit_ms/args.count:.2f} ms/call)")
    print(f"flush  {flush_ms:.1f} ms  (broker ack)")
    print(f"total  {emit_ms + flush_ms:.1f} ms")


if __name__ == "__main__":
    main()
