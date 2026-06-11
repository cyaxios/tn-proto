"""Throughput benchmark: tn→disk vs tn→Redpanda vs raw→Redpanda.

Three configurations:
  file   — tn.info() fanning out to FileRotatingHandler only
  tn-rp  — tn.info() fanning out to KafkaHandler only (outbox + encrypt)
  raw-rp — confluent_kafka.Producer.produce() directly, zero TN overhead

Profile: telemetry (no signing, no chaining — minimum per-emit overhead).

    python bench.py
    python bench.py --count 1000

Set before running:
    export RP_USERNAME=tn-firehose
    export RP_PASSWORD=PTkWReJpXJ10SA4O20M9oBNiwoMDL5
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

BOOTSTRAP = "d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com:9092"
TOPIC     = "tn.firehose.00000000-0000-0000-0000-000000000001"
TN_DIR    = Path(__file__).parent / "tn_bench"

PAYLOAD_SIZES = [100, 500, 1_000, 3_000]

# Silence TN's own console output so it doesn't skew timing
logging.getLogger("tn").setLevel(logging.CRITICAL)
os.environ.setdefault("TN_NO_STDOUT", "1")


def _payload(n: int) -> str:
    base = "abcdefghijklmnopqrstuvwxyz0123456789"
    return (base * ((n // len(base)) + 1))[:n]


def _kafka_conf() -> dict:
    conf: dict = {
        "bootstrap.servers": BOOTSTRAP,
        "compression.type": "gzip",
        "acks": "all",
        "enable.idempotence": True,
    }
    conf.update({
        "security.protocol": "SASL_SSL",
        "sasl.mechanisms": "SCRAM-SHA-256",
        "sasl.username": os.environ["RP_USERNAME"],
        "sasl.password": os.environ["RP_PASSWORD"],
    })
    return conf


# ──────────────────────────────────────────────
# Sink implementations
# ──────────────────────────────────────────────

def _bench_file(count: int, payload: str) -> tuple[float, float]:
    import tn
    import tn.logger as _lg
    from tn.handlers.file import FileRotatingHandler

    TN_DIR.mkdir(parents=True, exist_ok=True)
    tn.init(project_dir=str(TN_DIR), profile="telemetry", stdout=False)

    # Keep only file handlers
    _lg._runtime.handlers[:] = [
        h for h in _lg._runtime.handlers if isinstance(h, FileRotatingHandler)
    ]

    t0 = time.perf_counter()
    for i in range(count):
        tn.info("bench.message", payload=payload, seq=i)
    emit_ms = (time.perf_counter() - t0) * 1000

    flush_t0 = time.perf_counter()
    tn.flush_and_close()
    return emit_ms, (time.perf_counter() - flush_t0) * 1000


def _bench_tn_rp(count: int, payload: str) -> tuple[float, float]:
    import tn
    from tn.handlers.kafka import KafkaHandler
    import tn.logger as _lg
    from tn.handlers.file import FileRotatingHandler

    TN_DIR.mkdir(parents=True, exist_ok=True)
    kh = KafkaHandler(
        "rp",
        outbox_path=TN_DIR / "outbox" / "rp",
        bootstrap=BOOTSTRAP,
        topic=TOPIC,
        sasl={
            "mechanism": "SCRAM-SHA-256",
            "user": os.environ["RP_USERNAME"],
            "pass": os.environ["RP_PASSWORD"],
        },
        compression_type="gzip",
        acks="all",
    )
    tn.init(project_dir=str(TN_DIR), profile="telemetry", stdout=False,
            extra_handlers=[kh])

    # Keep only the kafka handler — no file
    _lg._runtime.handlers[:] = [
        h for h in _lg._runtime.handlers
        if not isinstance(h, FileRotatingHandler)
    ]

    t0 = time.perf_counter()
    for i in range(count):
        tn.info("bench.message", payload=payload, seq=i)
    emit_ms = (time.perf_counter() - t0) * 1000

    flush_t0 = time.perf_counter()
    tn.flush_and_close()
    return emit_ms, (time.perf_counter() - flush_t0) * 1000


def _bench_sync_rp(count: int, payload: str) -> tuple[float, float]:
    """tn.info() → _publish() direct — no SQLite, blocks per-message on broker ack."""
    import tn
    import tn.logger as _lg
    from tn.handlers.file import FileRotatingHandler
    from tn.handlers.kafka import KafkaHandler

    TN_DIR.mkdir(parents=True, exist_ok=True)
    kh = KafkaHandler(
        "rp-sync",
        outbox_path=TN_DIR / "outbox" / "rp-sync",
        bootstrap=BOOTSTRAP,
        topic=TOPIC,
        sasl={"mechanism": "SCRAM-SHA-256",
              "user": os.environ["RP_USERNAME"],
              "pass": os.environ["RP_PASSWORD"]},
        compression_type="gzip",
        acks="all",
    )
    # Bypass the outbox: call _publish() directly on the calling thread.
    kh.emit = lambda envelope, raw_line: kh._publish(envelope, raw_line)

    tn.init(project_dir=str(TN_DIR), profile="telemetry", stdout=False,
            extra_handlers=[kh])
    _lg._runtime.handlers[:] = [
        h for h in _lg._runtime.handlers
        if not isinstance(h, FileRotatingHandler)
    ]

    t0 = time.perf_counter()
    for i in range(count):
        tn.info("bench.message", payload=payload, seq=i)
    emit_ms = (time.perf_counter() - t0) * 1000

    flush_t0 = time.perf_counter()
    tn.flush_and_close()
    return emit_ms, (time.perf_counter() - flush_t0) * 1000


def _bench_batch_rp(count: int, payload: str) -> tuple[float, float]:
    """tn.info() → produce()+poll(0) — no SQLite, no per-message ack, single flush at end."""
    import tn
    import tn.logger as _lg
    from tn.handlers.file import FileRotatingHandler
    from tn.handlers.kafka import KafkaHandler
    from tn.handlers.kafka import _validate_topic

    TN_DIR.mkdir(parents=True, exist_ok=True)
    kh = KafkaHandler(
        "rp-batch",
        outbox_path=TN_DIR / "outbox" / "rp-batch",
        bootstrap=BOOTSTRAP,
        topic=TOPIC,
        sasl={"mechanism": "SCRAM-SHA-256",
              "user": os.environ["RP_USERNAME"],
              "pass": os.environ["RP_PASSWORD"]},
        compression_type="gzip",
        acks="all",
    )

    def _batch_emit(envelope: dict, raw_line: bytes) -> None:
        topic = _validate_topic(kh._topic_tmpl.format(event_type=envelope["event_type"]))
        kh._producer.produce(topic, value=raw_line,
                             key=envelope["event_id"].encode("utf-8"))
        kh._producer.poll(0)  # non-blocking — let librdkafka batch

    kh.emit = _batch_emit

    tn.init(project_dir=str(TN_DIR), profile="telemetry", stdout=False,
            extra_handlers=[kh])
    _lg._runtime.handlers[:] = [
        h for h in _lg._runtime.handlers
        if not isinstance(h, FileRotatingHandler)
    ]

    t0 = time.perf_counter()
    for i in range(count):
        tn.info("bench.message", payload=payload, seq=i)
    emit_ms = (time.perf_counter() - t0) * 1000

    flush_t0 = time.perf_counter()
    kh._producer.flush(timeout=60.0)
    tn.flush_and_close()
    return emit_ms, (time.perf_counter() - flush_t0) * 1000


def _bench_phases(count: int, payload: str) -> tuple[float, float, float]:
    """Three clean phases, nothing else:
      x — tn.info() seals the envelope (chain + encrypt). log=/dev/null, no handlers.
      y — produce() queues sealed bytes into librdkafka. Non-blocking.
      z — flush() waits for all broker acks.
    """
    import tn
    import tn.logger as _lg
    import shutil
    import yaml
    from pathlib import Path
    from tn.handlers.base import TNHandler
    from tn.handlers.kafka import _validate_topic
    from confluent_kafka import Producer

    phasedir = TN_DIR.parent / "tn_bench_phases"
    if phasedir.exists():
        shutil.rmtree(phasedir)
    phasedir.mkdir(parents=True)

    # In-memory capture handler — collects sealed raw_lines, zero I/O
    sealed: list[bytes] = []

    class Capture(TNHandler):
        def __init__(self) -> None:
            super().__init__("capture")
        def emit(self, envelope: dict, raw_line: bytes) -> None:
            sealed.append(raw_line)
        def resolved_address(self) -> None:  # type: ignore[override]
            return None

    # The log_path=/dev/null kwarg is dropped during project creation, so:
    # 1. create the ceremony normally, 2. patch logs.path -> /dev/null and
    # drop the file.rotating handler in the yaml, 3. re-init so Rust opens
    # /dev/null directly. Verified: rust log_path() == /dev/null, no file made.
    tn.init(project_dir=str(phasedir), profile="telemetry", stdout=False)
    yaml_p = _lg._runtime.cfg.yaml_path
    tn.flush_and_close()

    doc = yaml.safe_load(yaml_p.read_text())
    doc["logs"]["path"] = "/dev/null"
    doc["handlers"] = [h for h in doc["handlers"] if h.get("kind") != "file.rotating"]
    # NOTE: do NOT raise log_level above info — tn.info() is INFO level and
    # would be filtered out entirely (emit becomes a no-op). The per-emit
    # console lines are stdout from the logging facade, not the seal itself.
    yaml_p.write_text(yaml.safe_dump(doc, sort_keys=False))

    # ── x: TN protocol only — Rust seals to /dev/null, Capture grabs bytes ──
    tn.init(load=str(yaml_p), stdout=False, extra_handlers=[Capture()])
    assert tn._dispatch_rt._rt.log_path() == "/dev/null", "log NOT redirected!"

    t_x = time.perf_counter()
    for i in range(count):
        tn.info("bench.message", payload=payload, seq=i)
    x_ms = (time.perf_counter() - t_x) * 1000
    tn.flush_and_close()

    # Prove no disk write happened
    logf = phasedir / ".tn" / "default" / "logs" / "tn.ndjson"
    assert not logf.exists(), f"disk write leaked to {logf}"

    # ── y: produce() only ────────────────────────────────────────────
    prod = Producer(_kafka_conf())
    topic = _validate_topic(TOPIC)

    t_y = time.perf_counter()
    for raw in sealed:
        prod.produce(topic, value=raw)
        prod.poll(0)
    y_ms = (time.perf_counter() - t_y) * 1000

    # ── z: flush — wait for all broker acks ──────────────────────────
    t_z = time.perf_counter()
    prod.flush(timeout=60.0)
    z_ms = (time.perf_counter() - t_z) * 1000

    return x_ms, y_ms, z_ms


def _bench_batch_rp_nodisk(count: int, payload: str) -> tuple[float, float]:
    """batch-rp with log_path=/dev/null — Rust writes to /dev/null (instant discard).

    Uses a fresh project dir each run so tn.init() creates a new ceremony
    with log_path=/dev/null baked in (the kwarg is only honoured at creation
    time, not when loading an existing yaml). Rust still runs the full
    protocol pipeline; the file append just goes to the kernel's bit bucket.
    """
    import tn
    from tn.handlers.kafka import KafkaHandler, _validate_topic
    import shutil

    # Fresh dir each run so no existing yaml — log_path kwarg is honoured
    nodisk_dir = TN_DIR.parent / "tn_bench_nodisk"
    if nodisk_dir.exists():
        shutil.rmtree(nodisk_dir)
    nodisk_dir.mkdir(parents=True)

    kh = KafkaHandler(
        "rp-nodisk",
        outbox_path=nodisk_dir / "outbox",
        bootstrap=BOOTSTRAP,
        topic=TOPIC,
        sasl={"mechanism": "SCRAM-SHA-256",
              "user": os.environ["RP_USERNAME"],
              "pass": os.environ["RP_PASSWORD"]},
        compression_type="gzip",
        acks="all",
    )

    def _batch_emit(envelope: dict, raw_line: bytes) -> None:
        topic = _validate_topic(kh._topic_tmpl.format(event_type=envelope["event_type"]))
        kh._producer.produce(topic, value=raw_line,
                             key=envelope["event_id"].encode("utf-8"))
        kh._producer.poll(0)

    kh.emit = _batch_emit

    tn.init(project_dir=str(nodisk_dir), profile="telemetry", stdout=False,
            log_path="/dev/null", extra_handlers=[kh])

    t0 = time.perf_counter()
    for i in range(count):
        tn.info("bench.message", payload=payload, seq=i)
    emit_ms = (time.perf_counter() - t0) * 1000

    flush_t0 = time.perf_counter()
    kh._producer.flush(timeout=60.0)
    tn.flush_and_close()
    return emit_ms, (time.perf_counter() - flush_t0) * 1000


def _bench_raw_rp(count: int, payload: str) -> tuple[float, float]:
    """Direct confluent_kafka.Producer — no TN, no outbox, no encryption."""
    from confluent_kafka import Producer

    prod = Producer(_kafka_conf())
    raw = (payload + "\n").encode()

    errors = []
    def _dr(err, _msg):
        if err:
            errors.append(err)

    t0 = time.perf_counter()
    for i in range(count):
        prod.produce(TOPIC, value=raw, on_delivery=_dr)
        prod.poll(0)  # trigger callbacks without blocking
    emit_ms = (time.perf_counter() - t0) * 1000

    flush_t0 = time.perf_counter()
    prod.flush(timeout=60.0)
    flush_ms = (time.perf_counter() - flush_t0) * 1000

    if errors:
        print(f"  WARN: {len(errors)} delivery errors")
    return emit_ms, flush_ms


# ──────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────

SINKS = {
    "file":           _bench_file,
    "tn-rp":          _bench_tn_rp,
    "sync-rp":        _bench_sync_rp,
    "batch-rp":       _bench_batch_rp,
    "batch-rp-nodisk":_bench_batch_rp_nodisk,
    "raw-rp":         _bench_raw_rp,
}

# phases is handled separately — returns (x, y, z) not (emit, flush)
PHASES_SINK = "phases"


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--sizes", nargs="+", type=int, default=PAYLOAD_SIZES)
    ap.add_argument("--sinks", nargs="+", choices=list(SINKS),
                    default=["file", "tn-rp", "sync-rp", "batch-rp", "raw-rp"])
    ap.add_argument("--phases", action="store_true",
                    help="Isolate x=seal / y=produce / z=broker-ack")
    args = ap.parse_args()

    if args.phases:
        print(f"\n{'bytes':>6} {'count':>6}"
              f" {'x_seal_ms':>10} {'y_produce_ms':>13} {'z_ack_ms':>10}"
              f" {'total_ms':>10} {'x/msg':>8} {'y/msg':>8} {'z/msg':>8}")
        print("─" * 92)
        for size in args.sizes:
            payload = _payload(size)
            x, y, z = _bench_phases(args.count, payload)
            total = x + y + z
            n = args.count
            print(
                f"{size:>6} {n:>6}"
                f" {x:>10.1f} {y:>13.1f} {z:>10.1f} {total:>10.1f}"
                f" {x/n:>8.3f} {y/n:>8.3f} {z/n:>8.3f}"
            )
        print()
        return

    print(f"\n{'sink':<8} {'bytes':>6} {'count':>6} {'emit_ms':>9} {'flush_ms':>9} {'total_ms':>9} {'ms/msg':>8}")
    print("─" * 66)

    for sink in args.sinks:
        fn = SINKS[sink]
        for size in args.sizes:
            payload = _payload(size)
            emit_ms, flush_ms = fn(args.count, payload)
            total_ms = emit_ms + flush_ms
            print(
                f"{sink:<8} {size:>6} {args.count:>6}"
                f" {emit_ms:>9.1f} {flush_ms:>9.1f}"
                f" {total_ms:>9.1f} {total_ms/args.count:>8.3f}"
            )
        print()


if __name__ == "__main__":
    main()
