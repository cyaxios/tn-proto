"""Live Kafka test against Confluent Cloud.

Reads credentials from C:/codex/content_platform/.env (or CP_TN_* env
vars if already set). Creates `tn.test.<run-id>` topic, produces a few
attested log entries through the full tn.log + handler stack, consumes
them back, verifies each envelope matches what we sent, then deletes
the topic (best-effort).

Skips gracefully if:
  - The .env file isn't readable.
  - confluent-kafka isn't installed.
  - The broker refuses the connection.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# --- 1. Load .env ---------------------------------------------------------
def _load_env(env_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not env_path.exists():
        return out
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # strip matching quotes if any
        v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        out[k.strip()] = v
    return out


_ENV_CANDIDATES = [
    Path("C:/codex/content_platform/.env"),  # Windows native
    Path("/mnt/c/codex/content_platform/.env"),  # WSL
    Path(__file__).resolve().parents[3] / ".env",  # repo root (if nested)
]
_ENV_FILE = next((p for p in _ENV_CANDIDATES if p.exists()), _ENV_CANDIDATES[0])
_env = _load_env(_ENV_FILE)
for k, v in _env.items():
    os.environ.setdefault(k, v)


def _req(name: str) -> str | None:
    return os.environ.get(name) or None


BOOTSTRAP = _req("CP_TN_REDPANDA_BOOTSTRAP") or _req("CP_TN_KAFKA_BOOTSTRAP")
USERNAME = _req("CP_TN_KAFKA_SASL_USERNAME")
PASSWORD = _req("CP_TN_KAFKA_SASL_PASSWORD")
MECHANISM = _req("CP_TN_KAFKA_SASL_MECHANISM") or "PLAIN"
CLIENT_ID = _req("CP_TN_KAFKA_CLIENT_ID") or "tn-protocol-live-test"


def _have_creds() -> bool:
    return bool(BOOTSTRAP and USERNAME and PASSWORD)


def _have_kafka_lib() -> bool:
    try:
        import confluent_kafka  # noqa: F401

        return True
    except ImportError:
        return False


# --- 2. Main test ----------------------------------------------------------


def main() -> int:
    if not _have_creds():
        print(f"SKIP: Kafka credentials not found in .env (looked in {_ENV_FILE})")
        return 0
    if not _have_kafka_lib():
        print("SKIP: confluent-kafka not installed (pip install 'tn-protocol[kafka]')")
        return 0

    from confluent_kafka import Consumer
    from confluent_kafka.admin import AdminClient, NewTopic

    import tn

    run_id = uuid.uuid4().hex[:8]
    topic_base = f"tn.test.{run_id}"
    topic_ping = f"{topic_base}.ping"  # {event_type} template -> this

    # Common auth config used for admin + consumer (producer uses handler YAML)
    auth_conf = {
        "bootstrap.servers": BOOTSTRAP,
        "security.protocol": "SASL_SSL",
        "sasl.mechanisms": MECHANISM,
        "sasl.username": USERNAME,
        "sasl.password": PASSWORD,
    }

    # --- Pre-create topic (Confluent Cloud usually disables auto-create) ---
    admin = AdminClient(auth_conf)
    fut = admin.create_topics([NewTopic(topic_ping, num_partitions=1, replication_factor=3)])
    for t, f in fut.items():
        try:
            f.result(timeout=30)
            print(f"created topic: {t}")
        except Exception as e:
            # already exists is fine; anything else is a setup failure.
            msg = str(e)
            if "already exists" in msg.lower() or "TOPIC_ALREADY_EXISTS" in msg:
                print(f"topic exists: {t}")
            else:
                print(f"FAIL: could not create topic {t}: {e}")
                return 1

    # --- 3. Write a YAML that fans out to both a file AND Kafka ------------
    with tempfile.TemporaryDirectory(prefix="tnkflive_") as td:
        ws = Path(td)
        yaml_path = ws / "tn.yaml"

        # Bootstrap a base ceremony first (creates keys, writes YAML).
        tn.init(yaml_path)
        base_yaml = yaml_path.read_text(encoding="utf-8")
        kafka_block = f"""
handlers:
  - name: local_file
    kind: file.rotating
    path: ./.tn/logs/tn.ndjson
    max_bytes: 1048576
    backup_count: 2
  - name: confluent
    kind: kafka
    bootstrap: {BOOTSTRAP}
    topic: "{topic_base}.{{event_type}}"
    client_id: {CLIENT_ID}
    compression_type: zstd
    acks: all
    sasl:
      mechanism: {MECHANISM}
      user: env:CP_TN_KAFKA_SASL_USERNAME
      pass: env:CP_TN_KAFKA_SASL_PASSWORD
    filter:
      event_type:
        starts_with: "ping"
"""
        yaml_path.write_text(base_yaml + kafka_block, encoding="utf-8")

        tn.flush_and_close()
        tn.init(yaml_path)

        # --- 4. Produce 3 attested "ping" events via tn.log ----------------
        sent_ids: list[str] = []
        for i in range(3):
            env = tn.log("ping", seq=i, run_id=run_id, note="live kafka test")
            sent_ids.append(env["event_id"])
        print(f"produced 3 events to {topic_ping}")

        # Force drain of the async outbox before cleaning up.
        tn.flush_and_close()

    # --- 5. Consume them back ---------------------------------------------
    consumer_conf = {
        **auth_conf,
        "group.id": f"tn-protocol-test-{run_id}",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }
    consumer = Consumer(consumer_conf)
    consumer.subscribe([topic_ping])

    received: list[dict] = []
    deadline = time.time() + 30
    while time.time() < deadline and len(received) < 3:
        msg = consumer.poll(timeout=2.0)
        if msg is None:
            continue
        if msg.error():
            print(f"WARN: consumer error: {msg.error()}")
            continue
        received.append(json.loads(msg.value()))
    consumer.close()

    print(f"consumed {len(received)}/3 messages back from {topic_ping}")
    ok = len(received) == 3
    got_ids = {e.get("event_id") for e in received}
    if set(sent_ids) != got_ids:
        print(f"FAIL: event_id mismatch\n  sent={sent_ids}\n  got={sorted(got_ids)}")
        ok = False
    else:
        print(f"event_ids match: {sent_ids}")

    # Every round-tripped envelope should still have a valid signature.
    from tn.signing import DeviceKey, _signature_from_b64

    sig_ok = 0
    for env in received:
        if DeviceKey.verify(
            env["did"], env["row_hash"].encode("ascii"), _signature_from_b64(env["signature"])
        ):
            sig_ok += 1
    print(f"signatures verify after Kafka round-trip: {sig_ok}/{len(received)}")
    if sig_ok != len(received):
        ok = False

    # --- 6. Cleanup: delete the test topic -------------------------------
    try:
        fut = admin.delete_topics([topic_ping])
        for t, f in fut.items():
            f.result(timeout=30)
            print(f"deleted topic: {t}")
    except Exception as e:
        print(f"WARN: topic cleanup failed (harmless): {e}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
