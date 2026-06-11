"""Kafka handler — structural tests.

These run without `confluent-kafka` installed. They verify:
  - Missing extras raise a clear ImportError at import_module time.
  - With a monkey-patched Producer, the publish path actually
    runs: outbox queue -> _publish() -> (mocked) broker call.
"""

from __future__ import annotations

import sys
import tempfile
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# ---------------------------------------------------------------------
# 1. Clear error when the optional extra is missing
# ---------------------------------------------------------------------


def test_kafka_missing_extra_raises():
    # Ensure confluent_kafka is unimportable for this test.
    sys.modules.pop("confluent_kafka", None)
    types.ModuleType("confluent_kafka")
    # Mark as a blocker by making `import confluent_kafka` succeed (so our
    # try/import doesn't find it truly absent) — actually we want it
    # MISSING. Easier: just make sure it isn't there; if the test env does
    # have it (e.g. future CI), skip.
    try:
        import confluent_kafka  # noqa: F401

        print("kafka extra already installed — skipping missing-extra test")
        return
    except ImportError:
        pass

    from tn.handlers.kafka import KafkaHandler

    try:
        KafkaHandler(
            name="fail",
            outbox_path="/tmp/tn-nowhere",
            bootstrap="localhost:9092",
            topic="x.{event_type}",
        )
    except ImportError as e:
        assert "confluent-kafka" in str(e), e
    else:
        raise AssertionError("expected ImportError without confluent-kafka")
    print("kafka missing extra: clear ImportError raised")


# ---------------------------------------------------------------------
# 2. Happy-path with a monkey-patched broker
# ---------------------------------------------------------------------


class _FakeKafkaProducer:
    def __init__(self, conf):
        self.conf = conf
        self.produced: list[tuple[str, bytes]] = []

    def produce(self, topic, value, key=None, on_delivery=None):
        self.produced.append((topic, value))
        if on_delivery is not None:
            on_delivery(None, None)  # err=None, msg=None

    def flush(self, timeout=None):
        return 0


def test_kafka_happy_path_with_fake_producer(monkeypatch=None):
    # Inject a fake confluent_kafka module into sys.modules before the
    # handler imports it.
    fake_mod = types.ModuleType("confluent_kafka")
    fake_mod.Producer = _FakeKafkaProducer  # type: ignore[attr-defined]
    sys.modules["confluent_kafka"] = fake_mod

    # Force re-import of the handler if it already loaded.
    for k in list(sys.modules):
        if k.startswith("tn.handlers.kafka"):
            del sys.modules[k]
    from tn.handlers.kafka import KafkaHandler

    with tempfile.TemporaryDirectory(prefix="tnkf_") as td:
        h = KafkaHandler(
            name="fake-kafka",
            outbox_path=Path(td) / "kafka-outbox",
            bootstrap="fake:9092",
            topic="tn.{event_type}",
        )
        # The handler's base class auto-started a worker; emit and wait.
        h.emit(
            {"event_type": "order.created", "event_id": "e1"},
            b'{"event_id":"e1"}\n',
        )
        h.emit(
            {"event_type": "auth.login", "event_id": "e2"},
            b'{"event_id":"e2"}\n',
        )
        for _ in range(40):
            if len(h._producer.produced) == 2:  # type: ignore[attr-defined]
                break
            time.sleep(0.05)
        h.close(timeout=2.0)

        produced = h._producer.produced  # type: ignore[attr-defined]
        topics = sorted(t for t, _ in produced)
        assert topics == ["tn.auth.login", "tn.order.created"], topics
        print(f"kafka happy path: 2/2 produced to {topics}")


def main() -> int:
    test_kafka_missing_extra_raises()
    test_kafka_happy_path_with_fake_producer()
    print("\nkafka stubs: all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
