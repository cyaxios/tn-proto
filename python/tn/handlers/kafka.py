"""Kafka handler via confluent-kafka.

Gated behind the `tn-protocol[kafka]` extra so the base wheel stays lean.
Topic names are templated on `event_type` (already sanitized upstream) and
the result is checked against Apache's topic-name rules before publish.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .base import AsyncHandler

# Apache Kafka topic rules: [a-zA-Z0-9._-], max 249, not "." or "..".
_TOPIC_RE = re.compile(r"^[A-Za-z0-9._-]{1,249}$")


def _resolve(value: str | None) -> str | None:
    """Resolve `env:NAME` to os.environ[NAME]; pass anything else through."""
    if not value:
        return value
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value


def _validate_topic(topic: str) -> str:
    if topic in (".", ".."):
        raise ValueError(f"kafka: topic {topic!r} reserved")
    if not _TOPIC_RE.match(topic):
        raise ValueError(
            f"kafka: topic {topic!r} contains illegal chars (allowed: a-z A-Z 0-9 . _ -)"
        )
    return topic


class KafkaHandler(AsyncHandler):
    """Fan out to a Confluent-Cloud-style Kafka cluster.

    YAML:
        kind: kafka
        bootstrap: pkc-xxx.confluent.cloud:9092
        topic:     "tn.{event_type}"
        sasl:
          mechanism: PLAIN
          user: env:CONFLUENT_KEY
          pass: env:CONFLUENT_SECRET
        # optional extras
        client_id: tn-protocol-sdk
        compression_type: zstd
        acks: all
    """

    def __init__(
        self,
        name: str,
        *,
        outbox_path: str | Path,
        bootstrap: str,
        topic: str,
        sasl: dict[str, Any] | None = None,
        client_id: str = "tn-protocol",
        compression_type: str = "zstd",
        acks: str = "all",
        filter_spec: dict[str, Any] | None = None,
        **extra_config: Any,
    ):
        try:
            from confluent_kafka import Producer
        except ImportError as e:
            raise ImportError(
                "KafkaHandler requires confluent-kafka. "
                "Install via `pip install 'tn-protocol[kafka]'`."
            ) from e

        super().__init__(name, outbox_path, filter_spec=filter_spec)
        self._topic_tmpl = topic

        conf: dict[str, Any] = {
            "bootstrap.servers": bootstrap,
            "client.id": client_id,
            "compression.type": compression_type,
            "acks": acks,
            "enable.idempotence": True,
        }
        if sasl:
            conf.update(
                {
                    "security.protocol": "SASL_SSL",
                    "sasl.mechanisms": sasl.get("mechanism", "PLAIN"),
                    "sasl.username": _resolve(sasl.get("user", "")),
                    "sasl.password": _resolve(sasl.get("pass", "")),
                }
            )
        conf.update(extra_config)
        self._producer = Producer(conf)

    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        topic = _validate_topic(self._topic_tmpl.format(event_type=envelope["event_type"]))
        err = {"v": None}

        def _dr(e, _msg):
            if e is not None:
                err["v"] = e

        self._producer.produce(
            topic=topic,
            value=raw_line,
            key=envelope["event_id"].encode("utf-8"),
            on_delivery=_dr,
        )
        # Block until broker acks (or raises). acks=all + idempotence makes
        # this reliable. 30s upper bound aligns with outbox backoff ceiling.
        self._producer.flush(timeout=30.0)
        if err["v"] is not None:
            raise RuntimeError(f"kafka delivery: {err['v']}")

    def close(self, *, timeout: float = 30.0) -> None:
        super().close(timeout=timeout)
        self._producer.flush(timeout=timeout)
