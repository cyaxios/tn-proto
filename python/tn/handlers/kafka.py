"""Kafka handler via confluent-kafka.

Gated behind the `tn-proto[kafka]` extra so the base wheel stays lean.
Topic names are templated on `event_type` (already sanitized upstream) and
the result is checked against Apache's topic-name rules before publish.
"""

from __future__ import annotations

import atexit
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
        client_id: tn-proto-sdk
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
        client_id: str = "tn-proto",
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
                "Install via `pip install 'tn-proto[kafka]'`."
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
        # Store the consumer config separately so reader() can reuse it.
        # sasl.mechanisms → sasl_mechanism mapping differs between librdkafka
        # (confluent-kafka) and kafka-python; reader() uses kafka-python so
        # it translates below.
        self._bootstrap = bootstrap
        self._topic_fixed = topic  # may be a template; reader() only works for fixed topics
        self._sasl = sasl
        self._closed = False
        atexit.register(self._close_on_exit)

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

    # ------------------------------------------------------------------
    # Read-side contract
    #
    # INTENT (not yet wired into tn.read / tn.watch):
    #   tn.read() should auto-select its source from the active session's
    #   handler list, preferring a local file handler when one exists and
    #   falling back to this reader otherwise.  The caller never specifies
    #   a source; the session configuration decides.
    #
    #   When wired in:
    #     - resolved_address() is the identity key (file path for file
    #       handlers, kafka URI here) used by tn.read() to pick the source.
    #     - reader() yields raw sealed-envelope bytes, identical in shape
    #       to a line from the local .tn/logs/tn.ndjson file.  The decrypt
    #       + verify + key-matching layer above it is source-agnostic and
    #       unchanged.  Keys discovered via tn.absorb() automatically apply.
    #
    #   Same contract must land in the TS SDK (ts-sdk/src/handlers/kafka.ts)
    #   before tn.read() can be made source-aware end-to-end.
    # ------------------------------------------------------------------

    def resolved_address(self) -> str:
        return f"kafka://{self._bootstrap}/{self._topic_fixed}"

    def reader(
        self,
        *,
        group_id: str | None = None,
        since: str = "earliest",
    ):
        # TODO: wire into tn.read() / tn.watch() via TNHandler.reader() base
        # contract once base.py adds the method.  Until then, call directly
        # from read_real.py or any consumer that needs the Kafka source.
        try:
            from kafka import KafkaConsumer
        except ImportError as exc:
            raise ImportError("reader() requires kafka-python — pip install kafka-python") from exc

        kwargs: dict[str, Any] = dict(
            bootstrap_servers=self._bootstrap,
            group_id=group_id or f"tn-reader-{self.name}",
            auto_offset_reset=since,
            enable_auto_commit=False,
            consumer_timeout_ms=10000,
        )
        if self._sasl:
            # kafka-python uses sasl_mechanism (singular), not sasl.mechanisms
            kwargs.update(
                security_protocol="SASL_SSL",
                sasl_mechanism=self._sasl.get("mechanism", "PLAIN"),
                sasl_plain_username=_resolve(self._sasl.get("user", "")),
                sasl_plain_password=_resolve(self._sasl.get("pass", "")),
            )

        consumer = KafkaConsumer(self._topic_fixed, **kwargs)
        try:
            for msg in consumer:
                yield msg.value  # raw bytes — same shape as a line from tn.ndjson
        finally:
            consumer.close()

    def _close_on_exit(self) -> None:
        if not self._closed:
            try:
                self.close(timeout=30.0)
            except Exception:
                pass

    def close(self, *, timeout: float = 30.0) -> None:
        if self._closed:
            return
        self._closed = True
        super().close(timeout=timeout)
        self._producer.flush(timeout=timeout)
