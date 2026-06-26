"""TN Redpanda firehose handler.

Drop-in replacement for TnFirehoseHandler that routes encrypted TN frames
to Redpanda (Kafka-compatible) instead of the CF Worker + R2 path.

Encryption is identical to the WS handler — nonce(12) || AES-256-GCM
ciphertext+tag — so any future Redpanda-aware reader is interoperable with
the existing WS-originated R2 archives.

Key difference: `event_id` becomes the Kafka message key, guaranteeing
that all frames for a given envelope always land on the same partition and
arrive in chain order.

Config shape (tn.yaml)::

    handlers:
      - kind: tn.redpanda
        name: stream
        bootstrap: "localhost:9092"
        project_id: 00000000-0000-0000-0000-000000000000
        key_id: fhk_<base32>   # optional Phase-A stub
        filter:
          level_in: [info, warning, error]

Install extra: pip install kafka-python
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Support both standalone use (no tn-proto installed) and full SDK use.
try:
    from tn.handlers.base import AsyncHandler as _AsyncHandler
except ImportError:
    # Minimal shim so the module can be imported in environments where
    # tn-proto isn't installed (e.g. a standalone consumer script).
    class _AsyncHandler:  # type: ignore[no-redef]
        def __init__(self, name: str, outbox_path: Any, *, filter_spec: Any = None, **_: Any) -> None:
            self.name = name
        def emit(self, envelope: Any, raw_line: bytes) -> None:
            self._publish(envelope, raw_line)
        def close(self, *, timeout: float = 30.0) -> None:
            self._final_flush()
        def _final_flush(self) -> None: ...

_log = logging.getLogger("tn.handlers.redpanda")

_PROJECT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Crypto helpers (standalone-importable for the consumer)
# ---------------------------------------------------------------------------

def _stub_bek(project_id: str, key_id: str | None) -> bytes:
    """Phase-A stub BEK — identical derivation to the WS handler."""
    seed = f"{project_id}:{key_id or 'stub-default'}".encode()
    return hashlib.sha256(b"phase-a-stub-bek-do-not-use-in-prod:" + seed).digest()


def topic_for(project_id: str) -> str:
    """Canonical topic name for a project's firehose stream."""
    return f"tn.firehose.{project_id}"


def encrypt_frame(
    bek: bytes,
    project_id: str,
    key_id: str | None,
    event_type: str,
    raw: bytes,
) -> bytes:
    """nonce(12) || AES-256-GCM(key=bek, aad=(project|key|event_type), pt=raw)

    AAD binds the frame to (project, key, event_type) — identical to the WS
    handler so encrypted bytes are interchangeable between transports.
    """
    aad = f"{project_id}|{key_id or 'stub'}|{event_type}".encode()
    nonce = os.urandom(12)
    ct = AESGCM(bek).encrypt(nonce, raw, aad)
    return nonce + ct  # ct already includes 16-byte GCM tag


def decrypt_frame(
    bek: bytes,
    project_id: str,
    key_id: str | None,
    event_type: str,
    frame: bytes,
) -> bytes:
    """Inverse of encrypt_frame. Raises cryptography.exceptions.InvalidTag on auth failure."""
    nonce, ct = frame[:12], frame[12:]
    aad = f"{project_id}|{key_id or 'stub'}|{event_type}".encode()
    return AESGCM(bek).decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

class TnRedpandaHandler(_AsyncHandler):
    """Firehose handler that writes encrypted TN frames to Redpanda.

    Parameters
    ----------
    bootstrap:
        Kafka bootstrap servers, e.g. ``"localhost:9092"`` for local
        Redpanda, ``"tn-redpanda.fly.dev:9092"`` for the Fly.io instance.
    project_id:
        UUID identifying the TN project. Each project gets its own
        topic ``tn.firehose.{project_id}``.
    key_id:
        Optional test-stub BEK identifier. The real path wires
        keystore lookup.
    """

    def __init__(
        self,
        name: str,
        outbox_path: Any,
        *,
        bootstrap: str,
        project_id: str,
        key_id: str | None = None,
        sasl_username: str | None = None,
        sasl_password: str | None = None,
        filter_spec: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(name, outbox_path, filter_spec=filter_spec)
        if not _PROJECT_ID_RE.match(project_id):
            raise ValueError(
                f"tn.redpanda[{name}]: project_id must be UUID v4, got {project_id!r}"
            )
        self._bootstrap = bootstrap
        self._project_id = project_id
        self._key_id = key_id
        self._sasl_username = sasl_username
        self._sasl_password = sasl_password
        self._bek = _stub_bek(project_id, key_id)
        self._topic = topic_for(project_id)
        self._producer: Any = None

    def _ensure_producer(self) -> Any:
        if self._producer is not None:
            return self._producer
        try:
            from kafka import KafkaProducer
        except ImportError as exc:
            raise ImportError(
                "tn.redpanda requires kafka-python — pip install kafka-python"
            ) from exc

        kwargs: dict[str, Any] = dict(
            bootstrap_servers=self._bootstrap,
            acks="all",
            linger_ms=5,
            compression_type="gzip",
        )
        if self._sasl_username:
            kwargs.update(
                security_protocol="SASL_SSL",
                sasl_mechanism="SCRAM-SHA-256",
                sasl_plain_username=self._sasl_username,
                sasl_plain_password=self._sasl_password,
            )

        self._producer = KafkaProducer(**kwargs)
        _log.info("[%s] Redpanda producer connected → %s", self.name, self._bootstrap)
        return self._producer

    def _drop_producer(self) -> None:
        p, self._producer = self._producer, None
        if p is not None:
            try:
                p.close(timeout=5)
            except Exception:
                pass

    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        event_id = str(envelope.get("event_id") or "")
        event_type = str(envelope.get("event_type") or "")
        row_hash = str(envelope.get("row_hash") or "")
        ts = str(envelope.get("timestamp") or "")

        frame = encrypt_frame(self._bek, self._project_id, self._key_id, event_type, raw_line)

        # Headers carry plaintext metadata so consumers can route/filter
        # without decrypting every frame.
        headers = [
            ("tn-event-id",    event_id.encode()),
            ("tn-event-type",  event_type.encode()),
            ("tn-project-id",  self._project_id.encode()),
            ("tn-key-id",      (self._key_id or "stub").encode()),
            ("tn-ts",          ts.encode()),
            ("tn-row-hash",    row_hash.encode()),
        ]

        try:
            p = self._ensure_producer()
            future = p.send(
                self._topic,
                key=event_id.encode() if event_id else None,
                value=frame,
                headers=headers,
            )
            future.get(timeout=10)
        except Exception:
            self._drop_producer()
            raise

    def _final_flush(self) -> None:
        if self._producer is not None:
            try:
                self._producer.flush(timeout=10)
            except Exception:
                pass
        self._drop_producer()
        _log.debug("[%s] Redpanda producer closed", self.name)


__all__ = [
    "TnRedpandaHandler",
    "topic_for",
    "encrypt_frame",
    "decrypt_frame",
    "_stub_bek",
]
