"""S3 handler for attested log storage.

Writes newline-delimited-JSON envelopes to S3 as the canonical byte-exact
"source of truth" Tier-1 storage. Batches entries so we don't create one
object per log call (that'd be both slow and expensive).

Object layout:
    s3://<bucket>/<prefix>/{yyyy}/{mm}/{dd}/{hh}/{event_type}/{batch_uuid}.ndjson

Each object contains N envelopes as JSON Lines — exactly the same bytes
we'd write locally. The file is the byte-level preimage of any signature
check.

YAML:
    kind: s3
    bucket: my-tn-logs                # required
    prefix: tn/{ceremony_id}           # optional; default "tn"
    region: us-east-1
    access_key: env:AWS_ACCESS_KEY_ID   # optional; boto resolves creds
    secret_key: env:AWS_SECRET_ACCESS_KEY
    session_token: env:AWS_SESSION_TOKEN
    batch_max_rows:  500
    batch_max_bytes: 10485760         # 10 MB
    batch_window_sec: 60
    # Optional server-side encryption:
    sse: AES256                        # or aws:kms
    sse_kms_key_id: alias/my-key
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .base import AsyncHandler


def _resolve(value: str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:]) or None
    return value


class S3Handler(AsyncHandler):
    def __init__(
        self,
        name: str,
        *,
        outbox_path: str | Path,
        bucket: str,
        prefix: str = "tn",
        region: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
        endpoint_url: str | None = None,
        sse: str | None = None,
        sse_kms_key_id: str | None = None,
        batch_max_rows: int = 500,
        batch_max_bytes: int = 10 * 1024 * 1024,
        batch_window_sec: float = 60.0,
        filter_spec: dict[str, Any] | None = None,
    ):
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "S3Handler requires boto3. Install via `pip install 'tn-protocol[s3]'`."
            ) from e

        self._client = boto3.client(
            "s3",
            region_name=_resolve(region),
            aws_access_key_id=_resolve(access_key),
            aws_secret_access_key=_resolve(secret_key),
            aws_session_token=_resolve(session_token),
            endpoint_url=_resolve(endpoint_url),
        )
        self._bucket = bucket
        self._prefix = prefix.rstrip("/")
        self._sse = sse
        self._sse_kms_key_id = sse_kms_key_id
        self._batch_max_rows = batch_max_rows
        self._batch_max_bytes = batch_max_bytes
        self._batch_window_sec = batch_window_sec

        super().__init__(name, outbox_path, filter_spec=filter_spec)

        self._buf_lock = threading.Lock()
        self._buffer: list[bytes] = []
        self._buf_bytes = 0
        self._buf_first_ts = 0.0
        self._buf_first_env: dict[str, Any] | None = None

    # AsyncHandler interface -----------------------------------------------

    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        """Buffer; flush on row/bytes/time threshold."""
        should_flush = False
        with self._buf_lock:
            if not self._buffer:
                self._buf_first_ts = time.time()
                self._buf_first_env = envelope
            self._buffer.append(raw_line)
            self._buf_bytes += len(raw_line)

            if (
                len(self._buffer) >= self._batch_max_rows
                or self._buf_bytes >= self._batch_max_bytes
                or (time.time() - self._buf_first_ts) >= self._batch_window_sec
            ):
                should_flush = True

        if should_flush:
            self._flush()

    def _flush(self) -> None:
        with self._buf_lock:
            if not self._buffer:
                return
            batch = self._buffer
            first = self._buf_first_env
            self._buffer = []
            self._buf_bytes = 0
            self._buf_first_ts = 0.0
            self._buf_first_env = None

        # key is derived from the FIRST envelope's timestamp + event_type
        if first is None:
            raise RuntimeError(
                "S3 handler: buffer was non-empty but first-envelope marker missing"
            )
        ts = first["timestamp"]
        # "2026-04-19T15:47:42.123456Z" -> yyyy/mm/dd/hh
        yyyy, mm, dd = ts[:4], ts[5:7], ts[8:10]
        hh = ts[11:13] or "00"
        key = (
            f"{self._prefix}/{yyyy}/{mm}/{dd}/{hh}/{first['event_type']}/{uuid.uuid4().hex}.ndjson"
        )
        body = b"".join(batch)

        put_args: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": body,
            "ContentType": "application/x-ndjson",
        }
        if self._sse:
            put_args["ServerSideEncryption"] = self._sse
            if self._sse_kms_key_id:
                put_args["SSEKMSKeyId"] = self._sse_kms_key_id

        self._client.put_object(**put_args)

    def _final_flush(self) -> None:
        # Called by AsyncHandler.close() after the worker has drained the
        # outbox. Everything pending is now in our in-memory buffer.
        self._flush()
