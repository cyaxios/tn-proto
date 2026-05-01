"""ATProto PDS handler via the `atproto` Python SDK.

Creates one record per log entry under a configurable collection.
Gated behind `tn-protocol[atproto]`.

YAML:
    kind: atproto.pds
    endpoint:   https://bsky.social
    did:        did:plc:abcd...
    handle:     alice.tnproto.org      # optional; endpoint-dependent
    password:   env:PDS_APP_PASSWORD   # app-password recommended
    collection: org.tnproto.log        # your lexicon name
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .base import AsyncHandler


def _resolve(value: str | None) -> str:
    if not value:
        return ""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value


class PDSHandler(AsyncHandler):
    def __init__(
        self,
        name: str,
        *,
        outbox_path: str | Path,
        endpoint: str,
        did: str | None = None,
        handle: str | None = None,
        password: str | None = None,
        collection: str = "org.tnproto.log",
        filter_spec: dict[str, Any] | None = None,
    ):
        try:
            from atproto import Client
        except ImportError as e:
            raise ImportError(
                "PDSHandler requires the atproto SDK. "
                "Install via `pip install 'tn-protocol[atproto]'`."
            ) from e

        super().__init__(name, outbox_path, filter_spec=filter_spec)
        self._client = Client(base_url=endpoint)
        self._did = did
        self._collection = collection

        user = _resolve(handle) or _resolve(did)
        pwd = _resolve(password)
        if user and pwd:
            self._client.login(user, pwd)
        # If no credentials provided, a later publish() will fail with a
        # clear error from the SDK; better than silently black-holing.

    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        # We send the envelope as-is. The PDS record payload is whatever
        # the user's lexicon declares; we pass the attested envelope.
        if self._did is None:
            raise RuntimeError("PDSHandler.did must be configured")
        self._client.com.atproto.repo.create_record(
            data={
                "repo": self._did,
                "collection": self._collection,
                "record": envelope,
            },
        )
