"""TN firehose handler: encrypted log streaming to the TN vault.

Streams encrypted log frames over a long-lived WebSocket to the TN
vault, which forwards (via service-binding RPC) to the CF firehose
Worker, which buffers and writes batched `.tnpkg` artifacts to R2.

Zero-knowledge: each frame is encrypted client-side under the project
BEK (looked up by ``key_id`` in the local keystore) before it leaves
the device. The vault and CF Worker only ever see ciphertext.

Phase A status: this is the handler SCAFFOLD. The following pieces are
wired:

* Class structure (inherits ``AsyncHandler`` for outbox + worker drain).
* Config schema (endpoint, project_id, key_id, filter_spec).
* Filter spec support (inherited from base).
* ``_publish`` stub that validates inputs and records what would have
  been sent. Real WebSocket connection + reconnect logic ships in B3.

The following pieces are intentionally stubbed and ship later in Phase A:

* B3: real WebSocket client (open, reconnect-with-backoff, send).
* B4: frame encryption with project BEK from keystore. Phase A uses a
  test-stub BEK source so the handler can be exercised end-to-end
  before Phase B's manifest schema changes land.

Config shape (``tn.yaml``)::

    handlers:
      - kind: tn.firehose
        name: cloud-archive
        endpoint: https://vault.tn-proto.org
        project_id: 00000000-0000-0000-0000-000000000000
        key_id: fhk_<base32>             # optional in Phase A (test stub)
        filter:
          level_in: [info, warning, error]

Spec reference: ``docs/superpowers/specs/2026-05-15-firehose-design.md``
``§ Client handler (tn.firehose)``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from typing import Any
from urllib.parse import urlparse, urlunparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base import AsyncHandler

_log = logging.getLogger("tn.handlers.firehose")


def _stub_bek(project_id: str, key_id: str | None) -> bytes:
    """Phase A test-stub BEK derivation.

    Derives a deterministic 32-byte AES key from ``(project_id,
    key_id)`` so the encryption path can be exercised end-to-end before
    Phase B's real keystore integration lands.

    **This is not secure.** Two devices with the same project_id and
    key_id derive the same key, which is the OPPOSITE of what the real
    sealed-box flow does (only authorized member devices hold the BEK).
    Phase B replaces this function with ``keystore.lookup_bek(key_id)``
    which returns bytes provisioned via the mint flow.
    """
    seed = f"{project_id}:{key_id or 'stub-default'}".encode("utf-8")
    return hashlib.sha256(b"phase-a-stub-bek-do-not-use-in-prod:" + seed).digest()

# Strict UUID v4-shaped project id (matches the CF Worker's UUID_RE).
_PROJECT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Loose key_id format; production keys are minted by the vault UI and
# follow a "fhk_<base32>" shape, but Phase A accepts anything for
# test-stub purposes.
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class TnFirehoseHandler(AsyncHandler):
    """Streaming firehose handler.

    Constructor parameters
    ----------------------
    name
        Handler instance name. Used in logs and outbox path.
    endpoint
        Base URL of the TN vault, e.g. ``https://vault.tn-proto.org``.
        The vault is the only network endpoint the handler talks to;
        the CF Worker behind it is invisible to clients.
    project_id
        UUID identifying the project this handler streams under. Must
        match a project record at the vault that has the bearer DID as
        a member.
    key_id
        Optional. Identifier of the active project BEK to encrypt
        frames with. In Phase A this is a test-stub identifier; B4
        wires real BEK lookup from the local keystore.
    filter_spec
        Optional standard handler filter dict (``level_in``,
        ``event_type_prefix``, etc.). Pre-filtered envelopes don't
        reach ``_publish`` so the WS doesn't carry events the user
        doesn't want shipped.
    """

    def __init__(
        self,
        name: str,
        outbox_path: Any,
        *,
        endpoint: str,
        project_id: str,
        key_id: str | None = None,
        filter_spec: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(name, outbox_path, filter_spec=filter_spec)
        if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
            raise ValueError(
                f"tn.firehose[{name}]: endpoint must be http(s) URL, got {endpoint!r}"
            )
        if not _PROJECT_ID_RE.match(project_id):
            raise ValueError(
                f"tn.firehose[{name}]: project_id must be a UUID v4 string, got {project_id!r}"
            )
        if key_id is not None and not _KEY_ID_RE.match(key_id):
            raise ValueError(
                f"tn.firehose[{name}]: key_id {key_id!r} not in expected shape"
            )

        self._endpoint = endpoint.rstrip("/")
        self._project_id = project_id
        self._key_id = key_id

        # Phase A stub BEK. Phase B swaps for keystore lookup by key_id.
        self._bek = _stub_bek(project_id, key_id)
        self._aes = AESGCM(self._bek)

        # WebSocket connection lazy-opened on first _publish call. The
        # AsyncHandler worker thread serializes _publish calls so we
        # don't need locking around the connection in the steady state,
        # but use a lock for the open/close transitions which can race
        # with _final_flush.
        self._ws_lock = threading.Lock()
        self._ws: Any = None  # WebSocketApp / WebSocket instance

    # ------------------------------------------------------------------
    # WebSocket lifecycle
    # ------------------------------------------------------------------

    def _ws_url(self) -> str:
        """Convert the http(s) endpoint into a ws(s) URL for the
        per-project firehose stream.

        ``https://vault.tn-proto.org`` + project ``00000000-...`` becomes
        ``wss://vault.tn-proto.org/firehose/00000000-...``. In Phase A
        the path matches what the prototype Worker exposes; production
        will route via the vault, which proxies upstream to the Worker.
        """
        u = urlparse(self._endpoint)
        scheme = "wss" if u.scheme == "https" else "ws"
        path = (u.path.rstrip("/") + f"/firehose/{self._project_id}")
        return urlunparse((scheme, u.netloc, path, "", "", ""))

    def _ensure_connected(self) -> Any:
        """Open the WS lazily and cache it. Returns the live connection.

        Raises ImportError if the optional ``[firehose]`` extra is not
        installed, and any underlying network error if connect fails.
        Network failure propagates to the outbox worker for retry.
        """
        if self._ws is not None:
            return self._ws
        with self._ws_lock:
            if self._ws is not None:
                return self._ws
            try:
                import websocket  # type: ignore[import-not-found]
            except ImportError as e:
                raise ImportError(
                    "tn.firehose requires the `websocket-client` package. "
                    "Install via `pip install 'tn-protocol[firehose]'`."
                ) from e
            ws = websocket.create_connection(
                self._ws_url(),
                timeout=10.0,
                # Production sets a Bearer header from vault-issued JWT;
                # Phase A's scaffold connects unauthenticated against the
                # prototype Worker, which accepts the connection.
            )
            self._ws = ws
            _log.info("[%s] firehose WS connected to %s", self.name, self._ws_url())
            return ws

    def _drop_connection(self) -> None:
        """Close + forget the WS so the next _publish reopens."""
        with self._ws_lock:
            ws = self._ws
            self._ws = None
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001 — best-effort
                pass

    # ------------------------------------------------------------------
    # AsyncHandler contract
    # ------------------------------------------------------------------

    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        """Encrypt the frame under the project BEK and send to the vault.

        Wire format per frame: ``nonce(12) || ciphertext_with_tag(N+16)``.
        AAD is the manifest header tuple ``(project_id, key_id, event_type)``
        so the vault and CF Worker can't substitute frames between
        contexts without detection — even though they can't decrypt the
        body.

        Raises on any network or crypto error so the AsyncHandler outbox
        holds the frame for retry with exponential backoff. The next
        retry reopens the WS as needed.
        """
        event_type = str(envelope.get("event_type") or "")
        aad = f"{self._project_id}|{self._key_id or 'stub'}|{event_type}".encode("utf-8")
        nonce = os.urandom(12)
        try:
            ciphertext = self._aes.encrypt(nonce, raw_line, aad)
        except Exception:
            # AESGCM.encrypt shouldn't fail on valid inputs, but if it
            # does the frame is malformed; raise so the outbox can
            # decide what to do (in practice this is a bug, not a retry).
            raise
        wire = nonce + ciphertext
        try:
            ws = self._ensure_connected()
            ws.send_binary(wire)
        except Exception:
            # Drop the connection so the next attempt reopens. Re-raise
            # so the outbox worker retries with backoff.
            self._drop_connection()
            raise

    def _final_flush(self) -> None:
        """Close the WS on handler shutdown. Best-effort."""
        self._drop_connection()
        _log.debug("[%s] firehose WS closed", self.name)


__all__ = ["TnFirehoseHandler"]
