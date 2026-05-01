"""``vault.sync`` handler (RFC §4).

Ships attested envelopes to a tnproto-org cloud vault, addressed by DID,
authenticated by the same Ed25519 challenge-response that the vault already
implements in ``routes_auth.py``.

Config shape (tn.yaml)::

    - kind: vault.sync
      vault_did: did:web:tnproto.org        # or did:key:z...
      project_id: proj_abc123               # project enrolled in the vault
      batch_interval_ms: 5000               # flush cadence (default 5000)
      batch_max_events: 1000                # flush size threshold (default 100)
      filter:
        sync: true                          # only sync-flagged events

Auth flow (RFC §4.2):
1. ``POST {vault}/api/v1/auth/challenge`` with ``{did: alice_did}``.
2. Sign the nonce with the local Ed25519 private key.
3. ``POST /api/v1/auth/verify`` -- vault issues a JWT (24h lifetime).
4. Batch POST to ``/api/v1/projects/{project_id}/events`` with Bearer JWT.
5. On 401 -- rechallenge transparently.

Failure modes (RFC §4.4):
- Vault unreachable: exponential backoff via the inherited OutboxWorker.
- Vault rejects a batch (verification failure): log loudly, raise so the
  worker nacks and backs off.
- JWT expires: 401 triggers rechallenge before the next retry.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
from pathlib import Path
from typing import Any

from .base import AsyncHandler

_log = logging.getLogger("tn.handlers.vault_sync")

# Maximum batch size in bytes before we flush regardless of time.
_DEFAULT_BATCH_INTERVAL_SEC = 5.0
_DEFAULT_BATCH_MAX_EVENTS = 100


class VaultSyncHandler(AsyncHandler):
    """Ship attested envelopes to a tnproto-org vault over HTTPS.

    Batches envelopes in memory and flushes on a timer or size threshold.
    Authentication is a DID challenge-response that issues a short-lived
    JWT; the JWT is cached in memory and refreshed on 401.

    Constructor parameters:

    name
        Handler name (for logging).
    outbox_path
        Path to the durable SQLite outbox directory.
    vault_did
        DID of the vault service. Determines the transport URL via
        ``tn.identity._resolve_did_endpoint``.
    project_id
        Project ID registered in the vault.
    alice_did
        The publisher's DID (used to authenticate against the vault).
    alice_private_key_bytes
        Raw 32-byte Ed25519 seed for signing challenge nonces.
    batch_interval_sec
        Seconds between forced flushes (default 5).
    batch_max_events
        Maximum envelopes per batch before an early flush (default 100).
    filter_spec
        Optional RFC §3.2 filter dict.
    """

    def __init__(
        self,
        name: str,
        *,
        outbox_path: str | Path,
        vault_did: str,
        project_id: str,
        alice_did: str,
        alice_private_key_bytes: bytes,
        batch_interval_sec: float = _DEFAULT_BATCH_INTERVAL_SEC,
        batch_max_events: int = _DEFAULT_BATCH_MAX_EVENTS,
        filter_spec: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            name,
            outbox_path,
            filter_spec=filter_spec,
        )
        self._vault_did = vault_did
        self._project_id = project_id
        self._alice_did = alice_did
        self._alice_private_key_bytes = alice_private_key_bytes
        self._batch_interval_sec = batch_interval_sec
        self._batch_max_events = batch_max_events

        # JWT state (memory-only, never persisted).
        self._jwt: str | None = None
        self._jwt_lock = threading.Lock()

        # In-memory accumulator for batch POSTs.
        self._batch: list[dict[str, Any]] = []
        self._batch_lock = threading.Lock()

        # Resolve vault URL once at startup.
        from ..identity import _resolve_did_endpoint

        self._vault_base = _resolve_did_endpoint(vault_did)
        _log.info("[%s] vault.sync: resolved %s -> %s", name, vault_did, self._vault_base)

        # Background flusher thread (separate from the outbox worker).
        self._flush_stop = threading.Event()
        self._flusher = threading.Thread(
            target=self._flush_loop,
            name=f"tn-vault-flush-{name}",
            daemon=True,
        )
        self._flusher.start()

    # ------------------------------------------------------------------ #
    # AsyncHandler contract                                                #
    # ------------------------------------------------------------------ #

    def _publish(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        """Accumulate into the in-memory batch; flush when threshold hit."""
        with self._batch_lock:
            self._batch.append(envelope)
            should_flush = len(self._batch) >= self._batch_max_events

        if should_flush:
            self._flush_batch()

    def _final_flush(self) -> None:
        """Flush any remaining envelopes on close."""
        self._flush_batch()

    def close(self, *, timeout: float = 30.0) -> None:
        """Stop background threads, flush remaining events, close outbox."""
        self._flush_stop.set()
        self._flusher.join(timeout=min(timeout, 5.0))
        super().close(timeout=timeout)

    # ------------------------------------------------------------------ #
    # Batch flush                                                          #
    # ------------------------------------------------------------------ #

    def _flush_loop(self) -> None:
        """Timer thread: flush every ``batch_interval_sec`` seconds."""
        while not self._flush_stop.wait(self._batch_interval_sec):
            try:
                self._flush_batch()
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                _log.exception("[%s] vault.sync flush_loop error", self.name)

    def _flush_batch(self) -> None:
        """Drain the in-memory batch and POST to the vault."""
        with self._batch_lock:
            if not self._batch:
                return
            batch, self._batch = self._batch, []

        _log.debug("[%s] vault.sync: flushing %d envelopes", self.name, len(batch))
        try:
            self._post_batch(batch)
        except Exception:
            # Return the envelopes to the batch so they aren't lost.
            with self._batch_lock:
                self._batch = batch + self._batch
            raise

    # ------------------------------------------------------------------ #
    # HTTP helpers                                                         #
    # ------------------------------------------------------------------ #

    def _post_batch(self, envelopes: list[dict[str, Any]]) -> None:
        """POST a batch of envelopes to the vault. Re-challenges on 401."""
        jwt = self._ensure_jwt()
        url = f"{self._vault_base}/api/v1/projects/{self._project_id}/events"
        body = json.dumps(
            {
                "project_id": self._project_id,
                "envelopes": envelopes,
            }
        ).encode("utf-8")

        status, resp_body = self._http_post(url, body, jwt)

        if status == 401:
            _log.info("[%s] vault.sync: JWT rejected (401) -- re-challenging", self.name)
            with self._jwt_lock:
                self._jwt = None
            jwt = self._ensure_jwt()
            status, resp_body = self._http_post(url, body, jwt)

        if status not in (200, 201, 204):
            raise RuntimeError(
                f"vault.sync batch POST failed: HTTP {status} -- {resp_body[:200]!r}"
            )

        _log.info(
            "[%s] vault.sync: accepted %d envelopes (HTTP %d)",
            self.name,
            len(envelopes),
            status,
        )

    def _ensure_jwt(self) -> str:
        """Return cached JWT or perform a fresh challenge-response."""
        with self._jwt_lock:
            if self._jwt:
                return self._jwt
            token = self._do_challenge_response()
            self._jwt = token
            return token

    def _do_challenge_response(self) -> str:
        """Perform full challenge-response, return JWT string."""
        # Step 1: request a nonce.
        ch_url = f"{self._vault_base}/api/v1/auth/challenge"
        ch_body = json.dumps({"did": self._alice_did}).encode("utf-8")
        status, ch_resp = self._http_post(ch_url, ch_body, jwt=None)
        if status != 200:
            raise RuntimeError(f"vault.sync challenge failed: HTTP {status} -- {ch_resp[:200]!r}")
        nonce = json.loads(ch_resp)["nonce"]

        # Step 2: sign the nonce with Alice's device key.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.from_private_bytes(self._alice_private_key_bytes)
        sig_bytes = priv.sign(nonce.encode("utf-8"))
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")

        # Step 3: verify and obtain JWT.
        vr_url = f"{self._vault_base}/api/v1/auth/verify"
        vr_body = json.dumps(
            {
                "did": self._alice_did,
                "nonce": nonce,
                "signature": sig_b64,
            }
        ).encode("utf-8")
        status, vr_resp = self._http_post(vr_url, vr_body, jwt=None)
        if status != 200:
            raise RuntimeError(f"vault.sync verify failed: HTTP {status} -- {vr_resp[:200]!r}")
        token = json.loads(vr_resp)["token"]
        _log.info("[%s] vault.sync: obtained JWT for %s", self.name, self._alice_did)
        return token

    def _http_post(
        self,
        url: str,
        body: bytes,
        jwt: str | None,
    ) -> tuple[int, str]:
        """Thin HTTP POST wrapper using urllib (no extra deps).

        Returns (status_code, response_body_str).
        """
        import urllib.error
        import urllib.request

        headers = {"Content-Type": "application/json"}
        if jwt:
            headers["Authorization"] = f"Bearer {jwt}"

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body_txt = exc.read().decode("utf-8", errors="replace")
            return exc.code, body_txt
        except Exception as exc:
            raise RuntimeError(f"vault.sync HTTP error on {url}: {exc}") from exc
