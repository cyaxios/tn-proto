"""``zenoh.pull`` handler — long-lived Zenoh subscription on the agent's inbox.

Per spec ``docs/superpowers/specs/2026-05-03-zenoh-pull-handler-design.md``,
a running TN agent (Python process, no human present) holds an open
subscription on ``tn/inbox/{my_did}/snapshots/**`` and calls
``tn.absorb()`` on every incoming sample. Replacement kit_bundles and
admin_log_snapshot deliveries flow in steady-state without manual
intervention.

Differs from ``vault.pull`` (the REST polling counterpart) in:

* Subscription is push-driven, not poll-driven. One long-lived Zenoh
  session feeds samples into a worker queue.
* Bus reach is in addition to (not a replacement for) the REST inbox.
  An operator can run both handlers; idempotent absorb dedupes.
* Auth is the FastAPI mint pattern from the spike: present a JWT
  (DID-challenge or OAuth-bridged), receive short-lived usrpwd creds,
  open a Zenoh session, refresh creds before TTL.

The Zenoh import is lazy. ``import tn`` does not require ``eclipse-zenoh``
to be installed; only instantiating ``ZenohPullHandler`` does.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import TNHandler

_log = logging.getLogger("tn.handlers.zenoh")

DEFAULT_SUBSCRIBE_PATTERN = "tn/inbox/{did}/**"


@dataclass
class ZenohCredentials:
    """Short-lived Zenoh usrpwd credentials minted from the FastAPI auth gate."""

    username: str
    password: str
    expires_at: str  # ISO 8601


class _MintClient:
    """Default mint client. Calls a FastAPI ``/zenoh/credentials`` endpoint
    with a JWT bearer and returns ``ZenohCredentials``.

    Tests inject a mock that returns canned creds without hitting the
    network.
    """

    def __init__(self, mint_url: str, jwt_provider: Callable[[], str]) -> None:
        self._mint_url = mint_url
        self._jwt_provider = jwt_provider

    def fetch(self) -> ZenohCredentials:
        import httpx as _httpx

        token = self._jwt_provider()
        resp = _httpx.post(
            self._mint_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        resp.raise_for_status()
        doc = resp.json()
        return ZenohCredentials(
            username=str(doc["username"]),
            password=str(doc["password"]),
            expires_at=str(doc["expires_at"]),
        )


class ZenohPullHandler(TNHandler):
    """Subscribe to ``tn/inbox/{my_did}/**`` and absorb every sample.

    Constructor parameters
    ----------------------

    name
        Handler name (logging / cursor file).
    zenoh_endpoints
        List of Zenoh connect endpoints, e.g. ``["tcp/127.0.0.1:7447"]``.
    cfg_provider
        Callable returning the active ``LoadedConfig``. Default uses
        ``tn.current_config``.
    mint_client_factory
        Callable ``() -> _MintClient`` (or any object exposing
        ``.fetch() -> ZenohCredentials``). Default uses the FastAPI
        mint URL passed via ``mint_url``.
    mint_url
        URL of the ``/zenoh/credentials`` endpoint. Used by the default
        mint client factory.
    jwt_provider
        Callable returning a fresh JWT bearer token. Used by the default
        mint client. Tests/integration can short-circuit by passing
        their own ``mint_client_factory``.
    subscribe_pattern
        Bus key expression to subscribe to. Defaults to
        ``"tn/inbox/{did}/**"`` with ``{did}`` substituted from
        ``cfg.device.device_identity`` at startup.
    on_absorb_error
        ``"log"`` (default) — failures are logged, the subscription
        keeps running. ``"raise"`` — failures propagate out of the
        worker thread (handler stays subscribed; the next sample is
        independent).
    autostart
        Whether to open the session and start the worker on
        construction. Tests pass False so they can drive ticks
        manually.
    """

    def __init__(
        self,
        name: str,
        *,
        zenoh_endpoints: list[str],
        cfg_provider: Callable[[], Any] | None = None,
        mint_client_factory: Callable[[], Any] | None = None,
        mint_url: str | None = None,
        jwt_provider: Callable[[], str] | None = None,
        subscribe_pattern: str = DEFAULT_SUBSCRIBE_PATTERN,
        scouting_multicast_enabled: bool = False,
        on_absorb_error: str = "log",
        cursor_path_override: Path | None = None,
        filter_spec: dict[str, Any] | None = None,
        autostart: bool = True,
    ) -> None:
        super().__init__(name, filter_spec)
        if on_absorb_error not in ("log", "raise"):
            raise ValueError(
                f"zenoh.pull: on_absorb_error must be 'log' or 'raise', got {on_absorb_error!r}"
            )

        self._zenoh_endpoints = list(zenoh_endpoints)
        self._scouting_multicast_enabled = scouting_multicast_enabled
        self._cfg_provider = cfg_provider or _default_cfg_provider
        self._subscribe_pattern = subscribe_pattern
        self._on_absorb_error = on_absorb_error
        self._cursor_path_override = cursor_path_override

        if mint_client_factory is None and (mint_url is None or jwt_provider is None):
            # No-auth mode: the handler opens the Zenoh session without
            # usrpwd creds. Intended for in-process / single-host
            # development where the bus is trusted. Production deploys
            # set mint_client_factory or (mint_url + jwt_provider) so
            # the bus enforces per-DID subscribe ACLs.
            self._mint_factory: Callable[[], Any] | None = None
        elif mint_client_factory is not None:
            self._mint_factory = mint_client_factory
        else:
            assert mint_url is not None and jwt_provider is not None  # narrowed
            self._mint_factory = lambda: _MintClient(mint_url, jwt_provider)

        # Worker-thread state. Samples land in this queue; the worker
        # drains them one at a time. Bounded so a noisy bus doesn't
        # pile up unbounded memory; producers (Zenoh subscriber callback)
        # block briefly when the worker is behind.
        import queue as _queue

        self._queue: _queue.Queue[bytes] = _queue.Queue(maxsize=256)
        self._stop_ev = threading.Event()
        self._worker: threading.Thread | None = None
        self._closed = False
        self._lock = threading.Lock()

        # Zenoh session + subscription (lazy — opened in start()).
        self._session = None
        self._subscriber = None
        self._creds: ZenohCredentials | None = None

        # Stats for tests / diagnostics.
        self._absorbed_count = 0
        self._rejected_count = 0
        self._last_seen_key: str | None = None

        if autostart:
            self.start()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Open the Zenoh session and start the worker thread.

        Safe to call only once. Subsequent calls are a no-op (handler
        is already running).
        """
        with self._lock:
            if self._session is not None:
                return
            self._open_session()
            self._worker = threading.Thread(
                target=self._worker_loop,
                name=f"tn-zenoh-pull-{self.name}",
                daemon=True,
            )
            self._worker.start()

    def _open_session(self) -> None:
        cfg = self._cfg_provider()
        if cfg is None:
            raise RuntimeError(
                f"zenoh.pull[{self.name}]: no active LoadedConfig — call tn.init() "
                f"before instantiating this handler."
            )

        my_did = cfg.device.device_identity
        sub_key = self._subscribe_pattern.format(did=my_did)

        # Mint creds (skip in no-auth mode).
        if self._mint_factory is not None:
            mint_client = self._mint_factory()
            self._creds = mint_client.fetch()
        else:
            self._creds = None

        # Open Zenoh session with usrpwd auth + our connect endpoints.
        import zenoh as _zenoh

        zcfg = _zenoh.Config()
        zcfg.insert_json5(
            "connect/endpoints",
            json.dumps(self._zenoh_endpoints),
        )
        if not self._scouting_multicast_enabled:
            zcfg.insert_json5("scouting/multicast/enabled", "false")
        if self._creds is not None:
            zcfg.insert_json5(
                "transport/auth/usrpwd",
                json.dumps(
                    {"user": self._creds.username, "password": self._creds.password}
                ),
            )

        self._session = _zenoh.open(zcfg)
        _log.info(
            "[%s] zenoh.pull session opened, subscribing to %s",
            self.name,
            sub_key,
        )
        self._subscriber = self._session.declare_subscriber(sub_key, self._on_sample)

    def _on_sample(self, sample: Any) -> None:
        """Callback fired by the Zenoh subscriber. Push raw bytes onto
        the worker queue; the worker handles absorb. Keeping this
        callback lean is important — Zenoh runs it on the receiver
        thread.
        """
        try:
            payload = bytes(sample.payload)
        except Exception:  # noqa: BLE001
            _log.warning("[%s] zenoh.pull: malformed sample payload", self.name)
            return
        try:
            self._last_seen_key = str(sample.key_expr)
        except Exception:  # noqa: BLE001
            pass
        try:
            self._queue.put(payload, timeout=2.0)
        except Exception as exc:  # noqa: BLE001 — queue full / shutdown
            _log.warning(
                "[%s] zenoh.pull: queue put failed (%s); sample dropped",
                self.name,
                exc,
            )

    def _worker_loop(self) -> None:
        import queue as _queue

        while not self._stop_ev.is_set():
            try:
                payload = self._queue.get(timeout=0.25)
            except _queue.Empty:
                continue
            try:
                self._absorb_payload(payload)
            except Exception:
                if self._on_absorb_error == "raise":
                    raise
                _log.exception("[%s] zenoh.pull: absorb worker tick failed", self.name)
            finally:
                self._queue.task_done()

    def _absorb_payload(self, payload: bytes) -> None:
        # Late import: tn.absorb pulls in the runtime.
        from ..absorb import absorb as _absorb

        cfg = self._cfg_provider()
        if cfg is None:
            _log.warning(
                "[%s] zenoh.pull: cfg gone, dropping sample (%d bytes)",
                self.name,
                len(payload),
            )
            return
        receipt = _absorb(cfg, payload)
        status = getattr(receipt, "status", None) or getattr(receipt, "legacy_status", "")
        if status == "rejected":
            self._rejected_count += 1
            _log.warning(
                "[%s] zenoh.pull: absorb rejected: %s",
                self.name,
                getattr(receipt, "reason", "")
                or getattr(receipt, "legacy_reason", ""),
            )
            return
        self._absorbed_count += 1
        _log.info("[%s] zenoh.pull: absorbed sample, status=%s", self.name, status)

    # ------------------------------------------------------------------
    # TNHandler contract
    # ------------------------------------------------------------------

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        # Pull handlers don't react to local emits — the subscription
        # delivers what to absorb.
        return

    def close(self, *, timeout: float = 30.0) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True

        self._stop_ev.set()

        # Drain the queue so close() is "wait until quiescent." Cap by
        # timeout so we don't hang.
        deadline = None
        try:
            import time as _time

            deadline = _time.monotonic() + min(timeout, 30.0)
        except Exception:  # noqa: BLE001
            deadline = None

        # Best-effort: undeclare the subscriber (stops new samples).
        try:
            if self._subscriber is not None:
                self._subscriber.undeclare()
        except Exception:  # noqa: BLE001
            pass

        # Drain remaining queue items synchronously; safer than racing
        # the worker thread.
        if self._worker is not None:
            self._worker.join(timeout=min(timeout, 10.0))

        # If anything is still in the queue (rare — worker should have
        # drained it), absorb here.
        try:
            while not self._queue.empty():
                if deadline is not None:
                    import time as _time

                    if _time.monotonic() > deadline:
                        break
                payload = self._queue.get_nowait()
                try:
                    self._absorb_payload(payload)
                except Exception:  # noqa: BLE001
                    _log.exception(
                        "[%s] zenoh.pull: drain absorb failed", self.name
                    )
                finally:
                    self._queue.task_done()
        except Exception:  # noqa: BLE001
            pass

        try:
            if self._session is not None:
                self._session.close()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Public introspection helpers (tests, diagnostics)
    # ------------------------------------------------------------------

    @property
    def absorbed_count(self) -> int:
        return self._absorbed_count

    @property
    def rejected_count(self) -> int:
        return self._rejected_count

    @property
    def last_seen_key(self) -> str | None:
        return self._last_seen_key

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    def wait_for_absorbs(self, n: int, *, timeout: float = 5.0) -> bool:
        """Block until at least ``n`` samples have been absorbed (success
        or rejection counts toward the total). Returns True on success.

        Test helper. Not part of the production handler interface.
        """
        import time as _time

        deadline = _time.monotonic() + timeout
        while self._absorbed_count + self._rejected_count < n:
            if _time.monotonic() > deadline:
                return False
            _time.sleep(0.05)
        return True


# ---------------------------------------------------------------------------
# Default cfg / wiring
# ---------------------------------------------------------------------------


def _default_cfg_provider() -> Any:
    try:
        from .. import current_config

        return current_config()
    except RuntimeError:
        return None


__all__ = ["ZenohCredentials", "ZenohPullHandler"]
