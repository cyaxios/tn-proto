"""``vault.pull`` handler — fetch admin-log snapshots from a TN vault.

Per the 2026-04-24 admin log architecture plan §5.2: the pull side
runs on a schedule, GETs new ``.tnpkg`` files from the vault inbox
addressed to this DID, and calls ``tn.absorb()`` for each. Idempotent
(absorb dedupes by ``row_hash`` so re-fetching a snapshot is a no-op).

One-shot entry point
--------------------

Per the 2026-04-27 vault-passive-backup-and-sync-design §4.11 / §10
item 6: the bulk of the pull work is also exposed as a module-level
pure function ``pull_inbox(cfg, client, *, since_cursor=None) -> dict``.
The handler class simply schedules calls to this function and
persists the cursor; a future ``tn sync`` CLI verb can call
``pull_inbox`` directly without going through a scheduler thread.

Config shape (tn.yaml)::

    - kind: vault.pull
      endpoint: https://api.cyaxios.com
      project_id: proj_xxx
      poll_interval: 60s
      on_absorb_error: log | raise        # default: log

Vault REST contract:
* ``GET {endpoint}/api/v1/inbox/{my_did}/incoming?since={cursor}``
  returns ``{"items": [{"path": "...", "head_row_hash": "...",
  "received_at": "..."}]}``.
* ``GET {endpoint}{path}`` returns the raw ``.tnpkg`` bytes.

Cursor persistence: the last-fetched timestamp lives at
``<yaml_dir>/.tn/admin/vault_pull.cursor.json`` so a restart doesn't
re-pull every snapshot. The cursor advances after each successful tick
(not per-item), so a mid-tick crash safely re-fetches the in-flight
batch, which is fine because absorb is idempotent.

The pull runs on its own scheduler thread (separate from the outbox
worker pattern used by push handlers — pulls don't queue events, they
poll). On ``flush_and_close()`` the thread drains: any in-flight absorb
finishes, the cursor persists, and the thread exits.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .base import TNHandler

_log = logging.getLogger("tn.handlers.vault_pull")

_DEFAULT_POLL_INTERVAL_SEC = 60.0
_CURSOR_FILE = "vault_pull.cursor.json"


# ---------------------------------------------------------------------------
# Pure one-shot entry point (importable by `tn sync` CLI verb)
# ---------------------------------------------------------------------------


def pull_inbox(
    cfg: Any,
    client: Any,
    *,
    since_cursor: str | None = None,
    on_absorb_error: str = "log",
) -> dict[str, Any]:
    """Run one fetch+absorb cycle against a TN vault inbox.

    This is the daemon-free, scheduler-free version of the work that
    :class:`VaultPullHandler` performs on each tick. The handler is a
    thin wrapper that schedules calls to this function, loads/saves
    the on-disk cursor (``vault_pull.cursor.json``), and serialises
    ticks under a lock; a future ``tn sync`` CLI verb can call
    ``pull_inbox`` directly with its own cursor management.

    Parameters
    ----------
    cfg
        The active ``LoadedConfig``. Caller is responsible for resolving
        it (e.g. via ``tn.current_config()``).
    client
        An object exposing ``list_incoming(did, *, since)`` and
        ``download(path) -> bytes``. Caller owns the lifecycle.
    since_cursor
        Opaque cursor value to pass as ``since`` on ``list_incoming``.
        The handler loads this from ``vault_pull.cursor.json``; CLI
        callers can pass any value (or None for a full re-pull).
    on_absorb_error
        ``"log"`` (default) — failures are logged and the cursor stays
        put for the failed item. ``"raise"`` — failures propagate.

    Returns
    -------
    dict
        ``{"absorbed": int, "new_cursor": str | None}``. ``new_cursor``
        is the highest ``since_marker`` (or ``received_at``) seen
        across successfully-absorbed items, or ``since_cursor`` when
        nothing advanced. Caller persists it however it likes.
    """
    if on_absorb_error not in ("log", "raise"):
        raise ValueError(
            f"vault.pull: on_absorb_error must be 'log' or 'raise', got {on_absorb_error!r}"
        )

    my_did = cfg.device.did
    try:
        items = client.list_incoming(my_did, since=since_cursor)
    except Exception:
        _log.exception("vault.pull: list_incoming failed")
        if on_absorb_error == "raise":
            raise
        return {"absorbed": 0, "new_cursor": since_cursor}

    if not items:
        return {"absorbed": 0, "new_cursor": since_cursor}

    # Late import: tn.absorb pulls in the runtime which itself uses the
    # handler chain; importing at module-load creates a cycle.
    from ..absorb import absorb as _absorb

    absorbed = 0
    highest_seen = since_cursor
    for item in items:
        path = item.get("path")
        # Per spec §4.1, advance cursor by server-supplied since_marker
        # when present (opaque, order-preserving). Fall back to
        # received_at for backward compat with vault implementations
        # that don't emit since_marker yet.
        cursor_value = item.get("since_marker") or item.get("received_at")
        head_row_hash = item.get("head_row_hash")
        if not isinstance(path, str):
            continue
        try:
            blob = client.download(path)
        except Exception:
            _log.exception("vault.pull: download %s failed", path)
            if on_absorb_error == "raise":
                raise
            # Don't advance the cursor past a failed item — a retry on
            # the next call will re-fetch it.
            return {"absorbed": absorbed, "new_cursor": highest_seen}
        try:
            receipt = _absorb(cfg, blob)
        except Exception as exc:
            _log.exception(
                "vault.pull: absorb failed for %s (head=%s)", path, head_row_hash
            )
            if on_absorb_error == "raise":
                raise
            _ = exc
            continue
        status = getattr(receipt, "status", None) or getattr(
            receipt, "legacy_status", ""
        )
        if status in ("rejected",):
            _log.warning(
                "vault.pull: absorb rejected %s: %s",
                path,
                getattr(receipt, "reason", ""),
            )
            continue
        absorbed += 1
        if isinstance(cursor_value, str):
            if highest_seen is None or cursor_value > highest_seen:
                highest_seen = cursor_value

    return {"absorbed": absorbed, "new_cursor": highest_seen}


class VaultPullHandler(TNHandler):
    """Poll a TN vault inbox for ``.tnpkg`` snapshots and absorb them.

    The handler is "passive" with respect to the emit path — local emits
    do not trigger network calls. ``emit()`` is a no-op. All work happens
    on the scheduler thread.

    Constructor parameters
    ----------------------

    name
        Handler name.
    endpoint
        Base URL of the TN vault.
    project_id
        Project enrolled in the vault.
    cfg_provider
        Callable returning the active ``LoadedConfig``. Default uses
        ``tn.current_config``.
    client_factory
        Callable ``(endpoint, identity) -> object`` returning an
        authenticated client with ``list_incoming(since)`` and
        ``download(path) -> bytes`` methods. Tests inject a mock.
    poll_interval
        Seconds between polls.
    on_absorb_error
        ``"log"`` (default) — failures are logged, the cursor does NOT
        advance for that item. ``"raise"`` — failures propagate out of
        the scheduler tick (still logged).
    cursor_path_override
        Override for the cursor file. Defaults to
        ``<yaml_dir>/.tn/admin/vault_pull.cursor.json``.
    filter_spec
        Standard handler filter dict (forwarded to base; pull handlers
        don't use envelope filtering, but kept for symmetry).
    autostart
        Whether to start the scheduler thread immediately. Tests set
        this False so they can drive ticks deterministically.
    """

    def __init__(
        self,
        name: str,
        *,
        endpoint: str,
        project_id: str,
        cfg_provider: Callable[[], Any] | None = None,
        client_factory: Callable[[str, Any], Any] | None = None,
        poll_interval: float = _DEFAULT_POLL_INTERVAL_SEC,
        on_absorb_error: str = "log",
        cursor_path_override: Path | None = None,
        filter_spec: dict[str, Any] | None = None,
        autostart: bool = True,
    ) -> None:
        super().__init__(name, filter_spec)
        self._endpoint = endpoint.rstrip("/")
        self._project_id = project_id
        self._cfg_provider = cfg_provider or _default_cfg_provider
        self._client_factory = client_factory or _default_client_factory
        self._poll_interval = float(poll_interval)
        if on_absorb_error not in ("log", "raise"):
            raise ValueError(
                f"vault.pull: on_absorb_error must be 'log' or 'raise', got {on_absorb_error!r}"
            )
        self._on_absorb_error = on_absorb_error
        self._cursor_path_override = cursor_path_override

        self._stop_ev = threading.Event()
        self._tick_lock = threading.Lock()
        self._closed = False

        self._scheduler: threading.Thread | None = None
        if autostart:
            self._scheduler = threading.Thread(
                target=self._schedule_loop,
                name=f"tn-vault-pull-{name}",
                daemon=True,
            )
            self._scheduler.start()

    # ------------------------------------------------------------------
    # TNHandler contract
    # ------------------------------------------------------------------

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        # Pull handlers don't react to emits; all work is scheduled.
        return

    def close(self, *, timeout: float = 30.0) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_ev.set()
        if self._scheduler is not None:
            self._scheduler.join(timeout=min(timeout, 5.0))
        # If a tick is mid-flight when close() is called, the lock above
        # ensures it finishes before we return — this is the "drain
        # cleanly" requirement from the plan.
        with self._tick_lock:
            pass

    # ------------------------------------------------------------------
    # Scheduler
    # ------------------------------------------------------------------

    def _schedule_loop(self) -> None:
        # Run a tick immediately so a freshly-started handler doesn't sit
        # idle for the full interval. Then poll.
        try:
            self.tick_once()
        except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _log.exception("[%s] vault.pull initial tick failed", self.name)
        while not self._stop_ev.wait(self._poll_interval):
            try:
                self.tick_once()
            except Exception:
                if self._on_absorb_error == "raise":
                    raise
                _log.exception("[%s] vault.pull tick failed", self.name)

    def tick_once(self) -> int:
        """Run one fetch+absorb cycle. Returns the count of newly absorbed
        snapshots (0 when the inbox is empty or the cursor is current).

        Public so tests can drive the handler deterministically without
        racing against the scheduler thread.
        """
        with self._tick_lock:
            return self._tick_locked()

    def _tick_locked(self) -> int:
        """Thin wrapper around :func:`pull_inbox`: resolves cfg, builds
        a client via the configured factory, loads/saves the on-disk
        cursor file, and forwards ``on_absorb_error`` semantics.
        """
        cfg = self._cfg_provider()
        if cfg is None:
            _log.debug("[%s] vault.pull: no active cfg, skipping", self.name)
            return 0

        cursor = self._load_cursor(cfg)
        prior = cursor.get("last_seen")
        identity = self._resolve_identity(cfg)
        client = self._client_factory(self._endpoint, identity)
        try:
            result = pull_inbox(
                cfg,
                client,
                since_cursor=prior,
                on_absorb_error=self._on_absorb_error,
            )
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                    pass

        new_cursor = result["new_cursor"]
        if new_cursor and new_cursor != prior:
            cursor["last_seen"] = new_cursor
            self._save_cursor(cfg, cursor)
        return result["absorbed"]

    # ------------------------------------------------------------------
    # Cursor persistence
    # ------------------------------------------------------------------

    def _cursor_path(self, cfg: Any) -> Path:
        if self._cursor_path_override is not None:
            return self._cursor_path_override
        return cfg.yaml_path.parent / ".tn" / "admin" / _CURSOR_FILE

    def _load_cursor(self, cfg: Any) -> dict[str, Any]:
        # Prefer the unified sync state file (§4.9 + §10 item 5 part 2).
        # Falls back to the legacy `vault_pull.cursor.json` for backward
        # compat with existing on-disk state. Tests that pass
        # cursor_path_override stay on the legacy path so their
        # assertions still work.
        if self._cursor_path_override is None:
            from ..sync_state import load_sync_state

            unified = load_sync_state(cfg.yaml_path)
            inbox_cursor = unified.get("inbox_cursor")
            if isinstance(inbox_cursor, str):
                return {"last_seen": inbox_cursor}

        path = self._cursor_path(cfg)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _log.warning(
                "[%s] vault.pull: cursor at %s is corrupt; starting fresh",
                self.name,
                path,
            )
            return {}

    def _save_cursor(self, cfg: Any, cursor: dict[str, Any]) -> None:
        # Write to BOTH the unified sync state (canonical going forward)
        # AND the legacy cursor file (so existing tooling that reads
        # `vault_pull.cursor.json` directly keeps working during the
        # transition). When all callers have moved to sync_state, the
        # legacy write can be removed in a follow-up.
        if self._cursor_path_override is None:
            from ..sync_state import update_sync_state

            last_seen = cursor.get("last_seen")
            if isinstance(last_seen, str):
                update_sync_state(cfg.yaml_path, inbox_cursor=last_seen)

        path = self._cursor_path(cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic-ish write so a crash mid-write doesn't leave a half file.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(cursor, indent=2), encoding="utf-8")
        tmp.replace(path)

    # ------------------------------------------------------------------
    # Identity helper (mirrors vault_push)
    # ------------------------------------------------------------------

    def _resolve_identity(self, cfg: Any) -> Any:
        return _DeviceKeyIdentity(cfg.device)


# ---------------------------------------------------------------------------
# Default cfg / client wiring (overridable for tests)
# ---------------------------------------------------------------------------


def _default_cfg_provider() -> Any:
    try:
        from .. import current_config

        return current_config()
    except RuntimeError:
        return None


def _default_client_factory(endpoint: str, identity: Any) -> Any:
    """Build a thin client over VaultClient that exposes ``list_incoming``
    and ``download`` for the inbox endpoints described in the plan.
    """
    from ..vault_client import VaultClient

    client = VaultClient.for_identity(identity, endpoint, auto_auth=True)
    return _SnapshotInboxClient(client)


class _SnapshotInboxClient:
    """Adapter over VaultClient for the inbox GET endpoints."""

    def __init__(self, vc: Any) -> None:
        self._vc = vc

    def list_incoming(self, did: str, *, since: str | None = None) -> list[dict[str, Any]]:
        path = f"/api/v1/inbox/{did}/incoming"
        params = {"since": since} if since else {}
        from urllib.parse import urlencode

        url = f"{self._vc.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        headers = self._vc._headers()
        resp = self._vc._http.request("GET", url, headers=headers)
        if resp.status_code == 401 and self._vc.token:
            self._vc.token = None
            self._vc.authenticate()
            headers = self._vc._headers()
            resp = self._vc._http.request("GET", url, headers=headers)
        self._vc._raise_for_status(resp)
        doc = resp.json() if resp.content else {}
        return list(doc.get("items", []))

    def download(self, path: str) -> bytes:
        url = f"{self._vc.base_url}{path}"
        headers = self._vc._headers()
        resp = self._vc._http.request("GET", url, headers=headers)
        if resp.status_code == 401 and self._vc.token:
            self._vc.token = None
            self._vc.authenticate()
            headers = self._vc._headers()
            resp = self._vc._http.request("GET", url, headers=headers)
        self._vc._raise_for_status(resp)
        return resp.content

    def close(self) -> None:
        close = getattr(self._vc, "close", None)
        if callable(close):
            close()


class _DeviceKeyIdentity:
    """Same shim as vault_push — provides only what VaultClient.authenticate
    needs (``did`` + ``device_private_key_bytes``).
    """

    def __init__(self, device: Any) -> None:
        self._device = device

    @property
    def did(self) -> str:
        return self._device.did

    def device_private_key_bytes(self) -> bytes:
        return self._device.private_bytes

    def vault_wrap_key(self) -> bytes:
        raise NotImplementedError(
            "vault.pull handler does not expose a wrap key — sealed file "
            "download is not part of the snapshot pull path."
        )


__all__ = ["VaultPullHandler", "pull_inbox"]

# Keep imports stable; lint shouldn't complain.
_ = time
