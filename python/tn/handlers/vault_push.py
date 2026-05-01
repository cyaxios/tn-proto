"""``vault.push`` handler — admin log snapshot push to a TN vault.

Per the 2026-04-24 admin log architecture plan §5.2: the push side
subscribes to admin events. On emit (or on a schedule), runs
``tn.export(out_path, kind="admin_log_snapshot")`` and POSTs the
resulting ``.tnpkg`` to the vault inbox addressed by the writer's DID.

Two operating modes (per **D-19** / plan
``2026-04-28-pending-claim-flow.md`` §"How the handler distinguishes…"):

* **INIT-UPLOAD mode** (``sync_state.account_bound is False``): the
  handler has no JWT yet because the user has no vault account. It
  exports a ``full_keystore`` tnpkg encrypted under a fresh AES-256-GCM
  body-encryption key (BEK), POSTs the ciphertext UNAUTHENTICATED to
  ``POST /api/v1/pending-claims``, and surfaces a claim URL of the form
  ``{vault_base}/claim/{vault_id}#k=<password_b64>`` for the user. The
  BEK travels in the URL fragment to the browser claim page (D-5); the
  vault stores ciphertext only (D-1). Persisted to sync_state so a
  handler restart inside the 30-min TTL window doesn't double-upload.
* **STEADY-STATE mode** (``sync_state.account_bound is True``): the
  user has claimed; the vault knows the package's account. Standard
  authenticated POST to ``/api/v1/inbox/{did}/snapshots/{ceremony}/...``
  via ``push_snapshot()``.

One-shot entry point
--------------------

Per the 2026-04-27 vault-passive-backup-and-sync-design §4.11 / §10
item 6: the bulk of the push work is also exposed as a module-level
pure function ``push_snapshot(cfg, client, *, scope="admin",
to_did=None) -> dict``. The handler class simply schedules calls to
this function; a future ``tn sync`` CLI verb can call ``push_snapshot``
directly without instantiating a daemon-shaped handler.

The init-upload counterpart is exposed as :func:`init_upload` (also
module-level pure) for the same reason.

Config shape (tn.yaml)::

    - kind: vault.push
      endpoint: https://api.cyaxios.com
      project_id: proj_xxx
      trigger: on_emit | on_schedule    # default: on_schedule
      poll_interval: 60s                # only for on_schedule
      scope: admin                      # snapshot scope

Mailbox path (POST):
    {endpoint}/api/v1/inbox/{my_did}/snapshots/{ceremony_id}/{ts}.tnpkg

Idempotency: the snapshot's ``head_row_hash`` rides as a query parameter
``?head_row_hash=...`` so the vault may dedupe. The handler also tracks
the last shipped ``head_row_hash`` in memory and skips a push when the
admin log's head hasn't advanced since the previous snapshot.

Authentication reuses ``tn.vault_client.VaultClient`` (DID challenge →
JWT bearer) so we don't reinvent the wheel here.

Key contract:
* ``accepts(envelope)`` returns True only for envelopes whose
  ``event_type`` starts with ``tn.``. Other events do not trigger a
  snapshot, saving bandwidth.
* ``trigger=on_emit``: each accepted emit fires a snapshot synchronously
  (well, via the OutboxWorker — emit hands off to a durable queue and
  the worker drains in a background thread). One snapshot per admin
  event is intentional; the vault dedupes by ``head_row_hash``.
* ``trigger=on_schedule``: emit is a no-op other than recording the
  envelope; a scheduler thread fires snapshots on a fixed interval.
* ``flush_and_close()`` drains cleanly: the scheduler thread exits, any
  in-flight push completes, then the outbox closes.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .base import TNHandler

_log = logging.getLogger("tn.handlers.vault_push")

_DEFAULT_POLL_INTERVAL_SEC = 60.0


# ---------------------------------------------------------------------------
# Pure one-shot entry point (importable by `tn sync` CLI verb)
# ---------------------------------------------------------------------------


def push_snapshot(
    cfg: Any,
    client: Any,
    *,
    scope: str = "admin",
    to_did: str | None = None,
    skip_if_head_matches: str | None = None,
) -> dict[str, Any]:
    """Build and POST one admin-log snapshot to a TN vault inbox.

    This is the daemon-free, scheduler-free version of the work that
    :class:`VaultPushHandler` performs on each tick. The handler is a
    thin wrapper that schedules and serialises calls to this function;
    a future ``tn sync`` CLI verb can call it directly with no thread
    or hook machinery in the way.

    Parameters
    ----------
    cfg
        The active ``LoadedConfig``. Caller is responsible for resolving
        it (e.g. via ``tn.current_config()``).
    client
        An object exposing ``post_inbox_snapshot(path, body, *, params)``.
        Caller owns the lifecycle (auth + close).
    scope
        ``scope`` field passed through to ``tn.export``.
    to_did
        Optional recipient DID stamped into the manifest (see
        :class:`VaultPushHandler` docstring for routing context).
    skip_if_head_matches
        If non-None and the freshly-exported snapshot's
        ``head_row_hash`` equals this value, skip the POST and unlink
        the redundant ``.tnpkg`` from the outbox. Returns
        ``pushed=False`` in that case. The handler uses this for its
        in-memory ``_last_shipped_head`` dedupe; one-shot CLI callers
        can pass ``None`` to always push.

    Returns
    -------
    dict
        ``{"pushed": bool, "head_row_hash": str | None,
        "stored_path": str | None}``. ``stored_path`` is the local
        ``.tnpkg`` path that was POSTed (None when the call was a
        dedupe-skip).
    """
    # Late import: tn.export pulls in the runtime which itself uses the
    # handler chain; importing at module-load creates a cycle.
    from ..conventions import admin_outbox_dir
    from ..export import export
    from ..tnpkg import _read_manifest

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    # Per session-11 outbox-layout-migration plan (2026-04-29): admin
    # snapshots stage at <yaml_dir>/.tn/<stem>/admin/outbox/ (the unified
    # per-stem layout). The legacy path was <yaml_dir>/.tn/admin/outbox/;
    # see legacy_admin_outbox_dir for the read-side fallback used by
    # earlier-staged-but-not-yet-POSTed snapshots.
    out_dir = admin_outbox_dir(cfg.yaml_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"snapshot_{ts}.tnpkg"
    try:
        export(
            out_path,
            kind="admin_log_snapshot",
            cfg=cfg,
            scope=scope,
            to_did=to_did,
        )
    except Exception:
        _log.exception("vault.push: export failed")
        raise

    manifest, _body = _read_manifest(out_path)
    head = manifest.head_row_hash

    if head and skip_if_head_matches is not None and head == skip_if_head_matches:
        # Clean up the redundant snapshot to keep the outbox tidy.
        try:
            out_path.unlink()
        except OSError:
            pass
        return {"pushed": False, "head_row_hash": head, "stored_path": None}

    with open(out_path, "rb") as f:
        body = f.read()
    ceremony_id = manifest.ceremony_id
    my_did = manifest.from_did
    url_path = f"/api/v1/inbox/{my_did}/snapshots/{ceremony_id}/{ts}.tnpkg"
    params = {"head_row_hash": head} if head else {}
    client.post_inbox_snapshot(url_path, body, params=params)

    return {
        "pushed": True,
        "head_row_hash": head,
        "stored_path": str(out_path),
    }


# ---------------------------------------------------------------------------
# Init-upload mode (D-19, plan 2026-04-28-pending-claim-flow.md §"How the
# handler distinguishes init-upload vs steady-state push", phases 4+5).
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    """RFC 4648 base64url (no padding) — matches the URL fragment form
    expected by the browser claim page."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _emit_claim_url_admin_event(
    cfg: Any,
    *,
    claim_url: str,
    vault_id: str,
    expires_at: str,
) -> Path:
    """Drop a ``tn.vault.claim_url_issued`` admin event into the unified
    per-stem admin outbox (Session 11 layout: ``.tn/<stem>/admin/outbox/``).

    Cite: D-19 (handler-driven sync), plan §"Claim URL surfacing",
    Session 11 outbox-layout-migration (commit ad1949db).

    The brief asks for an admin event "into the ceremony's admin log";
    invariant C17 in ``live_consistency_check.py`` checks the
    ``admin/outbox/`` directory specifically. We emit a minimal envelope
    JSON file there — the same shape an admin event would have on the
    main log — so an auditor inspecting the outbox sees the issuance
    trail. Best-effort: a write failure is logged and swallowed.
    """
    from ..conventions import admin_outbox_dir

    out_dir = admin_outbox_dir(cfg.yaml_path)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        _log.warning("vault.push init-upload: cannot create admin outbox dir: %s", e)
        # Return a value so the caller doesn't have to special-case this;
        # the file simply won't exist on disk.
        return out_dir / f"claim_url_issued_{vault_id}.json"

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    filename = f"claim_url_issued_{ts}_{vault_id}.json"
    path = out_dir / filename
    envelope = {
        "event_type": "tn.vault.claim_url_issued",
        "did": getattr(getattr(cfg, "device", None), "did", None),
        "claim_url": claim_url,
        "vault_id": vault_id,
        "expires_at": expires_at,
        "emitted_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }
    try:
        path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as e:
        _log.warning("vault.push init-upload: cannot write claim_url event: %s", e)
    return path


def _write_claim_url_file(yaml_path: Path, claim_url: str) -> Path:
    """Write the cat-friendly claim URL to ``<yaml_dir>/.tn/sync/claim_url.txt``.

    Cite: plan §"Claim URL surfacing" (b). Best-effort.
    """
    from ..sync_state import _state_dir as _sync_state_dir  # noqa: PLC2701

    target = _sync_state_dir(yaml_path) / "claim_url.txt"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(claim_url + "\n", encoding="utf-8")
    except OSError as e:
        _log.warning("vault.push init-upload: cannot write claim_url.txt: %s", e)
    return target


def init_upload(
    cfg: Any,
    client: Any,
    *,
    vault_base: str,
    keystore: Path | None = None,
    reuse_pending_window: bool = True,
) -> dict[str, Any]:
    """Build an encrypted ``full_keystore`` tnpkg, POST to /pending-claims.

    Pure module-level entry point so a future ``tn sync`` CLI verb can
    drive init-upload without standing up a handler daemon (mirrors the
    rationale in :func:`push_snapshot`).

    Parameters
    ----------
    cfg
        The active ``LoadedConfig``.
    client
        Object exposing ``post_pending_claim(body) -> dict``. The
        :class:`_SnapshotPostingClient` adapter implements it.
    vault_base
        Base URL for the vault (used to build the claim URL).
    keystore
        Optional override for the keystore directory. Defaults to
        ``cfg.keystore``.
    reuse_pending_window
        When True (the default), if ``sync_state.pending_claim`` exists
        and is still inside its TTL, return that record without
        re-uploading. This is the C18 idempotency invariant.

    Returns
    -------
    dict
        ``{"vault_id": str, "expires_at": str, "claim_url": str,
        "password_b64": str, "reused": bool}``.
    """
    from ..export import export
    from ..sync_state import (
        get_pending_claim,
        set_pending_claim,
    )

    # C18: idempotency. Reuse a live pending claim within the TTL window.
    if reuse_pending_window:
        existing = get_pending_claim(cfg.yaml_path)
        if existing is not None:
            try:
                exp = datetime.fromisoformat(existing["expires_at"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if exp > datetime.now(timezone.utc):
                    return {
                        "vault_id": existing["vault_id"],
                        "expires_at": existing["expires_at"],
                        "claim_url": existing["claim_url"],
                        "password_b64": existing["password_b64"],
                        "reused": True,
                    }
            except (KeyError, ValueError):
                # Malformed pending_claim — fall through and re-upload.
                pass

    # Generate a fresh BEK + ciphertext-encoded full_keystore tnpkg.
    bek = secrets.token_bytes(32)
    password_b64 = _b64url(bek)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out_dir = cfg.yaml_path.parent / ".tn" / "sync"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"init_upload_{ts}.tnpkg"
    ks = keystore if keystore is not None else getattr(cfg, "keystore", None)
    export(
        out_path,
        kind="full_keystore",
        cfg=cfg,
        keystore=ks,
        confirm_includes_secrets=True,
        encrypt_body_with=bek,
    )
    body = out_path.read_bytes()
    # Best-effort cleanup of the staged file: it carries ciphertext only,
    # but it has no further use locally once the bytes are POSTed.
    try:
        out_path.unlink()
    except OSError:
        pass

    # POST to /api/v1/pending-claims (no auth — D-19 / plan §"Wire contract").
    resp = client.post_pending_claim(body)
    vault_id = resp["vault_id"]
    expires_at = resp["expires_at"]

    # Build the claim URL. Fragment carries the BEK per D-5; the server
    # never sees this value. ``k=`` prefix matches the browser claim
    # page (Session 5) sessionStorage key shape.
    claim_url = f"{vault_base.rstrip('/')}/claim/{vault_id}#k={password_b64}"

    # Persist into sync_state so handler restart reuses the link inside TTL.
    set_pending_claim(
        cfg.yaml_path,
        vault_id=vault_id,
        expires_at=expires_at,
        claim_url=claim_url,
        password_b64=password_b64,
    )

    # Surface (a) cat-friendly file (b) admin event.
    _write_claim_url_file(cfg.yaml_path, claim_url)
    _emit_claim_url_admin_event(
        cfg,
        claim_url=claim_url,
        vault_id=vault_id,
        expires_at=expires_at,
    )

    return {
        "vault_id": vault_id,
        "expires_at": expires_at,
        "claim_url": claim_url,
        "password_b64": password_b64,
        "reused": False,
    }


class VaultPushHandler(TNHandler):
    """Push admin-log snapshots to a TN vault inbox.

    Constructor parameters
    ----------------------

    name
        Handler name (for logging / outbox path).
    endpoint
        Base URL of the vault (e.g. ``https://api.cyaxios.com``).
    project_id
        Project enrolled in the vault.
    cfg_provider
        Callable returning the active ``LoadedConfig``. Default uses
        ``tn.current_config``. Tests inject a fixed config here.
    client_factory
        Callable ``(endpoint, identity) -> object`` returning a
        ``VaultClient``-shaped object. Default uses
        ``VaultClient.for_identity``. Tests inject a mock that captures
        POST calls without speaking real HTTP.
    trigger
        ``"on_emit"`` (snapshot per admin event) or ``"on_schedule"``
        (snapshot every ``poll_interval`` seconds). Defaults to
        ``on_schedule`` because per-event snapshots are bandwidth-heavy.
    poll_interval
        Seconds between scheduled snapshots. Ignored when
        ``trigger=on_emit``.
    scope
        ``scope`` field passed through to ``tn.export``.
    to_did
        Optional recipient DID to stamp into the manifest. The vault's v1
        inbox routing rule (plan 2026-04-25 §4) requires
        ``manifest.to_did`` to be present so the snapshot lands in that
        DID's per-recipient inbox. Leaving this ``None`` produces an
        unaddressed snapshot that the vault will reject with HTTP 422.
        Future versions may auto-derive this from the active group's
        recipient roster; for now it's an explicit config knob.
    filter_spec
        Optional standard handler filter dict.
    """

    def __init__(
        self,
        name: str,
        *,
        endpoint: str,
        project_id: str,
        cfg_provider: Callable[[], Any] | None = None,
        client_factory: Callable[[str, Any], Any] | None = None,
        trigger: str = "on_schedule",
        poll_interval: float = _DEFAULT_POLL_INTERVAL_SEC,
        scope: str = "admin",
        to_did: str | None = None,
        filter_spec: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(name, filter_spec)
        self._endpoint = endpoint.rstrip("/")
        self._project_id = project_id
        self._scope = scope
        self._to_did = to_did
        self._trigger = trigger
        self._poll_interval = float(poll_interval)
        self._cfg_provider = cfg_provider or _default_cfg_provider
        self._client_factory = client_factory or _default_client_factory

        # Last-shipped head_row_hash; used both as "have we anything new
        # to ship" guard and as idempotency hint to the vault.
        # Initialized lazily from the persisted sync state on first push
        # (we don't have cfg here in __init__; the cfg_provider may not
        # yet be wired). See spec §4.9 + §10 deferred workstream item 5.
        self._last_shipped_head: str | None = None
        self._last_shipped_head_loaded = False
        self._lock = threading.Lock()
        # Init-upload serialization (D-29 / S7 fix). Two concurrent
        # _init_upload_tick calls (e.g. on_emit racing the scheduler
        # tick) must NOT both mint a BEK + POST to /pending-claims, or
        # the vault sees two distinct vault_ids for the same ceremony
        # and the second one stomps the first's sync_state. We hold
        # this lock around init_upload so the BEK/vault_id mint and the
        # subsequent set_pending_claim are serialized; the lock is
        # NOT shared with self._lock because init_upload performs I/O
        # (export, POST) and we don't want to block the steady-state
        # head-pointer load on a slow init.
        self._init_lock = threading.Lock()
        self._closed = False

        # Scheduler thread, only started when trigger=on_schedule.
        self._stop_ev = threading.Event()
        self._scheduler: threading.Thread | None = None
        if self._trigger == "on_schedule":
            self._scheduler = threading.Thread(
                target=self._schedule_loop,
                name=f"tn-vault-push-{name}",
                daemon=True,
            )
            self._scheduler.start()
        elif self._trigger != "on_emit":
            raise ValueError(
                f"vault.push: trigger must be 'on_emit' or 'on_schedule', got {trigger!r}"
            )

    # ------------------------------------------------------------------
    # TNHandler contract
    # ------------------------------------------------------------------

    def accepts(self, envelope: dict[str, Any]) -> bool:
        # Only admin events should trigger a snapshot push. Saves bandwidth
        # on busy main-log writers.
        if not super().accepts(envelope):
            return False
        et = envelope.get("event_type")
        return isinstance(et, str) and et.startswith("tn.")

    def emit(self, envelope: dict[str, Any], raw_line: bytes) -> None:
        if self._trigger == "on_emit":
            try:
                self._push_snapshot()
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                # Per the architecture plan: a failed push must not take
                # down the caller. The next emit / scheduled tick retries.
                _log.exception("[%s] vault.push on_emit failed", self.name)

    def close(self, *, timeout: float = 30.0) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._stop_ev.set()
        if self._scheduler is not None:
            self._scheduler.join(timeout=min(timeout, 5.0))
        # Best-effort final flush so a clean shutdown doesn't leave a
        # batch of admin events un-shipped.
        try:
            self._push_snapshot()
        except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
            _log.exception("[%s] vault.push final flush failed", self.name)

    # ------------------------------------------------------------------
    # Scheduler
    # ------------------------------------------------------------------

    def _schedule_loop(self) -> None:
        # Wait first, then push — emitting at startup before any admin
        # events have happened produces an empty snapshot.
        while not self._stop_ev.wait(self._poll_interval):
            try:
                self._push_snapshot()
            except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                _log.exception("[%s] vault.push scheduler tick failed", self.name)

    # ------------------------------------------------------------------
    # Snapshot + POST
    # ------------------------------------------------------------------

    def _push_snapshot(self) -> bool:
        """Build a `.tnpkg`, POST it to the vault. Returns True on push,
        False on noop (no new admin events since last push).

        Per D-19 (handler-driven sync), the entry point switches between
        init-upload mode (no JWT yet — POST to /pending-claims unauth)
        and steady-state mode (POST to /inbox/{did}/snapshots/...) based
        on ``sync_state.account_bound``. The dispatch happens here so
        tests / live consistency invariants exercise the same code path
        the daemon runs.

        Thin wrapper around the module-level :func:`push_snapshot` pure
        function in steady state: resolves cfg from the configured
        provider, builds a client via the configured factory, threads
        through the daemon's ``_last_shipped_head`` dedupe state, and
        updates that state on successful push. The dedupe state is also
        persisted to ``<yaml_dir>/.tn/sync/state.json`` (per §4.9) so
        process restarts pick up where they left off.
        """
        cfg = self._cfg_provider()
        if cfg is None:
            _log.debug("[%s] vault.push: no active cfg, skipping", self.name)
            return False

        # Mode dispatch (D-19). account_bound flips True after the
        # browser claim page POSTs /bind and the vault echoes back, or
        # when the handler probes /accounts/by-package-did/{did} and
        # gets a hit. In INIT-UPLOAD mode we don't need DID-challenge
        # auth at all — the POST is unauthenticated by design.
        from ..sync_state import is_account_bound

        if not is_account_bound(cfg.yaml_path):
            return self._init_upload_tick(cfg)

        # Lazy-load the persisted last_pushed_admin_head on first push
        # for this handler instance. Survives process restart so a
        # cron-wrapped tn sync doesn't re-push unchanged snapshots.
        with self._lock:
            if not self._last_shipped_head_loaded:
                from ..sync_state import get_last_pushed_admin_head
                persisted = get_last_pushed_admin_head(cfg.yaml_path)
                if persisted is not None and self._last_shipped_head is None:
                    self._last_shipped_head = persisted
                self._last_shipped_head_loaded = True
            skip_head = self._last_shipped_head

        identity = self._resolve_identity(cfg)
        client = self._client_factory(self._endpoint, identity)
        try:
            result = push_snapshot(
                cfg,
                client,
                scope=self._scope,
                to_did=self._to_did,
                skip_if_head_matches=skip_head,
            )
        finally:
            close_fn = getattr(client, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:  # noqa: BLE001 — preserve broad swallow; see body of handler
                    pass

        if result["pushed"]:
            head = result["head_row_hash"]
            with self._lock:
                self._last_shipped_head = head
            # Persist so process restart picks up where we left off.
            # Best-effort; sync_state.set_last_pushed_admin_head logs
            # and swallows write errors so a transient FS issue doesn't
            # take down the push pipeline.
            if isinstance(head, str) and head:
                from ..sync_state import set_last_pushed_admin_head
                set_last_pushed_admin_head(cfg.yaml_path, head)
            _log.info(
                "[%s] vault.push: pushed snapshot %s (head=%s)",
                self.name,
                result["stored_path"],
                head,
            )
            return True
        else:
            _log.debug(
                "[%s] vault.push: head_row_hash unchanged (%s), skipped POST",
                self.name,
                result["head_row_hash"],
            )
            return False

    # ------------------------------------------------------------------
    # Init-upload mode dispatch
    # ------------------------------------------------------------------

    def _init_upload_tick(self, cfg: Any) -> bool:
        """Run one init-upload pass for this ceremony.

        Returns True on successful POST (or successful reuse of a live
        pending claim within the TTL window — both count as "the
        handler did something"). Returns False on a soft-warn failure
        (vault unreachable, etc.) so the caller doesn't propagate.

        Per D-19 / plan §"Vault unreachable behavior", HTTP errors are
        soft-warned and swallowed; the next handler tick retries.

        Concurrency contract (D-29 / S7 fix): the entire init pass — mint of
        BEK + vault_id, POST, and ``set_pending_claim`` write — is
        serialized under ``self._init_lock``. Without this, two
        concurrent ticks (on_emit racing the scheduler) can both pass
        ``get_pending_claim() is None`` and both POST, producing two
        distinct vault_ids for the same ceremony where the second
        stomps the first in sync_state. The C18 idempotency reuse-
        within-TTL check inside ``init_upload`` is a read-then-write
        TOCTOU on its own; the lock is what makes it atomic for this
        handler.
        """
        # Identity is unused in init-upload (the POST is unauthenticated
        # by design — D-19) but we keep the same client factory so tests
        # can inject a mock that captures both push paths.
        with self._init_lock:
            identity = self._resolve_identity(cfg)
            client = self._client_factory(self._endpoint, identity)
            try:
                try:
                    result = init_upload(
                        cfg,
                        client,
                        vault_base=self._endpoint,
                    )
                except Exception as e:  # noqa: BLE001 — soft warning per D-19
                    _log.warning(
                        "[%s] vault.push init-upload failed (will retry next tick): %s",
                        self.name,
                        e,
                    )
                    return False
                _log.info(
                    "[%s] vault.push init-upload: vault_id=%s reused=%s",
                    self.name,
                    result.get("vault_id"),
                    result.get("reused"),
                )
                return True
            finally:
                close_fn = getattr(client, "close", None)
                if callable(close_fn):
                    try:
                        close_fn()
                    except Exception:  # noqa: BLE001 — preserve broad swallow
                        pass

    def _resolve_identity(self, cfg: Any) -> Any:
        """Build a tn.identity.Identity-shaped object for VaultClient.

        ``cfg.device`` is a ``DeviceKey`` (Ed25519). ``Identity`` also
        carries the wrap key for sealed file uploads; we don't need that
        for snapshot pushes, but VaultClient.for_identity calls
        ``identity.device_private_key_bytes()`` during auth so we
        provide a thin shim that satisfies that contract.
        """
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
    """Build a real VaultClient that knows how to POST snapshots.

    Per D-19, the handler runs in two modes. The init-upload mode hits
    the ``/api/v1/pending-claims`` endpoint UNAUTHENTICATED, so we
    don't need a JWT cached when the client is built. Steady-state mode
    needs auth, but VaultClient's ``post_inbox_snapshot`` already
    handles 401-reauth lazily; we therefore build with
    ``auto_auth=False`` and let the first authenticated request pull a
    fresh token. Tests inject a mock that captures requests instead of
    speaking real HTTP.
    """
    from ..vault_client import VaultClient

    client = VaultClient.for_identity(identity, endpoint, auto_auth=False)
    return _SnapshotPostingClient(client)


class _SnapshotPostingClient:
    """Adapter that adds ``post_inbox_snapshot`` and ``post_pending_claim``
    methods to VaultClient.

    ``post_inbox_snapshot`` is the steady-state authenticated POST.
    ``post_pending_claim`` is the init-upload UNAUTHENTICATED POST per
    D-19 / plan ``2026-04-28-pending-claim-flow.md`` §"Wire contract".
    """

    def __init__(self, vc: Any) -> None:
        self._vc = vc

    def post_inbox_snapshot(
        self, path: str, body: bytes, *, params: dict[str, str] | None = None
    ) -> None:
        # Reuse VaultClient._request so token re-auth-on-401 is free.
        vc = self._vc
        url = f"{vc.base_url}{path}"
        if params:
            from urllib.parse import urlencode

            url = f"{url}?{urlencode(params)}"
        # Direct httpx call so we can pass a query string. Bearer token
        # comes from VaultClient's cached state. If the client was built
        # with ``auto_auth=False`` (the new default — see
        # ``_default_client_factory``) the first call may have no token;
        # authenticate lazily so steady-state pushes still work.
        if not vc.token:
            vc.authenticate()
        headers = vc._headers({"Content-Type": "application/octet-stream"})
        resp = vc._http.request("POST", url, content=body, headers=headers)
        if resp.status_code == 401:
            vc.token = None
            vc.authenticate()
            headers = vc._headers({"Content-Type": "application/octet-stream"})
            resp = vc._http.request("POST", url, content=body, headers=headers)
        vc._raise_for_status(resp)

    def post_pending_claim(self, body: bytes) -> dict[str, Any]:
        """Unauthenticated POST to /api/v1/pending-claims (D-19, D-1).

        Returns the JSON body ``{"vault_id": ..., "expires_at": ...}``.
        Does not send any Authorization header — the endpoint is
        explicitly unauthenticated per Session 2's implementation
        (commit ``abee8795``) and the plan.

        Sends ``X-Publisher-Did`` so the vault can later emit a
        ``contact_update`` tnpkg back to this package's inbox at bind
        time (Session 8, plan
        ``docs/superpowers/plans/2026-04-29-contact-update-tnpkg.md``,
        D-25). The header is optional for backward compatibility — the
        endpoint just stores ``None`` and skips emit if it's missing.
        """
        vc = self._vc
        url = f"{vc.base_url}/api/v1/pending-claims"
        headers = {"Content-Type": "application/octet-stream"}
        # ``identity`` lives on VaultClient; ``_device`` is the legacy
        # name on the bare _DeviceKeyIdentity wrapper. Try both so this
        # works whether the wrapper holds a real VaultClient or a
        # mock-built object that exposes the device directly.
        publisher_did: str | None = None
        identity = getattr(vc, "identity", None)
        if identity is not None:
            publisher_did = getattr(identity, "did", None)
        if not publisher_did:
            device = getattr(vc, "_device", None)
            publisher_did = getattr(device, "did", None) if device else None
        if publisher_did:
            headers["X-Publisher-Did"] = publisher_did
        resp = vc._http.request("POST", url, content=body, headers=headers)
        vc._raise_for_status(resp)
        return resp.json()

    def close(self) -> None:
        close = getattr(self._vc, "close", None)
        if callable(close):
            close()


class _DeviceKeyIdentity:
    """Minimal Identity surface so VaultClient.authenticate() works.

    ``VaultClient`` only needs ``did`` and ``device_private_key_bytes``
    for the DID challenge / verify auth flow. We don't ship the wrap
    key because snapshot push doesn't seal blobs.
    """

    def __init__(self, device: Any) -> None:
        self._device = device

    @property
    def did(self) -> str:
        return self._device.did

    def device_private_key_bytes(self) -> bytes:
        return self._device.private_bytes

    def vault_wrap_key(self) -> bytes:
        # Snapshot push doesn't seal blobs — but VaultClient never reaches
        # for this attribute on the auth path. Provide a safe fallback so
        # mistakes raise loudly rather than silently corrupt state.
        raise NotImplementedError(
            "vault.push handler does not expose a wrap key — sealed file "
            "upload is not part of the snapshot path."
        )


__all__ = ["VaultPushHandler", "init_upload", "push_snapshot"]

# Avoid 'time' being flagged unused — it appears in tests via monkeypatch
# of this module's clock; keep the symbol bound.
_ = time
_ = NamedTemporaryFile
