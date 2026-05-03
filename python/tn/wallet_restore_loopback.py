"""One-shot loopback HTTP server for the multi-device restore flow.

Implements the transfer-token-via-loopback dance referenced in
`docs/superpowers/specs/2026-04-27-vault-passive-backup-and-sync-design.md`
section 9.9 and resolves O-2 in
`docs/superpowers/specs/2026-04-28-vault-decisions-log.md`.

The CLI ``tn wallet restore`` cannot run WebAuthn directly. Instead it:

  1. Spins up this loopback server on ``127.0.0.1:<random_port>``.
  2. Opens the user's browser to the vault's ``/restore`` page
     embedding ``return_to=http://127.0.0.1:<port>/cb``.
  3. Browser completes OAuth + passkey unwrap, then POSTs the
     transfer token (``vault_jwt``, ``account_id``, ``project_id``,
     ``raw_bek_b64``) back to ``/cb``.
  4. CLI receives the token, shuts the server down, fetches the
     encrypted blob and decrypts.

Design notes:

* Pure stdlib (``http.server``). No deps so this lives next to the
  rest of the SDK and tests stay lightweight.
* Bound to ``127.0.0.1`` so the kernel will refuse off-host
  connections; we additionally check ``client_address[0]`` as
  defense in depth.
* ``state`` nonce echoes back in the POST so the CLI confirms the
  token belongs to the run that opened the browser. Prevents stale
  tokens from a previous attempt landing in a fresh CLI run.
* Server returns plain text on ``/cb`` so the user's browser tab
  shows a reasonable "you can close this tab" message even before
  the CLI finishes the rest of the restore.

Refs: D-3, D-19, D-20, D-22; plan
``docs/superpowers/plans/2026-04-29-multi-device-restore.md``.
"""

from __future__ import annotations

import json
import secrets
import socket
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


@dataclass
class TransferToken:
    """The payload the browser POSTs back to ``/cb``.

    Shapes (raw_bek_b64 is base64-url, padding optional). All fields
    are required except ``package_did`` which the browser may set to
    null when the project isn't bound to a package DID.
    """

    vault_jwt: str
    account_id: str
    project_id: str
    raw_bek_b64: str
    package_did: str | None = None
    state: str | None = None


class _Done(Exception):
    """Raised internally to signal the request handler should stop."""


class _Handler(BaseHTTPRequestHandler):
    # Suppress the default request-line stderr logging; the CLI prints
    # its own progress messages and we don't want to spam the terminal.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    # The owner LoopbackReceiver patches these as class-level attrs on a
    # subclass so each receiver gets its own state.
    expected_state: str | None = None
    received: dict[str, Any] | None = None
    received_event: threading.Event | None = None
    # CORS allow-origin for the vault page that drives the browser side
    # of the loopback dance. Set via LoopbackReceiver.start(allow_origin=)
    # at receiver construction. Empty string means "no CORS headers".
    # Without the headers, the browser fetch must be `mode: "no-cors"`,
    # which makes the response opaque and masks loopback failures as
    # success — exactly the S4 bug we're fixing here.
    allow_origin: str = ""

    def _cors_headers_for(self, origin_header: str) -> dict[str, str]:
        """Compute the CORS headers to emit for this request.

        The browser only honors the headers when the response's
        Access-Control-Allow-Origin EXACTLY matches the page origin (or
        ``*``, which we never use because credentials may flow). We
        configure ``allow_origin`` from the CLI side (vault URL) and
        echo it on every response — both the actual POST and the
        preflight OPTIONS.
        """
        headers: dict[str, str] = {}
        allow = self.allow_origin
        if not allow:
            return headers
        # Echo the request's Origin only when it matches the configured
        # vault origin. Defense-in-depth: a co-resident attacker that
        # somehow reaches the loopback can't trick us into echoing
        # their origin and getting a green light from the browser.
        if origin_header and origin_header == allow:
            headers["Access-Control-Allow-Origin"] = origin_header
        else:
            headers["Access-Control-Allow-Origin"] = allow
        headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type"
        # Modern browsers honor Vary: Origin so caches don't conflate
        # responses to different page origins.
        headers["Vary"] = "Origin"
        return headers

    def _reject(self, code: int, message: str) -> None:
        body = message.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in self._cors_headers_for(self.headers.get("Origin", "")).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        # Health probe path so users who hit the loopback URL with a
        # browser see a clean message instead of "method not allowed".
        if self.path == "/" or self.path.startswith("/cb"):
            self._reject(405, "POST only")
            return
        self._reject(404, "not found")

    def do_OPTIONS(self) -> None:  # noqa: N802
        # CORS preflight. The browser sends this when the actual fetch
        # is mode:"cors" with a non-simple Content-Type (application/json
        # is non-simple). Reply 204 with the allow-list headers so the
        # subsequent POST is permitted to hit our handler.
        client_host = self.client_address[0] if self.client_address else ""
        if not _is_loopback_host(client_host):
            self._reject(403, "non-loopback origin")
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        for k, v in self._cors_headers_for(self.headers.get("Origin", "")).items():
            self.send_header(k, v)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        # Defense-in-depth check: bind already restricts to loopback,
        # but verify anyway in case the OS surprises us. (S2 — Session
        # 10 review: keep this even though we now bind exclusively to
        # 127.0.0.1; cheap and forecloses any OS-level surprise where
        # an off-host packet somehow makes it through.)
        client_host = self.client_address[0] if self.client_address else ""
        if not _is_loopback_host(client_host):
            self._reject(403, "non-loopback origin")
            return

        if not self.path.startswith("/cb"):
            self._reject(404, "not found")
            return

        length_header = self.headers.get("Content-Length")
        if not length_header:
            self._reject(411, "Content-Length required")
            return
        try:
            length = int(length_header)
        except ValueError:
            self._reject(400, "bad Content-Length")
            return
        # Cap the body — token JSON is small (~1 KB).
        if length <= 0 or length > 64 * 1024:
            self._reject(413, "body too large")
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._reject(400, "invalid JSON")
            return

        if not isinstance(payload, dict):
            self._reject(400, "expected JSON object")
            return

        # Verify state if the caller required one. Mismatch = stale or
        # cross-run; don't deliver to the waiting CLI.
        if self.expected_state is not None:
            got_state = payload.get("state")
            if got_state != self.expected_state:
                self._reject(400, "state mismatch")
                return

        required = ("vault_jwt", "account_id", "project_id", "raw_bek_b64")
        missing = [k for k in required if not payload.get(k)]
        if missing:
            self._reject(400, f"missing fields: {','.join(missing)}")
            return

        # Stash on the class so the CLI thread can pick it up, then
        # signal completion. The thread waiting on ``received_event``
        # is responsible for shutting the server down.
        cls = type(self)
        cls.received = payload  # type: ignore[assignment]
        if cls.received_event is not None:
            cls.received_event.set()

        body = b"Restore initiated. You can close this tab."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in self._cors_headers_for(self.headers.get("Origin", "")).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def _is_loopback_host(host: str) -> bool:
    if host in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        return True
    return host.startswith("127.")


# Windows socket option for exclusive bind. socket.SO_EXCLUSIVEADDRUSE
# was added to stdlib in 3.13; on earlier versions the constant value
# is well-known (-5). Use getattr so this stays compatible.
_SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", -5)


class _ExclusiveLoopbackServer(HTTPServer):
    """HTTPServer that binds exclusively to 127.0.0.1.

    S2 fix: Session 10's original implementation used the default
    HTTPServer which sets SO_REUSEADDR on POSIX. That makes it
    possible for a co-resident process to ALSO bind to the same
    (host, port) tuple in some configurations, opening a window for
    a hostile process to steal the transfer-token POST.

    On Windows we set SO_EXCLUSIVEADDRUSE which actively prevents any
    other socket from sharing the port. On POSIX we explicitly set
    SO_REUSEADDR=0 (HTTPServer's default sets it to 1 via
    ``allow_reuse_address``). Plus we always bind to ``127.0.0.1`` so
    off-loopback traffic can't even reach the listener.
    """

    # Disable HTTPServer's default SO_REUSEADDR=1 — we want exclusive use.
    allow_reuse_address = False
    # Likewise SO_REUSEPORT (Linux/macOS) — disable explicitly.
    allow_reuse_port = False

    def server_bind(self) -> None:
        # On Windows, ask the kernel for exclusive use of the port.
        # If the option errors (e.g. older Python without the constant
        # at the right number), fall through to the default bind: we
        # still have the loopback restriction and the state-nonce check.
        if sys.platform == "win32":
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, _SO_EXCLUSIVEADDRUSE, 1)
            except (OSError, AttributeError):
                pass
        else:
            # Be explicit: a downstream subclass or future stdlib
            # change shouldn't accidentally re-enable address reuse.
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            except OSError:
                pass
        super().server_bind()


@dataclass
class LoopbackReceiver:
    """Manages the lifecycle of the one-shot loopback server.

    Usage:

        rx = LoopbackReceiver.start()  # picks free port
        # open browser to ...?return_to=rx.callback_url&state=rx.state
        token = rx.wait_for_token(timeout_seconds=300)
        rx.shutdown()

    The receiver is single-use: once a token is delivered, additional
    POSTs are rejected (the server has been shut down).
    """

    port: int
    state: str
    server: HTTPServer
    handler_cls: type[_Handler]
    thread: threading.Thread
    allow_origin: str = ""

    @property
    def callback_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/cb"

    @classmethod
    def start(
        cls,
        *,
        port: int | None = None,
        state: str | None = None,
        allow_origin: str = "",
    ) -> LoopbackReceiver:
        """Spin up the server. ``port=None`` lets the kernel pick.

        Returns immediately; the server runs in a background thread.
        The bind happens BEFORE returning — so by the time the caller
        prints the URL, the kernel already holds the port for us
        (closes the S2 race where a co-resident process could grab the
        port between print-and-fetch).

        ``allow_origin`` is the vault page origin (e.g.
        ``https://vault.tn-proto.org``). When set, the server emits
        ``Access-Control-Allow-Origin`` headers so the browser fetch
        can run with ``mode: "cors"`` and observe real status codes
        instead of opaque "no-cors" responses (S4 fix).
        """
        nonce = state or secrets.token_urlsafe(16)
        origin = (allow_origin or "").rstrip("/")

        # Per-receiver subclass so multiple receivers don't share class
        # state. ``received_event`` is what the wait method blocks on.
        evt = threading.Event()

        class Bound(_Handler):
            expected_state = nonce
            received = None
            received_event = evt
            allow_origin = origin

        # Pin to a port if the caller asked, otherwise let the kernel
        # pick (port=0). We pass that directly to the server so the
        # bind reservation happens atomically — no temporary socket,
        # no probe-then-rebind race.
        bind_port = port if port is not None else 0
        server = _ExclusiveLoopbackServer(("127.0.0.1", bind_port), Bound)
        # Short poll interval so shutdown() returns quickly.
        server.timeout = 0.25
        chosen_port = server.server_address[1]

        def _serve() -> None:
            # serve_forever exits when shutdown() is called.
            server.serve_forever(poll_interval=0.25)

        t = threading.Thread(target=_serve, name="tn-restore-loopback", daemon=True)
        t.start()

        return cls(
            port=chosen_port,
            state=nonce,
            server=server,
            handler_cls=Bound,
            thread=t,
            allow_origin=origin,
        )

    def wait_for_token(self, *, timeout_seconds: float = 300.0) -> TransferToken:
        """Block until the browser POSTs a valid token, or raise.

        Raises ``TimeoutError`` if the timeout elapses without delivery,
        and ``RuntimeError`` if the server thread died unexpectedly.
        """
        evt = self.handler_cls.received_event
        if evt is None:
            raise RuntimeError("loopback receiver has no event")
        delivered = evt.wait(timeout=timeout_seconds)
        if not delivered:
            raise TimeoutError(
                "no transfer token received within "
                f"{timeout_seconds:.0f}s — closing tab cancels the restore",
            )
        payload = self.handler_cls.received
        if payload is None:
            raise RuntimeError("event signaled but no payload stored")
        return TransferToken(
            vault_jwt=payload["vault_jwt"],
            account_id=payload["account_id"],
            project_id=payload["project_id"],
            raw_bek_b64=payload["raw_bek_b64"],
            package_did=payload.get("package_did"),
            state=payload.get("state"),
        )

    def shutdown(self) -> None:
        """Stop the server. Idempotent and safe to call from any thread."""
        try:
            self.server.shutdown()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
        try:
            self.server.server_close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
        # Don't join indefinitely — the thread is a daemon.
        self.thread.join(timeout=1.0)


__all__ = ["LoopbackReceiver", "TransferToken"]
