"""OAuth 2.0 Device Authorization Grant (RFC 8628) client — the browser
``tn auth login`` flow. Cross-impl parity with ``ts-sdk/src/auth/device_flow.ts``
(identical wire field + error names).

Idiomatic with ``az login`` / ``gh auth login``: open the browser AND print a
short, human-typeable code as the fallback. The device key stays the principal —
on success the vault returns ``{account_id, did}``; there is no token to store.

Contract:

    POST /api/v1/device/code  {did, signature_b64}
        signature over SHA-256("tn:device-code:<did>") — proves DID ownership.
        -> {device_code, user_code, verification_uri,
            verification_uri_complete, interval, expires_in}
    POST /api/v1/device/token {device_code}   (poll)
        -> 400 {error: authorization_pending | slow_down | expired_token
                | access_denied}  until approved, then 200 {account_id, did}
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

_USER_AGENT = "tn-proto-device-flow"
_DEFAULT_TIMEOUT = 30.0


class DeviceFlowError(Exception):
    """Device-flow failure. ``code`` carries the RFC 8628 error slug when the
    vault returned one (``expired_token`` / ``access_denied`` / ...)."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    interval: int
    expires_in: int


def _device_code_message(did: str) -> bytes:
    return hashlib.sha256(f"tn:device-code:{did}".encode()).digest()


def request_device_code(
    vault_base: str,
    sk: Any,
    did: str,
    *,
    label: str | None = None,
    client: httpx.Client | None = None,
) -> DeviceCode:
    """Start a device-authorization request. ``sk`` is an Ed25519 private key
    (``cryptography`` ``Ed25519PrivateKey``); the request is signed so the vault
    enrolls a DID the caller provably owns."""
    base = vault_base.rstrip("/")
    sig_b64 = base64.b64encode(sk.sign(_device_code_message(did))).decode("ascii")
    body: dict[str, Any] = {"did": did, "signature_b64": sig_b64}
    if label:
        body["label"] = label

    owns = client is None
    c = client or httpx.Client(timeout=_DEFAULT_TIMEOUT, headers={"User-Agent": _USER_AGENT})
    try:
        resp = c.post(f"{base}/api/v1/device/code", json=body)
    finally:
        if owns:
            c.close()
    if resp.status_code != 200:
        raise DeviceFlowError(f"device/code returned {resp.status_code}: {resp.text[:256]}")
    j = resp.json()
    user_code = j["user_code"]
    verification_uri = j["verification_uri"]
    return DeviceCode(
        device_code=j["device_code"],
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=j.get("verification_uri_complete")
        or f"{verification_uri}?code={user_code}",
        interval=int(j.get("interval", 5)),
        expires_in=int(j.get("expires_in", 900)),
    )


def poll_device_token(
    vault_base: str,
    dc: DeviceCode,
    *,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, str]:
    """Poll ``/device/token`` until the user approves, the code expires, or it's
    denied. Honors RFC 8628 ``authorization_pending`` (wait) / ``slow_down``
    (add 5s). Returns ``{"account_id", "did"}``. ``sleep`` is injectable for
    tests; the loop bounds itself on the poll budget so a stubbed sleep can't
    spin forever."""
    base = vault_base.rstrip("/")
    interval = dc.interval
    elapsed = 0

    owns = client is None
    c = client or httpx.Client(timeout=_DEFAULT_TIMEOUT, headers={"User-Agent": _USER_AGENT})
    try:
        while True:
            if elapsed >= dc.expires_in:
                raise DeviceFlowError("device code expired before approval", "expired_token")
            sleep(interval)
            elapsed += interval

            resp = c.post(f"{base}/api/v1/device/token", json={"device_code": dc.device_code})
            if resp.status_code == 200:
                j = resp.json()
                account_id = j.get("account_id")
                if not account_id:
                    raise DeviceFlowError(f"device/token ok but missing account_id: {j!r}")
                return {"account_id": account_id, "did": j.get("did", ""),
                        "awk_pickup_key_id": j.get("awk_pickup_key_id")}

            err = ""
            try:
                err = str(resp.json().get("error", ""))
            except Exception:  # noqa: BLE001 — non-JSON body → terminal below
                pass
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            if err == "expired_token":
                raise DeviceFlowError("device code expired before approval", "expired_token")
            if err == "access_denied":
                raise DeviceFlowError("sign-in was denied in the browser", "access_denied")
            raise DeviceFlowError(
                f"device/token returned {resp.status_code}" + (f" ({err})" if err else ""),
                err or None,
            )
    finally:
        if owns:
            c.close()


def open_browser(url: str) -> bool:
    """Best-effort browser open (the auto path). Returns True if a launcher was
    invoked. The caller ALWAYS prints the code + URL regardless, so False is a
    non-event. ``TN_NO_BROWSER=1`` skips. Never raises."""
    if os.environ.get("TN_NO_BROWSER") == "1":
        return False
    try:
        return webbrowser.open(url)
    except Exception:  # noqa: BLE001 — best-effort; the printed URL covers it
        return False
