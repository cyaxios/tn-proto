"""Device-authorization (RFC 8628) client — `tn.device_flow`.

Cross-impl parity with ts-sdk/test/auth_device_flow.test.ts: signs the DID on
/device/code, polls /device/token through authorization_pending -> 200, and
surfaces expired_token / access_denied as DeviceFlowError. Verified against an
httpx MockTransport so no live vault is needed.
"""

from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tn.device_flow import (
    DeviceFlowError,
    poll_device_token,
    request_device_code,
)

_DID = "did:key:zDeviceFlowTest"


def _mock(pending_polls: int = 0, token_error: str | None = None):
    state = {"polls": 0, "seen_did": None, "seen_sig": None}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/device/code":
            body = json.loads(request.content)
            state["seen_did"] = body.get("did")
            state["seen_sig"] = body.get("signature_b64")
            return httpx.Response(
                200,
                json={
                    "device_code": "dev_secret_123",
                    "user_code": "WDJB-MJHT",
                    "verification_uri": "https://vault.test/device",
                    "verification_uri_complete": "https://vault.test/device?code=WDJB-MJHT",
                    "interval": 1,
                    "expires_in": 60,
                },
            )
        if request.url.path == "/api/v1/device/token":
            if token_error:
                return httpx.Response(400, json={"error": token_error})
            if state["polls"] < pending_polls:
                state["polls"] += 1
                return httpx.Response(400, json={"error": "authorization_pending"})
            return httpx.Response(200, json={"account_id": "01ACCT_DEVICEFLOW", "did": _DID})
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler)), state


def test_request_signs_did_and_poll_resolves():
    client, state = _mock(pending_polls=2)
    sk = Ed25519PrivateKey.generate()
    dc = request_device_code("https://vault.test", sk, _DID, client=client)
    assert dc.user_code == "WDJB-MJHT"
    assert dc.verification_uri_complete.endswith("code=WDJB-MJHT")
    # The CLI sent its DID + a signature the vault can verify.
    assert state["seen_did"] == _DID
    expected_msg = hashlib.sha256(f"tn:device-code:{_DID}".encode()).digest()
    sk.public_key().verify(base64.b64decode(state["seen_sig"]), expected_msg)

    res = poll_device_token("https://vault.test", dc, client=client, sleep=lambda _s: None)
    assert res == {"account_id": "01ACCT_DEVICEFLOW", "did": _DID, "awk_pickup_key_id": None}


def test_poll_expired_raises():
    client, _ = _mock(token_error="expired_token")
    sk = Ed25519PrivateKey.generate()
    dc = request_device_code("https://vault.test", sk, _DID, client=client)
    with pytest.raises(DeviceFlowError) as ei:
        poll_device_token("https://vault.test", dc, client=client, sleep=lambda _s: None)
    assert ei.value.code == "expired_token"


def test_poll_denied_raises():
    client, _ = _mock(token_error="access_denied")
    sk = Ed25519PrivateKey.generate()
    dc = request_device_code("https://vault.test", sk, _DID, client=client)
    with pytest.raises(DeviceFlowError) as ei:
        poll_device_token("https://vault.test", dc, client=client, sleep=lambda _s: None)
    assert ei.value.code == "access_denied"
