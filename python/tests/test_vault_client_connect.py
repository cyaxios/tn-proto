"""Tests for tn.vault_client.redeem_connect_code.

The connect-code flow is the headless companion to the dashboard's
"Connect a new app or device" action. These tests mock the HTTP layer
via httpx.MockTransport and assert that the SDK builds the exact
request the vault expects:

  - POST /api/v1/account/connect-codes/redeem
  - JSON body has {code, did, signature_b64}
  - signature_b64 is Ed25519 over sha256(code.encode("utf-8"))
  - non-2xx raises VaultError carrying status + body

Run:
    python -m pytest python/tests/test_vault_client_connect.py -v
"""

from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tn.vault_client import VaultError, redeem_connect_code


# ---------------------------------------------------------------------------
# Fixture: a deterministic ed25519 keypair so signature verification is
# repeatable across runs.
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, str]:
    """Return a fresh ed25519 sk and the canonical did:key for its pk."""
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    # Same encoding as identity._did_key_from_ed25519_pub but inlined to
    # keep this test independent of identity.py wiring.
    prefixed = b"\xed\x01" + pub
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(prefixed, "big")
    out = b""
    while n > 0:
        n, r = divmod(n, 58)
        out = alphabet[r : r + 1] + out
    did = "did:key:z" + out.decode("ascii")
    return sk, did


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_redeem_connect_code_builds_canonical_request(keypair):
    """Body must carry {code, did, signature_b64} and sign sha256(code)."""
    sk, did = keypair
    code = "tn_connect_abc123"

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["json"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "account_id": "01HVAULT0123",
                "did": did,
                "name": "test-device",
                "project_id": "proj_xxx",
                "project_name": "test-project",
                "recipient_dids": [],
                "bound_at": "2026-05-21T00:00:00+00:00",
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    resp = redeem_connect_code(
        code, did, sk, base_url="https://mock.vault.local", http_client=client
    )

    assert captured["method"] == "POST"
    assert captured["url"] == (
        "https://mock.vault.local/api/v1/account/connect-codes/redeem"
    )
    assert captured["json"]["code"] == code
    assert captured["json"]["did"] == did

    # Signature verification: the bytes we POSTed must be a valid
    # ed25519 signature over sha256(code) under the DID's pubkey.
    sig_b64 = captured["json"]["signature_b64"]
    sig_bytes = base64.b64decode(sig_b64)
    message = hashlib.sha256(code.encode("utf-8")).digest()
    pub = sk.public_key()
    assert isinstance(pub, Ed25519PublicKey)
    pub.verify(sig_bytes, message)  # raises InvalidSignature on mismatch

    # Response is returned verbatim.
    assert resp["account_id"] == "01HVAULT0123"
    assert resp["project_id"] == "proj_xxx"


def test_redeem_connect_code_raises_on_non_2xx(keypair):
    """A 404 from the vault must surface as VaultError(status=404)."""
    sk, did = keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "connect code not found"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    with pytest.raises(VaultError) as info:
        redeem_connect_code(
            "tn_connect_missing",
            did,
            sk,
            base_url="https://mock.vault.local",
            http_client=client,
        )
    assert info.value.status == 404
    assert "connect code not found" in (info.value.body or "")


def test_redeem_connect_code_uses_resolve_vault_url(monkeypatch, keypair):
    """When base_url is None the function honors TN_VAULT_URL."""
    sk, did = keypair

    monkeypatch.setenv("TN_VAULT_URL", "https://override.example.com")

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "account_id": "acct",
                "did": did,
                "name": "x",
                "project_id": "p",
                "project_name": "x",
                "recipient_dids": [],
                "bound_at": "2026-05-21T00:00:00+00:00",
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    redeem_connect_code(
        "tn_connect_x", did, sk, base_url=None, http_client=client
    )
    assert captured["url"].startswith("https://override.example.com/")
