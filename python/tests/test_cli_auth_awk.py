"""TDD tests for Task 7: device-flow login caches the AWK on success.

Covers:
  - default (cache_key=None, no TN_NO_KEY_CACHE) -> redeem_awk_pickup called
  - cache_key=False                               -> redeem_awk_pickup NOT called
  - TN_NO_KEY_CACHE=1 env var                     -> redeem_awk_pickup NOT called
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from tn.cli_auth import _device_login


# ---------------------------------------------------------------------------
# Shared fake data
# ---------------------------------------------------------------------------
_FAKE_ACCOUNT_ID = "01ACCTXYZFAKE"
_FAKE_DID = "did:key:zFAKEDID"
_FAKE_KEY_ID = "kid_base64abc"
_VAULT = "https://vault.test"

_POLL_RESULT = {
    "account_id": _FAKE_ACCOUNT_ID,
    "did": _FAKE_DID,
    "awk_pickup_key_id": _FAKE_KEY_ID,
}

_DEVICE_CODE_STUB = MagicMock(
    device_code="dc_fake",
    user_code="FAKE-1234",
    verification_uri="https://vault.test/device",
    verification_uri_complete="https://vault.test/device?code=FAKE-1234",
    interval=5,
    expires_in=900,
)


def _make_identity_mock():
    """Return a mock Identity with the minimal surface used by _device_login."""
    m = MagicMock()
    m.linked_vault = _VAULT
    m.linked_account_id = None
    m.did = _FAKE_DID
    m.device_private_key_bytes.return_value = b"\x00" * 32
    return m


# ---------------------------------------------------------------------------
# Helper: patch everything except the AWK wiring
# ---------------------------------------------------------------------------
def _run_device_login(cache_key, env_override=None):
    """Invoke _device_login with all external I/O patched.

    Returns the list of calls made to the redeem_awk_pickup mock.
    """
    identity_mock = _make_identity_mock()
    redeem_calls = []

    def fake_redeem(**kwargs):
        redeem_calls.append(kwargs)
        return True

    patches = [
        patch("tn.cli_auth._load_or_mint_identity", return_value=identity_mock),
        patch("tn.cli_auth.request_device_code", return_value=_DEVICE_CODE_STUB),
        patch("tn.cli_auth.open_browser", return_value=False),
        patch("tn.cli_auth.poll_device_token", return_value=_POLL_RESULT),
        # stub identity.ensure_written so nothing touches the filesystem
        patch.object(identity_mock, "ensure_written"),
        # stub _auth_ns.status to avoid real vault calls in the print step
        patch("tn.cli_auth._auth_ns") ,
        patch("tn.cli_auth.redeem_awk_pickup", side_effect=fake_redeem),
        patch("tn.cli_auth.resolve_vault_url", return_value=_VAULT),
    ]

    env = dict(os.environ)
    if env_override:
        env.update(env_override)

    with (
        patches[0],
        patches[1],
        patches[2],
        patches[3],
        patches[4],
        patches[5],
        patches[6],
        patches[7],
    ):
        with patch.dict(os.environ, env_override or {}, clear=False):
            result = _device_login(vault=None, cache_key=cache_key)

    assert result == 0
    return redeem_calls


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDeviceLoginAwkCache:
    def test_default_calls_redeem(self):
        """With no opt-out, redeem_awk_pickup must be called once."""
        # Remove env override to ensure default behaviour
        calls = _run_device_login(cache_key=None,
                                  env_override={"TN_NO_KEY_CACHE": ""})
        assert len(calls) == 1
        assert calls[0]["key_id_b64"] == _FAKE_KEY_ID
        assert calls[0]["account_id"] == _FAKE_ACCOUNT_ID

    def test_cache_key_false_skips_redeem(self):
        """Explicit cache_key=False must suppress the AWK pickup."""
        calls = _run_device_login(cache_key=False,
                                  env_override={"TN_NO_KEY_CACHE": ""})
        assert calls == []

    def test_env_no_key_cache_skips_redeem(self):
        """TN_NO_KEY_CACHE=1 must suppress the AWK pickup regardless of cache_key."""
        calls = _run_device_login(cache_key=None,
                                  env_override={"TN_NO_KEY_CACHE": "1"})
        assert calls == []
