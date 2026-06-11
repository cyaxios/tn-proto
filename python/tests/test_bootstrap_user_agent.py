"""Smoke test: every outbound HTTP call from tn carries a non-urllib UA.

Regression guard for the CF 1010 block on the default ``Python-urllib/3.x``
User-Agent. Both _http_post / _http_get in tn.bootstrap and the
httpx.Client in tn.vault_client must send ``tn-proto/<version>``
instead of the urllib / httpx default, so requests reach the vault
application instead of being 403'd at the Cloudflare edge with
``error code: 1010``.

We assert the UA shape, not the version string, so this test doesn't
break every time the package version bumps.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx

from tn import bootstrap as bootstrap_mod
from tn import vault_client as vault_client_mod


def test_bootstrap_module_pins_user_agent_header():
    """``_DEFAULT_HEADERS`` carries a tn-proto User-Agent."""
    ua = bootstrap_mod._DEFAULT_HEADERS.get("User-Agent")
    assert ua, "bootstrap._DEFAULT_HEADERS missing User-Agent"
    assert ua.startswith("tn-proto/"), (
        f"bootstrap UA must start with 'tn-proto/' to avoid CF 1010 "
        f"(got {ua!r})"
    )


def test_vault_client_module_pins_user_agent_header():
    """``_DEFAULT_HEADERS`` carries a tn-proto User-Agent."""
    ua = vault_client_mod._DEFAULT_HEADERS.get("User-Agent")
    assert ua, "vault_client._DEFAULT_HEADERS missing User-Agent"
    assert ua.startswith("tn-proto/"), (
        f"vault_client UA must start with 'tn-proto/' to avoid CF 1010 "
        f"(got {ua!r})"
    )


def test_bootstrap_http_post_sets_user_agent_on_request():
    """``_http_post`` constructs a Request whose User-Agent is ours."""
    captured = {}

    class _FakeResponse:
        def __init__(self):
            self.status = 200

        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    def _fake_urlopen(req, *args, **kwargs):
        # Capture header dict on the way through. urllib lowercases
        # header keys when storing, so look for both shapes.
        captured["headers"] = dict(req.headers)
        return _FakeResponse()

    with patch.object(bootstrap_mod.urllib.request, "urlopen", _fake_urlopen):
        bootstrap_mod._http_post(
            "https://example.invalid/api/v1/auth/challenge",
            json.dumps({"did": "did:key:zX"}).encode(),
        )

    # urllib header dict lowercases the keys.
    ua_keys = {k for k in captured["headers"] if k.lower() == "user-agent"}
    assert ua_keys, f"no User-Agent header on request (saw {list(captured['headers'])})"
    ua = captured["headers"][next(iter(ua_keys))]
    assert ua.startswith("tn-proto/")


def test_bootstrap_http_get_sets_user_agent_on_request():
    """``_http_get`` constructs a Request whose User-Agent is ours."""
    captured = {}

    class _FakeResponse:
        def __init__(self):
            self.status = 200

        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    def _fake_urlopen(req, *args, **kwargs):
        captured["headers"] = dict(req.headers)
        return _FakeResponse()

    with patch.object(bootstrap_mod.urllib.request, "urlopen", _fake_urlopen):
        bootstrap_mod._http_get(
            "https://example.invalid/api/v1/something",
        )

    ua_keys = {k for k in captured["headers"] if k.lower() == "user-agent"}
    assert ua_keys, f"no User-Agent header on request (saw {list(captured['headers'])})"
    ua = captured["headers"][next(iter(ua_keys))]
    assert ua.startswith("tn-proto/")


def test_vault_client_http_uses_tn_user_agent_via_mocktransport():
    """A real httpx.Client built by VaultClient sends our UA on requests.

    Uses httpx.MockTransport to intercept the request without a network
    round-trip and read back the headers the client actually emitted.
    """
    seen_headers: list[dict[str, str]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    # Build a client the same way VaultClient.__post_init__ does, but
    # inject our MockTransport so we don't actually hit the network.
    client = httpx.Client(
        timeout=vault_client_mod.DEFAULT_TIMEOUT,
        headers=vault_client_mod._DEFAULT_HEADERS,
        transport=httpx.MockTransport(_handler),
    )
    try:
        client.get("https://example.invalid/api/v1/anything")
    finally:
        client.close()

    assert seen_headers, "MockTransport handler never ran"
    ua = seen_headers[0].get("user-agent", "")
    assert ua.startswith("tn-proto/"), (
        f"httpx.Client did not send our UA (saw {ua!r})"
    )
