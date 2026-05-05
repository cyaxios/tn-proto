"""Tests for tn.contacts.parse_address + resolve helpers.

Federation work, decisions log
2026-05-04-federation-and-management-decisions.md D-2 / D-7.

Covers:

* parse_address detects did / handle / email correctly.
* parse_address normalizes lowercase for handle and email; preserves DID.
* parse_address rejects malformed / empty / non-string input.
* resolve() POSTs to the bulk endpoint with the right body shape.
* resolve() caches by (kind, value) for the configured TTL.
* resolve() skips the cache when use_cache=False.
* flatten_active_dids unions + dedupes preserving order.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tn.contacts import (
    AddressInput,
    ResolveResult,
    clear_cache,
    flatten_active_dids,
    parse_address,
    resolve,
)


# ── parse_address ────────────────────────────────────────────────────


def test_parse_address_detects_did():
    kind, value = parse_address("did:key:z6MkABC123")
    assert kind == "did"
    assert value == "did:key:z6MkABC123"


def test_parse_address_detects_email_normalizes():
    kind, value = parse_address("Frank@Example.COM")
    assert kind == "email"
    assert value == "frank@example.com"


def test_parse_address_detects_handle_normalizes():
    kind, value = parse_address("Frank-The-Agent")
    assert kind == "handle"
    assert value == "frank-the-agent"


def test_parse_address_strips_whitespace():
    kind, value = parse_address("   alice@example.com  ")
    assert kind == "email"
    assert value == "alice@example.com"


def test_parse_address_rejects_empty():
    with pytest.raises(ValueError, match="empty"):
        parse_address("")
    with pytest.raises(ValueError, match="empty"):
        parse_address("   ")


def test_parse_address_rejects_non_string():
    with pytest.raises(ValueError):
        parse_address(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        parse_address(123)  # type: ignore[arg-type]


def test_parse_address_rejects_unrecognized_shape():
    with pytest.raises(ValueError):
        parse_address("not-an-email-or-handle-because-spaces-and-stuff!!!")
    with pytest.raises(ValueError):
        parse_address("ab")  # too short for handle, no @ for email


# ── resolve / cache ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_cache_each_test():
    clear_cache()
    yield
    clear_cache()


def _mock_http(response_payload):
    """Return an http_client mock whose .post() returns response_payload as JSON."""
    client = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = response_payload
    response.raise_for_status.return_value = None
    client.post.return_value = response
    return client


def test_resolve_calls_endpoint_with_expected_body():
    client = _mock_http({"results": []})
    resolve(
        ["alice", "bob@example.com", "did:key:z6MkABC"],
        vault_base="https://vault.example/",
        bearer_jwt="testjwt",
        http_client=client,
    )
    assert client.post.call_count == 1
    args, kwargs = client.post.call_args
    assert args[0] == "https://vault.example/api/v1/contacts/resolve"
    body = kwargs["json"]
    assert body == {
        "addresses": [
            {"kind": "handle", "value": "alice"},
            {"kind": "email", "value": "bob@example.com"},
            {"kind": "did", "value": "did:key:z6MkABC"},
        ]
    }
    assert kwargs["headers"]["Authorization"] == "Bearer testjwt"


def test_resolve_returns_results_in_order():
    payload = {
        "results": [
            {
                "input": {"kind": "handle", "value": "alice"},
                "status": "found",
                "account_handle": "alice",
                "active_dids": ["did:key:z6MkA1", "did:key:z6MkA2"],
                "invitable": False,
            },
            {
                "input": {"kind": "email", "value": "bob@example.com"},
                "status": "not_found",
                "active_dids": [],
                "invitable": True,
            },
        ]
    }
    client = _mock_http(payload)
    out = resolve(
        ["alice", "bob@example.com"],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
    )
    assert len(out) == 2
    assert out[0].status == "found"
    assert out[0].active_dids == ["did:key:z6MkA1", "did:key:z6MkA2"]
    assert out[1].status == "not_found"
    assert out[1].invitable is True


def test_resolve_caches_results_within_ttl():
    payload = {
        "results": [
            {
                "input": {"kind": "handle", "value": "alice"},
                "status": "found",
                "active_dids": ["did:key:z6MkA1"],
            },
        ]
    }
    client = _mock_http(payload)
    # First call hits server.
    resolve(
        ["alice"],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
    )
    assert client.post.call_count == 1
    # Second call within TTL → cached, no server hit.
    resolve(
        ["alice"],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
    )
    assert client.post.call_count == 1


def test_resolve_skips_cache_when_use_cache_false():
    payload = {
        "results": [
            {"input": {"kind": "handle", "value": "alice"}, "status": "found"},
        ]
    }
    client = _mock_http(payload)
    resolve(
        ["alice"],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
    )
    resolve(
        ["alice"],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
        use_cache=False,
    )
    assert client.post.call_count == 2


def test_resolve_partial_cache_only_fetches_missing():
    """Two addresses: one cached, one not. Server gets only the missing one."""
    payload_first = {
        "results": [
            {"input": {"kind": "handle", "value": "alice"}, "status": "found"},
        ]
    }
    payload_second = {
        "results": [
            {"input": {"kind": "handle", "value": "bob"}, "status": "found"},
        ]
    }
    client = _mock_http(payload_first)
    resolve(
        ["alice"],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
    )
    # Re-arm: next call should hit the server with ONLY 'bob'.
    response2 = MagicMock()
    response2.status_code = 200
    response2.json.return_value = payload_second
    response2.raise_for_status.return_value = None
    client.post.return_value = response2

    out = resolve(
        ["alice", "bob"],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
    )
    assert client.post.call_count == 2
    last_call_body = client.post.call_args[1]["json"]
    assert last_call_body == {
        "addresses": [{"kind": "handle", "value": "bob"}]
    }
    assert len(out) == 2


def test_resolve_handles_address_input_directly():
    """Pre-classified ``AddressInput`` instances bypass parse_address."""
    payload = {
        "results": [
            {"input": {"kind": "did", "value": "did:key:z6MkABC"}, "status": "found"},
        ]
    }
    client = _mock_http(payload)
    out = resolve(
        [AddressInput(kind="did", value="did:key:z6MkABC")],
        vault_base="https://vault.example",
        bearer_jwt="testjwt",
        http_client=client,
    )
    assert out[0].input.kind == "did"


# ── flatten_active_dids ──────────────────────────────────────────────


def test_flatten_active_dids_unions_and_dedupes():
    results = [
        ResolveResult(
            input=AddressInput(kind="handle", value="alice"),
            status="found",
            active_dids=["did:key:z6MkA1", "did:key:z6MkA2"],
        ),
        ResolveResult(
            input=AddressInput(kind="handle", value="bob"),
            status="found",
            active_dids=["did:key:z6MkA1", "did:key:z6MkB1"],  # A1 dup
        ),
        ResolveResult(
            input=AddressInput(kind="handle", value="missing"),
            status="not_found",
            active_dids=[],
        ),
    ]
    out = flatten_active_dids(results)
    # Order preserved (first-seen), duplicates removed, not_found excluded.
    assert out == ["did:key:z6MkA1", "did:key:z6MkA2", "did:key:z6MkB1"]


def test_flatten_active_dids_empty():
    assert flatten_active_dids([]) == []
    assert flatten_active_dids(
        [
            ResolveResult(
                input=AddressInput(kind="email", value="x@y.com"),
                status="not_found",
                invitable=True,
            )
        ]
    ) == []
