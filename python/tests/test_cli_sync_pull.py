"""Tests for the receive-side ``tn sync --pull`` CLI verb.

Drives ``_cmd_wallet_sync_pull`` against an httpx.MockTransport-backed
VaultClient and asserts that:

  - The account-scoped inbox aggregator at GET /api/v1/account/inbox is
    consulted (not the per-DID inbox endpoint — `pull --pull` mirrors
    the dashboard).
  - Each unconsumed snapshot is downloaded via
    GET /api/v1/account/inbox/{from_did}/{ceremony_id}/{ts}.tnpkg.
  - Bodies land at conventions.inbox_dir(yaml)/<from_did>/<ceremony_id>/<ts>.tnpkg.
  - Already-consumed items are skipped (no GET issued for them).
  - Without an account binding, the verb dies with a clear error and
    code 2.
  - Re-running is idempotent — already-staged files don't re-download.

Run:
    python -m pytest python/tests/test_cli_sync_pull.py -v
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import tn
from tn.cli import _cmd_wallet_sync_pull
from tn.conventions import inbox_dir
from tn.identity import Identity
from tn.sync_state import mark_account_bound
from tn.vault_client import VaultClient


# ---------------------------------------------------------------------------
# Fixture: tiny btn ceremony + identity bound to a fake account
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_runtime():
    tn.flush_and_close()
    yield
    tn.flush_and_close()


@pytest.fixture
def ident_and_yaml(tmp_path: Path) -> tuple[Identity, Path]:
    """Mint a fresh identity + minimal jwe ceremony bound to acct_test."""
    yaml_path = tmp_path / "tn.yaml"
    # jwe is the no-rust cipher; keeps the fixture light.
    tn.init(yaml_path, cipher="jwe")
    tn.flush_and_close()
    identity = Identity.create_new()
    # Pretend `tn account connect` already ran.
    mark_account_bound(yaml_path, "acct_test_01HVAULT")
    return identity, yaml_path


# ---------------------------------------------------------------------------
# httpx.MockTransport scaffolding: serves an inbox listing + bodies
# ---------------------------------------------------------------------------


def _make_inbox_handler(
    items: list[dict[str, Any]],
    bodies: dict[tuple[str, str, str], bytes],
):
    """Return a (handler, requests_seen) pair for httpx.MockTransport."""
    requests_seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = request.url
        requests_seen.append(f"{request.method} {url.path}")

        # Auth handshake — the VaultClient calls /auth/challenge then
        # /auth/verify on construction. Return a dummy token.
        if url.path == "/api/v1/auth/challenge":
            return httpx.Response(200, json={"nonce": "n0nce-test"})
        if url.path == "/api/v1/auth/verify":
            return httpx.Response(200, json={"token": "test-jwt"})

        if url.path == "/api/v1/account/inbox":
            return httpx.Response(
                200,
                json={
                    "package_dids": [
                        item["recipient_identity"] for item in items
                    ],
                    "items": items,
                },
            )

        # /api/v1/account/inbox/{from_did}/{ceremony_id}/{ts}.tnpkg
        prefix = "/api/v1/account/inbox/"
        if url.path.startswith(prefix):
            rest = url.path[len(prefix) :]
            assert rest.endswith(".tnpkg")
            rest = rest[: -len(".tnpkg")]
            parts = rest.rsplit("/", 2)
            if len(parts) == 3:
                from_did, ceremony_id, ts = parts
                body = bodies.get((from_did, ceremony_id, ts))
                if body is not None:
                    return httpx.Response(
                        200,
                        content=body,
                        headers={"Content-Type": "application/octet-stream"},
                    )
            return httpx.Response(404)

        return httpx.Response(404)

    return handler, requests_seen


def _install_mock_vault_client(
    monkeypatch: pytest.MonkeyPatch, handler: Any
) -> None:
    """Replace VaultClient.for_identity with one that wires our transport."""
    original = VaultClient.for_identity

    def fake_for_identity(identity: Identity, base_url: str | None = None, *, auto_auth: bool = True):
        from tn.vault_client import resolve_vault_url

        transport = httpx.MockTransport(handler)
        http = httpx.Client(transport=transport)
        client = VaultClient(
            base_url=resolve_vault_url(base_url),
            identity=identity,
            _http=http,
        )
        if auto_auth:
            client.authenticate()
        return client

    monkeypatch.setattr(VaultClient, "for_identity", staticmethod(fake_for_identity))

    return original  # not used; kept for forward extensibility


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sync_pull_stages_snapshots_into_local_inbox(
    ident_and_yaml, monkeypatch, capsys, tmp_path
):
    identity, yaml_path = ident_and_yaml
    pub_did = "did:key:zPublisherAlice"
    items = [
        {
            "path": f"/api/v1/account/inbox/{pub_did}/cer_abc/20260521T000000Z.tnpkg",
            "publisher_identity": pub_did,
            "recipient_identity": identity.did,
            "ceremony_id": "cer_abc",
            "ts": "20260521T000000Z",
            "received_at": "2026-05-21T00:00:00+00:00",
            "byte_size": 11,
            "head_row_hash": None,
            "consumed_at": None,
            "kind": "kit_bundle",
        },
        # Already-consumed: must be skipped, no GET issued.
        {
            "path": f"/api/v1/account/inbox/{pub_did}/cer_abc/20260520T120000Z.tnpkg",
            "publisher_identity": pub_did,
            "recipient_identity": identity.did,
            "ceremony_id": "cer_abc",
            "ts": "20260520T120000Z",
            "received_at": "2026-05-20T12:00:00+00:00",
            "byte_size": 11,
            "head_row_hash": None,
            "consumed_at": "2026-05-20T13:00:00+00:00",
            "kind": "kit_bundle",
        },
    ]
    body = b"FAKE_TNPKG_"
    bodies = {(pub_did, "cer_abc", "20260521T000000Z"): body}

    handler, seen = _make_inbox_handler(items, bodies)
    _install_mock_vault_client(monkeypatch, handler)

    rc = _cmd_wallet_sync_pull(SimpleNamespace(), identity, yaml_path)
    assert rc == 0

    # File landed at the conventional inbox path with ':' replaced.
    expected = (
        inbox_dir(yaml_path)
        / pub_did.replace(":", "_")
        / "cer_abc"
        / "20260521T000000Z.tnpkg"
    )
    assert expected.exists(), f"expected staged file at {expected}"
    assert expected.read_bytes() == body

    # Only one body GET was made — the consumed item was skipped.
    body_gets = [
        line for line in seen
        if line.startswith("GET /api/v1/account/inbox/") and line.endswith(".tnpkg")
    ]
    assert len(body_gets) == 1, f"expected 1 body GET, saw: {seen}"

    out = capsys.readouterr().out
    assert "Pulled 1 snapshot(s)" in out
    assert "tn absorb" in out


def test_sync_pull_dies_without_account_binding(ident_and_yaml, monkeypatch):
    """No `tn account connect` => exit 2 with a clear error."""
    identity, yaml_path = ident_and_yaml
    # Clear the binding the fixture stamped.
    from tn.sync_state import save_sync_state
    save_sync_state(yaml_path, {})

    # Even if the http client got built, it must not be called. Install
    # a handler that fails the test if hit.
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected HTTP call: {request.url}")

    _install_mock_vault_client(monkeypatch, handler)

    with pytest.raises(SystemExit) as info:
        _cmd_wallet_sync_pull(SimpleNamespace(), identity, yaml_path)
    assert info.value.code == 2


def test_sync_pull_is_idempotent_on_rerun(
    ident_and_yaml, monkeypatch, capsys
):
    """Already-staged files are skipped on the second run."""
    identity, yaml_path = ident_and_yaml
    pub_did = "did:key:zPublisherBob"
    items = [
        {
            "path": f"/api/v1/account/inbox/{pub_did}/cer_xyz/20260521T010000Z.tnpkg",
            "publisher_identity": pub_did,
            "recipient_identity": identity.did,
            "ceremony_id": "cer_xyz",
            "ts": "20260521T010000Z",
            "received_at": "2026-05-21T01:00:00+00:00",
            "byte_size": 4,
            "consumed_at": None,
            "kind": "kit_bundle",
        },
    ]
    body = b"BODY"
    bodies = {(pub_did, "cer_xyz", "20260521T010000Z"): body}

    handler, seen = _make_inbox_handler(items, bodies)
    _install_mock_vault_client(monkeypatch, handler)

    # First call: stages.
    rc = _cmd_wallet_sync_pull(SimpleNamespace(), identity, yaml_path)
    assert rc == 0
    first_body_gets = sum(
        1 for s in seen if "/account/inbox/" in s and s.endswith(".tnpkg")
    )

    # Second call: must NOT re-fetch the body.
    rc = _cmd_wallet_sync_pull(SimpleNamespace(), identity, yaml_path)
    assert rc == 0
    second_body_gets = sum(
        1 for s in seen if "/account/inbox/" in s and s.endswith(".tnpkg")
    )

    assert first_body_gets == 1
    assert second_body_gets == first_body_gets  # no new body GET on rerun
    out = capsys.readouterr().out
    assert "already staged locally" in out
