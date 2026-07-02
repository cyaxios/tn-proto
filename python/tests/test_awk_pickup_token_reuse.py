"""drain_pending_awk / redeem_awk_pickup accept an already-minted JWT.

A sync cycle authenticates once (VaultClient.for_identity) and hands that
JWT to the drain — without the param every drain ran its own
challenge/verify pair, doubling auth traffic on the vault (the 2026-07-02
call-home flood showed 2 pairs per autosync cycle).
"""
from __future__ import annotations

import pytest

from tn import awk_pickup


@pytest.fixture()
def no_challenge(monkeypatch):
    """Fail the test if the drain runs its own challenge/verify."""
    def _boom(*a, **kw):
        raise AssertionError("challenge/verify must be skipped when a token is supplied")
    monkeypatch.setattr(awk_pickup, "_challenge_verify", _boom)


def test_drain_with_token_skips_challenge(monkeypatch, no_challenge):
    captured: dict = {}

    def fake_get(url, headers=None):
        captured["url"] = url
        captured["headers"] = headers or {}
        return 200, '{"pending": []}'

    monkeypatch.setattr(awk_pickup, "_http_get", fake_get)
    out = awk_pickup.drain_pending_awk(
        vault_url="https://vault.example.com",
        device_seed=b"\x01" * 32,
        token="jwt-reused",
    )
    assert out == []
    assert captured["url"].endswith("/api/v1/account/awk-pickups/pending")
    assert captured["headers"]["Authorization"] == "Bearer jwt-reused"


def test_redeem_with_token_skips_challenge(monkeypatch, no_challenge):
    captured: dict = {}

    def fake_get(url, headers=None):
        captured["headers"] = headers or {}
        return 404, "not found"  # stop after the auth header is proven

    monkeypatch.setattr(awk_pickup, "_http_get", fake_get)
    ok = awk_pickup.redeem_awk_pickup(
        vault_url="https://vault.example.com",
        device_seed=b"\x01" * 32,
        account_id="01ACCT",
        key_id_b64="a2lk",
        token="jwt-reused",
    )
    assert ok is False
    assert captured["headers"]["Authorization"] == "Bearer jwt-reused"


def test_drain_without_token_still_challenges(monkeypatch):
    calls: list = []
    monkeypatch.setattr(awk_pickup, "_challenge_verify",
                        lambda *a, **kw: calls.append(a) or None)
    out = awk_pickup.drain_pending_awk(
        vault_url="https://vault.example.com",
        device_seed=b"\x01" * 32,
    )
    assert out == []
    assert calls, "no token supplied -> the drain must mint its own"
