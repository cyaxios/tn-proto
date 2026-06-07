"""Regression: wallet push must mint a fresh project BEK ONLY on a genuine 404.

PARITY-vault-sync #23 (silent data loss): ``push_ceremony_body`` used to treat
*any* non-200 from the wrapped-key GET (transient 5xx, 401/403, network) the
same as a 404 and mint a fresh BEK -- which overwrites the wrapped-key and
orphans the existing body backup (it's encrypted under the old, now-lost BEK).

The fix: ``_fetch_wrapped_key`` carries the HTTP ``status_code`` on the
``RestoreError`` it raises, and ``push_ceremony_body`` only mints on 404; any
other status aborts with ``PushError`` (so the backup is never orphaned).
The 404 -> mint path stays covered by the live backup/restore suites.
"""
from __future__ import annotations

import pytest

from tn import wallet_push
from tn.wallet_restore import RestoreError


def _fake_awk(**_kw: object) -> bytes:
    return b"\x00" * 32


def test_fetch_wrapped_key_propagates_status_code(monkeypatch: pytest.MonkeyPatch) -> None:
    from tn import wallet_restore_passphrase as wrp

    monkeypatch.setattr(wrp, "_bearer_get", lambda *a, **k: (503, b"upstream down"))
    with pytest.raises(RestoreError) as ei:
        wrp._fetch_wrapped_key(vault_url="http://x", bearer="t", project_id="p")
    assert ei.value.status_code == 503

    monkeypatch.setattr(wrp, "_bearer_get", lambda *a, **k: (404, b"no row"))
    with pytest.raises(RestoreError) as ei404:
        wrp._fetch_wrapped_key(vault_url="http://x", bearer="t", project_id="p")
    assert ei404.value.status_code == 404


@pytest.mark.parametrize("status", [500, 503, 401, 403, 502])
def test_push_refuses_to_mint_on_non_404(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    """A non-404 wrapped-key error must NOT mint -- it aborts with PushError."""
    monkeypatch.setattr(wallet_push, "_derive_awk_via_passphrase", _fake_awk)

    err = RestoreError(f"wrapped-key returned HTTP {status}: boom")
    err.status_code = status

    def _boom(**_kw: object) -> dict:
        raise err

    monkeypatch.setattr(wallet_push, "_fetch_wrapped_key", _boom)

    # If minting were reached, these would be called -- assert they are NOT.
    def _must_not_mint(**_kw: object) -> object:
        raise AssertionError("push minted a fresh BEK on a non-404 -- would orphan the backup")

    monkeypatch.setattr(wallet_push, "_put_wrapped_key", _must_not_mint)

    with pytest.raises(wallet_push.PushError, match="refusing to mint"):
        wallet_push.push_ceremony_body(
            vault_url="http://x",
            bearer="t",
            project_id="p",
            passphrase="pw",
            body={"body/tn.yaml": b"x: 1\n"},
        )
