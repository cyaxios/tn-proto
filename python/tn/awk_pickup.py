"""Redeem an account-level AWK single-pickup and cache the AWK. Mirrors
bootstrap.py's challenge/verify/GET, then unseals with the device key and
caches it. Never raises. Takes vault_url directly (NOT a vault DID)."""
from __future__ import annotations
import json, logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .bootstrap import _challenge_verify, _did_key_for_ed25519_pub, _http_get
from .credential_store import CredentialStore, awk_key_name, default_credential_store
from .recipient_seal import unseal_bek_from_wrap

_log = logging.getLogger("tn.awk_pickup")


def awk_pickup_aad(account_id: str) -> bytes:
    return f"tn-account-awk-pickup-v1:{account_id}".encode("utf-8")


def redeem_awk_pickup(*, vault_url: str, device_seed: bytes,
                      account_id: str, key_id_b64: str,
                      store: CredentialStore | None = None) -> bool:
    try:
        priv = Ed25519PrivateKey.from_private_bytes(device_seed)
        pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                             format=serialization.PublicFormat.Raw)
        did = _did_key_for_ed25519_pub(pub)
        base = vault_url.rstrip("/")
        token = _challenge_verify(base, did, priv)
        if token is None:
            return False
        status, body = _http_get(f"{base}/api/v1/account/awk-pickups/{key_id_b64}",
                                 headers={"Authorization": f"Bearer {token}"})
        if status != 200:
            _log.warning("awk pickup GET failed HTTP %d: %s", status, body[:200])
            return False
        wrap = json.loads(body)["wrap"]
        awk = unseal_bek_from_wrap(wrap, device_seed, awk_pickup_aad(account_id))
        if len(awk) != 32:
            _log.warning("unsealed AWK wrong length: %d", len(awk))
            return False
        (store or default_credential_store()).set(awk_key_name(account_id), awk)
        _log.info("awk pickup cached for account %s", account_id)
        return True
    except Exception as e:  # noqa: BLE001 — contain; caller degrades to "not cached"
        _log.warning("redeem_awk_pickup failed: %s", e, exc_info=True)
        return False


def drain_pending_awk(*, vault_url: str, device_seed: bytes,
                      store: CredentialStore | None = None) -> list[str]:
    """Check the vault's AWK inbox for pickups addressed to THIS device DID and
    redeem+cache each. Returns the account_ids whose AWK was cached (usually 0
    or 1). Never raises — a degraded vault just means 'nothing drained, retry
    next sync'. This is the device-pull half of the non-blocking flow: the
    browser mints an AWK pickup sealed to this DID at claim/approve time; the
    sync loop (or a brief init check) drains it whenever it shows up."""
    try:
        priv = Ed25519PrivateKey.from_private_bytes(device_seed)
        pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                             format=serialization.PublicFormat.Raw)
        did = _did_key_for_ed25519_pub(pub)
        base = vault_url.rstrip("/")
        token = _challenge_verify(base, did, priv)
        if token is None:
            return []
        status, body = _http_get(f"{base}/api/v1/account/awk-pickups/pending",
                                 headers={"Authorization": f"Bearer {token}"})
        if status != 200:
            return []
        pending = json.loads(body).get("pending", [])
        cached: list[str] = []
        for p in pending:
            acct, kid = p.get("account_id"), p.get("key_id")
            if not acct or not kid:
                continue
            if redeem_awk_pickup(vault_url=base, device_seed=device_seed,
                                 account_id=acct, key_id_b64=kid, store=store):
                cached.append(acct)
        if cached:
            _log.info("drained %d inbound AWK pickup(s)", len(cached))
        return cached
    except Exception as e:  # noqa: BLE001 — contain; next sync retries
        _log.warning("drain_pending_awk failed: %s", e, exc_info=True)
        return []


def resolve_cached_awk(*, vault_url: str, device_seed: bytes,
                       account_id_hint: str | None = None,
                       store: CredentialStore | None = None,
                       ) -> tuple[bytes | None, str | None]:
    """Drain this device's AWK inbox, then return ``(cached_awk, account_id)``.

    The single resolution every unattended sync path shares — the CLI
    ``tn wallet sync``, ``tn auth login``, AND the library autosync hook
    (``tn.admin._maybe_autosync``) that fires while a logger is running. The
    drain picks up a pickup a browser just sealed to this device DID, so a
    backup starts working the moment a claim lands, with no explicit command.

    Never raises; a degraded vault just yields ``(None, account_id_hint)``."""
    store = store or default_credential_store()
    account_id = account_id_hint
    learned = drain_pending_awk(vault_url=vault_url, device_seed=device_seed,
                                store=store)
    if learned and not account_id:
        account_id = learned[0]
    awk = store.get(awk_key_name(account_id)) if account_id else None
    return awk, account_id


__all__ = [
    "awk_pickup_aad",
    "redeem_awk_pickup",
    "drain_pending_awk",
    "resolve_cached_awk",
]
