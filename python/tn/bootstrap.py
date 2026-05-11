"""Cold-start keystore bootstrap from a TN_API_KEY bearer.

Per the 2026-05-11 design dispatch ("api-key cold-start bootstrap via
sealed kit_bundle"). The companion server-side routes are at
``tn_proto_web/src/routes_api_keys.py``.

Flow on a fresh node with only ``TN_API_KEY`` in env:

  1. Caller has an empty keystore and a YAML that declares ``vault.sync``.
  2. The handler-builder notices the empty keystore + the env var and
     calls :func:`bootstrap_from_api_key` BEFORE constructing the
     ``VaultSyncHandler`` (which would otherwise raise on a missing
     ``local.private``).
  3. We split the bearer into seed + key_id, derive the DID, run the
     standard ``/api/v1/auth/{challenge,verify}`` flow to mint a JWT,
     pull the sealed kit_bundle via ``/api/v1/api-keys/{key_id}/sealed-bundle``,
     and hand the bytes to :func:`tn.absorb`. The absorb path knows
     how to unseal recipient-wrapped bundles via the device seed.
  4. ``absorb`` installs the body into the keystore (a project_seed
     bundle with the publisher's keys + tn.yaml). The keystore is now
     "hot" and the handler-builder proceeds as usual.

We never raise — failures return False so the caller can fall through
to the existing INIT-UPLOAD-and-claim-URL path. The contract is "best
effort cold start": a stale / revoked / consumed bearer leaves the
keystore in whatever state it was in (typically still empty), and the
existing flow takes over.

This module is intentionally **internal** — there is no public
``tn.bootstrap_from_api_key`` symbol. The handler-builder is the only
caller; users discover the feature by setting ``TN_API_KEY``.
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .identity import _resolve_did_endpoint
from .sync_state import update_sync_state

_log = logging.getLogger("tn.bootstrap")

_BEARER_PREFIX = "tn_apikey_"
_HTTP_TIMEOUT_SEC = 15.0


# ── Helpers ──────────────────────────────────────────────────────────


def _b58encode(data: bytes) -> str:
    """Bitcoin-style base58 (no 0OIl). Matches tn.signing.DeviceKey."""
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = b""
    while n > 0:
        n, r = divmod(n, 58)
        out = alphabet[r : r + 1] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return ("1" * pad) + out.decode("ascii")


def _did_key_for_ed25519_pub(pub: bytes) -> str:
    """Compose a ``did:key:z...`` from raw Ed25519 public bytes."""
    if len(pub) != 32:
        raise ValueError(f"ed25519 pub must be 32 bytes; got {len(pub)}")
    return "did:key:z" + _b58encode(b"\xed\x01" + pub)


def _b64url_no_pad(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _parse_bearer(bearer: str) -> tuple[bytes, str, bytes] | None:
    """Split ``tn_apikey_<seed>_<key_id>`` into raw bytes.

    Returns ``(seed_32b, key_id_b64_str, key_id_bytes)`` on success, or
    None on shape failure. The b64 string is retained so the bundle GET
    URL uses the exact same urlsafe-no-pad encoding the server stored.
    """
    if not isinstance(bearer, str) or not bearer.startswith(_BEARER_PREFIX):
        return None
    rest = bearer[len(_BEARER_PREFIX):]
    # The seed_b64 IS urlsafe base64 (no padding) of 32 bytes — that's
    # exactly 43 chars and CAN contain "_" or "-". So rfind("_") is
    # wrong; we pin the split by length. seed_b64 must be 43 chars,
    # then "_", then key_id_b64 (22 chars from 16 raw bytes).
    SEED_LEN = 43
    KEY_ID_LEN = 22
    expected_total = SEED_LEN + 1 + KEY_ID_LEN
    if len(rest) != expected_total or rest[SEED_LEN] != "_":
        return None
    seed_b64 = rest[:SEED_LEN]
    kid_b64 = rest[SEED_LEN + 1:]
    if not seed_b64 or not kid_b64:
        return None
    try:
        seed = _b64url_no_pad(seed_b64)
        kid = _b64url_no_pad(kid_b64)
    except Exception:  # noqa: BLE001 — best-effort decode; any error means "bad bearer"
        return None
    if len(seed) != 32 or len(kid) != 16:
        return None
    return seed, kid_b64, kid


def _http_post(url: str, body: bytes, *, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SEC) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _http_get(url: str, *, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SEC) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _challenge_verify(base: str, did: str, priv: Ed25519PrivateKey) -> str | None:
    """Run /auth/challenge + /auth/verify, return JWT or None on failure."""
    ch_status, ch_body = _http_post(
        f"{base}/api/v1/auth/challenge",
        json.dumps({"did": did}).encode("utf-8"),
    )
    if ch_status != 200:
        _log.warning(
            "bootstrap: /auth/challenge failed HTTP %d: %s",
            ch_status, ch_body[:200],
        )
        return None
    try:
        nonce = json.loads(ch_body)["nonce"]
    except (KeyError, ValueError, json.JSONDecodeError):
        _log.warning("bootstrap: /auth/challenge response missing nonce")
        return None
    sig = priv.sign(nonce.encode("utf-8"))
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    vr_status, vr_body = _http_post(
        f"{base}/api/v1/auth/verify",
        json.dumps({"did": did, "nonce": nonce, "signature": sig_b64}).encode("utf-8"),
    )
    if vr_status != 200:
        _log.warning(
            "bootstrap: /auth/verify failed HTTP %d: %s",
            vr_status, vr_body[:200],
        )
        return None
    try:
        return json.loads(vr_body)["token"]
    except (KeyError, ValueError, json.JSONDecodeError):
        _log.warning("bootstrap: /auth/verify response missing token")
        return None


# ── Public (internal) entry point ───────────────────────────────────


def bootstrap_from_api_key(
    *,
    yaml_path: Path,
    keystore_path: Path,
    vault_did: str,
    api_key: str,
) -> bool:
    """Cold-start bootstrap from a TN_API_KEY bearer.

    Returns True if the keystore is now hot (local.private + local.public
    installed); False if the api_key is malformed, the vault rejected
    the challenge, the sealed bundle couldn't be pulled, or absorb
    refused the body. Callers fall through to existing INIT-UPLOAD or
    local-only behavior on False.

    Never raises — every failure path logs at WARNING and returns False.
    """
    try:
        parsed = _parse_bearer(api_key)
        if parsed is None:
            _log.warning(
                "bootstrap: TN_API_KEY shape invalid; falling through to init-upload",
            )
            return False
        seed, key_id_b64, _key_id_bytes = parsed

        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        did = _did_key_for_ed25519_pub(pub)

        try:
            base = _resolve_did_endpoint(vault_did)
        except Exception:  # noqa: BLE001 — DID resolution failure shouldn't break init
            _log.warning(
                "bootstrap: could not resolve vault endpoint for %s",
                vault_did,
                exc_info=True,
            )
            return False

        token = _challenge_verify(base, did, priv)
        if token is None:
            return False

        # Pull the sealed bundle. Per spec, persistent keys are
        # idempotent on this call; single-pickup keys flip on first
        # success.
        gb_status, gb_body = _http_get(
            f"{base}/api/v1/api-keys/{key_id_b64}/sealed-bundle",
            headers={"Authorization": f"Bearer {token}"},
        )
        if gb_status == 410:
            _log.warning(
                "bootstrap: api-key revoked at vault (HTTP 410); falling through",
            )
            return False
        if gb_status == 404:
            _log.warning(
                "bootstrap: sealed bundle not found / already consumed (HTTP 404)",
            )
            return False
        if gb_status != 200:
            _log.warning(
                "bootstrap: sealed-bundle GET failed HTTP %d: %s",
                gb_status, gb_body[:200],
            )
            return False
        try:
            doc = json.loads(gb_body)
            sealed_b64 = doc["sealed_bundle_b64"]
            sealed_bytes = base64.b64decode(sealed_b64)
        except (KeyError, ValueError) as exc:
            _log.warning("bootstrap: sealed-bundle response malformed: %s", exc)
            return False

        # tn.absorb handles _maybe_unseal_recipient_wrap so the body
        # opens under our device seed. The seed lives in memory only
        # on this call; the unwrap path reads cfg.device.private_bytes
        # which we set up by writing the seed to the keystore BEFORE
        # absorb so the dispatch synthesises the right cfg.
        #
        # The bundle is a project_seed tnpkg whose body carries the
        # *publisher's* keys (local.private/public). So we need a
        # ``cfg.device`` that holds OUR ephemeral seed (to unwrap the
        # sealed BEK), and absorb then OVERWRITES local.private with
        # the publisher's seed from the body. After absorb, the
        # keystore is keyed to the publisher (the original project
        # owner), not us — which is what the vault.sync handler needs.
        #
        # We achieve this by writing our seed to local.private at a
        # *throwaway* location, importing tn, calling absorb with a
        # synthesized cfg, then deleting that throwaway file. Or,
        # simpler: drop our seed into the real keystore_path/local.private,
        # let absorb's project_seed handler overwrite it on success,
        # and on failure rip it back out so the caller's INIT-UPLOAD
        # path sees an empty keystore.
        keystore_path.mkdir(parents=True, exist_ok=True)
        priv_path = keystore_path / "local.private"
        pub_path = keystore_path / "local.public"

        # Cold-start contract: empty keystore. We refuse to clobber an
        # existing identity (caller is supposed to gate on emptiness).
        # If the caller violates that, log and fail fast.
        if priv_path.exists():
            _log.warning(
                "bootstrap: %s already exists; refusing to overwrite via api-key",
                priv_path,
            )
            return False

        try:
            priv_path.write_bytes(seed)
            pub_path.write_text(did, encoding="utf-8")
        except OSError as exc:
            _log.warning("bootstrap: writing seed to keystore failed: %s", exc)
            return False

        # Now call absorb. The signature is ``absorb(source)`` (new)
        # or ``absorb(cfg, source)`` (legacy). We use the legacy form
        # because the SDK's global dispatch isn't initialised yet —
        # the whole point of this bootstrap is to make tn.init()
        # succeed afterward. ``tn.absorb`` is invoked with the bytes
        # source so the bundle is read directly from memory.
        # Build a minimal cfg via the bootstrap-cfg synthesiser in
        # absorb.py itself: passing bytes triggers it through the
        # one-arg shape, which is what we want.
        try:
            # ``tn.absorb`` (the symbol on the package) is the bound
            # function ``_absorb_impl``, not the submodule. Import the
            # underlying module via importlib to get at
            # ``_absorb_dispatch`` directly.
            import importlib

            _absorb_mod = importlib.import_module("tn.absorb")
            from .config import LoadedConfig
            from .signing import DeviceKey as _DeviceKey
        except Exception:  # noqa: BLE001 — import failure can't be allowed to escape
            _log.warning("bootstrap: tn imports failed", exc_info=True)
            _clear_keystore(priv_path, pub_path)
            return False

        # Build a synthetic cfg directly with our device key so the
        # absorb's _maybe_unseal_recipient_wrap can match recipient_did.
        # The cfg matches what _try_bootstrap_cfg would synthesise but
        # we control the device DeviceKey explicitly. Once absorb's
        # project_seed handler runs it overwrites the keystore with
        # the publisher's identity.
        device = _DeviceKey.from_private_bytes(seed)
        cfg = LoadedConfig(
            yaml_path=yaml_path,
            keystore=keystore_path,
            device=device,
            ceremony_id="_api_key_bootstrap",
            master_index_key=b"",
            cipher_name="btn",
            public_fields=[],
            default_policy="private",
            groups={},
            field_to_groups={},
            handler_specs=None,
            admin_log_location="./.tn/tn/admin/admin.ndjson",
            log_path="./.tn/tn/logs/tn.ndjson",
        )

        receipt = _absorb_mod._absorb_dispatch(cfg, sealed_bytes)
        if receipt.legacy_status == "rejected":
            _log.warning(
                "bootstrap: absorb rejected sealed bundle: %s",
                receipt.legacy_reason,
            )
            _clear_keystore(priv_path, pub_path)
            return False

        # absorb may have replaced our seed with the publisher's seed;
        # both halves of the keystore should be on disk now.
        if not priv_path.exists() or not pub_path.exists():
            _log.warning(
                "bootstrap: absorb succeeded but keystore is incomplete at %s",
                keystore_path,
            )
            return False

        # Stamp sync_state so subsequent runs know we cold-started
        # from an api-key. This is informational; the handler-builder
        # rebinds on every init regardless.
        try:
            update_sync_state(
                yaml_path,
                account_bound=True,
                bootstrapped_from="api_key",
            )
        except Exception:  # noqa: BLE001 — sync_state stamp is best-effort
            # Sync-state write is best-effort.
            _log.debug("bootstrap: sync_state stamp failed", exc_info=True)

        _log.info(
            "bootstrap: cold-started keystore at %s from api-key (kind=%s)",
            keystore_path,
            doc.get("kind"),
        )
        return True
    except Exception:  # noqa: BLE001 — never propagate; init must continue
        # Catch-all so this path can never break the caller's init.
        _log.warning(
            "bootstrap: unexpected exception during api-key bootstrap; falling through",
            exc_info=True,
        )
        return False


def _clear_keystore(priv_path: Path, pub_path: Path) -> None:
    """Best-effort cleanup when bootstrap aborts after writing the
    ephemeral seed but before absorb succeeded.

    Leaving the ephemeral seed on disk would let the caller's
    fall-through path (INIT-UPLOAD) accidentally publish under our
    throwaway DID instead of minting a fresh one. Yanking both files
    keeps the keystore "empty" so INIT-UPLOAD does the right thing.
    """
    for p in (priv_path, pub_path):
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass


__all__ = [
    "bootstrap_from_api_key",
]
