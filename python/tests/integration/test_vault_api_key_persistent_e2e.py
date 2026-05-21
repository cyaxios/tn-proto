"""End-to-end: api-key persistent bootstrap from a fresh keystore.

Mirrors the layout / fixtures of ``test_vault_push_pull_e2e.py``: the
vault is mounted in-process via httpx.AsyncClient + ASGITransport so
the SDK's bootstrap path exercises the REAL routes_api_keys.py
endpoints (mint + sealed-bundle GET) end-to-end.

Scenario:

  1. Alice mints a project under her account, builds a sealed kit_bundle
     to a fresh seed-derived DID (the "API key" recipient), POSTs to
     /api/v1/projects/{id}/api-keys/persistent. The Python in-test
     ceremony stands in for the browser ceremony documented at
     static/account/api_keys_panel.js.
  2. A fresh consumer process (clean tmp dir, empty keystore) sets
     TN_API_KEY=<bearer> in its env and binds vault.sync.
  3. tn_proto/python/tn/bootstrap.py's bootstrap_from_api_key splits
     the bearer, runs the DID-challenge flow against the in-process
     vault, pulls the sealed bundle, and absorb-installs the body
     into the consumer's keystore.
  4. After bootstrap the consumer's keystore contains the project's
     publisher seed (the local.private inside the kit_bundle).

Skips when the vault sibling repo isn't present (so this file doesn't
block tn_proto CI on a checkout without tn_proto_web alongside).
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import secrets
import sys
import zipfile
from pathlib import Path

import httpx
import pytest

_HERE = Path(__file__).resolve().parent


def _find_vault_repo() -> Path | None:
    """Look for the vault repo alongside tn_proto.

    Same candidates as test_vault_push_pull_e2e._find_vault_repo so the
    skip behaviour is identical.
    """
    candidates_relative = (
        Path("..") / ".." / ".." / ".." / "tnproto-org",
        Path("..") / ".." / ".." / ".." / "tn-proto-org",
        Path("..") / ".." / ".." / ".." / "tn_proto_web",
        Path("..") / ".." / ".." / "tnproto-org",
        Path("..") / ".." / ".." / "tn-proto-org",
        Path("..") / ".." / ".." / "tn_proto_web",
    )
    for rel in candidates_relative:
        cand = (_HERE / rel).resolve()
        if (cand / "src" / "app.py").exists() and (cand / "tn.yaml").exists():
            # Skip if the vault repo doesn't have the new api-key route file.
            if not (cand / "src" / "routes_api_keys.py").exists():
                return None
            return cand
    return None


_VAULT = _find_vault_repo()
if _VAULT is None:
    pytest.skip(
        "vault sibling repo with routes_api_keys.py not found; skipping "
        "api-key cold-start e2e (will land green once tn_proto_web merges).",
        allow_module_level=True,
    )

# Add the in-tree tn package and the vault src to sys.path.
_TN_SDK = _HERE.parent.parent.parent  # python/
for p in (_TN_SDK, _VAULT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

os.environ.setdefault("VAULT_MONGO_DB", "tn_vault_test_account")
os.environ.setdefault("VAULT_MAX_PROJECTS", "20")
os.environ.setdefault("VAULT_MAX_FILES", "200")

import src.db as _db
from src.app import app

from tn.bootstrap import bootstrap_from_api_key

API = "/api/v1"


# ── Loop / motor housekeeping (mirrors test_vault_push_pull_e2e) ─────


@pytest.fixture(autouse=True)
def _reset_motor_client():
    if _db._client is not None:
        _db._client.close()
    _db._client = None
    yield
    if _db._client is not None:
        _db._client.close()
    _db._client = None


_LOOP: asyncio.AbstractEventLoop | None = None


@pytest.fixture
def _shared_loop():
    global _LOOP
    loop = asyncio.new_event_loop()
    _LOOP = loop
    try:
        yield loop
    finally:
        if _db._client is not None:
            try:
                _db._client.close()
            except Exception:
                pass
            _db._client = None
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        loop.close()
        _LOOP = None


def _run(coro):
    if _LOOP is None:
        return asyncio.run(coro)
    return _LOOP.run_until_complete(coro)


@pytest.fixture(autouse=True)
def _clean_db_before_test(_shared_loop):
    async def _wipe():
        for coll in ("api_keys", "project_wrapped_keys", "encrypted_backups"):
            try:
                await getattr(_db, coll)().delete_many({})
            except Exception:
                pass
        try:
            await _db.accounts().delete_many({"role": {"$ne": "admin"}})
        except Exception:
            pass

    _shared_loop.run_until_complete(_wipe())
    yield


# ── Test helpers: simulate the browser ceremony in Python ───────────


def _b64_urlsafe_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b58encode(data: bytes) -> str:
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


def _did_key(pub: bytes) -> str:
    return "did:key:z" + _b58encode(b"\xed\x01" + pub)


def _mint_jwt_for_account(account_id: str) -> str:
    """Synthesize an account JWT the same way the OAuth path does."""
    import time

    import jwt as pyjwt
    from src import config

    payload = {
        "sub": f"acct:{account_id}",
        "account_id": account_id,
        "did": None,
        "iss": "tn-vault",
        "iat": int(time.time()),
        "exp": int(time.time()) + config.JWT_EXPIRY_HOURS * 3600,
        "scope": "vault",
        "role": "user",
    }
    return pyjwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def _seed_account_and_project(account_id: str, project_id: str) -> None:
    """Create the minimal mongo state the api-key routes assume."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)

    async def _go():
        await _db.accounts().insert_one({
            "_id": account_id,
            "account_id": account_id,
            "did": f"did:vault:oauth:{account_id}",
            "email": f"{account_id}@example.com",
            "display_name": "test-alice",
            "created_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
            "tier": "free",
            "role": "user",
        })
        await _db.project_wrapped_keys().insert_one({
            "_id": project_id,
            "project_id": project_id,
            "account_id": account_id,
            "wrapped_bek_b64": "AAAA",
            "wrap_nonce_b64": "AAAA",
            "cipher_suite": "aes-256-gcm",
            "label": "alice-prj",
            "package_did": None,
            "created_at": now,
            "updated_at": now,
        })

    _run(_go())


def _build_sealed_kit_bundle(*, recipient_did: str, signer_seed: bytes,
                              project_id: str) -> bytes:
    """Construct a recipient-sealed project_seed .tnpkg in memory.

    The manifest is signed by ``signer_seed``'s Ed25519 keypair and
    self-addressed (from_did == to_did == recipient_did). Body contains
    the publisher's local.private/.public/tn.yaml — what a fresh consumer
    needs to bring vault.sync online.

    Mirrors what the browser ceremony in api_keys_panel.js produces.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from tn.canonical import _canonical_bytes
    from tn.recipient_seal import manifest_aad_for_wrap, seal_bek_for_recipient

    # Body: a minimal valid project_seed payload.
    priv = Ed25519PrivateKey.from_private_bytes(signer_seed)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    body_pub_did = _did_key(pub)  # signer DID == recipient DID

    yaml_str = (
        "ceremony:\n"
        "  id: api_key_test\n"
        "  mode: local\n"
        "  cipher: btn\n"
        "  sign: true\n"
        "logs:\n"
        "  path: ./.tn/tn/logs/tn.ndjson\n"
        "keystore:\n"
        "  path: ./.tn/tn/keys\n"
        "me:\n"
        f"  did: {body_pub_did}\n"
        "handlers: []\n"
        "groups:\n"
        "  default:\n"
        "    policy: private\n"
        "    cipher: btn\n"
        f"    recipients: [{{did: {body_pub_did}}}]\n"
    )

    body_files = {
        "body/tn.yaml": yaml_str.encode("utf-8"),
        "body/keys/local.private": signer_seed,
        "body/keys/local.public": body_pub_did.encode("utf-8"),
    }

    # Body zip + AES-GCM encrypt under a fresh BEK.
    body_zip = io.BytesIO()
    with zipfile.ZipFile(body_zip, "w", zipfile.ZIP_STORED) as zf:
        for name, data in body_files.items():
            zf.writestr(name, data)
    body_zip_bytes = body_zip.getvalue()

    bek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    encrypted_blob = nonce + AESGCM(bek).encrypt(nonce, body_zip_bytes, None)

    from datetime import UTC, datetime

    as_of = datetime.now(UTC).isoformat(timespec="milliseconds")
    manifest = {
        "kind": "project_seed",
        "version": 1,
        "publisher_identity": body_pub_did,
        "ceremony_id": "_api_key_seed",
        "as_of": as_of,
        "scope": "project",
        "recipient_identity": body_pub_did,
        "clock": {},
        "event_count": 0,
        "state": {
            "project": {
                "schema": "tn-project-seed-v1",
                "project_id": project_id,
                "ceremony_id": "_api_key_seed",
                "minted_at": as_of,
            },
            "body_encryption": {
                "frame": "tn-body-encryption-v1",
                "cipher_suite": "aes-256-gcm",
            },
        },
    }
    # Compute AAD before adding wrap (helper strips signature + wrap anyway).
    aad = manifest_aad_for_wrap(manifest)
    wrap = seal_bek_for_recipient(bek, recipient_did, aad)
    manifest["state"]["body_encryption"]["recipient_wrap"] = wrap

    # Sign the manifest now (signature covers everything except itself).
    sig_bytes = priv.sign(_canonical_bytes(manifest))
    manifest["manifest_signature_b64"] = base64.b64encode(sig_bytes).decode("ascii")

    # Outer zip: manifest.json + body/encrypted.bin
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
        zf.writestr("body/encrypted.bin", encrypted_blob)
    return out.getvalue()


def _mint_persistent_api_key(*, account_id: str, project_id: str) -> str:
    """Run the in-test browser-ceremony: build sealed bundle, POST, return bearer."""
    seed = secrets.token_bytes(32)
    key_id = secrets.token_bytes(16)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    did = _did_key(pub)
    sealed_bytes = _build_sealed_kit_bundle(
        recipient_did=did,
        signer_seed=seed,
        project_id=project_id,
    )
    jwt = _mint_jwt_for_account(account_id)

    async def _go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as ac:
            r = await ac.post(
                f"{API}/projects/{project_id}/api-keys/persistent",
                json={
                    "did": did,
                    "seed_b64": _b64_urlsafe_no_pad(seed),
                    "key_id_b64": _b64_urlsafe_no_pad(key_id),
                    "sealed_bundle_b64": base64.b64encode(sealed_bytes).decode("ascii"),
                    "nickname": "ci-prod",
                },
                headers={"Authorization": f"Bearer {jwt}"},
            )
            assert r.status_code == 201, r.text
            return r.json()["bearer"]

    return _run(_go())


# ── The end-to-end test ─────────────────────────────────────────────


def test_persistent_api_key_bootstraps_fresh_keystore(tmp_path: Path, _shared_loop, monkeypatch):
    account_id = "01J0000000ALICEACCOUNT01"
    project_id = "01J0000000ALICEPROJECT01"
    _seed_account_and_project(account_id, project_id)

    bearer = _mint_persistent_api_key(account_id=account_id, project_id=project_id)
    assert bearer.startswith("tn_apikey_")

    # Point the SDK at the in-process vault. The SDK uses
    # _resolve_did_endpoint(did:key:...) which falls back to
    # $TN_VAULT_DEFAULT_BASE. Set that to the ASGITransport's
    # base url AND monkeypatch urllib at the bootstrap module so the
    # HTTP calls land on the in-process app instead of going over a
    # real network.
    monkeypatch.setenv("TN_VAULT_DEFAULT_BASE", "http://test")

    # Route bootstrap's urllib through the ASGI app.
    from tn import bootstrap as _bs

    def _asgi_post(url: str, body: bytes, *, headers=None):
        from urllib.parse import urlparse

        path = urlparse(url).path

        async def _go():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test",
            ) as ac:
                r = await ac.post(
                    path,
                    content=body,
                    headers={"Content-Type": "application/json", **(headers or {})},
                )
                return r.status_code, r.content

        return _run(_go())

    def _asgi_get(url: str, *, headers=None):
        from urllib.parse import urlparse

        path = urlparse(url).path

        async def _go():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test",
            ) as ac:
                r = await ac.get(path, headers=headers or {})
                return r.status_code, r.content

        return _run(_go())

    monkeypatch.setattr(_bs, "_http_post", _asgi_post)
    monkeypatch.setattr(_bs, "_http_get", _asgi_get)

    # Fresh consumer keystore + yaml.
    consumer_dir = tmp_path / "consumer"
    consumer_dir.mkdir(parents=True, exist_ok=True)
    yaml_path = consumer_dir / "tn.yaml"
    keystore = consumer_dir / ".tn" / "tn" / "keys"
    # Don't create local.private; bootstrap should populate it.
    assert not (keystore / "local.private").exists()

    ok = bootstrap_from_api_key(
        yaml_path=yaml_path,
        keystore_path=keystore,
        vault_did="did:key:zStubForResolve",
        api_key=bearer,
    )
    assert ok, "bootstrap_from_api_key should have populated the keystore"
    assert (keystore / "local.private").exists()
    assert (keystore / "local.public").exists()

    # The body-installed local.private must be 32 bytes (the publisher
    # seed from the sealed bundle, NOT our throwaway).
    installed_seed = (keystore / "local.private").read_bytes()
    assert len(installed_seed) == 32
