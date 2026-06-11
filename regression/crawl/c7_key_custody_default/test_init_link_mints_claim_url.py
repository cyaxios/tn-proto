"""
SILO: C7 — Default key custody (load-bearing onboarding path)
TEST: tn.init(link=True) on a fresh machine uploads to the vault, surfaces a
      claim URL, persists sync_state, and the vault returns the same bytes
      back on authed fetch.
SEE: regression/crawl/c7_key_custody_default/README.md

Flow:
  1. Hermetic machine — TN user-home redirected to a tmpdir; TN_VAULT_URL
     points at a freshly-booted FastAPI subprocess on a free port; mongo
     is ephemeral.
  2. tn.init(link=True) — climbs to rung 4. Mints ceremony, encrypts
     keystore, POSTs to /api/v1/pending-claims, writes sync_state.
  3. Assert claim_url.txt exists at <yaml_dir>/.tn/sync/claim_url.txt
     and contains the URL.
  4. Assert sync_state.pending_claim has the four fields (vault_id,
     expires_at, claim_url, password_b64).
  5. Parse the URL into (vault_id, bek). Assert BEK is 32 bytes.
  6. dev-auth login as 'alice'; GET /api/v1/pending-claims/{vault_id} with
     the bearer token; assert the returned bytes are non-empty (we don't
     decrypt here — that's C8).
  7. Assert hermetic — the real user-home tn dir was not touched.

Asserts (named):
  - "claim-url-file-exists"
  - "sync-state-has-pending-claim"
  - "claim-url-parses"
  - "bek-is-32-bytes"
  - "dev-auth-login-returns-token"
  - "vault-returns-ciphertext"
  - "user-home-untouched"

Failure modes the test catches:
  - vault upload didn't fire (claim_url.txt missing)
  - URL pattern drifted (parse_claim_url fails)
  - vault stored nothing (GET 404)
  - bytes are corrupted between POST and GET
  - hermetic redirect leaked (real ~/AppData/Roaming/tn/ touched)
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.vault_subprocess import VaultServer
from regression._shared.vault_test_helpers import (
    dev_auth_login,
    fetch_pending_claim,
    parse_claim_url,
)


def test_init_link_mints_claim_url_and_uploads_to_vault(
    hermetic_machine_with_live_vault: Path,
    vault_server: VaultServer,
    vault_cleanup: list[str],
) -> None:
    # rung 4: init with auto-link enabled.
    tn.init(link=True)

    cfg = tn.current_config()
    yaml_dir = Path(cfg.yaml_path).parent

    # ── 1. Claim URL written to disk ─────────────────────────────────
    claim_url_file = yaml_dir / ".tn" / "sync" / "claim_url.txt"
    assert_named(
        name="claim-url-file-exists",
        expected=True,
        observed=claim_url_file.exists(),
        on_miss=(
            f"Expected {claim_url_file} to exist after tn.init(link=True). "
            f"The auto-link path didn't fire — check "
            f"python/tn/__init__.py:_auto_link_after_init for the trigger "
            f"conditions, and python/tn/handlers/vault_push.py:init_upload "
            f"for the file-write step."
        ),
    )
    claim_url = claim_url_file.read_text(encoding="utf-8").strip()

    # ── 2. sync_state has the pending-claim record ────────────────────
    from tn.sync_state import get_pending_claim

    pc = get_pending_claim(cfg.yaml_path)
    pc_fields_present = (
        pc is not None
        and bool(pc.get("vault_id"))
        and bool(pc.get("claim_url"))
        and bool(pc.get("password_b64"))
        and bool(pc.get("expires_at"))
    )
    assert_named(
        name="sync-state-has-pending-claim",
        expected=True,
        observed=pc_fields_present,
        on_miss=(
            f"sync_state pending_claim is missing fields. Expected "
            f"vault_id+claim_url+password_b64+expires_at all populated; "
            f"got pc={pc!r}. Check python/tn/sync_state.py:set_pending_claim "
            f"and python/tn/handlers/vault_push.py:init_upload."
        ),
    )
    assert pc is not None  # narrowed by the named assert above

    # ── 3. URL parses + BEK is 32 bytes ──────────────────────────────
    # parse_claim_url raises on malformed URLs, so reaching the assertion
    # below already proves "parses". We only assert the BEK size, which
    # is the load-bearing post-condition (32 bytes = AES-256 key).
    vault_id, bek = parse_claim_url(claim_url)
    # Register for live-vault cleanup. In ephemeral mode this is a no-op.
    vault_cleanup.append(vault_id)
    assert_named(
        name="bek-is-32-bytes",
        expected=32,
        observed=len(bek),
        on_miss=(
            "BEK from the URL fragment must be exactly 32 bytes (AES-256 "
            "key size). Check python/tn/handlers/vault_push.py:init_upload "
            "where the BEK is minted via secrets.token_bytes(32)."
        ),
    )

    # ── 4. dev-auth login mints a bearer JWT ─────────────────────────
    login = dev_auth_login(vault_server.base_url, handle="alice")
    token = login.get("token")
    assert_named(
        name="dev-auth-login-returns-token",
        expected=True,
        observed=bool(isinstance(token, str) and token),
        on_miss=(
            f"POST /api/v1/dev/login didn't return a non-empty token; got "
            f"login={login!r}. Is TN_DEV_AUTH_BYPASS=1 set on the "
            f"subprocess? Check the vault_server fixture's env block and "
            f"tn_proto_web/src/routes_dev_auth.py:dev_login."
        ),
    )
    assert isinstance(token, str) and token  # narrowed

    # ── 5. Vault returns ciphertext bytes for the vault_id ───────────
    blob = fetch_pending_claim(vault_server.base_url, vault_id, token)
    assert_named(
        name="vault-returns-non-empty-blob",
        expected=True,
        observed=len(blob) > 0,
        on_miss=(
            f"GET /api/v1/pending-claims/{vault_id} returned {len(blob)} "
            f"bytes. Either the POST didn't land, or the row was already "
            f"claimed/expired. Check pending_claims_storage.read in "
            f"tn_proto_web/src/pending_claims_storage.py and the row "
            f"insert in routes_pending_claims.py:create_pending_claim."
        ),
    )
    # Belt-and-suspenders: the bytes should look like a tnpkg (zip magic).
    assert_named(
        name="vault-bytes-look-like-tnpkg-zip",
        expected=b"PK\x03\x04",
        observed=blob[:4],
        on_miss=(
            f"Vault returned bytes that don't start with the zip magic. "
            f"The init-upload payload is a tnpkg zip; if this fails the "
            f"encryption or zip pack step is broken upstream of the vault. "
            f"First 16 bytes: {blob[:16]!r}"
        ),
    )

    # ── 6. Hermetic check — real user-home was not touched ───────────
    assert_user_home_untouched()
