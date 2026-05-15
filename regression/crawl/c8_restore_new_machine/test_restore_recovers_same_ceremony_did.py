"""
SILO: C8 — Restore on new machine
TEST: machine A uploads, machine B fetches+decrypts+re-inits, B has the SAME
      ceremony DID as A.
SEE: regression/crawl/c8_restore_new_machine/README.md

Flow:
  1. **Machine A**: hermetic + live vault. `tn.init(link=True)`. Capture
     ceremony DID, claim URL, vault_id.
  2. `tn.flush_and_close()` — important: simulates user closing their
     laptop. Nothing on B's side relies on A's runtime being live.
  3. **Machine B**: dev-auth login → GET pending-claim → decrypt body
     blob with BEK from URL fragment → lay out tn.yaml + keys/ in
     machine_b_tmpdir.
  4. `tn.init(yaml_path=B/tn.yaml)` — B's first init from the restored
     yaml.
  5. Assert: B's `cfg.device.did` == A's captured DID.

Asserts (named):
  - "machine-a-captured-ceremony-did"
  - "claim-url-fetchable-with-dev-auth"
  - "decrypt-produces-yaml-and-keys"
  - "machine-b-yaml-on-disk"
  - "machine-b-did-matches-machine-a"
  - "user-home-untouched"

Failure modes the test catches:
  - GET /pending-claims fails (auth or row missing).
  - decrypt_body_blob raises (BEK doesn't match the cipher).
  - layout writer drops files or puts them in the wrong place.
  - tn.init(yaml_path=B/tn.yaml) doesn't find the keystore — wrong dir layout.
  - B's DID differs from A's — keys didn't survive the round-trip.
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
    restore_keystore_to,
)


def test_restore_recovers_same_ceremony_did(
    hermetic_machine_with_live_vault: Path,
    machine_b_tmpdir: Path,
    vault_server: VaultServer,
    vault_cleanup: list[str],
) -> None:
    # ── Machine A: init + upload + capture DID ──────────────────────
    tn.init(link=True)
    cfg_a = tn.current_config()
    machine_a_did = cfg_a.device.did
    yaml_dir_a = Path(cfg_a.yaml_path).parent
    claim_url = (yaml_dir_a / ".tn" / "sync" / "claim_url.txt").read_text(
        encoding="utf-8"
    ).strip()

    assert_named(
        name="machine-a-captured-ceremony-did",
        expected=True,
        observed=bool(machine_a_did) and machine_a_did.startswith("did:key:"),
        on_miss=(
            f"Machine A produced an unusable device DID: {machine_a_did!r}. "
            f"Check python/tn/identity.py — the DID is what we'll later "
            f"assert against on machine B."
        ),
    )

    # Simulate "the user closed their laptop". B doesn't share A's
    # runtime state. The vault is the only handoff channel.
    tn.flush_and_close()

    # ── Machine B: fetch + decrypt + lay out ────────────────────────
    vault_id, bek = parse_claim_url(claim_url)
    vault_cleanup.append(vault_id)

    login = dev_auth_login(vault_server.base_url, handle="alice")
    token = login["token"]

    ciphertext = fetch_pending_claim(vault_server.base_url, vault_id, token)
    assert_named(
        name="claim-url-fetchable-with-dev-auth",
        expected=True,
        observed=len(ciphertext) > 0,
        on_miss=(
            f"Vault returned {len(ciphertext)} bytes for vault_id="
            f"{vault_id!r}. Either GET handler errored or row was "
            f"already claimed/expired. Check "
            f"tn_proto_web/src/routes_pending_claims.py:get_pending_claim."
        ),
    )

    yaml_b = restore_keystore_to(
        target_dir=machine_b_tmpdir,
        ciphertext_tnpkg=ciphertext,
        bek=bek,
    )

    # Sanity: both expected directory artifacts exist.
    assert_named(
        name="machine-b-yaml-on-disk",
        expected=True,
        observed=yaml_b.exists() and yaml_b.is_file(),
        on_miss=(
            f"After restore_keystore_to, expected {yaml_b} to be on disk. "
            f"Either the decrypt produced no 'body/tn.yaml' or the "
            f"layout writer in _shared/vault_test_helpers.py:"
            f"restore_keystore_to dropped it."
        ),
    )
    keys_dir = machine_b_tmpdir / "keys"
    keystore_files = sorted(p.name for p in keys_dir.iterdir()) if keys_dir.exists() else []
    assert_named(
        name="decrypt-produces-yaml-and-keys",
        expected=True,
        observed=len(keystore_files) > 0,
        on_miss=(
            f"keys/ on machine B is empty after restore. Decrypted body "
            f"file inventory was apparently {keystore_files!r}. Check "
            f"_shared/vault_test_helpers.py:restore_keystore_to's "
            f"per-file routing — anything not tn.yaml lands in keys/."
        ),
    )

    # ── tn.init(yaml_path=B/tn.yaml) → same DID ────────────────────
    tn.init(yaml_b)
    cfg_b = tn.current_config()
    machine_b_did = cfg_b.device.did

    assert_named(
        name="machine-b-did-matches-machine-a",
        expected=machine_a_did,
        observed=machine_b_did,
        on_miss=(
            f"Machine B's ceremony DID ({machine_b_did!r}) differs from "
            f"machine A's ({machine_a_did!r}). The keystore round-tripped "
            f"through the vault but the runtime is loading a fresh "
            f"identity instead of the restored one. Check the keystore "
            f"path in {yaml_b}: the runtime's `keystore:` field must "
            f"point at the laid-out keys/ directory."
        ),
    )

    assert_user_home_untouched()
