"""
SILO: C7 — Default key custody
TEST: a second `tn.init(link=True)` on the same ceremony reuses the existing
      vault_id within the TTL window — no second POST to the vault.
SEE: regression/crawl/c7_key_custody_default/README.md

Why we care:
  - A user might restart their app, re-run a script, or hit `tn init`
    twice for any reason. If every init mints a fresh pending-claim
    we'd:
      a) leak pending-claim rows on the vault (each with its own 24h TTL),
      b) the user might paste the OLD claim URL after a re-init has
         orphaned it — silent funnel breakage.
  - The C18 idempotency rule says: while a previous pending claim is
    still inside TTL, the second tick must reuse it (no second POST,
    same vault_id in sync_state).

Flow:
  1. Hermetic + live vault subprocess.
  2. `tn.init(link=True)` — first time. Capture the vault_id.
  3. Re-init (without flush_and_close in between will fail; we close
     cleanly and re-init from the same yaml).
  4. Assert: second init's pending-claim has the SAME vault_id.

Asserts (named):
  - "first-init-mints-vault-id"
  - "second-init-reuses-vault-id"
  - "user-home-untouched"

Failure modes the test catches:
  - C18 reuse-within-TTL gate regressed (second init re-uploads).
  - sync_state.pending_claim got cleared on flush, forcing a re-upload.
  - The TTL check is using a stale clock somehow.
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


def test_reinit_within_ttl_reuses_vault_id(
    hermetic_machine_with_live_vault: Path,
    vault_cleanup: list[str],
) -> None:
    # ── First init ──────────────────────────────────────────────────
    tn.init(link=True)
    cfg = tn.current_config()
    yaml_path = cfg.yaml_path

    from tn.sync_state import get_pending_claim

    pc1 = get_pending_claim(yaml_path)
    first_vault_id = pc1.get("vault_id") if pc1 else None
    if first_vault_id:
        vault_cleanup.append(first_vault_id)

    assert_named(
        name="first-init-mints-vault-id",
        expected=True,
        observed=bool(first_vault_id),
        on_miss=(
            f"First tn.init(link=True) produced no vault_id in sync_state. "
            f"pc1={pc1!r}. Investigate vault_push.py:init_upload before "
            f"reading the idempotency path."
        ),
    )

    # ── Second init from the same yaml ──────────────────────────────
    # Important: keep yaml_path stable so discovery hits the same
    # ceremony. flush_and_close drops the runtime singleton; sync_state
    # on disk persists across the close.
    tn.flush_and_close()
    tn.init(yaml_path, link=True)

    pc2 = get_pending_claim(yaml_path)
    second_vault_id = pc2.get("vault_id") if pc2 else None

    assert_named(
        name="second-init-reuses-vault-id",
        expected=first_vault_id,
        observed=second_vault_id,
        on_miss=(
            f"Second tn.init(link=True) within TTL minted a fresh vault_id. "
            f"first={first_vault_id!r}, second={second_vault_id!r}. The "
            f"C18 reuse-within-TTL gate regressed — check "
            f"python/tn/handlers/vault_push.py:init_upload "
            f"(the `reused=True` fast path)."
        ),
    )

    assert_user_home_untouched()
