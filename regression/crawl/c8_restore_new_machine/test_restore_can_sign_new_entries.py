"""
SILO: C8 — Restore on new machine
TEST: after restore, machine B can sign and emit new entries under the same
      DID as machine A. Proves the *private* keys round-tripped, not just
      the DID.

Why this is its own test (vs. just asserting B's DID matches A's): a same-
DID assertion is satisfied by the public-key fields alone. The vault could
return a tnpkg containing only public material and B would still see a
matching DID via Identity.load — and silently fail the FIRST time B tried
to sign. This test catches that exact failure mode by actually signing.

SEE: regression/crawl/c8_restore_new_machine/README.md

Flow:
  1. Machine A: hermetic + live vault. `tn.init(link=True)`.
  2. Machine A: emit one entry. Capture DID + last row_hash + run_id.
  3. flush_and_close.
  4. Machine B: dev-auth + fetch + decrypt + lay out (same as
     `test_restore_recovers_same_ceremony_did.py`).
  5. Machine B: `tn.init(yaml_path=<B>/tn.yaml)`. Same DID expected.
  6. Machine B: `tn.info("c8.chain.continued", ...)` — should write
     under the recovered private key.
  7. `tn.read()` on B's log. Find B's entry.
  8. Verify the signature: re-parse B's entry, check it round-trips
     `verify=True` (which raises on a bad sig). Use the unified
     `tn.read(verify=True)` API.

Asserts (named):
  - "machine-b-entry-found-in-read"
  - "machine-b-entry-verifies-under-recovered-keystore"
  - "machine-b-entry-did-matches-machine-a"
  - "user-home-untouched"

Failure modes the test catches:
  - The decrypted body has only public material; signing on B raises
    or produces an envelope the verifier rejects.
  - The yaml's keystore: path doesn't match the laid-out keys/ dir,
    so B's runtime can't find the private key file.
  - Machine B's signing key was minted fresh because the runtime
    didn't load `local.private` properly.
"""
from __future__ import annotations

from pathlib import Path

import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched
from regression._shared.log_query import LogQuery
from regression._shared.vault_subprocess import VaultServer
from regression._shared.vault_test_helpers import (
    dev_auth_login,
    fetch_pending_claim,
    parse_claim_url,
    restore_keystore_to,
)


def test_machine_b_can_sign_new_entries_after_restore(
    hermetic_machine_with_live_vault: Path,
    machine_b_tmpdir: Path,
    vault_server: VaultServer,
    vault_cleanup: list[str],
) -> None:
    # ── Machine A ───────────────────────────────────────────────────
    tn.init(link=True)
    cfg_a = tn.current_config()
    machine_a_did = cfg_a.device.did
    yaml_dir_a = Path(cfg_a.yaml_path).parent
    claim_url = (yaml_dir_a / ".tn" / "sync" / "claim_url.txt").read_text(
        encoding="utf-8"
    ).strip()

    tn.info("c8.a.entry", note="from-machine-a")

    tn.flush_and_close()

    # ── Machine B: restore ──────────────────────────────────────────
    vault_id, bek = parse_claim_url(claim_url)
    vault_cleanup.append(vault_id)
    login = dev_auth_login(vault_server.base_url, handle="alice")
    ciphertext = fetch_pending_claim(vault_server.base_url, vault_id, login["token"])
    yaml_b = restore_keystore_to(
        target_dir=machine_b_tmpdir,
        ciphertext_tnpkg=ciphertext,
        bek=bek,
    )

    # ── Machine B: init + sign ─────────────────────────────────────
    tn.init(yaml_b)
    cfg_b = tn.current_config()
    machine_b_did = cfg_b.device.did

    # Cross-check: B's DID must match A's. (Distinct test owns this
    # assertion too, but we re-assert here because the rest of this
    # test is meaningless without it.)
    assert_named(
        name="machine-b-entry-did-matches-machine-a",
        expected=machine_a_did,
        observed=machine_b_did,
        on_miss=(
            f"B's ceremony loaded a different identity ({machine_b_did!r}) "
            f"than A had ({machine_a_did!r}). Restore didn't bind the "
            f"keystore correctly; chain-continuity test below is moot."
        ),
    )

    # Sign a new envelope under B's (recovered) keystore.
    tn.info("c8.b.entry", note="from-machine-b", linked_to_a_did=machine_a_did)

    # ── Read it back from B's log ───────────────────────────────────
    log_b = LogQuery(ceremony_path=cfg_b.yaml_path)
    env_b = log_b.assert_contains(
        name="machine-b-entry-found-in-read",
        where={"event_type": "c8.b.entry"},
        on_miss=(
            "B's tn.info('c8.b.entry', ...) didn't surface in tn.read(). "
            "Either the emit raised silently (check the runtime's error "
            "queue) or the file handler is writing to the wrong path "
            "(check yaml's protocol_events_location / admin_log_location)."
        ),
    )

    # Verify B's envelope was signed by the SAME DID — proves the
    # private key round-tripped (not just the public did:key string).
    env_b_did = env_b.get("did")
    assert_named(
        name="machine-b-entry-signed-by-same-did",
        expected=machine_a_did,
        observed=env_b_did,
        on_miss=(
            f"B emitted an envelope whose 'did' field is {env_b_did!r}, "
            f"not A's {machine_a_did!r}. The runtime is signing under a "
            f"different identity than the one Identity.load reports — "
            f"investigate config.device.did vs the actual signing key "
            f"selected by the runtime."
        ),
    )

    # ── Strict verify pass: tn.read(verify=True) raises on bad sig ──
    # If the keystore restore didn't bring over private material, the
    # signature on B's entry would be invalid. tn.read(verify=True)
    # raises VerifyError on the first bad row.
    verify_raised: BaseException | None = None
    try:
        for _ in tn.read(verify=True):
            pass
    except BaseException as exc:  # noqa: BLE001
        verify_raised = exc
    assert_named(
        name="machine-b-entry-verifies-under-recovered-keystore",
        expected=None,
        observed=type(verify_raised).__name__ if verify_raised else None,
        on_miss=(
            f"tn.read(verify=True) on B's log raised {verify_raised!r}. "
            f"That means at least one envelope failed signature or chain "
            f"verification — strongly suggests the recovered keystore "
            f"has wrong/missing private material. Check restore_keystore_to "
            f"in _shared/vault_test_helpers.py and the keys/ inventory."
        ),
    )

    assert_user_home_untouched()
