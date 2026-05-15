"""
SILO: C5 — Local groups + recipients in-process
TEST: a revoked recipient can read PRE-revoke entries but NOT post-revoke
      entries (revocation is forward-only).

Why this matters: a recipient whose kit becomes useless instantly (even
for past entries) would lose auditability of their own historic data;
a recipient whose kit keeps working post-revoke is a security hole.
Forward-only revoke + rotate is the protocol contract.

Flow:
  1. Alice: tn.init + add Carol (capture her leaf_index).
  2. Alice bundles Carol's kit BEFORE revoke.
  3. Alice writes ONE entry — encrypted under epoch N where Carol's
     leaf is active.
  4. Alice revokes Carol's leaf_index AND rotates "default" so the
     group key advances to epoch N+1. (Revoke alone may not rotate
     in all paths; the bundled deploy verb is rotate, which is what
     real operators run.)
  5. Alice writes ANOTHER entry — encrypted under epoch N+1.
  6. Carol absorbs her (pre-revoke) kit and reads Alice's log.
  7. Assert: Carol can decrypt the pre-revoke entry (hidden_groups
     does NOT include "default" for that row) but CANNOT decrypt the
     post-revoke entry (hidden_groups DOES include "default" for it).

Asserts (named):
  - "carol-decrypted-pre-revoke-entry"
  - "carol-did-not-decrypt-post-revoke-entry"
  - "user-home-untouched"
"""
from __future__ import annotations

from pathlib import Path

import pytest
import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


CAROL_DID = "did:key:zCarol01234567890abcdefghjkmnpqrstuvwxyz"


def test_revoke_locks_out_recipient(
    hermetic_machine: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alice_dir = hermetic_machine
    tn.init()
    alice_cfg = tn.current_config()
    alice_log = alice_cfg.resolve_log_path()

    bundle_dir = alice_dir / "alice_bundles"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    kit_path = bundle_dir / "default.btn.mykit"
    carol_add = tn.admin.add_recipient(
        "default", recipient_did=CAROL_DID, out_path=kit_path,
    )

    # Bundle Carol's kit BEFORE revoke + rotate. Use a workspace
    # dir + the canonical .btn.mykit filename pattern.
    carol_tnpkg = bundle_dir / "carol.tnpkg"
    tn.pkg.export(
        carol_tnpkg, kind="kit_bundle", cfg=alice_cfg,
        keystore=bundle_dir, to_did=CAROL_DID, groups=["default"],
    )

    # Pre-revoke entry.
    tn.info("c5.pre.revoke", marker="visible-to-carol")

    # Revoke Carol's leaf, then rotate so the post-revoke entries land
    # under a new epoch Carol's kit can't unwrap.
    tn.admin.revoke_recipient("default", leaf_index=carol_add.leaf_index)
    # Rotate exists at python/tn/admin/__init__.py:rotate — the deploy verb.
    tn.admin.rotate("default")

    # Post-revoke entry — encrypted under the new epoch.
    tn.info("c5.post.revoke", marker="should-be-hidden")

    tn.flush_and_close()

    # ── Carol's side ────────────────────────────────────────────────
    carol_dir = tmp_path / "carol_machine"
    carol_dir.mkdir()
    monkeypatch.chdir(carol_dir)
    tn.init()
    tn.pkg.absorb(carol_tnpkg)
    carol_keystore = tn.current_config().keystore
    tn.flush_and_close()

    # Carol reads — surface hidden_groups so we can distinguish "could
    # decrypt" from "couldn't".
    pre_visible_to_carol = False
    post_visible_to_carol = False
    for entry in tn.read(
        log=alice_log, as_recipient=carol_keystore, group="default",
    ):
        if entry.event_type == "c5.pre.revoke":
            pre_visible_to_carol = "default" not in entry.hidden_groups
        elif entry.event_type == "c5.post.revoke":
            post_visible_to_carol = "default" not in entry.hidden_groups

    assert_named(
        name="carol-decrypted-pre-revoke-entry",
        expected=True,
        observed=pre_visible_to_carol,
        on_miss=(
            "Carol could NOT decrypt the pre-revoke entry. Revocation "
            "should be forward-only — pre-revoke entries must remain "
            "readable by the recipient whose kit was minted BEFORE the "
            "revoke. Check admin/__init__.py:revoke_recipient AND the "
            "reader path; the kit Carol absorbed must still unwrap "
            "epoch-N material."
        ),
    )

    assert_named(
        name="carol-did-not-decrypt-post-revoke-entry",
        expected=False,
        observed=post_visible_to_carol,
        on_miss=(
            "Carol CAN decrypt the post-revoke entry — that's a "
            "security hole. After `revoke_recipient + rotate`, Carol's "
            "kit (minted under epoch N) should fail to unwrap epoch N+1 "
            "envelopes. Check that rotate actually bumped the epoch and "
            "that the publisher's emit chose the new epoch's keys."
        ),
    )

    assert_user_home_untouched()
