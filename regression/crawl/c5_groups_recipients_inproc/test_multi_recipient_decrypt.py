"""
SILO: C5 — Local groups + recipients in-process
TEST: Alice mints kits for Frank AND Bob. Both decrypt the same envelopes.

Why this is distinct from the single-recipient test: a BTN group's
"add second recipient" path exercises the tree-extend logic (the M in
"M-of-N" can grow). If that breaks, the second recipient's kit either
doesn't unlock the existing entries or silently shares state with the
first recipient's kit.

Flow:
  1. Alice: tn.init + add Frank + add Bob + bundle both kits.
  2. Alice writes 2 envelopes.
  3. Frank's tmpdir: ceremony + absorb frank.tnpkg.
     Read Alice's log under Frank's keystore; assert both envelopes
     decrypt cleanly.
  4. Bob's tmpdir: ceremony + absorb bob.tnpkg.
     Read Alice's log under Bob's keystore; assert both envelopes
     decrypt cleanly.
  5. Cross-check: Frank's decrypt result == Bob's decrypt result.

Asserts (named):
  - "alice-minted-two-distinct-kits"
  - "frank-decrypted-both-entries"
  - "bob-decrypted-both-entries"
  - "frank-and-bob-saw-same-content"
  - "user-home-untouched"
"""
from __future__ import annotations

from pathlib import Path

import pytest
import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


FRANK_DID = "did:key:zFrank01234567890abcdefghjkmnpqrstuvwxyz"
BOB_DID = "did:key:zBob01234567890abcdefghjkmnpqrstuvwxy"


def test_multi_recipient_decrypt(
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

    # Mint a kit for Frank, bundle it for transport.
    kit_path = bundle_dir / "default.btn.mykit"
    frank_add = tn.admin.add_recipient("default", recipient_did=FRANK_DID, out_path=kit_path)
    frank_tnpkg = bundle_dir / "frank.tnpkg"
    tn.pkg.export(
        frank_tnpkg, kind="kit_bundle", cfg=alice_cfg,
        keystore=bundle_dir, to_did=FRANK_DID, groups=["default"],
    )

    # The kit file is rewritten each call; mint Bob's kit AFTER bundling
    # Frank's so the bundled-state Frank gets matches the moment in
    # time when Frank's leaf index was the latest one.
    bob_add = tn.admin.add_recipient("default", recipient_did=BOB_DID, out_path=kit_path)
    bob_tnpkg = bundle_dir / "bob.tnpkg"
    tn.pkg.export(
        bob_tnpkg, kind="kit_bundle", cfg=alice_cfg,
        keystore=bundle_dir, to_did=BOB_DID, groups=["default"],
    )

    assert_named(
        name="alice-minted-two-distinct-kits",
        expected=True,
        observed=(
            frank_tnpkg.exists() and bob_tnpkg.exists() and
            frank_add.leaf_index != bob_add.leaf_index
        ),
        on_miss=(
            f"Two kits should land at distinct leaf indices. Frank's "
            f"leaf={getattr(frank_add, 'leaf_index', None)!r}, Bob's "
            f"leaf={getattr(bob_add, 'leaf_index', None)!r}, "
            f"frank.tnpkg exists={frank_tnpkg.exists()}, "
            f"bob.tnpkg exists={bob_tnpkg.exists()}"
        ),
    )

    # Alice writes two envelopes — both AFTER both recipients were added.
    tn.info("multi.event.one", marker="event-1")
    tn.info("multi.event.two", marker="event-2")
    tn.flush_and_close()

    # ── Frank reads ─────────────────────────────────────────────────
    frank_dir = tmp_path / "frank_machine"
    frank_dir.mkdir()
    monkeypatch.chdir(frank_dir)
    tn.init()
    tn.pkg.absorb(frank_tnpkg)
    frank_keystore = tn.current_config().keystore
    tn.flush_and_close()

    frank_decrypted = []
    for entry in tn.read(log=alice_log, as_recipient=frank_keystore, group="default"):
        if "default" not in entry.hidden_groups:
            frank_decrypted.append((entry.event_type, dict(entry.fields)))

    assert_named(
        name="frank-decrypted-both-entries",
        expected=2,
        observed=len(frank_decrypted),
        on_miss=(
            f"Frank decrypted {len(frank_decrypted)} entries; expected 2. "
            f"Got types: {[t for t, _ in frank_decrypted]}. "
            f"If 1 came back, the second event was encrypted to a tree "
            f"state Frank's kit doesn't see — check the add_recipient "
            f"sequencing in admin/__init__.py."
        ),
    )

    # ── Bob reads ───────────────────────────────────────────────────
    bob_dir = tmp_path / "bob_machine"
    bob_dir.mkdir()
    monkeypatch.chdir(bob_dir)
    tn.init()
    tn.pkg.absorb(bob_tnpkg)
    bob_keystore = tn.current_config().keystore
    tn.flush_and_close()

    bob_decrypted = []
    for entry in tn.read(log=alice_log, as_recipient=bob_keystore, group="default"):
        if "default" not in entry.hidden_groups:
            bob_decrypted.append((entry.event_type, dict(entry.fields)))

    assert_named(
        name="bob-decrypted-both-entries",
        expected=2,
        observed=len(bob_decrypted),
        on_miss=(
            f"Bob decrypted {len(bob_decrypted)} entries; expected 2. "
            f"Types: {[t for t, _ in bob_decrypted]}"
        ),
    )

    # ── Frank and Bob saw the same content ──────────────────────────
    frank_set = {(t, tuple(sorted(f.items()))) for t, f in frank_decrypted}
    bob_set = {(t, tuple(sorted(f.items()))) for t, f in bob_decrypted}
    assert_named(
        name="frank-and-bob-saw-same-content",
        expected=True,
        observed=frank_set == bob_set,
        on_miss=(
            f"Different recipients should see identical plaintext for "
            f"the same encrypted envelopes. Frank's set: {frank_set!r}. "
            f"Bob's set: {bob_set!r}."
        ),
    )

    assert_user_home_untouched()
