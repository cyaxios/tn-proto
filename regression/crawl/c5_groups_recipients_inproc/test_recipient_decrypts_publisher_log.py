"""
SILO: C5 — Local groups + recipients in-process
TEST: Alice writes encrypted events; Frank's kit decrypts them.
SEE: regression/crawl/c5_groups_recipients_inproc/README.md

This is the smallest test that proves the BTN crypto round-trip works
end-to-end — not just the API. Three things have to compose correctly:

  1. `tn.admin.add_recipient(group, recipient_did=..., out_path=kit)`
     mints a kit Frank can use.
  2. `tn.pkg.export(kind="kit_bundle", ...)` packs the kit into a
     `.tnpkg` that travels between processes.
  3. `tn.pkg.absorb(<tnpkg>)` on Frank's side installs the kit so the
     reader can find it.
  4. `tn.read(log=alice_log, as_recipient=frank_keystore, group="default")`
     decrypts Alice's envelopes under Frank's kit.

Flow:
  1. Hermetic. Alice's tmpdir + ceremony.
  2. Mint Frank's kit + bundle into <bundle_dir>/frank.tnpkg.
  3. Alice writes 3 events under tn.info.
  4. flush_and_close + chdir to Frank's tmpdir.
  5. Frank's ceremony + tn.pkg.absorb(<frank.tnpkg>).
  6. flush_and_close.
  7. Iterate tn.read(log=alice_log, as_recipient=frank_keystore,
     group="default") and assert all 3 events surface with fields
     intact.

Asserts (named):
  - "frank-kit-minted"
  - "frank-bundle-exists"
  - "frank-absorb-receipt-kind-kit-bundle"
  - "frank-absorbed-kit-on-disk"
  - "frank-decrypted-three-events"
  - "frank-fields-round-tripped"
  - "user-home-untouched"
"""
from __future__ import annotations

from pathlib import Path

import pytest
import tn

from regression._shared.assertions import assert_named
from regression._shared.fixtures import assert_user_home_untouched


FRANK_DID = "did:key:zFrank01234567890abcdefghjkmnpqrstuvwxyz"


def test_recipient_decrypts_publisher_log(
    hermetic_machine: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ── Alice's side ────────────────────────────────────────────────
    alice_dir = hermetic_machine  # already the test cwd
    tn.init()  # mints .tn/default/ under cwd
    alice_cfg = tn.current_config()
    alice_log = alice_cfg.resolve_log_path()

    # Mint Frank's kit into a separate workspace dir.
    bundle_dir = alice_dir / "alice_bundle_workspace"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    kit_path = bundle_dir / "default.btn.mykit"
    add_result = tn.admin.add_recipient(
        "default",
        recipient_did=FRANK_DID,
        out_path=kit_path,
    )
    assert_named(
        name="frank-kit-minted",
        expected=True,
        observed=kit_path.exists() and kit_path.stat().st_size > 0,
        on_miss=(
            f"add_recipient(default, recipient_did={FRANK_DID!r}, "
            f"out_path={kit_path}) returned {add_result!r} but no kit "
            f"file on disk."
        ),
    )

    # Bundle the kit into a .tnpkg for Frank to absorb.
    frank_tnpkg = bundle_dir / "frank.tnpkg"
    tn.pkg.export(
        frank_tnpkg,
        kind="kit_bundle",
        cfg=alice_cfg,
        keystore=bundle_dir,  # ship from the workspace dir, NOT alice's keystore
        to_did=FRANK_DID,
        groups=["default"],
    )
    assert_named(
        name="frank-bundle-exists",
        expected=True,
        observed=frank_tnpkg.exists() and frank_tnpkg.stat().st_size > 0,
        on_miss=(
            f"tn.pkg.export didn't produce {frank_tnpkg}. The kit was "
            f"minted but couldn't be bundled. Check "
            f"python/tn/pkg.py:export kit_bundle path."
        ),
    )

    # Alice writes three envelopes.
    tn.info("sale.line", item="bread", quantity=1, unit_price="3.25")
    tn.info("sale.line", item="butter", quantity=2, unit_price="4.00")
    tn.info("sale.total", subtotal="11.25")

    tn.flush_and_close()

    # ── Frank's side — separate tmpdir, separate ceremony ──────────
    frank_dir = tmp_path / "frank_machine"
    frank_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(frank_dir)

    tn.init()  # mints Frank's OWN ceremony
    receipt = tn.pkg.absorb(frank_tnpkg)
    assert_named(
        name="frank-absorb-receipt-kind-kit-bundle",
        expected="kit_bundle",
        observed=receipt.kind,
        on_miss=(
            f"absorb receipt kind={receipt.kind!r}; expected kit_bundle. "
            f"Check python/tn/pkg.py:absorb dispatch on manifest kind."
        ),
    )

    # The absorbed kit must land in Frank's keystore as
    # `default.btn.mykit`.
    frank_keystore = tn.current_config().keystore
    absorbed_kit = frank_keystore / "default.btn.mykit"
    assert_named(
        name="frank-absorbed-kit-on-disk",
        expected=True,
        observed=absorbed_kit.exists(),
        on_miss=(
            f"After absorb, expected {absorbed_kit} on disk. Receipt "
            f"reported {receipt.accepted_count} accepted items; "
            f"keystore inventory: "
            f"{sorted(p.name for p in frank_keystore.iterdir()) if frank_keystore.exists() else 'no-dir'}"
        ),
    )

    tn.flush_and_close()

    # ── Decrypt Alice's log under Frank's kit ───────────────────────
    decrypted: list[tuple[str, dict]] = []
    for entry in tn.read(
        log=alice_log,
        as_recipient=frank_keystore,
        group="default",
    ):
        # `hidden_groups` lists groups whose plaintext we couldn't
        # unlock; if "default" is in there, decrypt failed for that
        # entry. We assert by checking the OPPOSITE: only count entries
        # where default is NOT hidden.
        if "default" not in entry.hidden_groups:
            decrypted.append((entry.event_type, dict(entry.fields)))

    decrypted_types = [t for t, _ in decrypted]
    assert_named(
        name="frank-decrypted-three-events",
        expected=3,
        observed=len(decrypted_types),
        on_miss=(
            f"Frank's read decrypted {len(decrypted_types)} events; "
            f"expected 3 (sale.line x2 + sale.total). Got types: "
            f"{decrypted_types!r}. If 0 came back, the kit didn't land "
            f"where the reader looks (check python/tn/read.py keystore "
            f"discovery); if some came back as hidden, the cipher "
            f"dispatch failed for those rows."
        ),
    )

    # Fields round-tripped intact — bread + butter + subtotal recoverable.
    total_event = next(
        (fields for et, fields in decrypted if et == "sale.total"), None,
    )
    assert_named(
        name="frank-fields-round-tripped",
        expected="11.25",
        observed=(total_event or {}).get("subtotal"),
        on_miss=(
            f"sale.total's subtotal didn't round-trip. Got "
            f"{(total_event or {}).get('subtotal')!r}; "
            f"expected '11.25'. Canonical-encoding round-trip in "
            f"tn.canonical or the cipher payload framing."
        ),
    )

    assert_user_home_untouched()
