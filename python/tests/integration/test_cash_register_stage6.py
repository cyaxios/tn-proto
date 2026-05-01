"""End-to-end Stage 6 of the cash-register assignment.

This is the test the FINDINGS.md round identified as broken: a publisher
mints a kit for a foreign reader (the "professor"), bundles it as a
``.tnpkg``, hands it over, and the reader uses it to decrypt the
publisher's log.

The test exercises the same call sequence the student attempted in
``C:\\codex\\tnstage\\cash_register\\``, with the fixes for FINDINGS #4
(``all_runs=True`` in admin reducer) and #7 (btn-aware
``read_as_recipient``) applied.

Marked ``integration`` because it spawns two ceremonies and writes to
disk; pytest's ``-m "not integration"`` filter excludes it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import tn

pytestmark = pytest.mark.integration


PROFESSOR_DID = "did:key:z6MkfakefakefakefakefakefakefakefakefakefakeProfDID"


def _new_ceremony(tmp_path: Path, name: str) -> Path:
    """Create a fresh tn.yaml at ``tmp_path/<name>.yaml`` (btn cipher)."""
    yaml_path = tmp_path / f"{name}.yaml"
    tn.flush_and_close()
    # Each call mints its own ceremony — separate yaml, separate keystore.
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    return yaml_path


def test_stage6_cross_publisher_btn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Quiet the auto-init banner and stdout sink so output stays clean.
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    # Each ceremony lives in its own subdir so .tn/tn/keys/ stays isolated.
    student_dir = tmp_path / "student"
    professor_dir = tmp_path / "professor"
    student_dir.mkdir()
    professor_dir.mkdir()

    # ---------------- Publisher (student) ----------------
    monkeypatch.chdir(student_dir)
    student_yaml = _new_ceremony(student_dir, "register")

    # Open the publisher's ceremony and emit a small log.
    tn.init(student_yaml, cipher="btn")
    tn.info("sale.line", item="apple", quantity=2, unit_price="1.50")
    tn.info("sale.line", item="bread", quantity=1, unit_price="3.25")
    tn.info("sale.total", subtotal="6.25")
    student_log_path = tn.current_config().resolve_log_path()
    assert student_log_path.exists(), "publisher log not written"

    # Mint a kit with the canonical filename, then bundle it for the prof.
    # NOTE: use the canonical `<group>.btn.mykit` name — using anything else
    # (the FINDINGS #5 trap) makes export silently bundle the wrong file.
    bundle_dir = tmp_path / "bundle_workspace"
    bundle_dir.mkdir()
    kit_path = bundle_dir / "default.btn.mykit"
    tn.admin.add_recipient("default", recipient_did=PROFESSOR_DID, out_path=kit_path)
    assert kit_path.exists(), "kit was not minted"

    # recipients() must show the new recipient even though we just init'd
    # this process — FINDINGS #4 (admin reducer must read all_runs).
    cfg = tn.current_config()
    recs = tn.admin.recipients("default")
    assert any(r["recipient_did"] == PROFESSOR_DID for r in recs), \
        f"expected professor DID in recipients, got {recs!r}"

    # Bundle the kit (not the publisher's own keystore — that would ship the
    # publisher's self-kit and let the prof impersonate them).
    tnpkg_path = tmp_path / "professor.tnpkg"
    tn.pkg.export(
        tnpkg_path,
        kind="kit_bundle",
        cfg=cfg,
        keystore=bundle_dir,
        to_did=PROFESSOR_DID,
        groups=["default"],
    )
    assert tnpkg_path.exists() and tnpkg_path.stat().st_size > 0

    tn.flush_and_close()

    # ---------------- Recipient (professor) ----------------
    monkeypatch.chdir(professor_dir)
    professor_yaml = _new_ceremony(professor_dir, "prof")

    tn.init(professor_yaml, cipher="btn")
    receipt = tn.pkg.absorb(tnpkg_path)
    assert receipt.kind == "kit_bundle", f"unexpected absorb kind: {receipt.kind}"
    assert receipt.accepted_count >= 1, f"absorb did not apply kit: {receipt}"

    # The professor's keystore now holds the absorbed kit.
    prof_keystore = tn.current_config().keystore
    absorbed_kit = prof_keystore / "default.btn.mykit"
    assert absorbed_kit.exists(), "absorbed kit not present after absorb"

    tn.flush_and_close()

    # ---------------- Decrypt the publisher's log ----------------
    # Use read_as_recipient with the professor's keystore. After the FINDINGS
    # #7 fix this dispatches on the kit type (.btn.mykit → BtnGroupCipher).
    decrypted = []
    for entry in tn.read_as_recipient(student_log_path, prof_keystore, group="default"):
        env = entry["envelope"]
        plaintext = entry["plaintext"]
        if "default" in plaintext and not plaintext["default"].get("$no_read_key"):
            decrypted.append((env["event_type"], plaintext["default"]))

    # We logged 3 events; the prof should be able to decrypt all 3.
    event_types = [t for t, _ in decrypted]
    assert "sale.line" in event_types, f"missing sale.line in decrypted: {event_types}"
    assert "sale.total" in event_types, f"missing sale.total in decrypted: {event_types}"
    assert sum(1 for t in event_types if t == "sale.line") == 2

    # And the field values round-tripped intact.
    sale_lines = [pl for t, pl in decrypted if t == "sale.line"]
    items = sorted(pl.get("item") for pl in sale_lines)
    assert items == ["apple", "bread"], f"items round-trip failed: {items}"


def test_stage6_recipients_persists_across_processes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FINDINGS #4 regression: a recipient added in one process must still
    appear in ``tn.admin.recipients()`` from a fresh ``tn.init()`` later."""
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    yaml_path = _new_ceremony(work_dir, "register")

    # First "process": add a recipient.
    tn.init(yaml_path, cipher="btn")
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    kit_path = bundle_dir / "default.btn.mykit"
    tn.admin.add_recipient("default", recipient_did=PROFESSOR_DID, out_path=kit_path)
    in_run_recs = tn.admin.recipients("default")
    tn.flush_and_close()

    # Simulate a fresh process: clear the run_id so the next init mints a
    # new one (mirroring an actual process restart).
    monkeypatch.setattr(tn, "_run_id", None)
    if "TN_RUN_ID" in os.environ:
        monkeypatch.delenv("TN_RUN_ID")

    # Second "process": re-init and ask for recipients again. Without the
    # all_runs=True fix in _read_raw_admin_aware this returns [].
    tn.init(yaml_path, cipher="btn")
    cross_run_recs = tn.admin.recipients("default")
    tn.flush_and_close()

    assert in_run_recs and cross_run_recs, (
        f"recipients lost across run boundary: in-run={in_run_recs!r} "
        f"cross-run={cross_run_recs!r}"
    )
    in_run_dids = sorted(r["recipient_did"] for r in in_run_recs)
    cross_run_dids = sorted(r["recipient_did"] for r in cross_run_recs)
    assert in_run_dids == cross_run_dids, \
        f"recipient DIDs differ across runs: {in_run_dids!r} vs {cross_run_dids!r}"
