"""Real same-language `tn invite` -> `tn inbox accept` round-trip.

This round-trip was previously BLOCKED: there was no CLI/SDK verb in
``tn_proto`` that minted a ``tn-invite-*.zip`` (the outer
``manifest.json`` + kit wrapper), so every ``inbox accept`` test was
forced to hand-build the wrapper.

The new ``tn invite`` verb (``tn/cli_invite.py``) closes that gap. Here we:

1. Stand up a real publisher btn ceremony P and a separate recipient
   ceremony R (each with its own keystore).
2. P emits a few business entries to its log.
3. P runs the REAL ``tn invite`` verb to mint a genuine
   ``tn-invite-<id>.zip`` — the inner kit is minted by
   ``tn.admin.add_recipient(..., raw=True)`` and wrapped by
   ``cli_invite.make_invitation_zip`` (mirrors the server). Nothing is
   hand-built.
4. R runs ``tn.inbox.accept`` on that zip.
5. We assert the §4 PASS set from the test plan: kit installs as
   ``<group>.btn.mykit``, the installed bytes equal the minted bytes,
   ``kit_sha256`` verifies, and — the property only a real round-trip can
   prove — R can subsequently ``tn.read`` / decrypt P's entries with the
   installed kit.

Plus the §5 FAIL negative that the wrapper must be real to exercise: a
tampered ``kit_sha256`` is rejected by ``accept``.

Read-back note: the invite kit is an UNSEALED btn group kit (the same
``raw=True`` kit the server ``/invite`` path ships). An unsealed btn kit
carries the shared group reader key, so any holder of the kit can decrypt
the group — the recipient DID is attestation metadata, not a
cryptographic binding. The genuine read-back below therefore works and is
the real proof. (A SEALED kit would additionally bind to the recipient's
key; that is a separate `tn bundle --seal-for-recipient` path and out of
scope for the invite wrapper, which mirrors the server's unsealed kit.)

Run:
    cd python && COVERAGE_CORE=sysmon PYTHONPATH=. \
      /c/codex/tn/tn_proto_web/.venv/Scripts/python.exe \
      -m pytest -q tests/test_inbox_accept_roundtrip.py
"""

from __future__ import annotations


# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
import yaml as _yaml

import tn
from tn import inbox
from tn.cli import main as cli_main


# A well-formed (but synthetic) recipient device DID. For an UNSEALED btn
# kit the DID is attestation-only metadata, so a fake-but-valid did:key
# works for the cryptographic read-back (mirrors the cash-register Stage 6
# integration test, which uses the same shape).
RECIPIENT_DID = "did:key:z6MkfakefakefakefakefakefakefakefakefakefakeReadr"


def _absorbed_events_from_admin_log(yaml_path: Path) -> list[dict]:
    """Read `tn.enrolment.absorbed` envelopes from a ceremony's admin log.

    Admin events route to the stem-namespaced dedicated admin log
    (``ceremony.admin_log_location``, which every mint writes explicitly;
    ``./.tn/<stem>/admin/default.ndjson`` for an explicit-yaml mint), NOT
    the main ndjson log. Mirrors ``test_enrolment_events`` but resolves
    the location from the recipient yaml so it works for any stem.
    """
    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    loc = (doc.get("ceremony") or {}).get("admin_log_location")
    if not loc or loc == "main_log":
        loc = f"./.tn/{yaml_path.stem}/admin/default.ndjson"
    admin_log = Path(loc)
    if not admin_log.is_absolute():
        admin_log = (yaml_path.parent / admin_log).resolve()
    if not admin_log.exists():
        return []
    out = []
    with admin_log.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            env = json.loads(line)
            if env.get("event_type") == "tn.enrolment.absorbed":
                out.append(env)
    return out


@pytest.fixture(autouse=True)
def _clean_tn():  # noqa: PT004
    """Flush the module-level runtime around each test so a stray failure
    doesn't poison sibling tests sharing the process (see test_init_autoabsorb)."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass


def _new_btn_ceremony(dir_path: Path, stem: str) -> Path:
    """Create a fresh btn ceremony at ``dir_path/<stem>.yaml`` and return it."""
    dir_path.mkdir(parents=True, exist_ok=True)
    yaml_path = dir_path / f"{stem}.yaml"
    tn.flush_and_close()
    tn.init(yaml_path, cipher=_workflow_cipher("btn"))
    tn.flush_and_close()
    return yaml_path


def _mint_invite_zip(
    publisher_yaml: Path,
    recipient_did: str,
    out_zip: Path,
    group: str = "default",
) -> int:
    """Drive the REAL `tn invite` CLI verb. Returns its exit code."""
    return cli_main(
        [
            "invite",
            recipient_did,
            str(out_zip),
            "--group",
            group,
            "--yaml",
            str(publisher_yaml),
        ]
    )


def test_invite_mint_then_accept_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    pub_dir = tmp_path / "publisher"
    rec_dir = tmp_path / "recipient"

    # ---- Publisher P: ceremony + a few business entries ----
    monkeypatch.chdir(pub_dir if pub_dir.exists() else tmp_path)
    pub_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(pub_dir)
    pub_yaml = _new_btn_ceremony(pub_dir, "publisher")

    tn.init(pub_yaml, cipher=_workflow_cipher("btn"))
    tn.info("sale.line", item="apple", quantity=2, unit_price="1.50")
    tn.info("sale.line", item="bread", quantity=1, unit_price="3.25")
    tn.info("sale.total", subtotal="6.25")
    pub_log_path = tn.current_config().resolve_log_path()
    assert pub_log_path.exists(), "publisher log not written"
    tn.flush_and_close()

    # ---- Mint a REAL invite zip with the new verb ----
    out_zip = tmp_path / "tn-invite-roundtrip.zip"
    rc = _mint_invite_zip(pub_yaml, RECIPIENT_DID, out_zip, group="default")
    assert rc == 0, "tn invite should exit 0"
    assert out_zip.exists() and out_zip.stat().st_size > 0

    # Wrapper shape: real machinery produced {<group>.btn.mykit, manifest.json}.
    with zipfile.ZipFile(out_zip, "r") as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        minted_kit_bytes = zf.read("default.btn.mykit")
    assert names == {"default.btn.mykit", "manifest.json"}, (
        f"invite zip must mirror the server wrapper, got {names}"
    )
    assert manifest["group_name"] == "default"
    assert manifest["leaf_index"] is not None
    assert manifest["from_account_did"].startswith("did:key:")
    assert manifest["provenance"] == "cli-minted"
    # The manifest hash genuinely covers the minted kit bytes.
    assert manifest["kit_sha256"] == "sha256:" + hashlib.sha256(minted_kit_bytes).hexdigest()
    tn.flush_and_close()

    # ---- Recipient R: ceremony, then accept the real zip ----
    rec_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(rec_dir)
    rec_yaml = _new_btn_ceremony(rec_dir, "recipient")

    result = inbox.accept(out_zip, yaml_path=rec_yaml)

    # §4 PASS #2/#3: installed as <group>.btn.mykit, bytes equal minted bytes.
    rec_doc = _yaml.safe_load(rec_yaml.read_text(encoding="utf-8")) or {}
    keystore_rel = (rec_doc.get("keystore") or {}).get("path") or "./.tn/keys"
    keystore_dir = (rec_yaml.parent / keystore_rel).resolve()
    installed_kit = keystore_dir / "default.btn.mykit"
    assert Path(result["kit_path"]) == installed_kit
    assert installed_kit.exists()
    assert installed_kit.read_bytes() == minted_kit_bytes, (
        "installed kit bytes must equal the bytes tn invite minted"
    )
    # §4 PASS #4: kit_sha256 verified during accept (it raises otherwise).
    assert result["group_name"] == "default"
    assert result["leaf_index"] == manifest["leaf_index"]
    tn.flush_and_close()

    # ---- §4 PASS #7: R reads / decrypts P's entries with the installed kit ----
    # This is the property a hand-built fixture CANNOT prove: the kit is
    # genuinely minted for the group and actually decrypts the publisher log.
    tn.init(rec_yaml, cipher=_workflow_cipher("btn"))
    # Guard: the read below must use the INVITE kit (P's group reader),
    # not R's own self-kit. R is a distinct ceremony, so its self-kit
    # cannot decrypt P's log — but assert the installed bytes survived the
    # re-init so the proof is unambiguous.
    assert installed_kit.read_bytes() == minted_kit_bytes, (
        "invite kit must still be installed at read time (not clobbered by re-init)"
    )
    decrypted = []
    # ``as_recipient`` takes the keystore DIRECTORY holding the installed
    # ``<group>.btn.mykit`` (read_as_recipient appends the kit filename),
    # not the kit file path itself.
    for entry in tn.read(
        log=pub_log_path, as_recipient=keystore_dir, group="default"
    ):
        if "default" not in entry.hidden_groups:
            decrypted.append((entry.event_type, dict(entry.fields)))
    tn.flush_and_close()

    event_types = [t for t, _ in decrypted]
    assert event_types.count("sale.line") == 2, (
        f"recipient should decrypt both sale.line rows, got {event_types}"
    )
    assert "sale.total" in event_types, f"missing sale.total: {event_types}"
    sale_items = sorted(
        pl.get("item") for t, pl in decrypted if t == "sale.line"
    )
    assert sale_items == ["apple", "bread"], (
        f"decrypted field values must round-trip intact, got {sale_items}"
    )


def test_invite_accept_tampered_kit_sha256_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§5 FAIL: a real invite zip whose manifest kit_sha256 is tampered is
    rejected by accept. The zip is still produced by real machinery; only
    the recorded hash is corrupted, proving accept's integrity gate fires
    against a genuine wrapper (not a hand-built one)."""
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    pub_dir = tmp_path / "publisher"
    rec_dir = tmp_path / "recipient"
    pub_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(pub_dir)
    pub_yaml = _new_btn_ceremony(pub_dir, "publisher")

    out_zip = tmp_path / "tn-invite-tamper.zip"
    rc = _mint_invite_zip(pub_yaml, RECIPIENT_DID, out_zip, group="default")
    assert rc == 0
    tn.flush_and_close()

    # Rewrite the manifest with a bad kit_sha256, keeping the real kit bytes.
    with zipfile.ZipFile(out_zip, "r") as zf:
        kit_bytes = zf.read("default.btn.mykit")
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    manifest["kit_sha256"] = "sha256:" + "a" * 64
    tampered = tmp_path / "tn-invite-tamper-bad.zip"
    with zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("default.btn.mykit", kit_bytes)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    rec_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(rec_dir)
    rec_yaml = _new_btn_ceremony(rec_dir, "recipient")

    with pytest.raises(inbox.InboxError, match="hash mismatch"):
        inbox.accept(tampered, yaml_path=rec_yaml)


def test_accept_records_absorbed_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a real accept(), the `tn.enrolment.absorbed` attestation must
    genuinely land in the recipient's admin log — not be swallowed.

    This is the property the mocked unit tests (test_inbox_accept.py) cannot
    prove: they stub tn.init/tn.info, so a malformed emit (e.g. the wrong
    catalog field name) passes silently. Here accept() drives the REAL
    runtime, so the admin-catalog schema validation actually runs and the
    event is signed + written. We assert all four catalog fields are present
    and that `publisher_identity` is the publisher's device DID.
    """
    monkeypatch.setenv("TN_NO_STDOUT", "1")
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "1")

    pub_dir = tmp_path / "publisher"
    rec_dir = tmp_path / "recipient"
    pub_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(pub_dir)
    pub_yaml = _new_btn_ceremony(pub_dir, "publisher")

    out_zip = tmp_path / "tn-invite-absorbed.zip"
    rc = _mint_invite_zip(pub_yaml, RECIPIENT_DID, out_zip, group="default")
    assert rc == 0
    with zipfile.ZipFile(out_zip, "r") as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    publisher_did = manifest["from_account_did"]
    expected_sha = manifest["kit_sha256"]
    assert publisher_did.startswith("did:key:")
    tn.flush_and_close()

    rec_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(rec_dir)
    rec_yaml = _new_btn_ceremony(rec_dir, "recipient")

    result = inbox.accept(out_zip, yaml_path=rec_yaml)
    tn.flush_and_close()

    events = _absorbed_events_from_admin_log(rec_yaml)
    assert events, (
        "tn.enrolment.absorbed must appear in the recipient's admin log "
        "after accept() — the attestation was swallowed, not recorded"
    )
    e = events[0]
    assert e["group"] == "default", f"group mismatch: {e.get('group')!r}"
    assert e["publisher_identity"] == publisher_did, (
        f"publisher_identity must be the publisher device DID "
        f"{publisher_did!r}, got {e.get('publisher_identity')!r}"
    )
    assert e["package_sha256"] == expected_sha, (
        f"package_sha256 must equal the manifest kit_sha256 {expected_sha!r}, "
        f"got {e.get('package_sha256')!r}"
    )
    assert e["absorbed_at"] == result["absorbed_at"], (
        "absorbed_at in the event must match the value accept() returned"
    )
