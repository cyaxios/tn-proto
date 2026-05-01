"""Tests for Session 8: ``contact_update`` tnpkg + vault as publisher.

Plan: ``docs/superpowers/plans/2026-04-29-contact-update-tnpkg.md``.
Spec: §4.6 / §4.10. Decisions: D-11, D-25.

Three tracks:

1. ``KNOWN_KINDS`` recognizes ``contact_update`` and a signed manifest
   round-trips.
2. ``tn.contacts.validate_contact_update_body`` enforces the schema.
3. ``tn.contacts.apply_contact_update`` is idempotent on ``(account_id,
   package_did)`` — match → replace, miss → append.
4. End-to-end: build + sign + zip a contact_update tnpkg, run
   ``tn.pkg.absorb`` against an initialized ceremony, assert
   ``contacts.yaml`` carries the row.

Run::

    .venv/Scripts/python.exe -m pytest \\
        tn-protocol/python/tests/test_contact_update_tnpkg.py -x -v
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml as _yaml

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import tn
from tn.absorb import absorb
from tn.contacts import (
    _apply_contact_update,
    _contacts_yaml_path,
    _load_contacts,
    _validate_contact_update_body,
)
from tn.conventions import tn_dir
from tn.signing import DeviceKey
from tn.tnpkg import (
    KNOWN_KINDS,
    TnpkgManifest,
    _read_manifest,
    _verify_manifest_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _signed_contact_update_zip(
    *,
    signer: DeviceKey,
    to_did: str,
    body: dict,
    ceremony_id: str = "vault-publisher",
) -> bytes:
    """Build a signed ``contact_update`` tnpkg zip and return bytes."""
    manifest = TnpkgManifest(
        kind="contact_update",
        from_did=signer.did,
        to_did=to_did,
        ceremony_id=ceremony_id,
        as_of=datetime.now(UTC).isoformat(),
        scope="default",
        clock={},
        event_count=1,
    )
    manifest.sign(signer.signing_key())

    body_bytes = json.dumps(body, sort_keys=True).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n",
        )
        zf.writestr("body/contact_update.json", body_bytes)
    return buf.getvalue()


def _valid_body(**overrides) -> dict:
    base = {
        "account_id": "01J9X000000000000000000ABC",
        "label": "primary",
        "package_did": "did:key:z6MkPackage1",
        "x25519_pub_b64": None,
        "claimed_at": "2026-04-29T12:00:00+00:00",
        "source_link_id": None,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Track 1: KNOWN_KINDS + manifest round-trip
# ---------------------------------------------------------------------------


def test_contact_update_in_known_kinds():
    assert "contact_update" in KNOWN_KINDS


def test_signed_contact_update_manifest_round_trips(tmp_path: Path):
    signer = DeviceKey.generate()
    pkg_bytes = _signed_contact_update_zip(
        signer=signer,
        to_did="did:key:z6MkRecipient",
        body=_valid_body(),
    )
    pkg_path = tmp_path / "x.tnpkg"
    pkg_path.write_bytes(pkg_bytes)

    manifest, body = _read_manifest(pkg_path)
    assert manifest.kind == "contact_update"
    assert manifest.from_did == signer.did
    assert manifest.to_did == "did:key:z6MkRecipient"
    assert _verify_manifest_signature(manifest) is True
    assert "body/contact_update.json" in body


# ---------------------------------------------------------------------------
# Track 2: body schema validator
# ---------------------------------------------------------------------------


def test_validate_body_happy_path():
    assert _validate_contact_update_body(_valid_body()) == []


def test_validate_body_rejects_missing_required_keys():
    for missing in ("account_id", "label", "claimed_at", "package_did", "x25519_pub_b64", "source_link_id"):
        body = _valid_body()
        body.pop(missing)
        errors = _validate_contact_update_body(body)
        assert errors, f"missing {missing!r} should produce errors"
        assert any(missing in e for e in errors), errors


def test_validate_body_rejects_null_required_strings():
    for key in ("account_id", "label", "claimed_at"):
        body = _valid_body()
        body[key] = None
        errors = _validate_contact_update_body(body)
        assert any("must not be null" in e for e in errors)


def test_validate_body_accepts_null_optional_fields():
    body = _valid_body(package_did=None, x25519_pub_b64=None, source_link_id=None)
    assert _validate_contact_update_body(body) == []


def test_validate_body_rejects_non_dict():
    assert _validate_contact_update_body([1, 2, 3]) != []
    assert _validate_contact_update_body("not a dict") != []


# ---------------------------------------------------------------------------
# Track 3: _apply_contact_update idempotency
# ---------------------------------------------------------------------------


def _ceremony(tmp_path: Path) -> Path:
    """Init a tiny ceremony so _contacts_yaml_path resolves under .tn/<stem>/."""
    yaml_path = tmp_path / "tn.yaml"
    tn.init(yaml_path, cipher="btn")
    tn.flush_and_close()
    return yaml_path


def test_apply_contact_update_appends_new_row(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    body = _valid_body()
    doc = _apply_contact_update(yaml_path, body)
    assert len(doc["contacts"]) == 1
    row = doc["contacts"][0]
    assert row["account_id"] == body["account_id"]
    assert row["package_did"] == body["package_did"]
    assert row["label"] == body["label"]


def test_apply_contact_update_replaces_matching_row(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    _apply_contact_update(yaml_path, _valid_body(label="old"))
    doc = _apply_contact_update(yaml_path, _valid_body(label="new"))
    # Same (account_id, package_did) -> replaced in place, no second row.
    assert len(doc["contacts"]) == 1
    assert doc["contacts"][0]["label"] == "new"


def test_apply_contact_update_appends_when_package_changes(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    _apply_contact_update(yaml_path, _valid_body(package_did="did:key:z6MkPkgA"))
    doc = _apply_contact_update(yaml_path, _valid_body(package_did="did:key:z6MkPkgB"))
    # Different package_did under same account_id -> new row.
    assert len(doc["contacts"]) == 2
    pdids = sorted(r["package_did"] for r in doc["contacts"])
    assert pdids == ["did:key:z6MkPkgA", "did:key:z6MkPkgB"]


def test_apply_contact_update_rejects_invalid_body(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    with pytest.raises(ValueError, match="invalid body"):
        _apply_contact_update(yaml_path, {"account_id": "x"})  # missing fields


def test_load_contacts_returns_empty_for_missing(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    # Don't call apply — file doesn't exist yet.
    doc = _load_contacts(yaml_path)
    assert doc == {"contacts": []}


def test_contacts_yaml_path_under_stem_dir(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    target = _contacts_yaml_path(yaml_path)
    assert target == tn_dir(yaml_path) / "contacts.yaml"


# ---------------------------------------------------------------------------
# Track 4: end-to-end via tn.pkg.absorb
# ---------------------------------------------------------------------------


def test_absorb_writes_contacts_yaml(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    # Re-init so absorb can pull current_config (flush_and_close above
    # released the runtime).
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    signer = DeviceKey.generate()
    body = _valid_body(account_id="01J9XACCT", label="frank")
    pkg_bytes = _signed_contact_update_zip(
        signer=signer,
        to_did=cfg.device.did,
        body=body,
    )
    pkg_path = tmp_path / "contact.tnpkg"
    pkg_path.write_bytes(pkg_bytes)

    receipt = absorb(cfg, pkg_path)
    assert receipt.status == "enrolment_applied", receipt.reason
    tn.flush_and_close()

    target = _contacts_yaml_path(yaml_path)
    assert target.exists()
    written = _yaml.safe_load(target.read_text(encoding="utf-8"))
    assert len(written["contacts"]) == 1
    assert written["contacts"][0]["account_id"] == "01J9XACCT"
    assert written["contacts"][0]["label"] == "frank"


def test_absorb_rejects_invalid_contact_update_body(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    signer = DeviceKey.generate()
    bad_body = {"account_id": "only-this"}
    pkg_bytes = _signed_contact_update_zip(
        signer=signer,
        to_did=cfg.device.did,
        body=bad_body,
    )
    pkg_path = tmp_path / "bad.tnpkg"
    pkg_path.write_bytes(pkg_bytes)

    receipt = absorb(cfg, pkg_path)
    assert receipt.status == "rejected"
    assert "contact_update" in receipt.reason
    tn.flush_and_close()


def test_absorb_rejects_signature_tampering(tmp_path: Path):
    yaml_path = _ceremony(tmp_path)
    tn.init(yaml_path, cipher="btn")
    cfg = tn.current_config()

    signer = DeviceKey.generate()
    pkg_bytes = _signed_contact_update_zip(
        signer=signer,
        to_did=cfg.device.did,
        body=_valid_body(),
    )
    # Tamper with the body so the manifest signature no longer verifies.
    buf = io.BytesIO(pkg_bytes)
    with zipfile.ZipFile(buf, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        tampered_body = b'{"account_id":"hacked","label":"x","package_did":null,"x25519_pub_b64":null,"claimed_at":"2026-04-29T00:00:00+00:00","source_link_id":null}'
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("body/contact_update.json", tampered_body)
    # Manifest is unchanged so it still verifies — Session 8 isn't
    # building Merkle commitments over body bytes; tampering body
    # without re-signing is allowed by the wire format. We verify here
    # only that a TAMPERED MANIFEST gets rejected.
    pkg_path = tmp_path / "tampered.tnpkg"
    # Mutate manifest itself: flip a byte in the signature segment.
    doc = json.loads(manifest_bytes)
    sig = doc["manifest_signature_b64"]
    # base64: changing the first character almost always breaks
    # verification. Skip 'A' since it might cycle to itself for some
    # encodings.
    flipped = ("B" if sig[0] != "B" else "C") + sig[1:]
    doc["manifest_signature_b64"] = flipped
    bad_manifest = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("utf-8")
    out2 = io.BytesIO()
    with zipfile.ZipFile(out2, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", bad_manifest)
        zf.writestr("body/contact_update.json", b"{}")
    pkg_path.write_bytes(out2.getvalue())

    receipt = absorb(cfg, pkg_path)
    assert receipt.status == "rejected"
    assert "signature" in receipt.reason.lower()
    tn.flush_and_close()
