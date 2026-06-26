from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
if str(PYDIR) not in sys.path:
    sys.path.insert(0, str(PYDIR))

from tn.tnpkg import KNOWN_KINDS, TnpkgManifest, _verify_manifest_signature

REPO = PYDIR.parent
FIXTURE_DIR = REPO / "tests" / "fixtures" / "manifest"


def _load_json(name: str) -> object:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _load_hex(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8").strip()


def test_manifest_kind_catalog_matches_shared_fixture():
    assert sorted(KNOWN_KINDS) == sorted(_load_json("kinds.json"))


def test_project_seed_manifest_fixture_canonical_bytes():
    doc = _load_json("project_seed_unsigned.json")
    assert isinstance(doc, dict)
    manifest = TnpkgManifest.from_dict(doc)

    assert manifest.kind == "project_seed"
    assert manifest.recipient_identity == manifest.publisher_identity
    assert manifest.state is not None
    assert manifest.state["project"]["name"] == "payroll"

    got = manifest.signing_bytes().hex()
    assert got == _load_hex("project_seed_unsigned.canonical.hex")


def test_manifest_signing_bytes_strip_signature_field():
    doc = _load_json("project_seed_unsigned.json")
    assert isinstance(doc, dict)
    unsigned = TnpkgManifest.from_dict(doc).signing_bytes()

    doc["manifest_signature_b64"] = "not-a-real-signature"
    signed_shape = TnpkgManifest.from_dict(doc).signing_bytes()

    assert signed_shape == unsigned


def test_manifest_missing_required_field_rejected():
    doc = _load_json("project_seed_unsigned.json")
    assert isinstance(doc, dict)
    doc.pop("publisher_identity")

    with pytest.raises(ValueError, match="missing required"):
        TnpkgManifest.from_dict(doc)


def test_manifest_unknown_kind_rejected():
    doc = _load_json("project_seed_unsigned.json")
    assert isinstance(doc, dict)
    doc["kind"] = "future_experimental_kind"

    with pytest.raises(ValueError, match="unknown kind"):
        TnpkgManifest.from_dict(doc)


def test_signed_project_seed_manifest_fixture_verifies():
    doc = _load_json("project_seed_signed.json")
    assert isinstance(doc, dict)
    manifest = TnpkgManifest.from_dict(doc)

    assert manifest.manifest_signature_b64 is not None
    assert manifest.signing_bytes().hex() == _load_hex("project_seed_signed.canonical.hex")
    assert _verify_manifest_signature(manifest)


def test_signed_project_seed_manifest_rejects_tampering():
    doc = _load_json("project_seed_signed.json")
    assert isinstance(doc, dict)
    doc["event_count"] = 3

    assert not _verify_manifest_signature(TnpkgManifest.from_dict(doc))
