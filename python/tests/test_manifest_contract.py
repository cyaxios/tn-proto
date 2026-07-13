from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
if str(PYDIR) not in sys.path:
    sys.path.insert(0, str(PYDIR))

import tn.tnpkg as tnpkg
from tn.signing import DeviceKey
from tn.tnpkg import KNOWN_KINDS, TnpkgManifest, _verify_manifest_signature
from tn.trust import TrustError, TrustReason

REPO = PYDIR.parent
FIXTURE_DIR = REPO / "tests" / "fixtures" / "manifest"
BODY_INDEX_FIXTURE = REPO / "tests" / "fixtures" / "trust" / "v1" / "package_body_index.json"

EXPECTED_BODY_SHA256 = {
    "body/metadata.json": "sha256:c94350b6169c800eb2fab2666d1caaf7c07b81227da9a49942ce307f187ced99",
    "body/package.json": "sha256:ccae14e62acb7dcab2e5ad0491d3b40d7fb577b5fedec86543b6c2eeb8e95249",
}


def _load_json(name: str) -> object:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _load_hex(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8").strip()


def _body_index_case(case_id: str) -> dict[str, object]:
    fixture = json.loads(BODY_INDEX_FIXTURE.read_text(encoding="utf-8"))
    return next(case for case in fixture["cases"] if case["id"] == case_id)


def _decode_body_index_case(
    case_id: str,
) -> tuple[dict[str, object], dict[str, bytes], bytes]:
    case = _body_index_case(case_id)
    inputs = case["input"]
    assert isinstance(inputs, dict)
    manifest = json.loads(base64.b64decode(inputs["manifest_b64"], validate=True))
    body = {
        path: base64.b64decode(encoded, validate=True)
        for path, encoded in inputs["body_members_b64"].items()
    }
    canonical = base64.b64decode(case["canonical_b64"], validate=True)
    return manifest, body, canonical


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


@pytest.mark.parametrize("malformed_index", [None, [], "not-an-object"])
def test_manifest_rejects_present_non_object_body_index(malformed_index: object):
    doc = _load_json("project_seed_unsigned.json")
    assert isinstance(doc, dict)
    doc["body_sha256"] = malformed_index

    with pytest.raises(ValueError, match="body_sha256 must be a JSON object"):
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


def test_offer_body_index_fixture_exact_digests_signing_bytes_and_signature():
    doc, body, canonical = _decode_body_index_case("valid_offer_body_index")
    manifest = TnpkgManifest.from_dict(doc)

    assert manifest.body_sha256 == EXPECTED_BODY_SHA256
    assert tnpkg.compute_body_sha256(body) == EXPECTED_BODY_SHA256
    assert manifest.signing_bytes() == canonical
    assert manifest.manifest_signature_b64 == doc["manifest_signature_b64"]
    assert _verify_manifest_signature(manifest)
    tnpkg.verify_manifest_body_index(manifest, body, require_index=True)


@pytest.mark.parametrize(
    "case_id",
    [
        "substituted_offer_body",
        "missing_indexed_body",
        "extra_unindexed_body",
        "malformed_body_digest",
        "missing_body_index",
    ],
)
def test_offer_body_index_fixture_rejects_every_index_mismatch(case_id: str):
    doc, body, canonical = _decode_body_index_case(case_id)
    manifest = TnpkgManifest.from_dict(doc)

    assert manifest.signing_bytes() == canonical
    assert _verify_manifest_signature(manifest)
    with pytest.raises(TrustError) as raised:
        tnpkg.verify_manifest_body_index(manifest, body, require_index=True)
    assert raised.value.reason is TrustReason.BODY_DIGEST_MISMATCH


def test_sign_manifest_with_body_indexes_final_bytes_before_signing():
    device = DeviceKey.generate()
    body = {
        "body/a.bin": b"final stored bytes\x00",
        "body/nested/b.json": b'{"ok":true}\n',
    }
    manifest = TnpkgManifest(
        kind="offer",
        publisher_identity=device.did,
        ceremony_id="body-index-builder",
        as_of="2026-07-11T14:00:00Z",
        scope="default",
    )

    signed = tnpkg.sign_manifest_with_body(manifest, body, device.signing_key())

    assert signed is manifest
    assert signed.body_sha256 == tnpkg.compute_body_sha256(body)
    assert _verify_manifest_signature(signed)
