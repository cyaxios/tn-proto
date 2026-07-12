from __future__ import annotations

import base64
import json
import os
import sys
import warnings
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
if str(PYDIR) not in sys.path:
    sys.path.insert(0, str(PYDIR))

import tn.tnpkg as tnpkg
from tn.signing import DeviceKey
from tn.tnpkg import ManifestSignatureError, TnpkgManifest, _read_manifest, _write_tnpkg
from tn.trust import TrustError, TrustReason

REPO = PYDIR.parent
MANIFEST_FIXTURES = REPO / "tests" / "fixtures" / "manifest"
BODY_INDEX_FIXTURE = REPO / "tests" / "fixtures" / "trust" / "v1" / "package_body_index.json"


def _signed_project_seed_manifest() -> TnpkgManifest:
    doc = json.loads((MANIFEST_FIXTURES / "project_seed_signed.json").read_text("utf-8"))
    return TnpkgManifest.from_dict(doc)


def _body_signed_project_seed_manifest(body: dict[str, bytes]) -> TnpkgManifest:
    device = DeviceKey.generate()
    manifest = TnpkgManifest(
        kind="project_seed",
        publisher_identity=device.did,
        recipient_identity=device.did,
        ceremony_id="payroll",
        as_of="2026-07-11T14:00:00Z",
        scope="admin",
    )
    return tnpkg.sign_manifest_with_body(manifest, body, device.signing_key())


def _body_index_case(case_id: str) -> dict[str, object]:
    fixture = json.loads(BODY_INDEX_FIXTURE.read_text(encoding="utf-8"))
    return next(case for case in fixture["cases"] if case["id"] == case_id)


def _decode_body_index_case(case_id: str) -> tuple[bytes, dict[str, bytes]]:
    case = _body_index_case(case_id)
    inputs = case["input"]
    assert isinstance(inputs, dict)
    manifest = base64.b64decode(inputs["manifest_b64"], validate=True)
    body = {
        path: base64.b64decode(encoded, validate=True)
        for path, encoded in inputs["body_members_b64"].items()
    }
    return manifest, body


def _zip_with_members(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_tnpkg_reader_accepts_manifest_and_body_members(tmp_path: Path):
    body = {
        "body/tn.yaml": b"ceremony:\n  id: payroll\n",
        "body/keys/local.public": b"did:key:zBodyIndexedPublisher",
    }
    manifest = _body_signed_project_seed_manifest(body)
    pkg = tmp_path / "ok.tnpkg"
    _write_tnpkg(pkg, manifest, body)

    got_manifest, body = _read_manifest(pkg)

    assert got_manifest.kind == "project_seed"
    assert sorted(body) == ["body/keys/local.public", "body/tn.yaml"]


@pytest.mark.parametrize(
    "bad_name",
    [
        "README.txt",
        "keys/local.private",
        "body/",
        "body/../manifest.json",
        pytest.param(
            "body\\keys\\local.private",
            marks=pytest.mark.skipif(
                os.sep != "/",
                reason="zipfile rewrites os.sep to '/' on Windows, so a literal "
                "backslash member name cannot be authored here; the reader's "
                "backslash guard is still exercised on POSIX runners.",
            ),
        ),
    ],
)
def test_tnpkg_reader_rejects_invalid_non_manifest_members(tmp_path: Path, bad_name: str):
    manifest_doc = json.loads((MANIFEST_FIXTURES / "project_seed_signed.json").read_text("utf-8"))
    pkg = _zip_with_members(
        tmp_path / "bad.tnpkg",
        {
            "manifest.json": (json.dumps(manifest_doc, sort_keys=True, indent=2) + "\n").encode(
                "utf-8"
            ),
            bad_name: b"bad",
        },
    )

    with pytest.raises(ValueError, match="invalid package member"):
        _read_manifest(pkg)


def test_tnpkg_reader_rejects_duplicate_manifest_entries(tmp_path: Path):
    manifest_doc = json.loads((MANIFEST_FIXTURES / "project_seed_signed.json").read_text("utf-8"))
    manifest_bytes = (json.dumps(manifest_doc, sort_keys=True, indent=2) + "\n").encode("utf-8")
    pkg = tmp_path / "dupe.tnpkg"
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate name: 'manifest.json'")
        with zipfile.ZipFile(pkg, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("manifest.json", manifest_bytes)
            zf.writestr("manifest.json", manifest_bytes)
            zf.writestr("body/tn.yaml", b"ceremony:\n  id: payroll\n")

    with pytest.raises(ValueError, match="exactly one"):
        _read_manifest(pkg)


def test_verified_reader_rejects_duplicate_body_entries(tmp_path: Path):
    body = {"body/payload.bin": b"same bytes"}
    manifest = _body_signed_project_seed_manifest(body)
    manifest_bytes = (json.dumps(manifest.to_dict(), sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    pkg = tmp_path / "duplicate-body.tnpkg"
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate name: 'body/payload.bin'")
        with zipfile.ZipFile(pkg, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("manifest.json", manifest_bytes)
            zf.writestr("body/payload.bin", body["body/payload.bin"])
            zf.writestr("body/payload.bin", body["body/payload.bin"])

    with pytest.raises(ValueError, match="duplicate package member"):
        _read_manifest(pkg, verify_signature=True)


def test_tnpkg_writer_rejects_invalid_body_members(tmp_path: Path):
    manifest = _signed_project_seed_manifest()

    with pytest.raises(ValueError, match="invalid package member"):
        _write_tnpkg(tmp_path / "bad.tnpkg", manifest, {"root.txt": b"bad"})


def test_verified_reader_accepts_shared_body_index_fixture(tmp_path: Path):
    manifest_bytes, body = _decode_body_index_case("valid_offer_body_index")
    pkg = _zip_with_members(
        tmp_path / "fixture.tnpkg",
        {"manifest.json": manifest_bytes, **body},
    )

    manifest, got_body = _read_manifest(pkg, verify_signature=True)

    assert manifest.kind == "offer"
    assert got_body == body


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
def test_verified_reader_rejects_shared_body_index_mismatches(
    tmp_path: Path,
    case_id: str,
):
    manifest_bytes, body = _decode_body_index_case(case_id)
    pkg = _zip_with_members(
        tmp_path / f"{case_id}.tnpkg",
        {"manifest.json": manifest_bytes, **body},
    )

    with pytest.raises(TrustError) as raised:
        _read_manifest(pkg, verify_signature=True)
    assert raised.value.reason is TrustReason.BODY_DIGEST_MISMATCH


def test_verified_reader_checks_manifest_signature_before_loading_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    manifest_bytes, body = _decode_body_index_case("manifest_signature_mutated")
    pkg = _zip_with_members(
        tmp_path / "bad-signature.tnpkg",
        {"manifest.json": manifest_bytes, **body},
    )
    reads: list[str] = []
    original_read = zipfile.ZipFile.read

    def tracking_read(
        archive: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        *args: object,
        **kwargs: object,
    ) -> bytes:
        reads.append(name.filename if isinstance(name, zipfile.ZipInfo) else name)
        return original_read(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", tracking_read)

    with pytest.raises(ManifestSignatureError):
        _read_manifest(pkg, verify_signature=True)
    assert reads == ["manifest.json"]


@pytest.mark.parametrize("malformed_index", [None, []])
def test_verified_reader_rejects_non_object_body_index_before_loading_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed_index: object,
):
    manifest_doc = json.loads((MANIFEST_FIXTURES / "project_seed_signed.json").read_text("utf-8"))
    manifest_doc["body_sha256"] = malformed_index
    pkg = _zip_with_members(
        tmp_path / "malformed-index.tnpkg",
        {
            "manifest.json": json.dumps(manifest_doc).encode("utf-8"),
            "body/never-read.bin": b"untrusted body",
        },
    )
    reads: list[str] = []
    original_read = zipfile.ZipFile.read

    def tracking_read(
        archive: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        *args: object,
        **kwargs: object,
    ) -> bytes:
        reads.append(name.filename if isinstance(name, zipfile.ZipInfo) else name)
        return original_read(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", tracking_read)

    with pytest.raises(ValueError, match="body_sha256 must be a JSON object"):
        _read_manifest(pkg, verify_signature=True)
    assert reads == ["manifest.json"]


def test_verified_reader_checks_body_index_before_body_reaches_kind_parser(tmp_path: Path):
    manifest_bytes, body = _decode_body_index_case("substituted_offer_body")
    pkg = _zip_with_members(
        tmp_path / "substituted.tnpkg",
        {"manifest.json": manifest_bytes, **body},
    )
    parsed_or_applied: list[str] = []

    def parse_offer_after_verification() -> None:
        _manifest, verified_body = _read_manifest(pkg, verify_signature=True)
        parsed_or_applied.append(json.loads(verified_body["body/package.json"])["package_kind"])

    with pytest.raises(TrustError) as raised:
        parse_offer_after_verification()
    assert raised.value.reason is TrustReason.BODY_DIGEST_MISMATCH
    assert parsed_or_applied == []


def test_tnpkg_writer_rejects_signed_manifest_for_different_body(tmp_path: Path):
    body = {"body/payload.bin": b"final bytes"}
    manifest = _body_signed_project_seed_manifest(body)

    with pytest.raises(TrustError) as raised:
        _write_tnpkg(
            tmp_path / "substituted-at-write.tnpkg",
            manifest,
            {"body/payload.bin": b"different bytes"},
        )
    assert raised.value.reason is TrustReason.BODY_DIGEST_MISMATCH
