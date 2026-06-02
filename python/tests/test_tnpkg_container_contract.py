from __future__ import annotations

import json
import sys
import warnings
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PYDIR = HERE.parent
if str(PYDIR) not in sys.path:
    sys.path.insert(0, str(PYDIR))

from tn.tnpkg import TnpkgManifest, _read_manifest, _write_tnpkg

REPO = PYDIR.parent
MANIFEST_FIXTURES = REPO / "tests" / "fixtures" / "manifest"


def _signed_project_seed_manifest() -> TnpkgManifest:
    doc = json.loads((MANIFEST_FIXTURES / "project_seed_signed.json").read_text("utf-8"))
    return TnpkgManifest.from_dict(doc)


def _zip_with_members(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_tnpkg_reader_accepts_manifest_and_body_members(tmp_path: Path):
    manifest = _signed_project_seed_manifest()
    pkg = tmp_path / "ok.tnpkg"
    _write_tnpkg(
        pkg,
        manifest,
        {
            "body/tn.yaml": b"ceremony:\n  id: payroll\n",
            "body/keys/local.public": manifest.publisher_identity.encode("utf-8"),
        },
    )

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
        "body\\keys\\local.private",
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


def test_tnpkg_writer_rejects_invalid_body_members(tmp_path: Path):
    manifest = _signed_project_seed_manifest()

    with pytest.raises(ValueError, match="invalid package member"):
        _write_tnpkg(tmp_path / "bad.tnpkg", manifest, {"root.txt": b"bad"})
