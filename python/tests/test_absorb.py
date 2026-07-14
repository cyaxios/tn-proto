# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)


import json
from pathlib import Path

import pytest

from tn._bounded_json import MAX_JSON_NESTING
from tn.absorb import (
    _absorb_admin_log_snapshot,
    _absorb_contact_update,
    _absorb_kit_bundle,
    absorb,
)
from tn.config import load_or_create
from tn.conventions import outbox_dir, pending_offers_dir
from tn.offer import offer
from tn.signing import DeviceKey
from tn.tnpkg import TnpkgManifest, _write_tnpkg, sign_manifest_with_body


def test_absorb_offer_lands_in_pending_offers(tmp_path: Path):
    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    offer(bob_cfg, publisher_did="did:key:z6MkAlice")
    pkg_path = next(outbox_dir(bob_dir).glob("*.tnpkg"))

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result = absorb(alice_cfg, pkg_path)
    assert result.status == "offer_stashed"
    safe = bob_cfg.device.device_identity.replace(":", "_")
    assert (pending_offers_dir(alice_dir) / f"{safe}.json").exists()


def test_absorb_rejects_legacy_json_over_the_nesting_limit(tmp_path: Path):
    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    wire = (
        b'{"package_kind":"offer","nested":'
        + b"[" * (MAX_JSON_NESTING + 1)
        + b"0"
        + b"]" * (MAX_JSON_NESTING + 1)
        + b"}"
    )

    result = absorb(cfg, wire)

    assert result.status == "rejected"
    assert "JSON nesting" in result.reason


def test_absorb_rejects_bad_signature(tmp_path: Path):
    """A tampered offer must not get stashed.

    The signed body index rejects the mutated package bytes before the inner
    Package parser or signature verifier runs.
    """
    import zipfile

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    offer(bob_cfg, publisher_did="did:key:z6MkAlice")
    pkg_path = next(outbox_dir(bob_dir).glob("*.tnpkg"))

    # Mutate body/package.json inside the zip to break the inner sig.
    with zipfile.ZipFile(pkg_path, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        body_bytes = zf.read("body/package.json")
    doc = json.loads(body_bytes.decode("utf-8"))
    doc["payload"]["x25519_pub_b64"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    new_body = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with zipfile.ZipFile(pkg_path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("body/package.json", new_body)

    alice_cfg = load_or_create(
        (tmp_path / "alice_t.yaml").parent / "alice_t.yaml", cipher=_workflow_cipher("jwe")
    )
    result = absorb(alice_cfg, pkg_path)
    assert result.status == "rejected"
    assert "body_digest_mismatch" in result.reason.lower()


def test_absorb_rejects_unsupported_kind(tmp_path: Path):
    """An unknown package_kind must be rejected (not stashed, not crashed)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from tn.packaging import Package, dump_tnpkg, sign

    bogus = Package(
        package_version=1,
        package_kind="future_thing",
        ceremony_id="c",
        group="g",
        group_epoch=0,
        device_identity="did:key:x",
        signer_verify_pub_b64="",
        recipient_identity="did:key:y",
        payload={},
        compiled_at="2026-04-21T00:00:00Z",
    )
    sk = Ed25519PrivateKey.generate()
    pkg = sign(bogus, sk)
    path = tmp_path / "pkg.tnpkg"
    dump_tnpkg(pkg, path)

    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result = absorb(cfg, path)
    assert result.status == "rejected"
    assert "future_thing" in result.reason


import tn
from tn import admin
from tn.compile import compile_enrolment, emit_to_outbox
from tn.offer import _ensure_mykey


def test_absorb_enrolment_makes_recipient_read(tmp_path: Path):
    """End to end: Bob generates mykey, Alice adds him with his pub + compiles,
    Bob absorbs enrolment, Alice writes an entry, Bob reads + decrypts it."""
    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    bob_pub = _ensure_mykey(bob_cfg, "default")

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_cfg.device.device_identity, bob_pub)
    pkg = compile_enrolment(alice_cfg, "default", bob_cfg.device.device_identity)
    pkg_path = emit_to_outbox(alice_cfg, pkg)

    result = absorb(bob_cfg, pkg_path)
    assert result.status == "enrolment_applied", f"reason: {result.reason}"
    trust_doc = json.loads(
        (bob_cfg.keystore / "trust" / "verified_publishers.v1.json").read_text(encoding="utf-8")
    )
    assert trust_doc["publishers"][alice_cfg.device.device_identity]["source"] == (
        "verified-signed-enrolment"
    )

    # Alice writes, Bob reads with tn.read().
    tn.init(str(alice_cfg.yaml_path))
    tn.info("hello", body="from_alice")
    tn.flush_and_close()
    tn.init(str(bob_cfg.yaml_path))
    from tn._read_impl import _read_raw_inner

    entries = list(_read_raw_inner(alice_dir / ".tn/tn/logs" / "tn.ndjson", bob_cfg))
    decrypted = [
        e
        for e in entries
        if "default" in e.get("plaintext", {})
        and "$decrypt_error" not in e["plaintext"]["default"]
        and "$no_read_key" not in e["plaintext"]["default"]
    ]
    assert decrypted, f"Bob should decrypt default entries; got: {entries}"
    tn.flush_and_close()


# btn coupon/invite coverage lives in test_recipient_tracking.py +
# test_admin_state.py which exercise tn.admin_add_recipient and compile_kit_bundle.


def test_absorb_accepts_bytes_input(tmp_path: Path):
    """Bytes inputs are allowed: absorb spills to a temp .tnpkg, processes,
    then unlinks. End-to-end through the offer kind path."""
    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    offer(bob_cfg, publisher_did="did:key:z6MkAlice")
    pkg_path = next(outbox_dir(bob_dir).glob("*.tnpkg"))
    pkg_bytes = pkg_path.read_bytes()

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result = absorb(alice_cfg, pkg_bytes)
    assert result.status == "offer_stashed", f"reason: {result.reason}"
    safe = bob_cfg.device.device_identity.replace(":", "_")
    assert (pending_offers_dir(alice_dir) / f"{safe}.json").exists()


# ---------------------------------------------------------------------------
# P0-5: resource-bounded package reads. A malicious / malformed `.tnpkg`
# (zip bomb, oversized entry, entry flood, bloated manifest) must be rejected
# from zip METADATA before any body member is read into memory, and the
# manifest signature must be verified before any body read on the absorb path.
# ---------------------------------------------------------------------------


def _make_valid_offer_tnpkg(tmp_path: Path) -> Path:
    """Produce a real, signed offer `.tnpkg` that absorbs cleanly."""
    bob_dir = tmp_path / "bob_src"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    offer(bob_cfg, publisher_did="did:key:z6MkAlice")
    return next(outbox_dir(bob_dir).glob("*.tnpkg"))


def _patch_zip_member_metadata(
    path: Path,
    member: str,
    *,
    file_size: int | None = None,
    flag_bits: int = 0,
) -> None:
    """Patch local+central metadata without touching member payload bytes."""
    import zipfile

    with zipfile.ZipFile(path, "r") as archive:
        local_offset = archive.getinfo(member).header_offset
    raw = bytearray(path.read_bytes())
    if flag_bits:
        local_flags = int.from_bytes(raw[local_offset + 6 : local_offset + 8], "little")
        raw[local_offset + 6 : local_offset + 8] = (local_flags | flag_bits).to_bytes(2, "little")
    if file_size is not None:
        raw[local_offset + 22 : local_offset + 26] = file_size.to_bytes(4, "little")

    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    cursor = int.from_bytes(raw[eocd + 16 : eocd + 20], "little")
    while raw[cursor : cursor + 4] == b"PK\x01\x02":
        name_length = int.from_bytes(raw[cursor + 28 : cursor + 30], "little")
        extra_length = int.from_bytes(raw[cursor + 30 : cursor + 32], "little")
        comment_length = int.from_bytes(raw[cursor + 32 : cursor + 34], "little")
        name = bytes(raw[cursor + 46 : cursor + 46 + name_length]).decode("utf-8")
        if name == member:
            if flag_bits:
                flags = int.from_bytes(raw[cursor + 8 : cursor + 10], "little")
                raw[cursor + 8 : cursor + 10] = (flags | flag_bits).to_bytes(2, "little")
            if file_size is not None:
                raw[cursor + 24 : cursor + 28] = file_size.to_bytes(4, "little")
            path.write_bytes(raw)
            return
        cursor += 46 + name_length + extra_length + comment_length
    raise AssertionError(f"central record for {member!r} was not found")


def _patch_eocd(
    path: Path,
    *,
    entries: int | None = None,
    central_size: int | None = None,
    central_offset: int | None = None,
) -> None:
    raw = bytearray(path.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    if entries is not None:
        raw[eocd + 8 : eocd + 10] = entries.to_bytes(2, "little")
        raw[eocd + 10 : eocd + 12] = entries.to_bytes(2, "little")
    if central_size is not None:
        raw[eocd + 12 : eocd + 16] = central_size.to_bytes(4, "little")
    if central_offset is not None:
        raw[eocd + 16 : eocd + 20] = central_offset.to_bytes(4, "little")
    path.write_bytes(raw)


def _raw_eocd(
    *,
    disk_number: int = 0,
    central_disk: int = 0,
    entries_on_disk: int = 0,
    total_entries: int = 0,
    central_size: int = 0,
    central_offset: int = 0,
) -> bytes:
    return b"".join(
        (
            b"PK\x05\x06",
            disk_number.to_bytes(2, "little"),
            central_disk.to_bytes(2, "little"),
            entries_on_disk.to_bytes(2, "little"),
            total_entries.to_bytes(2, "little"),
            central_size.to_bytes(4, "little"),
            central_offset.to_bytes(4, "little"),
            b"\0\0",
        )
    )


@pytest.mark.parametrize("as_bytes", [False, True])
@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"entries_on_disk": 2001, "total_entries": 2001}, "entries"),
        (
            {"entries_on_disk": 1, "total_entries": 1, "central_size": 2**21 + 1},
            "central directory",
        ),
        ({"entries_on_disk": 0xFFFF, "total_entries": 0xFFFF}, "ZIP64"),
        ({"central_size": 0xFFFFFFFF}, "ZIP64"),
        ({"central_offset": 0xFFFFFFFF}, "ZIP64"),
        ({"disk_number": 1}, "multi-disk"),
    ],
)
def test_raw_eocd_preflight_rejects_before_zipfile_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    as_bytes: bool,
    fields: dict[str, int],
    message: str,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _open_zip

    raw = _raw_eocd(**fields)
    package = tmp_path / "raw-eocd.tnpkg"
    package.write_bytes(raw)
    source = raw if as_bytes else package
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor received hostile EOCD metadata")
        ),
    )

    with pytest.raises(PackageError, match=message):
        _open_zip(source)


@pytest.mark.parametrize("as_bytes", [False, True])
def test_open_zip_preserves_valid_stored_path_and_bytes(
    tmp_path: Path,
    as_bytes: bool,
) -> None:
    import zipfile

    from tn.tnpkg import _open_zip

    package = tmp_path / "valid-stored.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b'{"kind":"offer"}')
    source = package.read_bytes() if as_bytes else package

    with _open_zip(source) as archive:
        assert archive.read("manifest.json") == b'{"kind":"offer"}'


@pytest.mark.parametrize("as_bytes", [False, True])
def test_absorb_rejects_hostile_eocd_before_state(
    tmp_path: Path,
    as_bytes: bool,
) -> None:
    from tn.conventions import enrollment_dir
    from tn.tnpkg import MAX_PKG_ENTRY_COUNT

    raw = _raw_eocd(
        entries_on_disk=MAX_PKG_ENTRY_COUNT + 1,
        total_entries=MAX_PKG_ENTRY_COUNT + 1,
    )
    package = tmp_path / "hostile-eocd.tnpkg"
    package.write_bytes(raw)
    source = raw if as_bytes else package
    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))

    result = absorb(cfg, source)

    assert result.status == "rejected"
    assert "entries" in result.reason
    assert not enrollment_dir(cfg.yaml_path).exists()


@pytest.mark.parametrize("as_bytes", [False, True])
def test_open_zip_rejects_zip64_locator_before_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    as_bytes: bool,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _open_zip

    locator = b"PK\x06\x07" + b"\0" * 16
    raw = locator + _raw_eocd()
    package = tmp_path / "zip64-locator.tnpkg"
    package.write_bytes(raw)
    source = raw if as_bytes else package
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor received ZIP64 locator")
        ),
    )

    with pytest.raises(PackageError, match="ZIP64"):
        _open_zip(source)


def test_open_zip_requires_eocd_to_end_at_eof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _open_zip

    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor received trailing data")
        ),
    )

    with pytest.raises(PackageError, match="end.*at EOF"):
        _open_zip(_raw_eocd() + b"trailing")


def test_open_zip_rejects_inconsistent_central_offset_before_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _open_zip

    package = tmp_path / "bad-central-offset.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b"{}")
    _patch_eocd(package, central_offset=0xFFFFFF00)
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor received bad central offset")
        ),
    )

    with pytest.raises(PackageError, match="central directory metadata"):
        _open_zip(package)


def test_open_zip_rejects_entry_flood_before_zipfile_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import MAX_PKG_ENTRY_COUNT, PackageError, _open_zip

    package = tmp_path / "preconstructor-entry-flood.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        for index in range(MAX_PKG_ENTRY_COUNT + 1):
            archive.writestr(f"body/{index}", b"")
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor parsed an entry flood")
        ),
    )

    with pytest.raises(PackageError, match="entries"):
        _open_zip(package)


def test_open_zip_skips_false_eocd_signature_at_end_of_comment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import MAX_PKG_ENTRY_COUNT, PackageError, _open_zip

    package = tmp_path / "false-eocd-comment-flood.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        for index in range(MAX_PKG_ENTRY_COUNT + 1):
            archive.writestr(f"body/{index}", b"")
        archive.comment = b"comment ending in false signature PK\x05\x06"
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor parsed comment-hidden entry flood")
        ),
    )

    with pytest.raises(PackageError, match="entries"):
        _open_zip(package)


def test_open_zip_rejects_oversized_central_directory_before_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import MAX_PKG_CENTRAL_DIRECTORY_BYTES, PackageError, _open_zip

    package = tmp_path / "oversized-central-directory.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b"{}")
    _patch_eocd(package, central_size=MAX_PKG_CENTRAL_DIRECTORY_BYTES + 1)
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor parsed an oversized directory")
        ),
    )

    with pytest.raises(PackageError, match="central directory"):
        _open_zip(package)


def test_open_zip_rejects_zip64_sentinel_before_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _open_zip

    package = tmp_path / "zip64-sentinel.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b"{}")
    _patch_eocd(package, entries=0xFFFF)
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ZipFile constructor parsed ZIP64 metadata")
        ),
    )

    with pytest.raises(PackageError, match="ZIP64"):
        _open_zip(package)


def test_peek_rejects_forged_deflated_manifest_before_member_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _peek_manifest_kind

    package = tmp_path / "forged-deflated-manifest.tnpkg"
    manifest = b'{"kind":"offer","padding":"' + b"0" * 100_000 + b'"}'
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest)
    _patch_zip_member_metadata(package, "manifest.json", file_size=1)
    monkeypatch.setattr(
        zipfile.ZipFile,
        "read",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("forged manifest was inflated")
        ),
    )

    with pytest.raises(PackageError, match="ZIP_STORED"):
        _peek_manifest_kind(package)


def test_read_rejects_forged_stored_size_mismatch_before_member_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _read_manifest

    package = tmp_path / "forged-stored-body.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b'{"kind":"offer"}')
        archive.writestr("body/padding.bin", b"x" * 100_000)
    _patch_zip_member_metadata(package, "body/padding.bin", file_size=1)
    monkeypatch.setattr(
        zipfile.ZipFile,
        "read",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("forged stored member was read")
        ),
    )

    with pytest.raises(PackageError, match="stored size metadata"):
        _read_manifest(package)


def test_read_rejects_encrypted_flag_before_member_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _read_manifest

    package = tmp_path / "encrypted-flag.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b'{"kind":"offer"}')
    _patch_zip_member_metadata(package, "manifest.json", flag_bits=0x1)
    monkeypatch.setattr(
        zipfile.ZipFile,
        "read",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("encrypted member was read")
        ),
    )

    with pytest.raises(PackageError, match="encrypted"):
        _read_manifest(package)


@pytest.mark.parametrize("flag_bits", [0x20, 0x40])
def test_read_rejects_unsupported_zip_flags_before_member_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag_bits: int,
) -> None:
    import zipfile

    from tn.tnpkg import PackageError, _read_manifest

    package = tmp_path / f"unsupported-flag-{flag_bits:x}.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b'{"kind":"offer"}')
    _patch_zip_member_metadata(package, "manifest.json", flag_bits=flag_bits)
    monkeypatch.setattr(
        zipfile.ZipFile,
        "read",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unsupported ZIP member was read")
        ),
    )

    with pytest.raises(PackageError, match="unsupported ZIP flag bits"):
        _read_manifest(package)


def test_zip_member_reader_preserves_unrelated_runtime_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zipfile

    from tn.tnpkg import _read_manifest

    package = tmp_path / "programmer-runtime-error.tnpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", b'{"kind":"offer"}')
    monkeypatch.setattr(
        zipfile.ZipFile,
        "read",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("unrelated programmer defect")
        ),
    )

    with pytest.raises(RuntimeError, match="unrelated programmer defect"):
        _read_manifest(package)


def test_zip_member_reader_normalizes_not_implemented_zip_error() -> None:
    from tn.tnpkg import PackageError, _read_zip_member

    class UnsupportedZipReader:
        def read(self, _name: str) -> bytes:
            raise NotImplementedError("strong encryption (flag bit 6)")

    with pytest.raises(PackageError, match="ZIP member.*strong encryption"):
        _read_zip_member(UnsupportedZipReader(), "body/package.json")  # type: ignore[arg-type]


def test_read_manifest_rejects_zip_bomb_entry_before_reading_body(tmp_path: Path):
    """An entry whose declared uncompressed size dwarfs its on-disk size is a
    zip bomb. ``_read_manifest`` must reject it from ZipInfo metadata — the
    PackageError proves no body bytes were inflated, because the guard runs on
    metadata only, before any ``zf.read`` of a body member."""
    import zipfile

    from tn.tnpkg import (
        MAX_PKG_ENTRY_BYTES,
        PackageError,
        _read_manifest,
    )

    # A tiny on-disk DEFLATE entry that inflates well past the per-entry cap.
    # 200 MiB of zeros compresses to a few hundred bytes — file_size is what
    # the central directory reports, so the guard sees the bomb without us
    # ever allocating 200 MiB.
    huge = b"\x00" * (MAX_PKG_ENTRY_BYTES + 1)
    bomb = tmp_path / "bomb.tnpkg"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("body/huge.bin", huge, compress_type=zipfile.ZIP_DEFLATED)

    # Confirm the on-disk file is small (the body was NOT stored expanded).
    assert bomb.stat().st_size < 1 * 1024 * 1024

    try:
        _read_manifest(bomb, verify_signature=False)
    except PackageError as exc:
        msg = str(exc)
        assert "body/huge.bin" in msg
        assert "ZIP_STORED" in msg
    else:
        raise AssertionError("expected PackageError for an oversized entry")


def test_absorb_rejects_zip_bomb(tmp_path: Path):
    """End-to-end: absorb() refuses a zip-bomb `.tnpkg` with a typed rejection
    naming the limit, instead of inflating the entry into memory."""
    import zipfile

    from tn.tnpkg import MAX_PKG_ENTRY_BYTES

    huge = b"\x00" * (MAX_PKG_ENTRY_BYTES + 1)
    bomb = tmp_path / "bomb.tnpkg"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("body/huge.bin", huge, compress_type=zipfile.ZIP_DEFLATED)

    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result = absorb(cfg, bomb)
    assert result.status == "rejected"
    assert "body/huge.bin" in result.reason
    assert "zip bomb" in result.reason.lower()


def test_absorb_rejects_entry_flood(tmp_path: Path):
    """Thousands of entries is an attack, not a backup. Rejected from the
    entry-count limit before any entry is read."""
    import zipfile

    from tn.tnpkg import MAX_PKG_ENTRY_COUNT

    flood = tmp_path / "flood.tnpkg"
    with zipfile.ZipFile(flood, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", b"{}")
        for i in range(MAX_PKG_ENTRY_COUNT + 5):
            zf.writestr(f"body/e{i}", b"x")

    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result = absorb(cfg, flood)
    assert result.status == "rejected"
    assert str(MAX_PKG_ENTRY_COUNT) in result.reason
    assert "entries" in result.reason.lower()


def test_absorb_rejects_oversized_manifest(tmp_path: Path):
    """A multi-MiB manifest is malformed / hostile. Rejected from the manifest
    size limit before the manifest JSON is parsed."""
    import zipfile

    from tn.tnpkg import MAX_MANIFEST_BYTES

    # Oversized manifest written STORED so it clears the per-entry / ratio
    # guards (ratio ~1, well under 128 MiB) and trips ONLY the dedicated
    # manifest-size check. ~2 MiB on disk — cheap for a test.
    big_manifest = b" " * (MAX_MANIFEST_BYTES + 1)
    pkg = tmp_path / "bigmanifest.tnpkg"
    with zipfile.ZipFile(pkg, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", big_manifest)

    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result = absorb(cfg, pkg)
    assert result.status == "rejected"
    assert "manifest.json" in result.reason
    assert "manifest limit" in result.reason


def test_absorb_normal_package_still_absorbs_after_limits(tmp_path: Path):
    """The limit guard must NOT reject a legitimate package. A real signed
    offer `.tnpkg` (well within every bound) absorbs cleanly."""
    pkg_path = _make_valid_offer_tnpkg(tmp_path)

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher=_workflow_cipher("jwe"))
    result = absorb(alice_cfg, pkg_path)
    assert result.status == "offer_stashed", f"reason: {result.reason}"


def test_kit_bundle_cannot_overwrite_device_identity_from_counterparty(tmp_path: Path):
    """SECURITY: a counterparty kit_bundle/full_keystore (self-signed under
    the attacker's OWN DID) must never install body/local.private over the
    recipient's device key. Installing a device secret is legitimate only for
    a self-addressed restore of one's own backup; identity_seed handles the
    minted-key case. Without the guard this is a silent identity takeover."""
    victim = DeviceKey.generate()
    cfg = load_or_create(
        tmp_path / "victim" / "tn.yaml",
        cipher=_workflow_cipher("btn"),
        device_private_bytes=victim.private_bytes,
    )
    victim_priv = (cfg.keystore / "local.private").read_bytes()
    assert victim_priv == victim.private_bytes  # baseline

    attacker = DeviceKey.generate()
    body = {
        "body/local.private": bytes(attacker.private_bytes),
        "body/local.public": attacker.did.encode("utf-8"),
        "body/legit.kit": b"ordinary kit material",
    }
    # publisher != recipient: addressed AT the victim, not self-addressed.
    manifest = TnpkgManifest(
        kind="full_keystore",
        publisher_identity=attacker.did,
        recipient_identity=victim.did,
        ceremony_id="attack",
        as_of="2026-06-10T00:00:00Z",
    )

    receipt = _absorb_kit_bundle(cfg, manifest, body)

    # The device identity must be UNTOUCHED.
    assert (cfg.keystore / "local.private").read_bytes() == victim_priv
    assert (cfg.keystore / "local.public").read_text(encoding="utf-8").strip() == victim.did
    # ...and the ordinary kit file still installs (the guard is surgical).
    assert (cfg.keystore / "legit.kit").read_bytes() == b"ordinary kit material"
    assert receipt.accepted_count == 1
    assert receipt.deduped_count == 0


def test_refused_kit_material_does_not_grant_publisher_trust(tmp_path: Path):
    victim = DeviceKey.generate()
    cfg = load_or_create(
        tmp_path / "victim" / "tn.yaml",
        cipher=_workflow_cipher("btn"),
        device_private_bytes=victim.private_bytes,
    )
    attacker = DeviceKey.generate()
    body = {"body/local.private": bytes(attacker.private_bytes)}
    manifest = TnpkgManifest(
        kind="kit_bundle",
        publisher_identity=attacker.did,
        recipient_identity=victim.did,
        ceremony_id="refused-trust",
        as_of="2026-06-10T00:00:00Z",
    )
    sign_manifest_with_body(manifest, body, attacker.signing_key())
    package = _write_tnpkg(tmp_path / "refused.tnpkg", manifest, body)

    result = absorb(cfg, package)

    assert result.status == "no_op"
    trust_path = cfg.keystore / "trust" / "verified_publishers.v1.json"
    assert not trust_path.exists()


def test_contact_update_rejects_excessive_json_nesting(tmp_path: Path):
    cfg = load_or_create(tmp_path / "contact" / "tn.yaml", cipher=_workflow_cipher("btn"))
    manifest = TnpkgManifest(
        kind="contact_update",
        publisher_identity=cfg.device.device_identity,
        recipient_identity=cfg.device.device_identity,
        ceremony_id="nested-contact",
        as_of="2026-06-10T00:00:00Z",
    )
    wire = (
        b'{"nested":' + b"[" * (MAX_JSON_NESTING + 1) + b"0" + b"]" * (MAX_JSON_NESTING + 1) + b"}"
    )

    receipt = _absorb_contact_update(cfg, manifest, {"body/contact_update.json": wire})

    assert receipt.legacy_status == "rejected"
    assert "JSON nesting" in receipt.legacy_reason


def test_admin_snapshot_rejects_excessive_json_nesting(tmp_path: Path):
    cfg = load_or_create(tmp_path / "admin" / "tn.yaml", cipher=_workflow_cipher("btn"))
    manifest = TnpkgManifest(
        kind="admin_log_snapshot",
        publisher_identity=cfg.device.device_identity,
        recipient_identity=cfg.device.device_identity,
        ceremony_id="nested-admin",
        as_of="2026-06-10T00:00:00Z",
        clock={cfg.device.device_identity: {"tn.key.rotate": 1}},
    )
    wire = (
        b'{"nested":' + b"[" * (MAX_JSON_NESTING + 1) + b"0" + b"]" * (MAX_JSON_NESTING + 1) + b"}"
    )

    receipt = _absorb_admin_log_snapshot(cfg, manifest, {"body/admin.ndjson": wire})

    assert receipt.legacy_status == "rejected"
    assert "JSON nesting" in receipt.legacy_reason
