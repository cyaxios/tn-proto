# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)


import json
from pathlib import Path

from tn.absorb import _absorb_kit_bundle, absorb
from tn.config import load_or_create
from tn.conventions import outbox_dir, pending_offers_dir
from tn.offer import offer
from tn.signing import DeviceKey
from tn.tnpkg import TnpkgManifest


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
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("body/huge.bin", huge)

    # Confirm the on-disk file is small (the body was NOT stored expanded).
    assert bomb.stat().st_size < 1 * 1024 * 1024

    try:
        _read_manifest(bomb, verify_signature=False)
    except PackageError as exc:
        msg = str(exc)
        assert "body/huge.bin" in msg
        assert "per-entry" in msg or "compression ratio" in msg
    else:
        raise AssertionError("expected PackageError for an oversized entry")


def test_absorb_rejects_zip_bomb(tmp_path: Path):
    """End-to-end: absorb() refuses a zip-bomb `.tnpkg` with a typed rejection
    naming the limit, instead of inflating the entry into memory."""
    import zipfile

    from tn.tnpkg import MAX_PKG_ENTRY_BYTES

    huge = b"\x00" * (MAX_PKG_ENTRY_BYTES + 1)
    bomb = tmp_path / "bomb.tnpkg"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("body/huge.bin", huge)

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

    _absorb_kit_bundle(cfg, manifest, body)

    # The device identity must be UNTOUCHED.
    assert (cfg.keystore / "local.private").read_bytes() == victim_priv
    assert (cfg.keystore / "local.public").read_text(encoding="utf-8").strip() == victim.did
    # ...and the ordinary kit file still installs (the guard is surgical).
    assert (cfg.keystore / "legit.kit").read_bytes() == b"ordinary kit material"
