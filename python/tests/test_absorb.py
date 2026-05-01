import json
from pathlib import Path

from tn.absorb import absorb
from tn.config import load_or_create
from tn.conventions import outbox_dir, pending_offers_dir
from tn.offer import offer


def test_absorb_offer_lands_in_pending_offers(tmp_path: Path):
    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
    offer(bob_cfg, publisher_did="did:key:z6MkAlice")
    pkg_path = next(outbox_dir(bob_dir).glob("*.tnpkg"))

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher="jwe")
    result = absorb(alice_cfg, pkg_path)
    assert result.status == "offer_stashed"
    safe = bob_cfg.device.did.replace(":", "_")
    assert (pending_offers_dir(alice_dir) / f"{safe}.json").exists()


def test_absorb_rejects_bad_signature(tmp_path: Path):
    """A tampered offer must not get stashed.

    With the new universal `.tnpkg` wrapper, the payload tampering happens
    inside the body's package.json (the inner Package signature still has
    to verify after dispatch). We rewrite the zip with the mutated body
    so the inner Package signature fails.
    """
    import zipfile

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
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

    alice_cfg = load_or_create((tmp_path / "alice_t.yaml").parent / "alice_t.yaml", cipher="jwe")
    result = absorb(alice_cfg, pkg_path)
    assert result.status == "rejected"
    assert "signature" in result.reason.lower()


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
        signer_did="did:key:x",
        signer_verify_pub_b64="",
        peer_did="did:key:y",
        payload={},
        compiled_at="2026-04-21T00:00:00Z",
    )
    sk = Ed25519PrivateKey.generate()
    pkg = sign(bogus, sk)
    path = tmp_path / "pkg.tnpkg"
    dump_tnpkg(pkg, path)

    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
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
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
    bob_pub = _ensure_mykey(bob_cfg, "default")

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher="jwe")
    admin._add_recipient_jwe_impl(alice_cfg, "default", bob_cfg.device.did, bob_pub)
    pkg = compile_enrolment(alice_cfg, "default", bob_cfg.device.did)
    pkg_path = emit_to_outbox(alice_cfg, pkg)

    result = absorb(bob_cfg, pkg_path)
    assert result.status == "enrolment_applied", f"reason: {result.reason}"

    # Alice writes, Bob reads with tn.read().
    tn.init(str(alice_cfg.yaml_path))
    tn.info("hello", body="from_alice")
    tn.flush_and_close()
    tn.init(str(bob_cfg.yaml_path))
    entries = list(tn.read_raw(alice_dir / ".tn/tn/logs" / "tn.ndjson"))
    decrypted = [
        e
        for e in entries
        if "default" in e.get("plaintext", {})
        and "$decrypt_error" not in e["plaintext"]["default"]
        and "$no_read_key" not in e["plaintext"]["default"]
    ]
    assert decrypted, f"Bob should decrypt default entries; got: {entries}"
    tn.flush_and_close()


# test_bearer_coupon_roundtrip was removed alongside the BGW cipher (Workstream G).
# btn coupon/invite coverage lives in test_recipient_tracking.py +
# test_admin_state.py which exercise tn.admin_add_recipient and compile_kit_bundle.


def test_absorb_accepts_bytes_input(tmp_path: Path):
    """Bytes inputs are allowed: absorb spills to a temp .tnpkg, processes,
    then unlinks. End-to-end through the offer kind path."""
    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_cfg = load_or_create(bob_dir / "tn.yaml", cipher="jwe")
    offer(bob_cfg, publisher_did="did:key:z6MkAlice")
    pkg_path = next(outbox_dir(bob_dir).glob("*.tnpkg"))
    pkg_bytes = pkg_path.read_bytes()

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_cfg = load_or_create(alice_dir / "tn.yaml", cipher="jwe")
    result = absorb(alice_cfg, pkg_bytes)
    assert result.status == "offer_stashed", f"reason: {result.reason}"
    safe = bob_cfg.device.did.replace(":", "_")
    assert (pending_offers_dir(alice_dir) / f"{safe}.json").exists()
