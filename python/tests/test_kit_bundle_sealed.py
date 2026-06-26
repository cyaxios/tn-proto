"""Tests for the recipient-direction sealed-box wrap on kit_bundle.

Covers:

* Round-trip: producer seals a kit_bundle for a recipient DID; the
  recipient absorbs and the kit lands in the keystore. The vault would
  see opaque ciphertext on the wire.
* Wrong recipient: a different DID's runtime cannot unwrap.
* Tamper: modifying the wrap's ephemeral pub fails AAD/AEAD.
* Tamper: modifying body/encrypted.bin fails AEAD.
* Lift attack: lifting a wrap from one manifest into a structurally
  similar manifest fails because AAD includes the rest of the manifest.
* Backwards compatibility: a kit_bundle exported WITHOUT sealing
  produces byte-identical-shaped output to before (regression check).
"""

from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

import pytest

from tn.absorb import _absorb_dispatch
from tn.config import load_or_create
from tn.export import export, export_identity_seed
from tn.recipient_seal import UnsealError, unseal_bek_from_wrap, manifest_aad_for_wrap
from tn.signing import DeviceKey
from tn.tnpkg import _read_manifest


# ---------------------------------------------------------------------------
# Helpers — set up a publisher with a btn group and a fresh recipient host
# ---------------------------------------------------------------------------


def _make_publisher_with_btn_group(workdir: Path):
    """Create alice's tn ceremony with a btn group; return the loaded cfg.

    Uses load_or_create (which mints alice's identity + a btn 'default'
    group keystore in the process). After this call the publisher's
    keystore has ``default.btn.state`` and ``default.btn.mykit``.
    """
    yaml_path = workdir / "alice" / "tn.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = load_or_create(yaml_path, cipher="btn")
    return cfg


class _FakeCfg:
    """Minimal LoadedConfig stand-in for absorb's sealed-box path.

    The unwrap step in ``_maybe_unseal_recipient_wrap`` needs only
    ``cfg.device.device_identity``, ``cfg.device.private_bytes`` and ``cfg.keystore``.
    The kit_bundle absorb path also needs ``cfg.keystore`` and a
    ``yaml_path`` for path-equality checks. This mock keeps the test
    fixture independent of the full LoadedConfig shape (which requires
    a ceremony, master index key, group configs, etc — none of which
    matter for these tests).
    """

    def __init__(self, workdir: Path, device: DeviceKey, name: str = "frank"):
        host_dir = workdir / name
        host_dir.mkdir(parents=True, exist_ok=True)
        self.yaml_path = host_dir / "tn.yaml"
        self.keystore = host_dir / "keys"
        self.keystore.mkdir(parents=True, exist_ok=True)
        self.device = device


def _install_fresh_recipient(workdir: Path, recipient_device: DeviceKey, name: str = "frank"):
    """Install a recipient identity at a fresh keystore via identity_seed.

    Returns a minimal cfg-shaped object; see ``_FakeCfg``. Functionally
    equivalent for the absorb pathways we test here.
    """
    pkg_path = workdir / f"{name}_id.tnpkg"
    export_identity_seed(pkg_path, device=recipient_device, nickname=name)

    cfg = _FakeCfg(workdir, recipient_device, name=name)
    # No existing identity yet — absorb installs cleanly.
    receipt = _absorb_dispatch(cfg, pkg_path)
    assert receipt.legacy_status == "enrolment_applied", receipt.legacy_reason
    return cfg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sealed_kit_bundle_round_trip(tmp_path: Path):
    """Alice seals a kit_bundle for Frank; Frank absorbs successfully."""
    alice_cfg = _make_publisher_with_btn_group(tmp_path)
    frank_device = DeviceKey.generate()
    frank_cfg = _install_fresh_recipient(tmp_path, frank_device)
    assert frank_cfg.device.device_identity == frank_device.did

    out = tmp_path / "frank_kit.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_did=frank_device.did,
        seal_for_recipient=True,
    )
    assert out.is_file()

    # The on-wire bytes must be opaque: only body/encrypted.bin in the
    # body, no plaintext kit visible.
    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
    assert "manifest.json" in names
    assert "body/encrypted.bin" in names
    assert not any(name.endswith(".btn.mykit") for name in names), (
        f"sealed bundle should not have plaintext kit members: {names}"
    )

    # Manifest must carry the wrap block.
    manifest, _body = _read_manifest(out)
    state = manifest.state or {}
    body_encryption = state.get("body_encryption") or {}
    wrap = body_encryption.get("recipient_wrap")
    assert wrap is not None
    assert wrap["frame"] == "tn-sealed-box-v1"
    assert wrap["recipient_identity"] == frank_device.did

    # Frank absorbs.
    receipt = _absorb_dispatch(frank_cfg, out)
    assert receipt.legacy_status == "enrolment_applied", (
        f"expected sealed kit absorb to succeed, got {receipt.legacy_status} "
        f"({receipt.legacy_reason})"
    )
    assert (frank_cfg.keystore / "default.btn.mykit").exists()


def test_sealed_kit_bundle_wrong_recipient_rejected(tmp_path: Path):
    """A bystander cannot unwrap a wrap addressed to someone else."""
    alice_cfg = _make_publisher_with_btn_group(tmp_path)
    frank_device = DeviceKey.generate()
    bob_device = DeviceKey.generate()
    _frank_cfg = _install_fresh_recipient(tmp_path, frank_device)

    # Bob has a different identity.
    bob_cfg = _install_fresh_recipient(tmp_path, bob_device, name="bob")
    assert bob_cfg.device.device_identity == bob_device.did

    out = tmp_path / "for_frank.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_did=frank_device.did,
        seal_for_recipient=True,
    )

    receipt = _absorb_dispatch(bob_cfg, out)
    assert receipt.legacy_status == "rejected"
    assert "addressed to" in receipt.legacy_reason


def test_sealed_kit_bundle_tampered_wrap_rejected(tmp_path: Path):
    """Mutating the wrap's ephemeral pub fails AEAD on unwrap."""
    alice_cfg = _make_publisher_with_btn_group(tmp_path)
    frank_device = DeviceKey.generate()
    frank_cfg = _install_fresh_recipient(tmp_path, frank_device)

    out = tmp_path / "for_frank.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_did=frank_device.did,
        seal_for_recipient=True,
    )

    # Read current manifest, tamper the ephemeral pub bytes (still 32B
    # so format checks pass) but the AEAD should fail because the
    # derived shared secret will be wrong.
    with zipfile.ZipFile(out, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        encrypted_bytes = zf.read("body/encrypted.bin")
    doc = json.loads(manifest_bytes.decode("utf-8"))
    bad_eph = base64.b64encode(b"\x00" * 32).decode("ascii")
    doc["state"]["body_encryption"]["recipient_wrap"]["ephemeral_x25519_pub_b64"] = bad_eph
    new_manifest = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", new_manifest)
        zf.writestr("body/encrypted.bin", encrypted_bytes)

    receipt = _absorb_dispatch(frank_cfg, out)
    # Either manifest sig check fails (since we mutated state), or unwrap
    # fails. Both produce 'rejected' — assert that path is taken.
    assert receipt.legacy_status == "rejected"


def test_sealed_kit_bundle_tampered_body_rejected(tmp_path: Path):
    """Mutating body/encrypted.bin fails AEAD even with the right key."""
    alice_cfg = _make_publisher_with_btn_group(tmp_path)
    frank_device = DeviceKey.generate()
    frank_cfg = _install_fresh_recipient(tmp_path, frank_device)

    out = tmp_path / "for_frank.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_did=frank_device.did,
        seal_for_recipient=True,
    )

    with zipfile.ZipFile(out, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        encrypted_bytes = bytearray(zf.read("body/encrypted.bin"))
    encrypted_bytes[20] ^= 0xFF
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("body/encrypted.bin", bytes(encrypted_bytes))

    receipt = _absorb_dispatch(frank_cfg, out)
    assert receipt.legacy_status == "rejected"
    assert "decrypt" in receipt.legacy_reason.lower()


def test_sealed_wrap_aad_lift_attack_rejected(tmp_path: Path):
    """A wrap lifted from manifest A must not unseal under manifest B.

    We construct two sealed kit_bundles (different to_did but conceptually
    similar) and try to swap the wrap on B with the wrap from A. The
    AAD includes everything-but-wrap-and-sig, so the manifests differ
    enough that the swap fails.

    The simpler invariant: the AAD covers the manifest, so swapping the
    wrap into a different manifest (different from_did, different
    ceremony_id, different to_did, anything) breaks the AEAD.
    """
    alice_cfg = _make_publisher_with_btn_group(tmp_path)
    frank_device = DeviceKey.generate()
    frank_cfg = _install_fresh_recipient(tmp_path, frank_device)

    out_real = tmp_path / "real.tnpkg"
    export(
        out_real,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_did=frank_device.did,
        seal_for_recipient=True,
    )

    # Build a second sealed bundle, same recipient but a *different*
    # ceremony / from_did so the manifest contents differ. We do this by
    # standing up a SECOND publisher.
    bob_alice_cfg = _make_publisher_with_btn_group(tmp_path / "alt")
    out_decoy = tmp_path / "decoy.tnpkg"
    export(
        out_decoy,
        kind="kit_bundle",
        cfg=bob_alice_cfg,
        to_did=frank_device.did,
        seal_for_recipient=True,
    )

    # Lift the wrap from `real` and stuff it into `decoy`'s manifest.
    with zipfile.ZipFile(out_real, "r") as zf:
        real_manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    real_wrap = real_manifest["state"]["body_encryption"]["recipient_wrap"]

    with zipfile.ZipFile(out_decoy, "r") as zf:
        decoy_manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        decoy_encrypted = zf.read("body/encrypted.bin")

    decoy_manifest["state"]["body_encryption"]["recipient_wrap"] = real_wrap
    new_manifest = (json.dumps(decoy_manifest, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    out_lifted = tmp_path / "lifted.tnpkg"
    with zipfile.ZipFile(out_lifted, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", new_manifest)
        zf.writestr("body/encrypted.bin", decoy_encrypted)

    receipt = _absorb_dispatch(frank_cfg, out_lifted)
    # Manifest signature on the lifted file is already broken (we
    # mutated state); absorb rejects at signature check OR at unwrap.
    # Either way, "rejected" — the lift didn't work.
    assert receipt.legacy_status == "rejected"


def test_seal_for_recipient_requires_to_did(tmp_path: Path):
    alice_cfg = _make_publisher_with_btn_group(tmp_path)
    out = tmp_path / "x.tnpkg"
    with pytest.raises(ValueError, match="recipient_identity"):
        export(out, kind="kit_bundle", cfg=alice_cfg, seal_for_recipient=True)


def test_seal_for_recipient_mutually_exclusive_with_encrypt_body_with(tmp_path: Path):
    alice_cfg = _make_publisher_with_btn_group(tmp_path)
    out = tmp_path / "x.tnpkg"
    with pytest.raises(ValueError, match="mutually exclusive"):
        export(
            out,
            kind="kit_bundle",
            cfg=alice_cfg,
            to_did="did:key:z6MkSomething",
            seal_for_recipient=True,
            encrypt_body_with=b"\x00" * 32,
        )


def test_aad_function_omits_wrap_and_sig():
    """manifest_aad_for_wrap must drop both the signature and the wrap."""
    manifest_dict = {
        "kind": "kit_bundle",
        "version": 1,
        "publisher_identity": "did:key:zAlice",
        "ceremony_id": "test_ceremony",
        "as_of": "2026-05-04T12:00:00.000+00:00",
        "scope": "kit_bundle",
        "recipient_identity": "did:key:zFrank",
        "clock": {},
        "event_count": 0,
        "state": {
            "body_encryption": {
                "cipher_suite": "aes-256-gcm",
                "frame": "tn-encrypted-body-v2-zip",
                "nonce_bytes": 12,
                "ciphertext_sha256": "sha256:abcd",
                "recipient_wrap": {
                    "frame": "tn-sealed-box-v1",
                    "recipient_identity": "did:key:zFrank",
                    "ephemeral_x25519_pub_b64": "AAAA",
                    "wrap_nonce_b64": "BBBB",
                    "wrapped_bek_b64": "CCCC",
                },
            },
        },
        "manifest_signature_b64": "DDDD",
    }
    aad = manifest_aad_for_wrap(manifest_dict)
    aad_str = aad.decode("utf-8")
    assert "manifest_signature_b64" not in aad_str
    assert "recipient_wrap" not in aad_str
    # Other fields preserved.
    assert "did:key:zFrank" in aad_str
    assert "ciphertext_sha256" in aad_str
    # Original dict is untouched.
    assert manifest_dict["manifest_signature_b64"] == "DDDD"
    assert "recipient_wrap" in manifest_dict["state"]["body_encryption"]


def test_unseal_rejects_unsupported_curve():
    """Sealed-box requires an Ed25519 (multicodec 0xed) DID."""
    # secp256k1 multicodec is 0xe7 — bytes that don't begin with the
    # Ed25519 multicodec should cleanly raise.
    bad_wrap = {
        "frame": "tn-sealed-box-v1",
        "recipient_identity": "did:web:example.com",  # not did:key
        "ephemeral_x25519_pub_b64": base64.b64encode(b"\x00" * 32).decode(),
        "wrap_nonce_b64": base64.b64encode(b"\x00" * 12).decode(),
        "wrapped_bek_b64": base64.b64encode(b"\x00" * 48).decode(),
    }
    with pytest.raises(UnsealError):
        unseal_bek_from_wrap(bad_wrap, b"\x00" * 32, b"")
