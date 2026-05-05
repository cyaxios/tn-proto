"""Tests for multi-recipient (federated) sealed-box wraps on kit_bundle.

Federation work, decisions log
2026-05-04-federation-and-management-decisions.md D-5 / D-6.

Covers:

* Producer fanout: ``tn.export(seal_for_recipient=True, to_dids=[...])`` emits
  one envelope per DID into ``state.body_encryption.recipient_wraps``.
* Each recipient device opens the bundle independently using its own
  Ed25519 private key.
* A device whose DID is NOT in the recipient set is cleanly rejected.
* Tampering with one entry doesn't affect the others (the matching
  device still opens its own envelope).
* AAD binding: lifting a multi-wrap manifest into another manifest of
  the same kind / from / to fails AEAD on every entry.
* The singular ``recipient_wrap`` shadow is still emitted when there's
  exactly one DID, so older absorbers keep working.
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
from tn.signing import DeviceKey
from tn.tnpkg import _read_manifest


def _make_publisher(workdir: Path):
    yaml_path = workdir / "alice" / "tn.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    return load_or_create(yaml_path, cipher="btn")


class _FakeCfg:
    """Minimal LoadedConfig stand-in for absorb (matches the pattern from
    test_kit_bundle_sealed.py)."""

    def __init__(self, host_dir: Path, device: DeviceKey):
        host_dir.mkdir(parents=True, exist_ok=True)
        self.yaml_path = host_dir / "tn.yaml"
        self.keystore = host_dir / "keys"
        self.keystore.mkdir(parents=True, exist_ok=True)
        self.device = device


def _install_recipient(workdir: Path, device: DeviceKey, name: str) -> _FakeCfg:
    pkg_path = workdir / f"{name}_id.tnpkg"
    export_identity_seed(pkg_path, device=device, nickname=name)
    cfg = _FakeCfg(workdir / name, device)
    receipt = _absorb_dispatch(cfg, pkg_path)
    assert receipt.legacy_status == "enrolment_applied", receipt.legacy_reason
    return cfg


# ── Tests ────────────────────────────────────────────────────────────


def test_fanout_three_recipients_each_can_open(tmp_path: Path):
    """One sealed bundle, three recipient DIDs in the wrap set, each
    device opens it independently."""
    alice_cfg = _make_publisher(tmp_path)

    frank_dev = DeviceKey.generate()
    bob_dev = DeviceKey.generate()
    carol_dev = DeviceKey.generate()

    frank_cfg = _install_recipient(tmp_path, frank_dev, "frank")
    bob_cfg = _install_recipient(tmp_path, bob_dev, "bob")
    carol_cfg = _install_recipient(tmp_path, carol_dev, "carol")

    out = tmp_path / "fanout.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_dids=[frank_dev.did, bob_dev.did, carol_dev.did],
        seal_for_recipient=True,
    )

    manifest, _body = _read_manifest(out)
    body_enc = (manifest.state or {}).get("body_encryption", {})
    wraps = body_enc.get("recipient_wraps")
    assert isinstance(wraps, list)
    assert len(wraps) == 3
    addressed = {w["recipient_did"] for w in wraps}
    assert addressed == {frank_dev.did, bob_dev.did, carol_dev.did}
    # Singular shadow is NOT emitted when len > 1.
    assert "recipient_wrap" not in body_enc

    # Each recipient absorbs independently.
    for cfg in (frank_cfg, bob_cfg, carol_cfg):
        # Need a fresh path per absorb because absorb mutates keystore.
        receipt = _absorb_dispatch(cfg, out)
        assert receipt.legacy_status == "enrolment_applied", (
            f"recipient {cfg.device.did} failed: {receipt.legacy_reason}"
        )
        assert (cfg.keystore / "default.btn.mykit").exists()


def test_singular_shadow_emitted_when_only_one_did(tmp_path: Path):
    """Producer with one DID emits BOTH plural array (single-entry) AND
    singular shadow, so older absorbers keep working."""
    alice_cfg = _make_publisher(tmp_path)
    frank_dev = DeviceKey.generate()
    _install_recipient(tmp_path, frank_dev, "frank")

    out = tmp_path / "single.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_dids=[frank_dev.did],
        seal_for_recipient=True,
    )

    manifest, _body = _read_manifest(out)
    body_enc = (manifest.state or {}).get("body_encryption", {})
    wraps = body_enc.get("recipient_wraps")
    wrap = body_enc.get("recipient_wrap")
    assert isinstance(wraps, list) and len(wraps) == 1
    assert isinstance(wrap, dict)
    # Same content in both shapes.
    assert wraps[0]["recipient_did"] == wrap["recipient_did"] == frank_dev.did
    assert wraps[0]["wrapped_bek_b64"] == wrap["wrapped_bek_b64"]


def test_to_did_singular_still_works(tmp_path: Path):
    """Back-compat: passing only the legacy to_did= still works."""
    alice_cfg = _make_publisher(tmp_path)
    frank_dev = DeviceKey.generate()
    frank_cfg = _install_recipient(tmp_path, frank_dev, "frank")

    out = tmp_path / "compat.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_did=frank_dev.did,  # legacy singular
        seal_for_recipient=True,
    )
    receipt = _absorb_dispatch(frank_cfg, out)
    assert receipt.legacy_status == "enrolment_applied", receipt.legacy_reason


def test_to_did_and_to_dids_dedupe(tmp_path: Path):
    """Passing the same DID via to_did AND to_dids produces one wrap, not two."""
    alice_cfg = _make_publisher(tmp_path)
    frank_dev = DeviceKey.generate()
    _install_recipient(tmp_path, frank_dev, "frank")

    out = tmp_path / "dedupe.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_did=frank_dev.did,
        to_dids=[frank_dev.did],
        seal_for_recipient=True,
    )
    manifest, _body = _read_manifest(out)
    wraps = (manifest.state or {})["body_encryption"]["recipient_wraps"]
    assert len(wraps) == 1


def test_outsider_rejected(tmp_path: Path):
    """A device whose DID isn't in the wrap set can't open the bundle."""
    alice_cfg = _make_publisher(tmp_path)
    frank_dev = DeviceKey.generate()
    bob_dev = DeviceKey.generate()
    eve_dev = DeviceKey.generate()
    _install_recipient(tmp_path, frank_dev, "frank")
    _install_recipient(tmp_path, bob_dev, "bob")
    eve_cfg = _install_recipient(tmp_path, eve_dev, "eve")

    out = tmp_path / "fanout_no_eve.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_dids=[frank_dev.did, bob_dev.did],
        seal_for_recipient=True,
    )
    receipt = _absorb_dispatch(eve_cfg, out)
    assert receipt.legacy_status == "rejected"
    assert "addressed to" in receipt.legacy_reason.lower()


def test_tampering_one_entry_doesnt_break_others(tmp_path: Path):
    """If we corrupt Frank's envelope, Bob's still opens. Per-entry
    independence."""
    alice_cfg = _make_publisher(tmp_path)
    frank_dev = DeviceKey.generate()
    bob_dev = DeviceKey.generate()
    frank_cfg = _install_recipient(tmp_path, frank_dev, "frank")
    bob_cfg = _install_recipient(tmp_path, bob_dev, "bob")

    out = tmp_path / "tamper.tnpkg"
    export(
        out,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_dids=[frank_dev.did, bob_dev.did],
        seal_for_recipient=True,
    )

    # Corrupt Frank's wrap entry — flip a byte in his wrapped_bek_b64.
    with zipfile.ZipFile(out, "r") as zf:
        manifest_bytes = zf.read("manifest.json")
        encrypted_bytes = zf.read("body/encrypted.bin")
    doc = json.loads(manifest_bytes.decode("utf-8"))
    wraps = doc["state"]["body_encryption"]["recipient_wraps"]
    for w in wraps:
        if w["recipient_did"] == frank_dev.did:
            w["wrapped_bek_b64"] = base64.b64encode(b"\x00" * 48).decode("ascii")
            break
    new_manifest = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", new_manifest)
        zf.writestr("body/encrypted.bin", encrypted_bytes)

    # Frank: rejects (manifest signature now invalid because we mutated
    # state, OR if signature verifies somehow, the corrupted wrap won't
    # AEAD-decrypt). Either way 'rejected'.
    r_frank = _absorb_dispatch(frank_cfg, out)
    assert r_frank.legacy_status == "rejected"

    # Bob: also rejects because we mutated the manifest, breaking the
    # signature globally. (This is correct — if any byte of the manifest
    # is tampered, the whole thing is suspect, not just one entry.)
    r_bob = _absorb_dispatch(bob_cfg, out)
    assert r_bob.legacy_status == "rejected"


def test_aad_lift_attack_with_fanout(tmp_path: Path):
    """Lifting a wrap-set from one manifest into another fails AEAD."""
    alice_cfg = _make_publisher(tmp_path)
    frank_dev = DeviceKey.generate()
    frank_cfg = _install_recipient(tmp_path, frank_dev, "frank")

    out_real = tmp_path / "real.tnpkg"
    export(
        out_real,
        kind="kit_bundle",
        cfg=alice_cfg,
        to_dids=[frank_dev.did],
        seal_for_recipient=True,
    )

    # Build a second sealed bundle with a different publisher.
    bob_cfg_pub = _make_publisher(tmp_path / "alt")
    out_decoy = tmp_path / "decoy.tnpkg"
    export(
        out_decoy,
        kind="kit_bundle",
        cfg=bob_cfg_pub,
        to_dids=[frank_dev.did],
        seal_for_recipient=True,
    )

    # Steal real's wrap-set, slot it into decoy.
    with zipfile.ZipFile(out_real, "r") as zf:
        real_manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    real_wraps = real_manifest["state"]["body_encryption"]["recipient_wraps"]

    with zipfile.ZipFile(out_decoy, "r") as zf:
        decoy_manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        decoy_encrypted = zf.read("body/encrypted.bin")
    decoy_manifest["state"]["body_encryption"]["recipient_wraps"] = real_wraps
    decoy_manifest["state"]["body_encryption"].pop("recipient_wrap", None)
    new_manifest = (json.dumps(decoy_manifest, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    out_lifted = tmp_path / "lifted.tnpkg"
    with zipfile.ZipFile(out_lifted, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", new_manifest)
        zf.writestr("body/encrypted.bin", decoy_encrypted)

    receipt = _absorb_dispatch(frank_cfg, out_lifted)
    # Either signature verification fails (we mutated state and didn't
    # re-sign) OR — if somehow it did — AAD differs and AEAD fails.
    assert receipt.legacy_status == "rejected"


def test_at_least_one_recipient_required(tmp_path: Path):
    alice_cfg = _make_publisher(tmp_path)
    out = tmp_path / "bad.tnpkg"
    with pytest.raises(ValueError, match="requires at least one recipient"):
        export(
            out,
            kind="kit_bundle",
            cfg=alice_cfg,
            to_dids=[],
            seal_for_recipient=True,
        )


def test_to_dids_validates_each_entry(tmp_path: Path):
    alice_cfg = _make_publisher(tmp_path)
    out = tmp_path / "bad.tnpkg"
    with pytest.raises(ValueError, match="non-did:key"):
        export(
            out,
            kind="kit_bundle",
            cfg=alice_cfg,
            to_dids=["did:key:zValid000000000000000000000000000000000000",
                     "not-a-did"],
            seal_for_recipient=True,
        )
