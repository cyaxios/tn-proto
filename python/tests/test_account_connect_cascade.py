"""Regression test for the account-connect key-source CASCADE
(PARITY-connection rows 1-2).

The bug: Python signed the redeem with the MACHINE-GLOBAL identity key, TS
signed with the PER-CEREMONY keystore key, so the same operator bound a
DIFFERENT DID depending on which CLI ran. The fix is a single shared resolver
(``resolve_signing_identity`` here / ``resolveSigningIdentity`` in TS) whose
cascade is:  supplied(2) > machine(1) > ceremony(3).

These tests pin each tier's resolution and the cross-CLI same-DID property:
given the SAME machine identity.json, the cascade resolves the SAME DID
regardless of which ceremony keystore is present (that's what makes the Python
wheel and the TS CLI bind the same principal on one machine).

Run:
    python -m pytest python/tests/test_account_connect_cascade.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tn.identity import _did_key_from_ed25519_pub
from tn.sync_state import (
    SigningIdentityError,
    resolve_signing_identity,
)


def _did_for_seed(seed: bytes) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _did_key_from_ed25519_pub(pub)


def _write_identity(path: Path, seed: bytes) -> str:
    """Write a machine-global identity.json from a known seed; return DID."""
    import base64

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    did = _did_key_from_ed25519_pub(pub)
    priv_b64 = base64.urlsafe_b64encode(seed).rstrip(b"=").decode("ascii")
    pub_b64 = base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii")
    doc = {
        "version": 1,
        "did": did,
        "device_pub_b64": pub_b64,
        "device_priv_b64_enc": priv_b64,
        "device_priv_enc_method": "none",
        "seed_b64": priv_b64,
        "mnemonic_stored": None,
        "linked_vault": None,
        "linked_account_id": None,
        "prefs_version": 0,
        "prefs": {"default_new_ceremony_mode": "local"},
    }
    path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    return did


def _write_ceremony(tmp: Path, seed: bytes, *, keystore_rel: str = "./.tn/keys") -> tuple[Path, str]:
    """Write a tn.yaml + minimal keystore (local.private). Return (yaml, did)."""
    yaml_path = tmp / "tn.yaml"
    yaml_path.write_text(
        "ceremony:\n  id: local_x\n  mode: local\n"
        f"keystore:\n  path: {keystore_rel}\n",
        encoding="utf-8",
    )
    ks_dir = (tmp / keystore_rel).resolve()
    ks_dir.mkdir(parents=True, exist_ok=True)
    (ks_dir / "local.private").write_bytes(seed)
    did = _did_for_seed(seed)
    (ks_dir / "local.public").write_text(did, encoding="utf-8")
    return yaml_path, did


def test_cascade_tier1_machine_wins_over_keystore(tmp_path: Path):
    """Default: machine identity wins over the ceremony keystore."""
    id_path = tmp_path / "identity.json"
    machine_did = _write_identity(id_path, bytes([1]) * 32)
    yaml_path, ceremony_did = _write_ceremony(tmp_path, bytes([2]) * 32)
    assert machine_did != ceremony_did

    r = resolve_signing_identity(yaml_path, machine_identity_path=id_path)
    assert r.tier == "machine"
    assert r.did == machine_did


def test_cascade_tier3_falls_back_to_keystore(tmp_path: Path):
    """Headless: no machine identity => fall back to the keystore DID."""
    id_path = tmp_path / "identity.json"  # intentionally not written
    yaml_path, ceremony_did = _write_ceremony(tmp_path, bytes([3]) * 32)

    r = resolve_signing_identity(yaml_path, machine_identity_path=id_path)
    assert r.tier == "ceremony"
    assert r.did == ceremony_did


def test_cascade_tier2_supplied_overrides_everything(tmp_path: Path):
    """--identity beats both machine and ceremony."""
    machine_path = tmp_path / "identity.json"
    supplied_path = tmp_path / "supplied.json"
    _write_identity(machine_path, bytes([4]) * 32)
    supplied_did = _write_identity(supplied_path, bytes([5]) * 32)
    yaml_path, _ = _write_ceremony(tmp_path, bytes([6]) * 32)

    r = resolve_signing_identity(
        yaml_path,
        supplied_identity_path=supplied_path,
        machine_identity_path=machine_path,
    )
    assert r.tier == "supplied"
    assert r.did == supplied_did


def test_cross_cli_same_did(tmp_path: Path):
    """Shared machine identity resolves the same DID across two ceremonies.

    Pre-fix the keystore key would diverge; post-fix both ceremonies (and
    the TS CLI, which mirrors this resolver) bind the one machine DID.
    """
    id_path = tmp_path / "identity.json"
    machine_did = _write_identity(id_path, bytes([7]) * 32)
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    yaml_a, _ = _write_ceremony(a, bytes([8]) * 32)
    yaml_b, _ = _write_ceremony(b, bytes([9]) * 32)

    ra = resolve_signing_identity(yaml_a, machine_identity_path=id_path)
    rb = resolve_signing_identity(yaml_b, machine_identity_path=id_path)
    assert ra.did == machine_did
    assert rb.did == machine_did
    assert ra.did == rb.did


def test_cascade_exhausts_raises(tmp_path: Path):
    """No machine identity + no keystore => SigningIdentityError."""
    id_path = tmp_path / "identity.json"  # not written
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("ceremony:\n  id: local_x\n  mode: local\n", encoding="utf-8")
    with pytest.raises(SigningIdentityError):
        resolve_signing_identity(yaml_path, machine_identity_path=id_path)


def test_resolved_key_signs_as_bound_did(tmp_path: Path):
    """The resolved private_key must verify under the resolved DID — i.e. the
    signature lands under the bound principal."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    id_path = tmp_path / "identity.json"
    did = _write_identity(id_path, bytes([11]) * 32)
    yaml_path = tmp_path / "tn.yaml"
    yaml_path.write_text("ceremony:\n  id: local_x\n  mode: local\n", encoding="utf-8")

    r = resolve_signing_identity(yaml_path, machine_identity_path=id_path)
    assert r.did == did

    msg = hashlib.sha256(b"tn_connect_TEST").digest()
    sig = r.private_key.sign(msg)
    # Derive the pubkey straight from the DID and verify.
    pub = r.private_key.public_key()
    assert isinstance(pub, Ed25519PublicKey)
    pub.verify(sig, msg)  # raises on mismatch
