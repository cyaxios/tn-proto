"""Unit tests for tn.identity."""

from __future__ import annotations

import json
import os
import sys

import pytest

from tn.identity import (
    HKDF_INFO_DEVICE,
    HKDF_INFO_VAULT_WRAP,
    HKDF_SALT,
    Identity,
    IdentityError,
    _hkdf,
    _default_identity_dir,
    _default_identity_path,
)

# --- HKDF stability regressions ------------------------------------------


def test_hkdf_info_strings_are_stable():
    """Regression: the HKDF info strings are part of the ABI.

    If this test ever fails because someone changed a byte, users'
    recovery breaks. Either they didn't change it (wire bytes
    unchanged) or they had an extremely good reason + migration plan.
    """
    assert HKDF_SALT == b"tn:v1"
    assert HKDF_INFO_DEVICE == b"tn:device:v1"
    assert HKDF_INFO_VAULT_WRAP == b"tn:vault:wrap:v1"


def test_hkdf_deterministic():
    out1 = _hkdf(b"x" * 32, b"info-a", 32)
    out2 = _hkdf(b"x" * 32, b"info-a", 32)
    assert out1 == out2
    assert len(out1) == 32
    out3 = _hkdf(b"x" * 32, b"info-b", 32)
    assert out3 != out1


# --- Mnemonic round-trip -------------------------------------------------


def test_mnemonic_roundtrip_produces_same_did_and_seed():
    a = Identity.create_new()
    assert a._mnemonic is not None
    # Re-derive from the same words — must yield the same DID.
    b = Identity.from_mnemonic(a._mnemonic)
    assert a.did == b.did
    assert a.device_pub_b64 == b.device_pub_b64
    assert a.device_priv_b64_enc == b.device_priv_b64_enc


def test_mnemonic_different_words_different_did():
    a = Identity.create_new()
    c = Identity.create_new()
    assert a.did != c.did
    assert a._mnemonic != c._mnemonic


def test_mnemonic_rejects_bad_checksum():
    bad = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon wrong"
    )
    with pytest.raises(IdentityError):
        Identity.from_mnemonic(bad)


def test_mnemonic_word_count_variants():
    for n in (12, 15, 18, 21, 24):
        ident = Identity.create_new(word_count=n)
        assert len(ident._mnemonic.split()) == n


# --- DID shape -----------------------------------------------------------


def test_did_is_did_key_ed25519():
    ident = Identity.create_new()
    assert ident.did.startswith("did:key:z")
    # Ed25519 did:key values under multicodec 0xed01 start with 'z6Mk'
    assert ident.did.startswith("did:key:z6Mk")


# --- Vault wrap key ------------------------------------------------------


def test_vault_wrap_key_deterministic_from_same_mnemonic():
    a = Identity.create_new()
    b = Identity.from_mnemonic(a._mnemonic)
    assert a.vault_wrap_key() == b.vault_wrap_key()
    assert len(a.vault_wrap_key()) == 32


def test_vault_wrap_key_requires_seed():
    ident = Identity.create_ephemeral()
    # Ephemeral identity has no seed — vault_wrap_key must refuse.
    with pytest.raises(IdentityError):
        ident.vault_wrap_key()


def test_vault_wrap_key_differs_from_device_key():
    a = Identity.create_new()
    assert a.vault_wrap_key() != a.device_private_key_bytes()


# --- Ephemeral identity --------------------------------------------------


def test_create_ephemeral_yields_valid_did():
    a = Identity.create_ephemeral()
    assert a.did.startswith("did:key:z6Mk")
    assert a._ephemeral is True
    assert a._mnemonic is None


def test_ephemeral_refuses_persistence(tmp_path):
    a = Identity.create_ephemeral()
    with pytest.raises(IdentityError):
        a.ensure_written(tmp_path / "identity.json")


# --- Persistence ---------------------------------------------------------


def test_ensure_written_roundtrips(tmp_path):
    a = Identity.create_new()
    p = a.ensure_written(tmp_path / "identity.json")
    assert p.exists()
    b = Identity.load(p)
    assert a.did == b.did
    assert a.device_pub_b64 == b.device_pub_b64


def test_ensure_written_never_persists_mnemonic(tmp_path):
    a = Identity.create_new()
    p = a.ensure_written(tmp_path / "identity.json")
    raw = p.read_text(encoding="utf-8")
    assert a._mnemonic not in raw
    # No mnemonic-related key appears
    doc = json.loads(raw)
    assert "mnemonic" not in {k.lower() for k in doc}


def test_ensure_written_perms_0600_on_posix(tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX-only permission check")
    a = Identity.create_new()
    p = a.ensure_written(tmp_path / "identity.json")
    mode = os.stat(p).st_mode & 0o777
    assert mode == 0o600


def test_load_missing_raises(tmp_path):
    with pytest.raises(IdentityError):
        Identity.load(tmp_path / "nope.json")


def test_load_corrupt_raises(tmp_path):
    p = tmp_path / "identity.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(IdentityError):
        Identity.load(p)


def test_load_wrong_schema_version_raises(tmp_path):
    p = tmp_path / "identity.json"
    p.write_text(
        json.dumps(
            {
                "version": 999,
                "did": "did:key:z6Mkxxx",
                "device_pub_b64": "aa",
                "device_priv_b64_enc": "bb",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(IdentityError):
        Identity.load(p)


def test_load_or_ephemeral_returns_ephemeral_when_missing(tmp_path):
    ident = Identity.load_or_ephemeral(tmp_path / "nope.json")
    assert ident._ephemeral is True


def test_load_or_ephemeral_returns_loaded_when_present(tmp_path):
    a = Identity.create_new()
    p = a.ensure_written(tmp_path / "identity.json")
    b = Identity.load_or_ephemeral(p)
    assert b.did == a.did
    assert b._ephemeral is False


# --- Default paths -------------------------------------------------------


def test_default_identity_dir_respects_xdg_on_posix(monkeypatch, tmp_path):
    if sys.platform == "win32":
        pytest.skip("XDG is POSIX")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert _default_identity_dir() == tmp_path / "tn"
    assert _default_identity_path() == tmp_path / "tn" / "identity.json"


def test_default_identity_dir_respects_appdata_on_windows(monkeypatch, tmp_path):
    if sys.platform != "win32":
        pytest.skip("Windows-only")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    assert _default_identity_dir() == tmp_path / "tn"


# --- Linked vault + prefs ------------------------------------------------


def test_linked_vault_and_prefs_persist(tmp_path):
    a = Identity.create_new()
    a.linked_vault = "https://api.cyaxios.com"
    a.prefs.default_new_ceremony_mode = "linked"
    a.prefs_version = 3
    p = a.ensure_written(tmp_path / "identity.json")
    b = Identity.load(p)
    assert b.linked_vault == "https://api.cyaxios.com"
    assert b.prefs.default_new_ceremony_mode == "linked"
    assert b.prefs_version == 3


def test_fresh_identity_defaults_mode_local():
    a = Identity.create_new()
    assert a.prefs.default_new_ceremony_mode == "local"
    assert a.linked_vault is None
