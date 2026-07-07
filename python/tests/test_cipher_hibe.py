"""Round-trip, grant, and dispatch tests for the HIBE group cipher class.

Needs the tn._native extension (tn-hibe submodule) — run from a venv with
the wheel installed or after `maturin develop`.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tn import _hibe
from tn.cipher import (
    BtnGroupCipher,
    HibeGroupCipher,
    JWEGroupCipher,
    NotARecipientError,
)


def _hibe_available() -> bool:
    try:
        _hibe.setup(1)
    except RuntimeError as exc:
        if "HIBE native extension is unavailable" in str(exc):
            return False
        raise
    return True


pytestmark = pytest.mark.skipif(
    not _hibe_available(),
    reason="tn._native was built without the HIBE submodule",
)


def test_hibe_solo_mint_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        c = HibeGroupCipher.create(ks, "g1")
        blob = c.encrypt(b"section body")
        assert c.decrypt(blob) == b"section body"
        # Solo mint leaves the authority material in the keystore.
        assert (ks / "g1.hibe.msk").exists()
        assert (ks / "g1.hibe.sk").exists()


def test_hibe_load_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        created = HibeGroupCipher.create(ks, "g1")
        sealed_before = created.encrypt(b"before reload")
        loaded = HibeGroupCipher.load(ks, "g1")
        assert loaded.decrypt(sealed_before) == b"before reload"
        assert created.decrypt(loaded.encrypt(b"after reload")) == b"after reload"
        assert loaded.id_path() == "self"
        assert loaded.mpk_fingerprint() == created.mpk_fingerprint()


def test_hibe_external_authority_write_only_then_granted() -> None:
    """Sealing to an external authority: writable at once, readable only
    after the granted identity key lands (what absorb will install)."""
    mpk, msk = _hibe.setup(2)
    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        c = HibeGroupCipher.create(ks, "g1", authority_mpk=mpk, id_path="reader-did/policy-1")
        blob = c.encrypt(b"governed")
        try:
            c.decrypt(blob)
            raise AssertionError("decrypt must fail before a key is granted")
        except NotARecipientError:
            pass
        # The authority grants the exact-path key (Phase 5 ships this as a
        # hibe-id-key kit; installing the file is what absorb will do).
        (ks / "g1.hibe.sk").write_bytes(_hibe.keygen(mpk, msk, "reader-did/policy-1"))
        assert HibeGroupCipher.load(ks, "g1").decrypt(blob) == b"governed"


def test_hibe_ancestor_key_derives_down() -> None:
    """A key for a PARENT path opens the group by delegating down locally."""
    mpk, msk = _hibe.setup(2)
    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        c = HibeGroupCipher.create(ks, "g1", authority_mpk=mpk, id_path="reader-did/policy-1")
        blob = c.encrypt(b"delegated read")
        (ks / "g1.hibe.sk").write_bytes(_hibe.keygen(mpk, msk, "reader-did"))
        assert HibeGroupCipher.load(ks, "g1").decrypt(blob) == b"delegated read"


def test_hibe_wrong_path_key_cannot_decrypt() -> None:
    mpk, msk = _hibe.setup(2)
    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        c = HibeGroupCipher.create(ks, "g1", authority_mpk=mpk, id_path="reader-did/policy-1")
        blob = c.encrypt(b"not for you")
        (ks / "g1.hibe.sk").write_bytes(_hibe.keygen(mpk, msk, "other-did/policy-1"))
        try:
            HibeGroupCipher.load(ks, "g1").decrypt(blob)
            raise AssertionError("wrong-path key must not decrypt")
        except NotARecipientError:
            pass


def test_hibe_grant_helpers() -> None:
    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        authority = HibeGroupCipher.create(ks, "g1", id_path="team/reader")
        blob = authority.encrypt(b"for the team")
        # msk holder mints a parent key; parent delegates down without msk.
        parent_sk = authority.mint_reader_key("team")
        child_sk = _hibe.delegate(authority.mpk(), parent_sk, "reader")
        assert _hibe.key_id_path(child_sk) == "team/reader"
        assert _hibe.open(authority.mpk(), child_sk, blob) == b"for the team"


def test_cipher_interchangeability() -> None:
    """The same caller code round-trips btn, jwe, and hibe groups with no
    branching on cipher kind — the deliverable of the HIBE spec."""
    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        ciphers = [
            BtnGroupCipher.create(ks, "g_btn"),
            JWEGroupCipher.create(ks, "g_jwe", recipient_dids=["self"]),
            HibeGroupCipher.create(ks, "g_hibe"),
        ]
        for c in ciphers:
            assert c.decrypt(c.encrypt(b"same code path")) == b"same code path", c.name


def test_config_mint_and_load_dispatch() -> None:
    from tn import config as config_mod

    with tempfile.TemporaryDirectory() as td:
        ks = Path(td)
        gc = config_mod._create_group(
            ks,
            "governed",
            master_index_key=b"\x01" * 32,
            ceremony_id="cer-hibe-test",
            cipher_name="hibe",
        )
        assert gc.cipher.name == "hibe"
        blob = gc.cipher.encrypt(b"minted via config")
        loaded = config_mod._instantiate_group_cipher("governed", "hibe", ks)
        assert loaded.decrypt(blob) == b"minted via config"
        # Unknown ciphers still refuse loudly.
        try:
            config_mod._create_group(
                ks,
                "nope",
                master_index_key=b"\x01" * 32,
                ceremony_id="cer-hibe-test",
                cipher_name="rot13",
            )
            raise AssertionError("unknown cipher must raise")
        except ValueError:
            pass


def main() -> int:
    tests = [
        test_hibe_solo_mint_roundtrip,
        test_hibe_load_roundtrip,
        test_hibe_external_authority_write_only_then_granted,
        test_hibe_ancestor_key_derives_down,
        test_hibe_wrong_path_key_cannot_decrypt,
        test_hibe_grant_helpers,
        test_cipher_interchangeability,
        test_config_mint_and_load_dispatch,
    ]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"all {len(tests)} hibe cipher tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
