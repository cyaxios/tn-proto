from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _normalized(relative: str) -> str:
    return " ".join(_text(relative).replace("//!", " ").replace(">", " ").split())


def test_ceremony_guide_describes_secure_default_read_and_explicit_weakening() -> None:
    guide = _normalized("docs/guide/jwe-hibe-key-ceremonies.md")
    assert "ordinary `tn.read()` also defaults to verification off" not in guide.lower()
    for phrase in (
        "`tn.read()` is secure by default",
        '`verify="auto"`',
        '`verify="skip"`',
        "`verify=False`",
    ):
        assert phrase in guide


def test_ceremony_guide_distinguishes_skip_from_security_weakening() -> None:
    guide = _normalized("docs/guide/jwe-hibe-key-ceremonies.md")
    for phrase in (
        '`verify="skip"` retains the same checks',
        "drops rejected records",
        "Actual weakening remains explicit",
    ):
        assert phrase in guide


def test_ceremony_guide_requires_both_foreign_unsigned_overrides() -> None:
    guide = _normalized("docs/guide/jwe-hibe-key-ceremonies.md")
    assert (
        "Foreign or detached unsigned records require both "
        "`require_signature=False` and `allow_unauthenticated=True`"
    ) in guide


def test_ceremony_guide_pins_depth_and_key_authenticity_rules() -> None:
    guide = _text("docs/guide/jwe-hibe-key-ceremonies.md")
    assert "max_depth=3" in guide
    assert "mpk_max_depth" in guide
    assert "mpk_fingerprint" in guide
    assert "authenticated binding" in guide
    assert "does not authenticate" in guide


def test_ceremony_guide_documents_real_delivery_and_rotation_semantics() -> None:
    guide = _text("docs/guide/jwe-hibe-key-ceremonies.md")
    for phrase in (
        "bearer capability",
        "recipient_key_is_resolvable",
        "plaintext",
        "bundle_for_recipient",
        "BTN-only",
        "external writers",
        "new sibling path",
        "re-enrolled",
    ):
        assert phrase in guide


def test_jwe_epk_and_aad_claims_are_qualified() -> None:
    guide = _normalized("docs/guide/jwe-hibe-key-ceremonies.md")
    for text in (guide,):
        assert "ephemeral `epk` per recipient" in text
        assert "unsigned and unchained" in text
        assert "decryption" in text


def test_hibe_howto_and_protocol_keep_capability_and_trust_caveats() -> None:
    for relative in ("docs/guide/hibe-howto.md", "docs/guide/protocol.md"):
        text = _normalized(relative).lower()
        assert "bearer capability" in text, relative
        assert "external writer" in text, relative
        assert "ancestor" in text, relative
        assert "does not authenticate" in text, relative
        assert "unsigned and unchained" in text, relative

    howto = _text("docs/guide/hibe-howto.md")
    assert "recipient_key_is_resolvable" in howto
    assert 'reader_did="did:key:z6MkAlice"' not in howto


def test_cross_guide_package_and_rotation_tables_are_cipher_specific() -> None:
    getting_started = _normalized("docs/guide/getting-started.md")
    groups = _normalized("docs/guide/groups-readers-rotation.md")
    assert "BTN-only reader-kit packaging" in getting_started
    assert "`tn.admin.rotate(\"g\")` (BTN/JWE)" in getting_started
    assert "JWE does not emit those BTN survivor kits" in groups
    assert "publisher's self-recipient" in groups
    assert "re-enroll" in groups
