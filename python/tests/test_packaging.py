from tn.packaging import Package, _canonical_bytes


def test_canonical_bytes_is_deterministic():
    pkg = Package(
        package_version=1,
        package_kind="enrolment",
        ceremony_id="local_abc123",
        group="finance",
        group_epoch=1,
        signer_did="did:key:z6MkAlice",
        signer_verify_pub_b64="AAAA",
        peer_did="did:key:z6MkBob",
        payload={"publisher_did": "did:key:z6MkAlice", "sender_pub_b64": "BBBB"},
        compiled_at="2026-04-21T17:22:00Z",
    )
    assert _canonical_bytes(pkg) == _canonical_bytes(pkg)
    assert isinstance(_canonical_bytes(pkg), bytes)


def test_canonical_bytes_excludes_signature():
    pkg1 = Package(
        package_version=1,
        package_kind="enrolment",
        ceremony_id="c",
        group="g",
        group_epoch=1,
        signer_did="did:key:a",
        signer_verify_pub_b64="x",
        peer_did="did:key:b",
        payload={},
        compiled_at="2026-04-21T00:00:00Z",
    )
    pkg2 = Package(**{**pkg1.__dict__, "sig_b64": "some-signature"})
    assert _canonical_bytes(pkg1) == _canonical_bytes(pkg2)


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tn.packaging import sign, verify


def _mk_pkg():
    return Package(
        package_version=1,
        package_kind="enrolment",
        ceremony_id="c",
        group="g",
        group_epoch=1,
        signer_did="did:key:alice",
        signer_verify_pub_b64="",
        peer_did="did:key:bob",
        payload={"k": "v"},
        compiled_at="2026-04-21T00:00:00Z",
    )


def test_sign_fills_sig_and_pub():
    sk = Ed25519PrivateKey.generate()
    pkg = sign(_mk_pkg(), sk)
    assert pkg.sig_b64 and pkg.signer_verify_pub_b64


def test_verify_accepts_good_sig():
    sk = Ed25519PrivateKey.generate()
    assert verify(sign(_mk_pkg(), sk)) is True


def test_verify_rejects_tampered_payload():
    sk = Ed25519PrivateKey.generate()
    pkg = sign(_mk_pkg(), sk)
    pkg.payload["k"] = "TAMPERED"
    assert verify(pkg) is False


def test_verify_rejects_missing_sig():
    assert verify(_mk_pkg()) is False


from pathlib import Path

from tn.packaging import dump_tnpkg, load_tnpkg


def test_tnpkg_round_trip(tmp_path: Path):
    sk = Ed25519PrivateKey.generate()
    pkg = sign(_mk_pkg(), sk)
    path = tmp_path / "p.tnpkg"
    dump_tnpkg(pkg, path)
    loaded = load_tnpkg(path)
    assert loaded.sig_b64 == pkg.sig_b64
    assert loaded.payload == pkg.payload
    assert verify(loaded) is True
