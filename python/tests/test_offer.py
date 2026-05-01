import base64
from pathlib import Path

from tn.config import load_or_create
from tn.conventions import outbox_dir
from tn.offer import offer
from tn.packaging import verify


def test_offer_emits_signed_package(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher="jwe")
    pkg = offer(cfg, publisher_did="did:key:z6MkAlice")
    assert pkg.package_kind == "offer"
    assert pkg.peer_did == "did:key:z6MkAlice"
    assert "x25519_pub_b64" in pkg.payload
    assert len(base64.b64decode(pkg.payload["x25519_pub_b64"])) == 32
    assert verify(pkg) is True
    assert list(outbox_dir(tmp_path).glob("*.tnpkg"))


def test_offer_reuses_existing_mykey(tmp_path: Path):
    cfg = load_or_create(tmp_path / "tn.yaml", cipher="jwe")
    pkg1 = offer(cfg, publisher_did="did:key:z6MkAlice")
    pub1 = pkg1.payload["x25519_pub_b64"]
    pkg2 = offer(cfg, publisher_did="did:key:z6MkBob")
    pub2 = pkg2.payload["x25519_pub_b64"]
    assert pub1 == pub2, "the same mykey should back both offers; one pub per group is the design"
