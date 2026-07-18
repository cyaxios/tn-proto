
# TN_TEST_CIPHER reruns this workflow under another cipher (the cipher-parity
# sweep, tests/run_cipher_sweep.py). Unset, behavior is byte-identical.
import os as _cipher_os


def _workflow_cipher(default: str) -> str:
    return _cipher_os.environ.get("TN_TEST_CIPHER", default)

import base64
import importlib
from pathlib import Path

from tn.config import load_or_create
from tn.conventions import outbox_dir
from tn.offer import offer
from tn.packaging import verify
from tn.signing import DeviceKey


def test_offer_emits_signed_package(tmp_path: Path):
    yaml_path = tmp_path / "tn.yaml"
    cfg = load_or_create(yaml_path, cipher=_workflow_cipher("jwe"))
    publisher = DeviceKey.generate()
    pkg = offer(cfg, publisher_did=publisher.did, ceremony_id="remote-a")
    assert pkg.package_kind == "offer"
    assert pkg.recipient_identity == publisher.did
    assert "x25519_pub_b64" in pkg.payload
    assert len(base64.b64decode(pkg.payload["x25519_pub_b64"])) == 32
    assert verify(pkg) is True
    assert list(outbox_dir(tmp_path).glob("*.tnpkg"))


def test_offer_reuses_existing_mykey(tmp_path: Path):
    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    publisher_a = DeviceKey.generate()
    publisher_b = DeviceKey.generate()
    pkg1 = offer(cfg, publisher_did=publisher_a.did, ceremony_id="remote-a")
    pub1 = pkg1.payload["x25519_pub_b64"]
    pkg2 = offer(cfg, publisher_did=publisher_b.did, ceremony_id="remote-b")
    pub2 = pkg2.payload["x25519_pub_b64"]
    assert pub1 == pub2, "the same mykey should back both offers; one pub per group is the design"


def test_offer_persists_reader_key_with_secret_writer(tmp_path: Path, monkeypatch):
    offer_module = importlib.import_module("tn.offer")
    writes: list[tuple[Path, bytes]] = []

    def secret_write(path: Path, data: bytes) -> None:
        writes.append((Path(path), data))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    monkeypatch.setattr(offer_module, "atomic_write_bytes", secret_write, raising=False)

    cfg = load_or_create(tmp_path / "tn.yaml", cipher=_workflow_cipher("jwe"))
    (cfg.keystore / "default.jwe.mykey").unlink(missing_ok=True)
    offer_module.offer(
        cfg,
        publisher_did=DeviceKey.generate().did,
        ceremony_id="remote-a",
    )

    assert len(writes) == 1
    assert writes[0][0] == cfg.keystore / "default.jwe.mykey"
    assert len(writes[0][1]) == 32
