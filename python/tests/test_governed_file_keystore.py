"""Persistent examples run publication and reading in separate Python processes."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from tn.providers import FileKeyStore

EXAMPLES = Path(os.environ.get("TN_PERSISTENT_EXAMPLES", Path(__file__).resolve().parents[1] / "examples" / "persistent_keys"))

def run(script, *args):
    return subprocess.run([sys.executable,"-B",str(EXAMPLES / script),*map(str,args)],check=True,capture_output=True,text=True).stdout.strip()

@pytest.mark.parametrize("cipher", ["btn", "jwe", "hibe"])
def test_example_reopens_saved_keys_in_another_process(tmp_path, cipher):
    root = tmp_path / cipher
    assert cipher.upper() in run("setup.py",root,"--cipher",cipher)
    key_path = root / "keys" / "keystore.json"
    key_bytes = key_path.read_bytes()
    first = FileKeyStore.open(key_path).resolve("hello-service").did
    assert run(f"hello_{cipher}.py",root,"publish") == "Published hello.tn"
    retained = {p.name:p.read_bytes() for p in root.glob("*.jsonl")}
    wire = (root / "hello.tn").read_bytes()
    assert run(f"hello_{cipher}.py",root,"read") == "Hello, world!"
    assert key_path.read_bytes() == key_bytes
    assert (root / "hello.tn").read_bytes() == wire
    assert {p.name:p.read_bytes() for p in root.glob("*.jsonl")} == retained
    assert FileKeyStore.open(key_path).resolve("hello-service").did == first
    assert sorted(str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*") if p.is_file()) == ["agents.md","config.json","creations.jsonl","hello.tn","keys/keystore.json","releases.jsonl"]
    envelope = json.loads(wire)
    for group in ["messages","tn.agents"]:
        ciphertext = base64.b64decode(envelope[group]["ciphertext"])
        if cipher == "btn":
            assert ciphertext[:3] == bytes([0xb7,1,1])
        elif cipher == "hibe":
            from tn import _hibe
            stored = next(g for g in json.loads(key_bytes)["groups"] if g["name"] == group)["material"]
            assert _hibe.key_id_path(bytes(stored["reader"])) == group
            assert ciphertext
        else:
            jwe = json.loads(ciphertext)
            protected = json.loads(base64.urlsafe_b64decode(jwe["protected"] + "=="))
            assert protected["enc"] == "A256GCM"
            assert jwe["recipients"][0]["header"]["alg"] == "ECDH-ES+A256KW"
            assert "aad" in jwe
            # Independently open the real TN group's JWE with joserfc.
            from joserfc import jwe as jose
            from joserfc.jwk import OKPKey
            stored = next(g for g in json.loads(key_bytes)["groups"] if g["name"] == group)["material"]
            encode = lambda b: base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode()
            key = OKPKey.import_key({"kty":"OKP","crv":"X25519","x":encode(stored["public"]),"d":encode(stored["private"])})
            recipient = jwe["recipients"][0]
            flattened = {k:v for k,v in jwe.items() if k != "recipients"}
            flattened.update(recipient)
            plaintext = jose.decrypt_json(flattened,key,algorithms=["ECDH-ES+A256KW","A256GCM"]).plaintext
            fields = json.loads(plaintext)
            if group == "messages":
                assert fields["message"] == "Hello, world!"
            else:
                assert fields["policy"].startswith("agents.md#hello.message@")
                assert fields["instruction"] == "Read and display the greeting."

@pytest.mark.parametrize("cipher", ["btn", "jwe", "hibe"])
def test_file_provider_refuses_overwrite_and_foreign_identity(tmp_path, cipher):
    path = tmp_path / "keys.json"
    store = FileKeyStore.create(path,"app",["messages"],cipher=cipher)
    original = path.read_bytes()
    with pytest.raises(OSError): FileKeyStore.create(path,"app",["messages"],cipher=cipher)
    assert path.read_bytes() == original
    with pytest.raises(ValueError): store.resolve("other")
    other = FileKeyStore.create(tmp_path / "other.json","other",["messages"],cipher=cipher)
    with pytest.raises(ValueError): store.resolve(other.resolve("other"))
    assert store.resolve(store.resolve("app")).groups == ["messages","tn.agents"]
    assert store.cipher == cipher

def test_missing_store_is_not_created(tmp_path):
    path = tmp_path / "missing.json"
    with pytest.raises(OSError): FileKeyStore.open(path)
    assert not path.exists()


def test_hibe_delegated_governed_example():
    assert run("hibe_delegation.py") == "Delegated grant: governed greeting opened; sibling grant rejected"
