"""Persist and restore - state, kits, and ciphertexts are all just bytes.

The producer state serializes with to_bytes()/from_bytes() (it holds the master
seed - secret). Kits and ciphertexts are already bytes. Where they live - a
file here, a vault, a KMS - is entirely your call."""

import pathlib
from tn import btn

p = btn.setup()
alice_kit = p.mint()
ct = p.encrypt(b'{"order": "A100"}')

# Save whatever you like, wherever you like. Here: temp files.
here = pathlib.Path(__file__).parent
(here / "producer.state").write_bytes(p.to_bytes())     # secret: holds the seed
(here / "alice.kit").write_bytes(alice_kit)
(here / "message.ct").write_bytes(ct)

# Later, in another process: load and carry on.
p2 = btn.Producer.from_bytes((here / "producer.state").read_bytes())
kit2 = (here / "alice.kit").read_bytes()
ct2 = (here / "message.ct").read_bytes()

print("restored producer seals + reads:", p2.decrypt(p2.encrypt(b'{"order": "A101"}')))
print("restored kit opens restored ct :", btn.subscribe(kit2).decrypt(ct2))

for f in ("producer.state", "alice.kit", "message.ct"):
    (here / f).unlink()
